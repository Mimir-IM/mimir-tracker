use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ironwood::Addr;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use ygg_stream::{ConnectHandle, DatagramListener, StreamManager};
use yggdrasil::config::Config;
use yggdrasil::core::Core;

// ── Protocol constants ───────────────────────────────────────────────────────

const VERSION: u8 = 1;
const PORT_TRACKER: u16 = 69;

const CMD_ANNOUNCE: u8 = 0;
const CMD_GET_ADDRS: u8 = 1;
const CMD_SYNC_DATA: u8 = 10;
const CMD_SYNC_PING: u8 = 20;

const MAX_HOP_COUNT: u8 = 3;

const KEY_FILE: &str = "tracker.key";
const DATA_FILE: &str = "data.bin";

// ── Data types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    node_pub: [u8; 32],
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    priority: u8,
    client_id: u32,
    expires: SystemTime,
    prev_ttl: u32,
}

#[derive(Clone, Debug)]
struct SyncItem {
    key: [u8; 32],
    data: Record,
    hop: u8,
}

struct TrackerState {
    records: RwLock<HashMap<[u8; 32], Vec<Record>>>,
    recent: RwLock<HashMap<[u8; 32], Instant>>,
    connected: Mutex<HashSet<[u8; 32]>>,
    sync_tx: broadcast::Sender<SyncItem>,
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,mimir_tracker=debug,ygg_stream=info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optmulti("p", "peer", "Yggdrasil peer URI (repeatable)", "URI");
    opts.optmulti("s", "server", "Tracker peer public key hex (repeatable)", "HEX");
    opts.optopt("k", "key", "Hex-encoded 32-byte private key seed", "HEX");
    opts.optflag("h", "help", "Print help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage("Usage: mimir-tracker [options]"));
            std::process::exit(1);
        }
    };

    if matches.opt_present("h") {
        print!("{}", opts.usage("Usage: mimir-tracker [options]"));
        return;
    }

    let peers: Vec<String> = matches.opt_strs("p");
    let servers: Vec<String> = matches.opt_strs("s");

    if peers.is_empty() {
        eprintln!("{}", opts.usage("Usage: mimir-tracker -p PEER [-p PEER ...] [-s SERVER ...] [-k KEY]"));
        std::process::exit(1);
    }

    // Key management
    let signing_key = match matches.opt_str("k") {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key.trim()).expect("Invalid hex key");
            assert_eq!(bytes.len(), 32, "Key must be exactly 32 bytes");
            let seed: [u8; 32] = bytes.try_into().unwrap();
            let sk = SigningKey::from_bytes(&seed);
            info!("Using provided key, public: {}", hex::encode(sk.verifying_key().as_bytes()));
            sk
        }
        None => load_or_gen_key(),
    };

    let pub_key_bytes: [u8; 32] = *signing_key.verifying_key().as_bytes();

    // Load persisted records
    let records = load_records(DATA_FILE);
    info!("Loaded {} user entries from {}", records.len(), DATA_FILE);

    // Shared state
    let (sync_tx, _) = broadcast::channel::<SyncItem>(512);
    let state = Arc::new(TrackerState {
        records: RwLock::new(records),
        recent: RwLock::new(HashMap::new()),
        connected: Mutex::new(HashSet::new()),
        sync_tx,
    });

    // Start Yggdrasil node
    let mut config = Config::default();
    config.peers = peers;
    let core = Core::new(signing_key.clone(), config);
    core.init_links().await;
    core.start().await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    info!("Tracker started, public key: {}", hex::encode(pub_key_bytes));

    // Create stream manager and split
    let manager = StreamManager::new(core.packet_conn());
    let handle = manager.split();

    // Register listeners
    let dg_listener = handle.listen_datagram(PORT_TRACKER).await;
    let mut stream_listener = handle.listen(PORT_TRACKER).await;

    let cancel = CancellationToken::new();

    // Spawn client datagram handler
    let state_c = state.clone();
    let handle_c = handle.clone();
    let cancel_c = cancel.clone();
    tokio::spawn(async move {
        client_handler(state_c, dg_listener, handle_c, cancel_c).await;
    });

    // Spawn sync acceptor
    let state_a = state.clone();
    let cancel_a = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = stream_listener.accept() => {
                    match result {
                        Ok(mut stream) => {
                            let state = state_a.clone();
                            let cancel = cancel_a.clone();
                            tokio::spawn(async move {
                                // Read 32-byte remote pubkey
                                let mut remote_pub = [0u8; 32];
                                if AsyncReadExt::read_exact(&mut stream, &mut remote_pub).await.is_err() {
                                    return;
                                }
                                if already_connected(&state, &remote_pub).await {
                                    info!("Duplicate sync from {}…, dropping", hex::encode(&remote_pub[..6]));
                                    return;
                                }
                                info!("Accepted sync from {}…", hex::encode(&remote_pub[..6]));
                                mark_connected(&state, &remote_pub).await;
                                run_sync_connection(&state, &mut stream, &remote_pub, cancel).await;
                                mark_disconnected(&state, &remote_pub).await;
                                let _ = stream.shutdown().await;
                            });
                        }
                        Err(e) => {
                            warn!("Accept error: {}", e);
                            break;
                        }
                    }
                }
                _ = cancel_a.cancelled() => break,
            }
        }
    });

    // Spawn outbound sync peers
    for server_hex in &servers {
        let server_hex = server_hex.clone();
        let state = state.clone();
        let handle = handle.clone();
        let cancel = cancel.clone();
        let local_pub = pub_key_bytes;
        tokio::spawn(async move {
            run_sync_peer(state, handle, &server_hex, local_pub, cancel).await;
        });
    }

    // Spawn GC tasks
    let state_gc = state.clone();
    let cancel_gc = cancel.clone();
    tokio::spawn(async move { gc_recent(state_gc, cancel_gc).await });

    let state_gc2 = state.clone();
    let cancel_gc2 = cancel.clone();
    tokio::spawn(async move { gc_records(state_gc2, cancel_gc2).await });

    // Spawn save loop
    let state_save = state.clone();
    let cancel_save = cancel.clone();
    tokio::spawn(async move { save_loop(state_save, cancel_save).await });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down...");
    cancel.cancel();

    // Final save
    let records = state.records.read().await;
    save_records(DATA_FILE, &records);
    info!("Saved {} entries. Goodbye.", records.len());
}

// ── Client handler (datagram-based) ──────────────────────────────────────────

async fn client_handler(state: Arc<TrackerState>, mut dg: DatagramListener, handle: ConnectHandle, cancel: CancellationToken) {
    loop {
        tokio::select! {
            result = dg.recv() => {
                let (data, sender) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };

                if data.len() < 38 || data[0] != VERSION {
                    continue;
                }

                let nonce = u32::from_be_bytes(data[1..5].try_into().unwrap());
                let cmd = data[5];
                let user_pub: [u8; 32] = data[6..38].try_into().unwrap();

                match cmd {
                    CMD_ANNOUNCE => {
                        handle_announce(&state, &handle, &sender, nonce, user_pub, &data[38..]).await;
                    }
                    CMD_GET_ADDRS => {
                        handle_get_addrs(&state, &handle, &sender, nonce, user_pub).await;
                    }
                    _ => {}
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

async fn handle_announce(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, user_pub: [u8; 32], body: &[u8]) {
    // body: priority(1) + clientID(4) + addrPub(32) + signature(64) = 101 bytes
    if body.len() < 101 {
        return;
    }

    let priority = body[0];
    let client_id = u32::from_be_bytes(body[1..5].try_into().unwrap());
    let addr_pub: [u8; 32] = body[5..37].try_into().unwrap();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&body[37..101]);

    info!("Announce addr: {}… from user: {}…", hex::encode(&addr_pub[..8]), hex::encode(&user_pub[..8]));

    // Verify signature: user_pub signs addr_pub
    let verifying_key = match VerifyingKey::from_bytes(&user_pub) {
        Ok(k) => k,
        Err(_) => return,
    };
    let sig = match Signature::from_bytes(&signature) {
        sig => sig,
    };
    if verifying_key.verify(&addr_pub, &sig).is_err() {
        warn!("Wrong signature from {}…", hex::encode(&user_pub[..4]));
        return;
    }

    let mut records = state.records.write().await;

    // Find previous TTL for this client_id + addr_pub combo
    let mut prev_ttl = 2u32;
    if let Some(recs) = records.get(&user_pub) {
        for r in recs {
            if r.client_id == client_id && r.node_pub == addr_pub && r.prev_ttl > 0 {
                prev_ttl = r.prev_ttl;
            }
        }
    }
    let new_ttl = (prev_ttl * 2).min(16);

    let new_record = Record {
        node_pub: addr_pub,
        signature,
        priority,
        client_id,
        expires: SystemTime::now() + Duration::from_secs((new_ttl as u64 + 1) * 60),
        prev_ttl: new_ttl,
    };

    // Replace: keep new record first, remove old records with same client_id
    let old_recs = records.remove(&user_pub).unwrap_or_default();
    let mut new_recs = vec![new_record.clone()];
    for r in old_recs {
        if r.client_id != client_id {
            new_recs.push(r);
        }
    }
    records.insert(user_pub, new_recs);
    drop(records);

    // Send ACK: nonce(4) + cmd(1) + ttl_seconds(8)
    let mut resp = [0u8; 13];
    resp[0..4].copy_from_slice(&nonce.to_be_bytes());
    resp[4] = CMD_ANNOUNCE;
    let ttl_secs = (new_ttl as u64) * 60;
    resp[5..13].copy_from_slice(&ttl_secs.to_be_bytes());

    if let Err(e) = handle.send_datagram(sender, PORT_TRACKER, resp.to_vec()).await {
        warn!("Failed to send announce ACK: {}", e);
    }

    // Push to sync peers
    let _ = state.sync_tx.send(SyncItem {
        key: user_pub,
        data: new_record,
        hop: MAX_HOP_COUNT,
    });
    mark_recent(state, &user_pub).await;
}

async fn handle_get_addrs(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, user_pub: [u8; 32]) {
    let records = state.records.read().await;
    let recs = records.get(&user_pub).cloned().unwrap_or_default();
    drop(records);

    info!("Search for {}…", hex::encode(&user_pub[..4]));

    let now = SystemTime::now();

    // Filter out expired records
    let valid: Vec<&Record> = recs.iter().filter(|r| r.expires > now).collect();

    // Build response: nonce(4) + cmd(1) + count(1) + N*(addrPub(32)+sig(64)+priority(1)+clientID(4)+expiresMs(8))
    let mut buf = Vec::with_capacity(6 + valid.len() * 109);
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.push(CMD_GET_ADDRS);
    buf.push(valid.len() as u8);

    for r in &valid {
        buf.extend_from_slice(&r.node_pub);
        buf.extend_from_slice(&r.signature);
        buf.push(r.priority);
        buf.extend_from_slice(&r.client_id.to_be_bytes());
        let expires_ms = r.expires.duration_since(now).unwrap_or_default().as_millis() as u64;
        buf.extend_from_slice(&expires_ms.to_be_bytes());
    }

    if let Err(e) = handle.send_datagram(sender, PORT_TRACKER, buf).await {
        warn!("Failed to send getAddrs response: {}", e);
    }
}

// ── Sync (stream-based) ─────────────────────────────────────────────────────

async fn run_sync_peer(state: Arc<TrackerState>, handle: ConnectHandle, peer_hex: &str, local_pub: [u8; 32], cancel: CancellationToken) {
    let peer_bytes = match hex::decode(peer_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            error!("Invalid peer hex: {}", peer_hex);
            return;
        }
    };
    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&peer_bytes);
    let peer_addr = Addr::from(peer_pub);

    let backoff = Duration::from_secs(30);

    loop {
        if cancel.is_cancelled() {
            return;
        }

        if already_connected(&state, &peer_pub).await {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => continue,
                _ = cancel.cancelled() => return,
            }
        }

        // Connect and open stream
        let connection = match handle.connect(peer_addr).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Sync connect to {}… failed: {}", &peer_hex[..8.min(peer_hex.len())], e);
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => continue,
                    _ = cancel.cancelled() => return,
                }
            }
        };

        let mut stream = match connection.open_stream(PORT_TRACKER).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Sync open_stream to {}… failed: {}", &peer_hex[..8.min(peer_hex.len())], e);
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => continue,
                    _ = cancel.cancelled() => return,
                }
            }
        };

        // Handshake: write our pubkey
        if stream.write_all(&local_pub).await.is_err() {
            let _ = stream.shutdown().await;
            tokio::select! {
                _ = tokio::time::sleep(backoff) => continue,
                _ = cancel.cancelled() => return,
            }
        }

        mark_connected(&state, &peer_pub).await;
        info!("Sync connected to {}…", &peer_hex[..8.min(peer_hex.len())]);

        run_sync_connection(&state, &mut stream, &peer_pub, cancel.clone()).await;

        mark_disconnected(&state, &peer_pub).await;
        let _ = stream.shutdown().await;

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {},
            _ = cancel.cancelled() => return,
        }
    }
}

async fn run_sync_connection(state: &TrackerState, stream: &mut ygg_stream::Stream, remote_pub: &[u8; 32], cancel: CancellationToken) {
    let mut sync_rx = state.sync_tx.subscribe();
    let mut last_ping = Instant::now();

    // Randomized ping interval: 15-31 seconds
    let jitter = (rand::random::<u64>() % 16) as u64;
    let ping_interval = Duration::from_secs(15 + jitter);
    let mut ping_ticker = tokio::time::interval(ping_interval);
    ping_ticker.tick().await; // skip first immediate tick

    let mut cmd_buf = [0u8; 1];

    loop {
        if cancel.is_cancelled() {
            return;
        }

        // Check ping timeout
        if last_ping.elapsed() > Duration::from_secs(30) {
            info!("Sync connection to {}… timed out", hex::encode(&remote_pub[..6]));
            break;
        }

        tokio::select! {
            // Read a command from the stream
            result = tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut cmd_buf)) => {
                match result {
                    Ok(Ok(_)) => {
                        match cmd_buf[0] {
                            CMD_SYNC_PING => {
                                last_ping = Instant::now();
                            }
                            CMD_SYNC_DATA => {
                                if let Err(e) = handle_sync_data(state, stream).await {
                                    debug!("Sync data error: {}", e);
                                    break;
                                }
                            }
                            _ => {
                                warn!("Unknown sync cmd {} from {}…", cmd_buf[0], hex::encode(&remote_pub[..6]));
                                break;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // Read error (EOF, reset, etc.)
                        info!("Sync peer {}… gone: {}", hex::encode(&remote_pub[..6]), e);
                        break;
                    }
                    Err(_) => {
                        // Timeout — no data available, that's fine
                    }
                }
            }

            // Send periodic ping
            _ = ping_ticker.tick() => {
                if stream.write_all(&[CMD_SYNC_PING]).await.is_err() {
                    break;
                }
            }

            // Forward sync items to peer
            result = sync_rx.recv() => {
                match result {
                    Ok(item) => {
                        if item.hop == 0 {
                            continue;
                        }
                        if let Err(_) = write_sync_data(stream, &item).await {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!("Sync broadcast lagged by {} items", n);
                    }
                    Err(_) => break,
                }
            }

            _ = cancel.cancelled() => break,
        }
    }
}

async fn handle_sync_data(state: &TrackerState, stream: &mut ygg_stream::Stream) -> Result<(), Box<dyn std::error::Error>> {
    // Read: hop(1) + key(32) + nodePub(32) + sig(64) + priority(1) + clientID(4) + ttlSec(4) + prevTtl(4) = 142
    let mut hop = [0u8; 1];
    stream.read_exact(&mut hop).await?;
    if hop[0] == 0 {
        return Ok(());
    }

    let mut key = [0u8; 32];
    stream.read_exact(&mut key).await?;

    let mut node_pub = [0u8; 32];
    stream.read_exact(&mut node_pub).await?;

    let mut signature = [0u8; 64];
    stream.read_exact(&mut signature).await?;

    let mut priority = [0u8; 1];
    stream.read_exact(&mut priority).await?;

    let mut client_id_buf = [0u8; 4];
    stream.read_exact(&mut client_id_buf).await?;
    let client_id = u32::from_be_bytes(client_id_buf);

    let mut ttl_sec_buf = [0u8; 4];
    stream.read_exact(&mut ttl_sec_buf).await?;
    let ttl_sec = u32::from_be_bytes(ttl_sec_buf);

    let mut prev_ttl_buf = [0u8; 4];
    stream.read_exact(&mut prev_ttl_buf).await?;
    let prev_ttl = u32::from_be_bytes(prev_ttl_buf);

    // Verify signature
    let verifying_key = VerifyingKey::from_bytes(&key)?;
    let sig = Signature::from_bytes(&signature);
    verifying_key.verify(&node_pub, &sig)?;

    info!("Synced addr: {}… from user: {}…", hex::encode(&node_pub[..4]), hex::encode(&key[..4]));

    let record = Record {
        node_pub,
        signature,
        priority: priority[0],
        client_id,
        expires: SystemTime::now() + Duration::from_secs(ttl_sec as u64),
        prev_ttl,
    };

    // Store
    let mut records = state.records.write().await;
    let recs = records.entry(key).or_default();
    // Put new record first, remove old with same client_id
    recs.retain(|r| r.client_id != client_id);
    recs.insert(0, record.clone());
    drop(records);

    // Forward with decremented hop
    if hop[0] > 1 && !have_recent(state, &key).await {
        let _ = state.sync_tx.send(SyncItem {
            key,
            data: record,
            hop: hop[0] - 1,
        });
    }
    mark_recent(state, &key).await;

    Ok(())
}

async fn write_sync_data(stream: &mut ygg_stream::Stream, item: &SyncItem) -> Result<(), std::io::Error> {
    // cmd(1) + hop(1) + key(32) + nodePub(32) + sig(64) + priority(1) + clientID(4) + ttlSec(4) + prevTtl(4) = 143
    let mut buf = Vec::with_capacity(143);
    buf.push(CMD_SYNC_DATA);
    buf.push(item.hop);
    buf.extend_from_slice(&item.key);
    buf.extend_from_slice(&item.data.node_pub);
    buf.extend_from_slice(&item.data.signature);
    buf.push(item.data.priority);
    buf.extend_from_slice(&item.data.client_id.to_be_bytes());

    let ttl = item.data.expires
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs() as u32;
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&item.data.prev_ttl.to_be_bytes());

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

// ── Recent dedup ─────────────────────────────────────────────────────────────

async fn mark_recent(state: &TrackerState, key: &[u8; 32]) {
    state.recent.write().await.insert(*key, Instant::now());
}

async fn have_recent(state: &TrackerState, key: &[u8; 32]) -> bool {
    let recent = state.recent.read().await;
    match recent.get(key) {
        Some(t) => t.elapsed() < Duration::from_secs(10),
        None => false,
    }
}

async fn gc_recent(state: Arc<TrackerState>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(11)) => {},
            _ = cancel.cancelled() => return,
        }
        let mut recent = state.recent.write().await;
        recent.retain(|_, t| t.elapsed() < Duration::from_secs(11));
    }
}

async fn gc_records(state: Arc<TrackerState>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            _ = cancel.cancelled() => return,
        }
        let now = SystemTime::now();
        let mut records = state.records.write().await;
        records.retain(|_, recs| {
            recs.retain(|r| r.expires > now);
            !recs.is_empty()
        });
    }
}

// ── Connection tracking ──────────────────────────────────────────────────────

async fn already_connected(state: &TrackerState, pub_key: &[u8; 32]) -> bool {
    state.connected.lock().await.contains(pub_key)
}

async fn mark_connected(state: &TrackerState, pub_key: &[u8; 32]) {
    state.connected.lock().await.insert(*pub_key);
}

async fn mark_disconnected(state: &TrackerState, pub_key: &[u8; 32]) {
    state.connected.lock().await.remove(pub_key);
}

// ── Persistence ──────────────────────────────────────────────────────────────

fn save_records(path: &str, records: &HashMap<[u8; 32], Vec<Record>>) {
    match bincode::serialize(records) {
        Ok(data) => {
            if let Err(e) = fs::write(path, data) {
                error!("Failed to save records: {}", e);
            }
        }
        Err(e) => error!("Failed to serialize records: {}", e),
    }
}

fn load_records(path: &str) -> HashMap<[u8; 32], Vec<Record>> {
    match fs::read(path) {
        Ok(data) => bincode::deserialize(&data).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

async fn save_loop(state: Arc<TrackerState>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            _ = cancel.cancelled() => return,
        }
        let records = state.records.read().await;
        save_records(DATA_FILE, &records);
        debug!("Auto-saved {} entries", records.len());
    }
}

// ── Key management ───────────────────────────────────────────────────────────

fn load_or_gen_key() -> SigningKey {
    if let Ok(data) = fs::read(KEY_FILE) {
        if data.len() == 32 {
            let seed: [u8; 32] = data.try_into().unwrap();
            let sk = SigningKey::from_bytes(&seed);
            info!("Loaded key from {}, public: {}", KEY_FILE, hex::encode(sk.verifying_key().as_bytes()));
            return sk;
        }
    }

    let sk = SigningKey::generate(&mut OsRng);
    if let Err(e) = fs::write(KEY_FILE, sk.to_bytes()) {
        error!("Failed to save key: {}", e);
    }
    info!("Generated new key (saved to {}), public: {}", KEY_FILE, hex::encode(sk.verifying_key().as_bytes()));
    sk
}
