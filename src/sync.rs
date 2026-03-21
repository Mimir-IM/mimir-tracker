use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ironwood::Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use ygg_stream::ConnectHandle;

use crate::protocol::*;
use crate::state::*;
use crate::tlv::*;

// ── Sync acceptor (called from main) ─────────────────────────────────────────

pub async fn accept_sync_connections(state: Arc<TrackerState>, mut stream_listener: ygg_stream::Listener, cancel: CancellationToken) {
    loop {
        tokio::select! {
            result = stream_listener.accept() => {
                match result {
                    Ok(mut stream) => {
                        let state = state.clone();
                        let cancel = cancel.clone();
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
            _ = cancel.cancelled() => break,
        }
    }
}

// ── Outbound sync peer ───────────────────────────────────────────────────────

pub async fn run_sync_peer(state: Arc<TrackerState>, handle: ConnectHandle, peer_hex: &str, local_pub: [u8; 32], cancel: CancellationToken) {
    let peer_bytes = match hex::decode(peer_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            tracing::error!("Invalid peer hex: {}", peer_hex);
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

// ── Sync connection loop ─────────────────────────────────────────────────────

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
                        if write_sync_data(stream, &item).await.is_err() {
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

// ── TLV sync read/write ─────────────────────────────────────────────────────

async fn handle_sync_data(state: &TrackerState, stream: &mut ygg_stream::Stream) -> Result<(), Box<dyn std::error::Error>> {
    // [payload_len:4 BE][TLV payload]
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len > 65536 {
        return Err("sync payload too large".into());
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let map = parse_tlvs(&payload)?;

    let hop = tlv_get_u8(&map, TAG_HOP).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    if hop == 0 {
        return Ok(());
    }

    let key: [u8; 32] = tlv_get_bytes(&map, TAG_USER_PUB, 32)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
        .try_into().unwrap();
    let node_pub: [u8; 32] = tlv_get_bytes(&map, TAG_NODE_PUB, 32)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
        .try_into().unwrap();
    let signature: [u8; 64] = tlv_get_bytes(&map, TAG_SIGNATURE, 64)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
        .try_into().unwrap();
    let priority = tlv_get_u8(&map, TAG_PRIORITY).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let client_id = tlv_get_u32(&map, TAG_CLIENT_ID).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let ttl_secs = tlv_get_u64(&map, TAG_TTL_SECS).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let prev_ttl = tlv_get_u32(&map, TAG_PREV_TTL).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    process_sync_record(state, hop, key, node_pub, signature, priority, client_id, ttl_secs, prev_ttl).await
}

async fn write_sync_data(stream: &mut ygg_stream::Stream, item: &SyncItem) -> Result<(), std::io::Error> {
    let ttl = item.data.expires
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();

    let payload = build_tlv_payload(|w| {
        tlv_encode_u8(w, TAG_HOP, item.hop)?;
        tlv_encode_bytes(w, TAG_USER_PUB, &item.key)?;
        tlv_encode_bytes(w, TAG_NODE_PUB, &item.data.node_pub)?;
        tlv_encode_bytes(w, TAG_SIGNATURE, &item.data.signature)?;
        tlv_encode_u8(w, TAG_PRIORITY, item.data.priority)?;
        tlv_encode_u32(w, TAG_CLIENT_ID, item.data.client_id)?;
        tlv_encode_u64(w, TAG_TTL_SECS, ttl)?;
        tlv_encode_u32(w, TAG_PREV_TTL, item.data.prev_ttl)?;
        Ok(())
    })?;

    // cmd(1) + payload_len(4) + payload
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(CMD_SYNC_DATA);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

// ── Shared sync logic ────────────────────────────────────────────────────────

async fn process_sync_record(
    state: &TrackerState,
    hop: u8,
    key: [u8; 32],
    node_pub: [u8; 32],
    signature: [u8; 64],
    priority: u8,
    client_id: u32,
    ttl_secs: u64,
    prev_ttl: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify signature
    let verifying_key = VerifyingKey::from_bytes(&key)?;
    let sig = Signature::from_bytes(&signature);
    verifying_key.verify(&node_pub, &sig)?;

    info!("Synced addr: {}… from user: {}…", hex::encode(&node_pub[..4]), hex::encode(&key[..4]));

    let record = Record {
        node_pub,
        signature,
        priority,
        client_id,
        expires: SystemTime::now() + Duration::from_secs(ttl_secs),
        prev_ttl,
    };

    // Store
    let mut records = state.records.write().await;
    let recs = records.entry(key).or_default();
    recs.retain(|r| r.client_id != client_id);
    recs.insert(0, record.clone());
    drop(records);

    // Forward with decremented hop
    if hop > 1 && !have_recent(state, &key).await {
        let _ = state.sync_tx.send(SyncItem {
            key,
            data: record,
            hop: hop - 1,
        });
    }
    mark_recent(state, &key).await;

    Ok(())
}