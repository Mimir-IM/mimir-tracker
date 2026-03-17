mod client;
mod keys;
mod persistence;
mod protocol;
mod state;
mod sync;
mod tlv;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::info;
use ygg_stream::StreamManager;
use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::protocol::*;
use crate::state::*;

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
        None => keys::load_or_gen_key(),
    };

    let pub_key_bytes: [u8; 32] = *signing_key.verifying_key().as_bytes();

    // Load persisted records
    let records = persistence::load_records(DATA_FILE);
    info!("Loaded {} user entries from {}", records.len(), DATA_FILE);

    // Shared state
    let (sync_tx, _) = broadcast::channel::<SyncItem>(512);
    let state = Arc::new(TrackerState {
        records: tokio::sync::RwLock::new(records),
        recent: tokio::sync::RwLock::new(HashMap::new()),
        connected: tokio::sync::Mutex::new(std::collections::HashSet::new()),
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
    let stream_listener = handle.listen(PORT_TRACKER).await;

    let cancel = CancellationToken::new();

    // Spawn client datagram handler
    let state_c = state.clone();
    let handle_c = handle.clone();
    let cancel_c = cancel.clone();
    tokio::spawn(async move {
        client::client_handler(state_c, dg_listener, handle_c, cancel_c).await;
    });

    // Spawn sync acceptor
    let state_a = state.clone();
    let cancel_a = cancel.clone();
    tokio::spawn(async move {
        sync::accept_sync_connections(state_a, stream_listener, cancel_a).await;
    });

    // Spawn outbound sync peers
    for server_hex in &servers {
        let server_hex = server_hex.clone();
        let state = state.clone();
        let handle = handle.clone();
        let cancel = cancel.clone();
        let local_pub = pub_key_bytes;
        tokio::spawn(async move {
            sync::run_sync_peer(state, handle, &server_hex, local_pub, cancel).await;
        });
    }

    // Spawn GC tasks
    let state_gc = state.clone();
    let cancel_gc = cancel.clone();
    tokio::spawn(async move { persistence::gc_recent(state_gc, cancel_gc).await });

    let state_gc2 = state.clone();
    let cancel_gc2 = cancel.clone();
    tokio::spawn(async move { persistence::gc_records(state_gc2, cancel_gc2).await });

    // Spawn save loop
    let state_save = state.clone();
    let cancel_save = cancel.clone();
    tokio::spawn(async move { persistence::save_loop(state_save, cancel_save).await });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down...");
    cancel.cancel();

    // Final save
    let records = state.records.read().await;
    persistence::save_records(DATA_FILE, &records);
    info!("Saved {} entries. Goodbye.", records.len());
}
