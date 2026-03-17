use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::sync::{broadcast, Mutex, RwLock};

// ── Data types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub node_pub: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub priority: u8,
    pub client_id: u32,
    pub expires: SystemTime,
    pub prev_ttl: u32,
}

#[derive(Clone, Debug)]
pub struct SyncItem {
    pub key: [u8; 32],
    pub data: Record,
    pub hop: u8,
}

pub struct TrackerState {
    pub records: RwLock<HashMap<[u8; 32], Vec<Record>>>,
    pub recent: RwLock<HashMap<[u8; 32], Instant>>,
    pub connected: Mutex<HashSet<[u8; 32]>>,
    pub sync_tx: broadcast::Sender<SyncItem>,
}

// ── Recent dedup ─────────────────────────────────────────────────────────────

pub async fn mark_recent(state: &TrackerState, key: &[u8; 32]) {
    state.recent.write().await.insert(*key, Instant::now());
}

pub async fn have_recent(state: &TrackerState, key: &[u8; 32]) -> bool {
    let recent = state.recent.read().await;
    match recent.get(key) {
        Some(t) => t.elapsed() < Duration::from_secs(10),
        None => false,
    }
}

// ── Connection tracking ──────────────────────────────────────────────────────

pub async fn already_connected(state: &TrackerState, pub_key: &[u8; 32]) -> bool {
    state.connected.lock().await.contains(pub_key)
}

pub async fn mark_connected(state: &TrackerState, pub_key: &[u8; 32]) {
    state.connected.lock().await.insert(*pub_key);
}

pub async fn mark_disconnected(state: &TrackerState, pub_key: &[u8; 32]) {
    state.connected.lock().await.remove(pub_key);
}
