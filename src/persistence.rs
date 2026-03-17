use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::protocol::DATA_FILE;
use crate::state::{Record, TrackerState};

pub fn save_records(path: &str, records: &HashMap<[u8; 32], Vec<Record>>) {
    match bincode::serialize(records) {
        Ok(data) => {
            if let Err(e) = fs::write(path, data) {
                error!("Failed to save records: {}", e);
            }
        }
        Err(e) => error!("Failed to serialize records: {}", e),
    }
}

pub fn load_records(path: &str) -> HashMap<[u8; 32], Vec<Record>> {
    match fs::read(path) {
        Ok(data) => bincode::deserialize(&data).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

pub async fn save_loop(state: Arc<TrackerState>, cancel: CancellationToken) {
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

pub async fn gc_recent(state: Arc<TrackerState>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(11)) => {},
            _ = cancel.cancelled() => return,
        }
        let mut recent = state.recent.write().await;
        recent.retain(|_, t| t.elapsed() < Duration::from_secs(11));
    }
}

pub async fn gc_records(state: Arc<TrackerState>, cancel: CancellationToken) {
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
