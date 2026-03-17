use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ironwood::Addr;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use ygg_stream::{ConnectHandle, DatagramListener};

use crate::protocol::*;
use crate::state::*;
use crate::tlv::*;

// ── Client handler (datagram-based) ──────────────────────────────────────────

pub async fn client_handler(state: Arc<TrackerState>, mut dg: DatagramListener, handle: ConnectHandle, cancel: CancellationToken) {
    loop {
        tokio::select! {
            result = dg.recv() => {
                let (data, sender) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };

                if data.is_empty() {
                    continue;
                }

                match data[0] {
                    VERSION_V1 => handle_v1_datagram(&state, &handle, &sender, &data).await,
                    VERSION_V2 => handle_v2_datagram(&state, &handle, &sender, &data).await,
                    _ => {}
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

// ── V1 datagram handling ─────────────────────────────────────────────────────

async fn handle_v1_datagram(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, data: &[u8]) {
    // V1: [version:1][nonce:4][cmd:1][user_pub:32]... = min 38 bytes
    if data.len() < 38 {
        return;
    }

    let nonce = u32::from_be_bytes(data[1..5].try_into().unwrap());
    let cmd = data[5];
    let user_pub: [u8; 32] = data[6..38].try_into().unwrap();

    match cmd {
        CMD_ANNOUNCE => {
            handle_announce_v1(state, handle, sender, nonce, user_pub, &data[38..]).await;
        }
        CMD_GET_ADDRS => {
            handle_get_addrs_v1(state, handle, sender, nonce, user_pub).await;
        }
        _ => {}
    }
}

async fn handle_announce_v1(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, user_pub: [u8; 32], body: &[u8]) {
    // body: priority(1) + clientID(4) + addrPub(32) + signature(64) = 101 bytes
    if body.len() < 101 {
        return;
    }

    let priority = body[0];
    let client_id = u32::from_be_bytes(body[1..5].try_into().unwrap());
    let addr_pub: [u8; 32] = body[5..37].try_into().unwrap();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&body[37..101]);

    let new_ttl = match do_announce(state, user_pub, addr_pub, signature, priority, client_id).await {
        Some(ttl) => ttl,
        None => return,
    };

    // Send V1 ACK: nonce(4) + cmd(1) + ttl_seconds(8)
    let mut resp = [0u8; 13];
    resp[0..4].copy_from_slice(&nonce.to_be_bytes());
    resp[4] = CMD_ANNOUNCE;
    let ttl_secs = (new_ttl as u64) * 60;
    resp[5..13].copy_from_slice(&ttl_secs.to_be_bytes());

    if let Err(e) = handle.send_datagram(sender, PORT_TRACKER, resp.to_vec()).await {
        warn!("Failed to send announce ACK: {}", e);
    }
}

async fn handle_get_addrs_v1(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, user_pub: [u8; 32]) {
    let (valid, now) = get_valid_records(state, &user_pub).await;

    // Build V1 response: nonce(4) + cmd(1) + count(1) + N*(addrPub(32)+sig(64)+priority(1)+clientID(4)+expiresMs(8))
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

// ── V2 datagram handling ─────────────────────────────────────────────────────

async fn handle_v2_datagram(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, data: &[u8]) {
    // V2: [version:1][nonce:4][cmd:1][TLV payload...]
    if data.len() < 6 {
        return;
    }

    let nonce = u32::from_be_bytes(data[1..5].try_into().unwrap());
    let cmd = data[5];
    let tlv_payload = &data[6..];

    match cmd {
        CMD_ANNOUNCE => {
            handle_announce_v2(state, handle, sender, nonce, tlv_payload).await;
        }
        CMD_GET_ADDRS => {
            handle_get_addrs_v2(state, handle, sender, nonce, tlv_payload).await;
        }
        _ => {}
    }
}

async fn handle_announce_v2(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, tlv_payload: &[u8]) {
    let map = match parse_tlvs(tlv_payload) {
        Ok(m) => m,
        Err(e) => {
            warn!("V2 announce TLV parse error: {}", e);
            return;
        }
    };

    let user_pub: [u8; 32] = match tlv_get_bytes(&map, TAG_USER_PUB, 32) {
        Ok(b) => b.try_into().unwrap(),
        Err(e) => { warn!("V2 announce: {}", e); return; }
    };
    let addr_pub: [u8; 32] = match tlv_get_bytes(&map, TAG_NODE_PUB, 32) {
        Ok(b) => b.try_into().unwrap(),
        Err(e) => { warn!("V2 announce: {}", e); return; }
    };
    let signature: [u8; 64] = match tlv_get_bytes(&map, TAG_SIGNATURE, 64) {
        Ok(b) => b.try_into().unwrap(),
        Err(e) => { warn!("V2 announce: {}", e); return; }
    };
    let priority = match tlv_get_u8(&map, TAG_PRIORITY) {
        Ok(v) => v,
        Err(e) => { warn!("V2 announce: {}", e); return; }
    };
    let client_id = match tlv_get_u32(&map, TAG_CLIENT_ID) {
        Ok(v) => v,
        Err(e) => { warn!("V2 announce: {}", e); return; }
    };

    let new_ttl = match do_announce(state, user_pub, addr_pub, signature, priority, client_id).await {
        Some(ttl) => ttl,
        None => return,
    };

    // Build V2 response: nonce(4) + cmd(1) + TLV(TAG_TTL_SECS)
    let ttl_secs = (new_ttl as u64) * 60;
    let tlv_body = match build_tlv_payload(|w| {
        tlv_encode_u64(w, TAG_TTL_SECS, ttl_secs)
    }) {
        Ok(b) => b,
        Err(_) => return,
    };

    let mut resp = Vec::with_capacity(5 + tlv_body.len());
    resp.extend_from_slice(&nonce.to_be_bytes());
    resp.push(CMD_ANNOUNCE);
    resp.extend_from_slice(&tlv_body);

    if let Err(e) = handle.send_datagram(sender, PORT_TRACKER, resp).await {
        warn!("Failed to send V2 announce ACK: {}", e);
    }
}

async fn handle_get_addrs_v2(state: &TrackerState, handle: &ConnectHandle, sender: &Addr, nonce: u32, tlv_payload: &[u8]) {
    let map = match parse_tlvs(tlv_payload) {
        Ok(m) => m,
        Err(e) => {
            warn!("V2 get_addrs TLV parse error: {}", e);
            return;
        }
    };

    let user_pub: [u8; 32] = match tlv_get_bytes(&map, TAG_USER_PUB, 32) {
        Ok(b) => b.try_into().unwrap(),
        Err(e) => { warn!("V2 get_addrs: {}", e); return; }
    };

    let (valid, now) = get_valid_records(state, &user_pub).await;

    // Build V2 response: nonce(4) + cmd(1) + TLV(TAG_COUNT + N × TAG_RECORD)
    let tlv_body = match build_tlv_payload(|w| {
        tlv_encode_u8(w, TAG_COUNT, valid.len() as u8)?;
        for r in &valid {
            let record_tlv = build_tlv_payload(|rw| {
                tlv_encode_bytes(rw, TAG_NODE_PUB, &r.node_pub)?;
                tlv_encode_bytes(rw, TAG_SIGNATURE, &r.signature)?;
                tlv_encode_u8(rw, TAG_PRIORITY, r.priority)?;
                tlv_encode_u32(rw, TAG_CLIENT_ID, r.client_id)?;
                let expires_ms = r.expires.duration_since(now).unwrap_or_default().as_millis() as u64;
                tlv_encode_u64(rw, TAG_EXPIRES_MS, expires_ms)?;
                Ok(())
            })?;
            tlv_encode_bytes(w, TAG_RECORD, &record_tlv)?;
        }
        Ok(())
    }) {
        Ok(b) => b,
        Err(_) => return,
    };

    let mut resp = Vec::with_capacity(5 + tlv_body.len());
    resp.extend_from_slice(&nonce.to_be_bytes());
    resp.push(CMD_GET_ADDRS);
    resp.extend_from_slice(&tlv_body);

    if let Err(e) = handle.send_datagram(sender, PORT_TRACKER, resp).await {
        warn!("Failed to send V2 getAddrs response: {}", e);
    }
}

// ── Shared logic ─────────────────────────────────────────────────────────────

/// Perform announce logic shared between V1 and V2. Returns the new TTL (in minutes) on success.
async fn do_announce(state: &TrackerState, user_pub: [u8; 32], addr_pub: [u8; 32], signature: [u8; 64], priority: u8, client_id: u32) -> Option<u32> {
    info!("Announce addr: {}… from user: {}…", hex::encode(&addr_pub[..8]), hex::encode(&user_pub[..8]));

    // Verify signature: user_pub signs addr_pub
    let verifying_key = VerifyingKey::from_bytes(&user_pub).ok()?;
    let sig = Signature::from_bytes(&signature);
    if verifying_key.verify(&addr_pub, &sig).is_err() {
        warn!("Wrong signature from {}…", hex::encode(&user_pub[..4]));
        return None;
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

    // Push to sync peers
    let _ = state.sync_tx.send(SyncItem {
        key: user_pub,
        data: new_record,
        hop: MAX_HOP_COUNT,
    });
    mark_recent(state, &user_pub).await;

    Some(new_ttl)
}

/// Get valid (non-expired) records for a user key.
async fn get_valid_records(state: &TrackerState, user_pub: &[u8; 32]) -> (Vec<Record>, SystemTime) {
    let records = state.records.read().await;
    let recs = records.get(user_pub).cloned().unwrap_or_default();
    drop(records);

    info!("Search for {}…", hex::encode(&user_pub[..4]));

    let now = SystemTime::now();
    let valid: Vec<Record> = recs.into_iter().filter(|r| r.expires > now).collect();
    (valid, now)
}
