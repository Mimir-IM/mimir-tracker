use std::fs;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::{error, info};

use crate::protocol::KEY_FILE;

pub fn load_or_gen_key() -> SigningKey {
    if let Ok(data) = fs::read(KEY_FILE) {
        let seed: Option<[u8; 32]> = if data.len() == 32 {
            Some(data.try_into().unwrap())
        } else if data.len() == 64 {
            // Try to parse as hex-encoded seed
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            hex::decode(text).ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        } else {
            // Handle hex with possible trailing newline/whitespace
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            if text.len() == 64 {
                hex::decode(text).ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            } else {
                None
            }
        };
        if let Some(seed) = seed {
            let key = SigningKey::from_bytes(&seed);
            info!("Loaded key from {}, public: {}", KEY_FILE, hex::encode(key.verifying_key().as_bytes()));
            return key;
        }
    }

    let key = SigningKey::generate(&mut OsRng);
    if let Err(e) = fs::write(KEY_FILE, key.to_bytes()) {
        error!("Failed to save key: {}", e);
    }
    info!("Generated new key (saved to {}), public: {}", KEY_FILE, hex::encode(key.verifying_key().as_bytes()));
    key
}
