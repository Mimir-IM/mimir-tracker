use std::fs;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::{error, info};

use crate::protocol::KEY_FILE;

pub fn load_or_gen_key() -> SigningKey {
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
