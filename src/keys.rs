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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Minimum number of leading zero bytes for a "pretty" public key.
    const MIN_LEADING_ZEROS: usize = 2;

    pub fn is_pretty_pubkey(sk: &SigningKey) -> bool {
        let pub_bytes = sk.verifying_key().to_bytes();
        pub_bytes.iter().take(MIN_LEADING_ZEROS).all(|&b| b == 0)
    }

    #[test]
    fn mine_pretty_key() {
        let mut attempts: u64 = 0;
        loop {
            attempts += 1;
            let sk = SigningKey::generate(&mut OsRng);
            if is_pretty_pubkey(&sk) {
                let pub_hex = hex::encode(sk.verifying_key().as_bytes());
                let seed_hex = hex::encode(sk.to_bytes());
                println!("Found pretty key after {attempts} attempts!");
                println!("Public key: {pub_hex}");
                println!("Secret seed: {seed_hex}");
                assert!(pub_hex.starts_with(&"00".repeat(MIN_LEADING_ZEROS)));
                return;
            }
            if attempts % 100_000 == 0 {
                println!("Tried {attempts} keys...");
            }
        }
    }
}
