//! Retained items of the visual-core port: `sha256_digest`, used by the
//! retained visual reviewer code. PNG codec, inflate and coverage logic
//! reachable only from deleted tests were removed in the native-provider sweep.
use sha2::{Digest, Sha256};

pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
