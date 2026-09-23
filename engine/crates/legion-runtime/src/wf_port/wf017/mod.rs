//! Packet wf017: JS -> Rust port of src/lib/remediation/{producers/structural,
//! reasoning-packets,rollback,sandbox,verify-patch}.mjs.
//!
//! Owned by chunk wf017. `pub mod wf_port;` and `pub mod wf017;` wiring in
//! `legion-runtime`'s `lib.rs` / `wf_port/mod.rs` is added by the integrator,
//! not by this file.

pub mod envelope;
pub mod reasoning_packets;
pub mod rollback;
pub mod sandbox;
pub mod structural;
pub mod verify_patch;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Recursively sort a JSON value's object keys so that serialization matches
/// the JS source's `canonical()` helper (which always emits object keys in
/// sorted order). Arrays keep their element order.
pub(crate) fn canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical).collect())
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

/// `sha256:<hex>` digest of `namespace \0 JSON.stringify(canonical(value))`,
/// matching the shape (not the byte-for-byte hash) of every `digestOf` helper
/// in the ported JS modules.
pub(crate) fn digest_of<T: Serialize>(namespace: &str, value: &T) -> String {
    let json = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    let canonical_json = canonical(&json);
    let body = serde_json::to_string(&canonical_json).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
