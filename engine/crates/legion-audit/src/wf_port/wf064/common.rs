//! Shared canonical JSON + digest helpers ported from
//! `src/registry/provider-registry.mjs` (`canonicalize`, `canonicalJson`,
//! `sha256`). Every `tools/audit/audit-*.mjs` module ported under `wf064`
//! depends on these exact semantics for plan sealing and stable ids.

use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Mirrors JS `canonicalize`: recursively sorts object keys; arrays and
/// scalars pass through unchanged.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

/// Mirrors JS `canonicalJson`: `JSON.stringify(canonicalize(value))` —
/// compact, no whitespace, keys sorted at every nesting level.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).expect("canonicalized JSON always serializes")
}

/// Mirrors JS `sha256`: hashes the raw bytes of a string value directly, or
/// the canonical JSON form of anything else, and returns `sha256:<hex>`.
pub fn sha256_value(value: &Value) -> String {
    match value {
        Value::String(s) => sha256_str(s),
        other => sha256_str(&canonical_json(other)),
    }
}

/// Hashes a raw string's UTF-8 bytes and returns `sha256:<hex>`.
pub fn sha256_str(bytes: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

type HmacSha256 = Hmac<Sha256>;

/// Mirrors JS `createHmac('sha256', signingKey).update(message).digest('hex')`.
pub fn hmac_sha256_hex(signing_key: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_nested_keys() {
        let value = json!({"b": 1, "a": {"z": 1, "y": 2}});
        assert_eq!(canonical_json(&value), r#"{"a":{"y":2,"z":1},"b":1}"#);
    }

    #[test]
    fn sha256_of_string_hashes_raw_bytes_not_json() {
        // JS: sha256("abc") hashes the literal bytes "abc", NOT the JSON
        // string `"abc"` (with quotes) that canonicalJson("abc") would give.
        let digest = sha256_value(&json!("abc"));
        let direct = sha256_str("abc");
        assert_eq!(digest, direct);
        assert_ne!(digest, sha256_str("\"abc\""));
    }

    #[test]
    fn sha256_of_object_hashes_canonical_json() {
        let value = json!({"b": 1, "a": 2});
        let digest = sha256_value(&value);
        assert_eq!(digest, sha256_str(&canonical_json(&value)));
        assert!(digest.starts_with("sha256:"));
    }
}
