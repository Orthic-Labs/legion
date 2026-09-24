//! Port of the three symbols `providers/sdk/index.mjs` re-exports from
//! `src/registry/provider-registry.mjs`: `canonicalize`, `canonicalJson`,
//! `sha256`.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Recursively sorts object keys; arrays keep their order. Mirrors
/// `canonicalize(value)`.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&map[k]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// `JSON.stringify(canonicalize(value))`. Mirrors `canonicalJson(value)`.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).expect("canonicalized JSON always serializes")
}

/// Value form of `sha256`: hashes the canonical JSON serialization.
pub fn sha256_value(value: &Value) -> String {
    sha256_str(&canonical_json(value))
}

/// String form of `sha256`: hashes the string bytes directly (no JSON
/// re-encoding), mirroring the JS `typeof value === 'string'` branch.
pub fn sha256_str(bytes: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_object_keys_recursively() {
        let v = canonicalize(&json!({"b": 1, "a": {"y": 2, "x": 1}}));
        assert_eq!(canonical_json(&v), r#"{"a":{"x":1,"y":2},"b":1}"#);
    }

    #[test]
    fn canonicalize_preserves_array_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonical_json(&v), "[3,1,2]");
    }

    #[test]
    fn sha256_value_is_stable_regardless_of_key_order() {
        let a = sha256_value(&json!({"x": 1, "y": 2}));
        let b = sha256_value(&json!({"y": 2, "x": 1}));
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn sha256_str_hashes_raw_bytes_not_json() {
        let a = sha256_str("hello");
        let b = sha256_value(&json!("hello"));
        // `"hello"` as a JSON string re-encodes to `"hello"` (with quotes),
        // so the two must differ.
        assert_ne!(a, b);
    }
}
