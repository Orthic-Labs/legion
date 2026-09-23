//! Port of `src/lib/core/binding.mjs` (canonicalize/digest/sameBinding),
//! reused by every L3 inventory record. Mirrors the JS semantics exactly:
//! object keys are sorted recursively, backslashes in strings become
//! forward slashes, arrays keep their given order, then the canonical form
//! is JSON-encoded and SHA-256 hashed.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(s.replace('\\', "/")),
        other => other.clone(),
    }
}

pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let json = serde_json::to_string(&canonical).unwrap_or_default();
    let hash = Sha256::digest(json.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

pub fn same_binding(left: &Value, right: &Value) -> bool {
    digest(left) == digest(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_keys_and_normalizes_paths() {
        let value = json!({"b": 1, "a": "foo\\bar"});
        let canonical = canonicalize(&value);
        assert_eq!(canonical, json!({"a": "foo/bar", "b": 1}));
    }

    #[test]
    fn digest_is_stable_regardless_of_key_order() {
        let a = digest(&json!({"x": 1, "y": 2}));
        let b = digest(&json!({"y": 2, "x": 1}));
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn same_binding_treats_null_as_equal_null() {
        assert!(same_binding(&Value::Null, &Value::Null));
    }
}
