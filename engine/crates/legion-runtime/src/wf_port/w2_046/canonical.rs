//! Canonical serialization + digests, ported from
//! `src/lib/contracts/arcane/canonical.mjs`. This chunk needs only
//! `canonical_json` / `digest_value`; the crypto helpers (`constantTimeEqual`,
//! `projectBoundFields`) are not exercised by the five ported files and are
//! left for whichever chunk ports `errors.mjs` / `receipt-auth.mjs`.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical JSON text for `value`: object keys sorted by code unit,
/// recursively, no insignificant whitespace. Mirrors `canonicalJson` in
/// canonical.mjs. `-0.0` normalizes to `0`, matching `Object.is(value, -0)`.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    return "0".to_string();
                }
            }
            n.to_string()
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Raw lowercase hex sha256 of a string.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Repo-wide digest form: `sha256:<64 lowercase hex>`.
pub fn digest(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input))
}

/// Digest of the canonical serialization of a structured value.
pub fn digest_value(value: &Value) -> String {
    digest(&canonical_json(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let a = canonical_json(&json!({"b": 1, "a": 2}));
        assert_eq!(a, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn negative_zero_normalizes() {
        let v: Value = serde_json::from_str("-0").unwrap();
        assert_eq!(canonical_json(&v), "0");
    }

    #[test]
    fn digest_is_stable_regardless_of_key_order() {
        let d1 = digest_value(&json!({"x": 1, "y": 2}));
        let d2 = digest_value(&json!({"y": 2, "x": 1}));
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
        assert_eq!(d1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn nested_arrays_and_objects() {
        let d = canonical_json(&json!({"a": [1, 2, {"z": 1, "y": 2}], "b": null}));
        assert_eq!(d, r#"{"a":[1,2,{"y":2,"z":1}],"b":null}"#);
    }
}
