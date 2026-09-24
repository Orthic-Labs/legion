//! Canonical serialization + digests, ported from
//! `src/lib/contracts/arcane/canonical.mjs`. Originally only `canonical_json`
//! / `digest_value` were needed; packet r50 added `constant_time_equal`,
//! `project_bound_fields`, and `hmac_sha256_hex` (mirroring `constantTimeEqual`
//! / `projectBoundFields` in canonical.mjs and the HMAC construction in
//! `receipt-auth.mjs`) to close the `DenialCircuit` persistence gap in
//! `denial_circuit.rs` via the new `receipt_auth` module.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

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

/// Constant-time comparison of two byte strings. Mirrors `constantTimeEqual`
/// in `canonical.mjs`: returns `false` on a length mismatch rather than
/// short-circuiting on the first differing byte, so string length is not a
/// timing oracle.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256, hex-encoded. Manual construction: `hmac` is not in this
/// crate's dependency set, and `sha2` 0.11 alone is sufficient to build the
/// standard block-size-64 HMAC by hand (same approach as
/// `legion-policy`'s `wf_port::wf070::canon::hmac_sha256_hex`).
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        block_key[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(&inner_digest);
    let outer_digest = outer.finalize();
    let mut out = String::with_capacity(64);
    for byte in outer_digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Project a record down to an explicit field list before signing. Mirrors
/// `projectBoundFields`: a missing bound field is an error, not an implicit
/// null.
pub fn project_bound_fields(record: &Value, fields: &[&str]) -> Result<Value, String> {
    let map = record.as_object().ok_or_else(|| "record must be an object".to_string())?;
    let mut out = Map::new();
    for field in fields {
        match map.get(*field) {
            Some(value) => {
                out.insert((*field).to_string(), value.clone());
            }
            None => return Err(format!("bound field missing: {field}")),
        }
    }
    Ok(Value::Object(out))
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

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        // RFC 4231 test case 1: key 0x0b*20, data "Hi There".
        let key = vec![0x0bu8; 20];
        let mac = hmac_sha256_hex(&key, b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn constant_time_equal_rejects_length_mismatch() {
        assert!(!constant_time_equal(b"abc", b"ab"));
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
    }

    #[test]
    fn project_bound_fields_requires_every_field() {
        let record = json!({"a": 1, "b": 2, "c": 3});
        let projected = project_bound_fields(&record, &["a", "c"]).unwrap();
        assert_eq!(projected, json!({"a": 1, "c": 3}));
        assert!(project_bound_fields(&record, &["a", "missing"]).is_err());
    }
}
