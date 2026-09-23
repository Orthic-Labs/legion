//! Minimal canonical-serialization + digest + HMAC primitives for wf007.
//!
//! Faithful port of the subset of `src/lib/contracts/arcane/canonical.mjs`
//! that `replay.mjs` and `user-approval.mjs` actually use: canonical JSON
//! over small known-shape records (sorted keys, no insignificant
//! whitespace), `sha256Hex`/`digest`/`digestValue`, and `constantTimeEqual`.
//!
//! wf006 (`crate::wf_port::wf006::canonical`) already ports the same JS
//! module, but wf006 is not wired into `wf_port::mod` yet and this chunk
//! owns only `wf_port/wf007/**`, so this is a small self-contained sibling
//! rather than a cross-module dependency on another owner's unwired code.
//! `legion-policy` already depends on `sha2` (see `Cargo.toml`), so SHA-256
//! itself is not hand-rolled here — only the canonical-JSON encoding and the
//! RFC 2104 HMAC construction (no `hmac` crate in this crate's
//! dependencies) are.

use sha2::{Digest, Sha256};

/// A minimal JSON value sufficient for the small record shapes this chunk
/// signs and digests: strings, i64 (contract versions), and objects with a
/// fixed field list. Object keys are sorted at encode time, matching JS
/// `canonicalJson`'s `Object.keys(value).sort()`.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    I64(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
}

fn escape_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn encode(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::I64(n) => out.push_str(&n.to_string()),
        Json::Str(s) => escape_json_string(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out);
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            let mut sorted: Vec<&(&'static str, Json)> = pairs.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_json_string(k, out);
                out.push(':');
                encode(v, out);
            }
            out.push('}');
        }
    }
}

/// Canonical JSON text for `value`. Mirrors JS `canonicalJson` for the
/// value shapes this chunk needs (no floats, no non-finite rejection
/// required since callers never build one here).
pub fn canonical_json(value: &Json) -> String {
    let mut out = String::new();
    encode(value, &mut out);
    out
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Repo-wide digest form: `sha256:<64 lowercase hex>`. Mirrors JS `digest`.
pub fn digest(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

/// Digest of the canonical serialization of `value`. Mirrors JS `digestValue`.
pub fn digest_value(value: &Json) -> String {
    digest(&canonical_json(value))
}

/// `digestValue({ domain, values })` as used throughout `user-approval.mjs`:
/// a fixed two-field object whose `values` array elements are plain strings
/// (missing/optional values pass through as JSON `null`, matching JS
/// `[a, b, ...]` holding `undefined`/`null` entries verbatim).
pub fn digest_value_domain(domain: &str, values: &[Option<&str>]) -> String {
    let arr = values
        .iter()
        .map(|v| match v {
            Some(s) => Json::str(*s),
            None => Json::Null,
        })
        .collect();
    digest_value(&Json::Obj(vec![
        ("domain", Json::str(domain)),
        ("values", Json::Arr(arr)),
    ]))
}

/// RFC 2104 HMAC-SHA256. `legion-policy` has `sha2` but not `hmac`, so the
/// ipad/opad construction is written out explicitly rather than hand-rolling
/// SHA-256 itself (that part reuses `sha2::Sha256`).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed = hasher.finalize();
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let out = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let bytes = hmac_sha256(key, message);
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time comparison. Returns false on length mismatch, same
/// contract as JS `constantTimeEqual` (built on `node:crypto.timingSafeEqual`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys() {
        let v = Json::Obj(vec![("b", Json::I64(1)), ("a", Json::I64(2))]);
        assert_eq!(canonical_json(&v), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_has_sha256_prefix() {
        assert_eq!(
            digest(""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hmac_sha256_hex(&key, b"Hi There"), expected);
    }

    #[test]
    fn constant_time_equal_rejects_length_mismatch() {
        assert!(!constant_time_equal(b"abc", b"ab"));
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
    }

    #[test]
    fn digest_value_domain_matches_manual_canonical_form() {
        let d = digest_value_domain("dom", &[Some("x"), None, Some("y")]);
        let expected = digest(r#"{"domain":"dom","values":["x",null,"y"]}"#);
        assert_eq!(d, expected);
    }
}
