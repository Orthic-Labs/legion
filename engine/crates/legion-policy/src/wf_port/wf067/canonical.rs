//! Self-contained canonical JSON + digest primitives for wf067.
//!
//! Faithful port of `src/lib/contracts/arcane/canonical.mjs`'s rules:
//! object keys sorted by code unit (recursively), no insignificant
//! whitespace, `undefined`/functions rejected (not representable in this
//! `Json` enum at all), non-finite numbers rejected, `-0` normalizes to `0`.
//!
//! This module deliberately depends on nothing outside `std`: wf067 does not
//! own `Cargo.toml`. A later integration pass can replace it with
//! `legion-contracts::canonical` (see wf067 report for the dependency
//! note). SHA-256 is implemented locally (FIPS 180-4) for the same reason.

use std::collections::BTreeMap;
use std::fmt;

/// A minimal JSON value sufficient for Arcane's record shapes.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    I64(i64),
    F64(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Insertion order is irrelevant — `canonical_json` always sorts keys.
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.message, self.path)
    }
}
impl std::error::Error for CanonicalError {}

fn fail(path: &str, message: &str) -> CanonicalError {
    CanonicalError {
        path: if path.is_empty() { "<root>".to_string() } else { path.to_string() },
        message: message.to_string(),
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

fn encode(value: &Json, path: &str, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::I64(n) => out.push_str(&n.to_string()),
        Json::F64(n) => {
            if !n.is_finite() {
                return Err(fail(path, "non-finite number"));
            }
            let v = if *n == 0.0 { 0.0 } else { *n };
            out.push_str(&v.to_string());
        }
        Json::Str(s) => escape_json_string(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, &format!("{path}[{i}]"), out)?;
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            let mut sorted: BTreeMap<&str, &Json> = BTreeMap::new();
            for (k, v) in pairs {
                sorted.insert(k.as_str(), v);
            }
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_json_string(k, out);
                out.push(':');
                encode(v, &format!("{path}.{k}"), out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonical JSON text for `value`. Mirrors JS `canonicalJson`.
pub fn canonical_json(value: &Json) -> Result<String, CanonicalError> {
    let mut out = String::new();
    encode(value, "", &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// SHA-256 (FIPS 180-4), dependency-free.
// ---------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Raw lowercase hex sha256, mirrors JS `sha256Hex`.
pub fn sha256_hex(input: &[u8]) -> String {
    hex_encode(&sha256(input))
}

/// Repo-wide digest form: `sha256:<64 lowercase hex>` (ids.md). Mirrors JS `digest`.
pub fn digest(input: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(input))
}

const DIGEST_HEX_LEN: usize = 64;

/// True when `value` matches the `sha256:<64 hex>` digest grammar. Mirrors JS `isDigest`.
pub fn is_digest(value: &str) -> bool {
    match value.strip_prefix("sha256:") {
        Some(hex) => hex.len() == DIGEST_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        None => false,
    }
}

/// Digest of the canonical serialization of a structured value. Mirrors JS `digestValue`.
pub fn digest_value(value: &Json) -> Result<String, CanonicalError> {
    Ok(digest(canonical_json(value)?.as_bytes()))
}

/// Constant-time comparison of two byte strings of equal length. Returns
/// `false` (never panics) on length mismatch, so callers cannot leak length
/// information through a differently timed path. Mirrors JS `constantTimeEqual`.
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

/// Project a record down to an explicit field list before signing. Missing
/// bound fields are an error, not an implicit null. Mirrors JS `projectBoundFields`.
pub fn project_bound_fields(record: &Json, fields: &[&str]) -> Result<Json, CanonicalError> {
    let mut out = Vec::new();
    for f in fields {
        let v = record.get(f).ok_or_else(|| fail(f, "bound field missing"))?;
        out.push((f.to_string(), v.clone()));
    }
    Ok(Json::Obj(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let v = Json::Obj(vec![
            ("b".into(), Json::Obj(vec![("z".into(), Json::I64(1)), ("a".into(), Json::I64(2))])),
            ("a".into(), Json::I64(2)),
        ]);
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":2,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn canonical_json_rejects_non_finite() {
        assert!(canonical_json(&Json::F64(f64::NAN)).is_err());
        assert!(canonical_json(&Json::F64(f64::INFINITY)).is_err());
    }

    #[test]
    fn canonical_json_normalizes_negative_zero() {
        assert_eq!(canonical_json(&Json::F64(-0.0)).unwrap(), "0");
    }

    #[test]
    fn canonical_json_has_no_insignificant_whitespace() {
        let v = Json::Arr(vec![Json::I64(1), Json::I64(2)]);
        assert_eq!(canonical_json(&v).unwrap(), "[1,2]");
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn digest_has_sha256_prefix_form() {
        let d = digest(b"abc");
        assert!(d.starts_with("sha256:"));
        assert!(is_digest(&d));
    }

    #[test]
    fn is_digest_rejects_malformed_forms() {
        assert!(!is_digest("not-a-digest"));
        assert!(!is_digest("sha256:short"));
        assert!(!is_digest(&format!("sha256:{}", "A".repeat(64)))); // uppercase not accepted
    }

    #[test]
    fn digest_value_matches_digest_of_canonical_json() {
        let v = Json::Obj(vec![("domain".into(), Json::str("d")), ("values".into(), Json::Arr(vec![]))]);
        let expected = digest(canonical_json(&v).unwrap().as_bytes());
        assert_eq!(digest_value(&v).unwrap(), expected);
    }

    #[test]
    fn constant_time_equal_rejects_length_mismatch() {
        assert!(!constant_time_equal(b"abc", b"ab"));
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
    }

    #[test]
    fn project_bound_fields_errors_on_missing_field() {
        let record = Json::Obj(vec![("a".into(), Json::I64(1))]);
        assert!(project_bound_fields(&record, &["a", "b"]).is_err());
        let ok = project_bound_fields(&record, &["a"]).unwrap();
        assert_eq!(ok.get("a"), Some(&Json::I64(1)));
    }
}
