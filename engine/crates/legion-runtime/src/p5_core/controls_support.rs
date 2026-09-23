//! Ported from src/lib/core/binding.mjs (packet P5-runtime-core), scoped to
//! what the P5b controls/config port needs: a minimal dynamic JSON value,
//! canonical (sorted-key, `\`->`/`) stringification, and a sha256 `digest()`
//! matching `digest(value)` in the JS source. std-only: legion-runtime's
//! Cargo.toml has no serde_json/sha2 dependency and is a shared file this
//! packet may not edit (see report for the suggested patch). This is a
//! self-contained SHA-256 implementation (FIPS 180-4), not a crate.
//!
//! `Value::to_canonical_string` mirrors JS `JSON.stringify` on the output of
//! `canonicalize()`: object keys sorted lexicographically (byte-wise, which
//! matches `Array.prototype.sort()` default on ASCII/UTF-8 key names used
//! here), arrays left in order, strings have `\` replaced with `/`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    /// Insertion order is irrelevant: canonicalization always sorts by key.
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn str(value: impl Into<String>) -> Self {
        Value::String(value.into())
    }

    pub fn object(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn array(items: impl IntoIterator<Item = Value>) -> Self {
        Value::Array(items.into_iter().collect())
    }

    /// Port of `canonicalize()` composed with `JSON.stringify`: this writes
    /// the canonical JSON text directly instead of building an intermediate
    /// canonicalized `Value`, since `BTreeMap` already yields sorted keys.
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => {
                if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{}", n);
                }
            }
            Value::String(s) => write_json_string(out, s),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(out, k);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_json_string(out: &mut String, s: &str) {
    // canonicalize() replaces `\` with `/` in string values before
    // JSON.stringify runs its own escaping; JSON.stringify would otherwise
    // double-escape `\` to `\\`, so post-replacement there is no backslash
    // left for JSON.stringify to escape.
    let replaced = s.replace('\\', "/");
    out.push('"');
    for c in replaced.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Port of `digest(value)`: `sha256:` + hex sha256 of the canonical JSON text.
pub fn digest(value: &Value) -> String {
    format!("sha256:{}", sha256_hex(value.to_canonical_string().as_bytes()))
}

/// Port of `sameBinding(left, right)`: digest equality, treating `None` as
/// JS `null`.
pub fn same_binding(left: Option<&Value>, right: Option<&Value>) -> bool {
    let l = left.cloned().unwrap_or(Value::Null);
    let r = right.cloned().unwrap_or(Value::Null);
    digest(&l) == digest(&r)
}

// ---- Self-contained SHA-256 (FIPS 180-4), std-only. ----

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

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
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
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
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

    let mut out = String::with_capacity(64);
    for word in h {
        let _ = write!(out, "{:08x}", word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // sha256("") per FIPS 180-4 test vectors.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_string_sorts_object_keys() {
        let value = Value::object([
            ("b", Value::Number(1.0)),
            ("a", Value::Number(2.0)),
        ]);
        assert_eq!(value.to_canonical_string(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonical_string_replaces_backslashes_in_strings() {
        let value = Value::str("a\\b");
        assert_eq!(value.to_canonical_string(), r#""a/b""#);
    }

    #[test]
    fn digest_is_stable_sha256_prefixed() {
        let value = Value::object([("id", Value::str("x"))]);
        let d = digest(&value);
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
        assert_eq!(d, digest(&value));
    }

    #[test]
    fn same_binding_treats_missing_as_null() {
        assert!(same_binding(None, None));
        assert!(!same_binding(Some(&Value::Null), Some(&Value::str("x"))));
    }
}
