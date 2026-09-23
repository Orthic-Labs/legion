//! Minimal canonical-JSON digesting, ported from
//! `src/lib/contracts/arcane/canonical.mjs` (`digestValue` only — the
//! subset `eval-adr-canon-clarify.mjs` and `evidence-closure.mjs` need).
//!
//! This is a self-contained port scoped to wf074: it does not depend on
//! `serde_json` (not a non-dev dependency of `legion-policy` today; see the
//! wf074 report for the Cargo.toml patch that would let a future packet
//! consolidate on one canonical-JSON implementation crate-wide instead of
//! each wf module rolling its own `Json` enum).
//!
//! Rules mirrored from the JS source:
//!   - object keys sorted by code unit (byte/UTF-16 code-unit order — Rust
//!     `String`'s `Ord` is byte-order on UTF-8, which matches JS code-unit
//!     order for the BMP text these evaluators use);
//!   - no insignificant whitespace;
//!   - `-0.0` normalizes to `0`;
//!   - non-finite floats have no canonical form (`digest_value` returns
//!     `None` rather than JS's throw, since eval-adr-canon-clarify.mjs
//!     catches the throw and reports PENDING).

use sha2::{Digest, Sha256};

/// A minimal JSON value, sufficient for the fixtures these evaluators pass
/// through `digestValue`. Mirrors the JS module's encodable value set:
/// null, bool, number, string, array, object (no bigint/undefined/function/
/// Date, which JS rejects and which this Rust type cannot express anyway).
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Insertion order does not matter: `encode` sorts keys.
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Self {
        Json::Str(s.into())
    }
    pub fn obj(pairs: impl IntoIterator<Item = (&'static str, Json)>) -> Self {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

/// Encodes a JSON string literal the same way `JSON.stringify` would for a
/// plain string: double-quoted, with `"`, `\`, and control characters
/// escaped. Sufficient for the ASCII/simple-text fixtures these evaluators
/// use; not a full JS-string-escaping implementation.
fn encode_str(s: &str, out: &mut String) {
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

/// Returns `None` on a non-finite number, mirroring the JS `fail()` path
/// (which `digestValue`'s callers catch and turn into PENDING).
fn encode(value: &Json, out: &mut String) -> Option<()> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => {
            if !n.is_finite() {
                return None;
            }
            let n = if *n == 0.0 { 0.0 } else { *n };
            if n.fract() == 0.0 && n.abs() < 1e15 {
                out.push_str(&format!("{}", n as i64));
            } else {
                out.push_str(&format!("{}", n));
            }
        }
        Json::Str(s) => encode_str(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out)?;
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            let mut sorted: Vec<&(String, Json)> = pairs.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_str(k, out);
                out.push(':');
                encode(v, out)?;
            }
            out.push('}');
        }
    }
    Some(())
}

/// Canonical JSON text for `value`, or `None` if it contains a non-finite
/// number (the JS `canonicalJson` throws `ARC_CANONICALIZATION_FAILED`
/// there instead).
pub fn canonical_json(value: &Json) -> Option<String> {
    let mut out = String::new();
    encode(value, &mut out)?;
    Some(out)
}

/// Raw lowercase hex sha256 of a string.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Repo-wide digest form: `sha256:<64 lowercase hex>` (ids.md).
pub fn digest(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input))
}

/// Digest of the canonical serialization of a structured value. `None`
/// mirrors the JS `try { digestValue(...) } catch { PENDING }` path used by
/// `evaluateGeneratedSourceDrift`.
pub fn digest_value(value: &Json) -> Option<String> {
    canonical_json(value).map(|s| digest(&s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_key_order_independent() {
        let a = Json::obj([("b", Json::Num(1.0)), ("a", Json::str("x"))]);
        let b = Json::obj([("a", Json::str("x")), ("b", Json::Num(1.0))]);
        assert_eq!(digest_value(&a), digest_value(&b));
    }

    #[test]
    fn digests_differ_on_value_change() {
        let a = Json::obj([("rule", Json::str("source"))]);
        let b = Json::obj([("rule", Json::str("drift"))]);
        assert_ne!(digest_value(&a), digest_value(&b));
    }

    #[test]
    fn negative_zero_normalizes_to_zero() {
        let a = Json::Num(-0.0);
        let b = Json::Num(0.0);
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a).unwrap(), "0");
    }

    #[test]
    fn non_finite_number_has_no_digest() {
        assert_eq!(digest_value(&Json::Num(f64::NAN)), None);
        assert_eq!(digest_value(&Json::Num(f64::INFINITY)), None);
    }

    #[test]
    fn digest_form_matches_sha256_prefix() {
        let d = digest_value(&Json::str("x")).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }
}
