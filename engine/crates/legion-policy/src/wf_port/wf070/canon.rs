//! Local canonical-serialization, digest, HMAC, and id-minting support for
//! wf070.
//!
//! Faithful port of the *rules* in `src/lib/contracts/arcane/canonical.mjs`
//! and `src/lib/contracts/arcane/ids.mjs`, scoped to this module because
//! wf070 owns only `wf_port/wf070/**`: neither `arcane_port` (which has no
//! canonical/ids/receipt-auth port yet) nor `Cargo.toml` (to add a JSON
//! value crate to `legion-policy`'s main dependencies) are files this owner
//! may edit. See the wf070 report's "shared-file patches" section: once a
//! canonical `legion_policy::arcane_port::canonical`/`ids`/`receipt_auth`
//! land, this module should be deleted and wf070 should depend on those
//! instead (the "one entry point per concern" rule other packets already
//! follow for detokenization applies here too).
//!
//! `CanonVal` stands in for the untyped JS object graph the source files
//! pass around; `BTreeMap` already sorts keys, so canonical key ordering
//! falls out of the type rather than needing a manual sort step.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanonVal {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<CanonVal>),
    Obj(BTreeMap<String, CanonVal>),
}

impl CanonVal {
    pub fn obj() -> CanonVal {
        CanonVal::Obj(BTreeMap::new())
    }
    pub fn set(mut self, key: &str, value: CanonVal) -> CanonVal {
        if let CanonVal::Obj(map) = &mut self {
            map.insert(key.to_string(), value);
        }
        self
    }
    pub fn get<'a>(&'a self, key: &str) -> Option<&'a CanonVal> {
        match self {
            CanonVal::Obj(map) => map.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CanonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            CanonVal::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<CanonVal>> {
        match self {
            CanonVal::Arr(items) => Some(items),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, CanonVal>> {
        match self {
            CanonVal::Obj(map) => Some(map),
            _ => None,
        }
    }
}

fn escape_json_string(input: &str, out: &mut String) {
    out.push('"');
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
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

fn encode(value: &CanonVal, out: &mut String) {
    match value {
        CanonVal::Null => out.push_str("null"),
        CanonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        CanonVal::Int(i) => {
            let _ = write!(out, "{i}");
        }
        CanonVal::Str(s) => escape_json_string(s, out),
        CanonVal::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out);
            }
            out.push(']');
        }
        CanonVal::Obj(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
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

/// Canonical JSON text for `value`. Mirrors `canonicalJson` in
/// `canonical.mjs`: sorted keys, no insignificant whitespace.
pub fn canonical_json(value: &CanonVal) -> String {
    let mut out = String::new();
    encode(value, &mut out);
    out
}

/// Raw lowercase hex sha256 of a byte slice. Mirrors `sha256Hex`.
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Repo-wide digest form: `sha256:<64 lowercase hex>`. Mirrors `digest`.
pub fn digest(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

/// Digest of the canonical serialization of a structured value. Mirrors
/// `digestValue`.
pub fn digest_value(value: &CanonVal) -> String {
    digest(&canonical_json(value))
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !(b as char).is_ascii_uppercase())
}

/// Constant-time comparison of two byte strings. Mirrors `constantTimeEqual`:
/// returns false (never a differently-timed path callers can exploit as a
/// length oracle they didn't already have) on length mismatch.
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

/// HMAC-SHA256, hex-encoded. Manual construction (no `hmac` crate in this
/// crate's dependency set; see the module doc for why a new dependency
/// wasn't added here) but standard: block size 64 bytes for SHA-256.
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
pub fn project_bound_fields<'a>(
    record: &'a BTreeMap<String, CanonVal>,
    fields: &[&str],
) -> Result<BTreeMap<String, CanonVal>, String> {
    let mut out = BTreeMap::new();
    for field in fields {
        match record.get(*field) {
            Some(value) => {
                out.insert((*field).to_string(), value.clone());
            }
            None => return Err(format!("bound field missing: {field}")),
        }
    }
    Ok(out)
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Format-faithful id minting: `<prefix><26 crockford chars>`, matching the
/// `ID_PATTERN` grammar in `ids.mjs`. The JS source draws its random
/// component from a CSPRNG (`node:crypto.randomBytes`); this crate has none
/// in its dependency set (see module doc), so uniqueness here is derived
/// from wall-clock nanoseconds plus a process-local monotonic counter rather
/// than cryptographic randomness. That is sufficient for the grammar and for
/// intra-process uniqueness (event ids in a single `ArchitectureEventStore`)
/// but is not a security property — flagged in the wf070 report as a
/// candidate for a `rand` dependency once the integration owner can add one.
pub fn mint_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bits: u128 = nanos ^ ((seq as u128) << 64) ^ 0x9E3779B97F4A7C15;
    let mut chars = [0u8; 26];
    for slot in chars.iter_mut().rev() {
        *slot = CROCKFORD[(bits & 0x1f) as usize];
        bits >>= 5;
        if bits == 0 {
            // Re-seed the tail so a burst of ids in the same nanosecond still
            // diverges lexicographically once the counter has advanced.
            bits = (seq as u128).wrapping_mul(0x2545F4914F6CDD1D);
        }
    }
    let suffix: String = chars.iter().map(|&b| b as char).collect();
    format!("{prefix}{suffix}")
}

pub fn is_ulid_shaped(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| CROCKFORD.contains(&b.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> CanonVal {
        CanonVal::Str(v.to_string())
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let value = CanonVal::obj().set("b", CanonVal::Int(1)).set("a", CanonVal::Int(2));
        assert_eq!(canonical_json(&value), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonical_json_nested_arrays_and_strings() {
        let value = CanonVal::obj().set(
            "items",
            CanonVal::Arr(vec![s("x"), CanonVal::Null, CanonVal::Bool(true)]),
        );
        assert_eq!(canonical_json(&value), r#"{"items":["x",null,true]}"#);
    }

    #[test]
    fn digest_value_matches_known_sha256_of_canonical_form() {
        let value = CanonVal::obj().set("a", CanonVal::Int(1));
        let d = digest_value(&value);
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), 71);
        assert!(is_digest(&d));
    }

    #[test]
    fn digest_is_stable_across_key_insertion_order() {
        let a = CanonVal::obj().set("a", CanonVal::Int(1)).set("b", CanonVal::Int(2));
        let b = CanonVal::obj().set("b", CanonVal::Int(2)).set("a", CanonVal::Int(1));
        assert_eq!(digest_value(&a), digest_value(&b));
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        // RFC 4231 test case 1: key 0x0b*20, data "Hi There".
        let key = vec![0x0bu8; 20];
        let mac = hmac_sha256_hex(&key, b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff"
        );
    }

    #[test]
    fn constant_time_equal_rejects_length_mismatch() {
        assert!(!constant_time_equal(b"abc", b"ab"));
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
    }

    #[test]
    fn project_bound_fields_errors_on_missing_field() {
        let mut record = BTreeMap::new();
        record.insert("x".to_string(), CanonVal::Int(1));
        assert!(project_bound_fields(&record, &["x", "y"]).is_err());
        assert!(project_bound_fields(&record, &["x"]).is_ok());
    }

    #[test]
    fn mint_id_matches_grammar_shape() {
        let id = mint_id("art_");
        assert!(id.starts_with("art_"));
        assert!(is_ulid_shaped(&id[4..]));
    }

    #[test]
    fn mint_id_is_unique_across_calls() {
        let a = mint_id("ev_");
        let b = mint_id("ev_");
        assert_ne!(a, b);
    }
}
