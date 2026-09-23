//! Self-contained JSON/canonicalization/digest/decision primitives for wf072.
//!
//! Faithful port of the subset of `src/lib/contracts/arcane/canonical.mjs`
//! and `src/lib/contracts/arcane/errors.mjs` that the wf072 modules need.
//! Deliberately dependency-free (std only) and self-contained: wf072 does
//! not own `Cargo.toml`, and `legion-policy`'s own `arcane_port`/other `wf_*`
//! siblings are not guaranteed to be wired into `wf_port::mod` at the same
//! time as this module (see the wf006/wf067 packets, which took the same
//! approach for the same reason). A later integration pass can replace this
//! with a single shared `legion-contracts::canonical` + `arcane_port::errors`
//! once every packet needing it is wired in.

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------
// Minimal JSON value + canonical serialization + sha256 digest.
// ---------------------------------------------------------------------

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
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::I64(n) => out.push_str(&n.to_string()),
        Json::F64(n) => {
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
                encode(item, out);
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
                encode(v, out);
            }
            out.push('}');
        }
    }
}

/// Canonical JSON text for `value`. Mirrors JS `canonicalJson` (finite-only
/// numbers are assumed here — non-finite `f64` is rejected upstream by
/// callers that build `Json` values, matching wf006/wf067's convention).
pub fn canonical_json(value: &Json) -> String {
    let mut out = String::new();
    encode(value, &mut out);
    out
}

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

/// Repo-wide digest form: `sha256:<64 lowercase hex>`.
pub fn digest(input: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&sha256(input)))
}

/// Digest of the canonical serialization of a structured value. Mirrors JS
/// `digestValue`.
pub fn digest_value(value: &Json) -> String {
    digest(canonical_json(value).as_bytes())
}

// ---------------------------------------------------------------------
// Typed error/decision, scoped to the codes wf072's five modules raise.
// Faithful in shape to `src/lib/contracts/arcane/errors.mjs`.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcCode {
    ArcSchemaInvalid,
    ArcDependencyUnknown,
    ArcAuthLegacyDigest,
    ArcUnsoundSeal,
    ArcSelfCertification,
    ArcEvidenceInsufficient,
    ArcEvidenceStale,
    ArcBindingMismatch,
    ArcGateInvalid,
    ArcClaimPrerequisiteUnmet,
    ArcModelSelfReport,
    ArcHostEventUntrusted,
    ArcHostEventInvalid,
    ArcIngestCorrelationMissing,
}

impl ArcCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArcCode::ArcSchemaInvalid => "ARC_SCHEMA_INVALID",
            ArcCode::ArcDependencyUnknown => "ARC_DEPENDENCY_UNKNOWN",
            ArcCode::ArcAuthLegacyDigest => "ARC_AUTH_LEGACY_DIGEST",
            ArcCode::ArcUnsoundSeal => "ARC_UNSOUND_SEAL",
            ArcCode::ArcSelfCertification => "ARC_SELF_CERTIFICATION",
            ArcCode::ArcEvidenceInsufficient => "ARC_EVIDENCE_INSUFFICIENT",
            ArcCode::ArcEvidenceStale => "ARC_EVIDENCE_STALE",
            ArcCode::ArcBindingMismatch => "ARC_BINDING_MISMATCH",
            ArcCode::ArcGateInvalid => "ARC_GATE_INVALID",
            ArcCode::ArcClaimPrerequisiteUnmet => "ARC_CLAIM_PREREQUISITE_UNMET",
            ArcCode::ArcModelSelfReport => "ARC_MODEL_SELF_REPORT",
            ArcCode::ArcHostEventUntrusted => "ARC_HOST_EVENT_UNTRUSTED",
            ArcCode::ArcHostEventInvalid => "ARC_HOST_EVENT_INVALID",
            ArcCode::ArcIngestCorrelationMissing => "ARC_INGEST_CORRELATION_MISSING",
        }
    }
}

impl fmt::Display for ArcCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub code: Option<ArcCode>,
    pub message: String,
    pub detail: BTreeMap<String, String>,
}

pub fn allow(message: impl Into<String>) -> Decision {
    Decision { allowed: true, code: None, message: message.into(), detail: BTreeMap::new() }
}

pub fn allow_detail(message: impl Into<String>, detail: BTreeMap<String, String>) -> Decision {
    Decision { allowed: true, code: None, message: message.into(), detail }
}

pub fn deny(code: ArcCode, message: impl Into<String>, detail: BTreeMap<String, String>) -> Decision {
    Decision { allowed: false, code: Some(code), message: message.into(), detail }
}

pub fn detail_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}
