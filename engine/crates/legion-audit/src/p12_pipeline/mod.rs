//! P12 audit-lib port: plan sealing/authenticity and finding-id derivation.
//!
//! Faithful port of `tools/audit/audit-plan.mjs` (seal/verify functions) and
//! `tools/audit/audit_store.py` (`derive_finding_id`) plus
//! `src/registry/provider-registry.mjs` canonicalization helpers, which those
//! functions depend on byte-for-byte.
//!
//! Scope: packet P12-audit-lib. Do not edit `plan.rs`, `inventory.rs`, or
//! `lib.rs` in this crate, or `engine/bins/legion/**` — those are owned by a
//! concurrent packet. This module is self-contained and only depends on
//! `serde_json::Value` so it can be wired in later via a `lib.rs` patch
//! (see the packet report).

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Recursively sort object keys, mirroring `canonicalize()` in
/// `src/registry/provider-registry.mjs` (arrays map element-wise, objects
/// get their keys sorted, scalars pass through unchanged).
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

/// Mirrors `canonicalJson()`: `JSON.stringify(canonicalize(value))`.
/// `serde_json::to_string` on a `Map` preserves insertion order, and we
/// insert in sorted order above, so this matches Node's `JSON.stringify`
/// key ordering. Node's `JSON.stringify` uses no extra whitespace, which
/// `serde_json::to_string` (compact) also matches.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).expect("canonicalized JSON value always serializes")
}

/// Mirrors `sha256(value)`: hash the canonical JSON form (or the raw string,
/// if `value` is already a JSON string) and prefix with `sha256:`.
pub fn sha256_value(value: &Value) -> String {
    let bytes = match value {
        Value::String(s) => s.clone(),
        other => canonical_json(other),
    };
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Mirrors `sha256(string)` when the caller already has a raw string (Node's
/// `sha256()` skips canonicalization for `typeof value === 'string'`).
pub fn sha256_str(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Schema labels understood by `assertSupportedSchemaVersion`. Mirrors the
/// frozen `SCHEMA_VERSIONS` map in `audit-plan.mjs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaLabel {
    Plan,
    ProviderResult,
    SecurityVerdict,
}

impl SchemaLabel {
    fn as_str(self) -> &'static str {
        match self {
            SchemaLabel::Plan => "plan",
            SchemaLabel::ProviderResult => "providerResult",
            SchemaLabel::SecurityVerdict => "securityVerdict",
        }
    }

    fn supported_version(self) -> u32 {
        // Mirrors: { plan: 1, providerResult: 1, securityVerdict: 1 }
        match self {
            SchemaLabel::Plan => 1,
            SchemaLabel::ProviderResult => 1,
            SchemaLabel::SecurityVerdict => 1,
        }
    }
}

/// Mirrors `assertSupportedSchemaVersion(version, label)`. Returns the
/// version on success, or an error whose message matches the JS original.
pub fn assert_supported_schema_version(version: u32, label: SchemaLabel) -> Result<u32, String> {
    let supported = label.supported_version();
    if version > supported {
        return Err(format!(
            "{} schemaVersion {} is newer than this Legion build supports ({}); refusing to execute",
            label.as_str(),
            version,
            supported
        ));
    }
    Ok(version)
}

/// Mirrors `planSignature(unsigned, signingKey)`:
/// `hmac-sha256:<hex hmac-sha256(signingKey, canonicalJson(unsigned))>`.
fn plan_signature(unsigned: &Value, signing_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(canonical_json(unsigned).as_bytes());
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

/// Mirrors `signingKeyId(signingKey)`:
/// `sha256("audit-plan-key\0" + signingKey)`, then the first 16 hex chars
/// after the `sha256:` prefix.
fn signing_key_id(signing_key: &str) -> String {
    let raw = format!("audit-plan-key\0{}", signing_key);
    let digest = sha256_str(&raw);
    // digest is "sha256:" + 64 hex chars; take chars [7, 23).
    digest["sha256:".len().."sha256:".len() + 16].to_string()
}

/// Mirrors `sealPlan(plan, signingKey)`. `plan` must be a JSON object;
/// any existing `seal` key is dropped before sealing, exactly as the JS
/// spreads `{ ...plan }` and `delete unsigned.seal`.
pub fn seal_plan(plan: &Value, signing_key: Option<&str>) -> Value {
    let mut unsigned = plan.as_object().cloned().unwrap_or_default();
    unsigned.remove("seal");
    let unsigned_value = Value::Object(unsigned.clone());

    let digest = sha256_value(&unsigned_value);
    let mut seal = Map::new();
    seal.insert("algorithm".into(), Value::String("sha256".into()));
    seal.insert("digest".into(), Value::String(digest));

    if let Some(key) = signing_key {
        seal.insert("authenticity".into(), Value::String("hmac-sha256".into()));
        seal.insert(
            "signature".into(),
            Value::String(plan_signature(&unsigned_value, key)),
        );
        seal.insert("keyId".into(), Value::String(signing_key_id(key)));
        seal.insert(
            "semantics".into(),
            Value::String(
                "integrity digest plus key-backed HMAC signature bound to revision, dirty digest, Blueprint packet, registry digest, provider set, and denominators"
                    .into(),
            ),
        );
    } else {
        seal.insert("authenticity".into(), Value::String("unsigned".into()));
        seal.insert("signature".into(), Value::Null);
        seal.insert("keyId".into(), Value::Null);
        seal.insert(
            "semantics".into(),
            Value::String(
                "integrity digest only; authenticity is unproven until AUDIT_PLAN_SIGNING_KEY is supplied"
                    .into(),
            ),
        );
    }

    let mut result = unsigned;
    result.insert("seal".into(), Value::Object(seal));
    Value::Object(result)
}

/// Mirrors `verifyPlanSeal(plan)`.
pub fn verify_plan_seal(plan: &Value) -> bool {
    let seal = match plan.get("seal") {
        Some(Value::Object(s)) => s,
        _ => return false,
    };
    let algo_ok = matches!(seal.get("algorithm"), Some(Value::String(a)) if a == "sha256");
    let digest = match seal.get("digest") {
        Some(Value::String(d)) if !d.is_empty() => d,
        _ => return false,
    };
    if !algo_ok {
        return false;
    }
    let mut unsigned = plan.as_object().cloned().unwrap_or_default();
    unsigned.remove("seal");
    &sha256_value(&Value::Object(unsigned)) == digest
}

/// Mirrors `verifyPlanSignature(plan, signingKey)`.
pub fn verify_plan_signature(plan: &Value, signing_key: Option<&str>) -> bool {
    let signing_key = match signing_key {
        Some(k) => k,
        None => return false,
    };
    if !verify_plan_seal(plan) {
        return false;
    }
    let seal = match plan.get("seal").and_then(Value::as_object) {
        Some(s) => s,
        None => return false,
    };
    let authenticity_ok =
        matches!(seal.get("authenticity"), Some(Value::String(a)) if a == "hmac-sha256");
    let signature = match seal.get("signature") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return false,
    };
    if !authenticity_ok {
        return false;
    }
    let mut unsigned = plan.as_object().cloned().unwrap_or_default();
    unsigned.remove("seal");
    let unsigned_value = Value::Object(unsigned);

    let key_id_ok = matches!(seal.get("keyId"), Some(Value::String(k)) if *k == signing_key_id(signing_key));
    key_id_ok && signature == plan_signature(&unsigned_value, signing_key)
}

/// Mirrors `_locus_content_hash(path, start_line, end_line)` in
/// `tools/audit/audit_store.py`: normalize `path` to forward slashes and
/// strip a leading `/`, then `"sha256:" + sha256(f"{norm}:{start}-{end}")`
/// (full hex digest, `sha256:`-prefixed).
pub fn locus_content_hash(path: &str, start_line: i64, end_line: i64) -> String {
    let norm = normalize_locus_path(path);
    let raw = format!("{}:{}-{}", norm, start_line, end_line);
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn normalize_locus_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    slashed.trim_start_matches('/').to_string()
}

const ID_KIND_PREFIX: &str = "audit:rule:";

/// A finding's identity-bearing first evidence locus: `path`, `start_line`,
/// `end_line`. Mirrors the subset of `evidence_loci[0]` that
/// `derive_finding_id` reads (`path`, `startLine`, `endLine`).
#[derive(Debug, Clone)]
pub struct FindingLocus {
    pub path: String,
    pub start_line: i64,
    pub end_line: i64,
}

/// Mirrors `derive_finding_id(repository_id, rule_id, evidence_loci)` in
/// `tools/audit/audit_store.py`. Returns
/// `audit:rule:<7-hex-repo-digest>-<ruleId>:<normPath>:<7-hex-locus-digest>`.
/// Errors mirror the Python `ValueError`s (empty repository id, empty rule
/// id, or no evidence loci) verbatim in message shape, not text, since the
/// Python message text is not otherwise depended upon by callers ported so
/// far — see packet report for the exact strings if a caller needs them.
pub fn derive_finding_id(
    repository_id: &str,
    rule_id: &str,
    first_locus: Option<&FindingLocus>,
) -> Result<String, String> {
    let norm_repo = repository_id.trim();
    if norm_repo.is_empty() {
        return Err("repositoryId is required for stable finding ID".to_string());
    }
    let norm_rule = rule_id.trim();
    if norm_rule.is_empty() {
        return Err("ruleId is required for stable finding ID".to_string());
    }
    let first = first_locus
        .ok_or_else(|| "at least one evidence locus is required for stable finding ID".to_string())?;

    let locus_hash = locus_content_hash(&first.path, first.start_line, first.end_line);
    let norm_path = normalize_locus_path(&first.path);

    let mut repo_hasher = Sha256::new();
    repo_hasher.update(norm_repo.as_bytes());
    let repo_digest = &hex::encode(repo_hasher.finalize())[..7];

    // locus_hash is "sha256:<64 hex>"; take the first 7 hex chars after the prefix
    // (mirrors Python's `locus_hash.rsplit(":", 1)[-1][:7]`).
    let locus_digest = &locus_hash["sha256:".len()..][..7];

    Ok(format!(
        "{}{}-{}:{}:{}",
        ID_KIND_PREFIX, repo_digest, norm_rule, norm_path, locus_digest
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_object_keys_recursively() {
        let value = json!({"b": 1, "a": {"z": 1, "y": 2}, "c": [3, {"b": 1, "a": 2}]});
        let out = canonical_json(&value);
        assert_eq!(out, r#"{"a":{"y":2,"z":1},"b":1,"c":[3,{"a":2,"b":1}]}"#);
    }

    #[test]
    fn sha256_value_matches_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256_str("");
        assert_eq!(
            digest,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn assert_supported_schema_version_rejects_future_versions() {
        assert!(assert_supported_schema_version(1, SchemaLabel::Plan).is_ok());
        let err = assert_supported_schema_version(2, SchemaLabel::Plan).unwrap_err();
        assert_eq!(
            err,
            "plan schemaVersion 2 is newer than this Legion build supports (1); refusing to execute"
        );
    }

    #[test]
    fn seal_plan_unsigned_round_trips_through_verify() {
        let plan = json!({"revision": "abc123", "providers": []});
        let sealed = seal_plan(&plan, None);
        assert_eq!(sealed["seal"]["authenticity"], "unsigned");
        assert!(sealed["seal"]["signature"].is_null());
        assert!(verify_plan_seal(&sealed));
        assert!(!verify_plan_signature(&sealed, None));
        assert!(!verify_plan_signature(&sealed, Some("some-key")));
    }

    #[test]
    fn seal_plan_signed_round_trips_through_verify() {
        let plan = json!({"revision": "abc123", "providers": []});
        let sealed = seal_plan(&plan, Some("test-signing-key"));
        assert_eq!(sealed["seal"]["authenticity"], "hmac-sha256");
        assert!(sealed["seal"]["signature"].is_string());
        assert!(verify_plan_seal(&sealed));
        assert!(verify_plan_signature(&sealed, Some("test-signing-key")));
        assert!(!verify_plan_signature(&sealed, Some("wrong-key")));
        assert!(!verify_plan_signature(&sealed, None));
    }

    #[test]
    fn verify_plan_seal_detects_tampering() {
        let plan = json!({"revision": "abc123", "providers": []});
        let mut sealed = seal_plan(&plan, Some("test-signing-key"));
        sealed["revision"] = json!("tampered");
        assert!(!verify_plan_seal(&sealed));
        assert!(!verify_plan_signature(&sealed, Some("test-signing-key")));
    }

    #[test]
    fn re_sealing_is_idempotent_on_the_seal_field() {
        // sealPlan first strips any existing `seal` key before computing the
        // new one, so sealing an already-sealed plan twice with the same key
        // produces the same seal (digest is over the unsigned body only).
        let plan = json!({"revision": "abc123", "providers": []});
        let once = seal_plan(&plan, Some("k"));
        let twice = seal_plan(&once, Some("k"));
        assert_eq!(once["seal"], twice["seal"]);
    }

    #[test]
    fn locus_content_hash_matches_python_format() {
        // Python: "sha256:" + hashlib.sha256(f"{norm}:{start}-{end}".encode()).hexdigest()
        let h = locus_content_hash("src/foo.rs", 10, 20);
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), "sha256:".len() + 64);
        // Same inputs are stable; different inputs differ.
        assert_eq!(h, locus_content_hash("src/foo.rs", 10, 20));
        assert_ne!(h, locus_content_hash("src/foo.rs", 10, 21));
        // Leading slash and backslashes are normalized away.
        assert_eq!(h, locus_content_hash("/src/foo.rs", 10, 20));
        assert_eq!(
            locus_content_hash("src\\foo.rs", 10, 20),
            locus_content_hash("src/foo.rs", 10, 20)
        );
    }

    #[test]
    fn derive_finding_id_is_stable_and_prefixed() {
        let locus = FindingLocus { path: "src/foo.rs".into(), start_line: 10, end_line: 20 };
        let id = derive_finding_id("legion-audit/opengrep", "rule-001", Some(&locus)).unwrap();
        assert!(id.starts_with("audit:rule:"));
        assert!(id.contains("rule-001"));
        assert!(id.contains("src/foo.rs"));
        assert_eq!(
            id,
            derive_finding_id("legion-audit/opengrep", "rule-001", Some(&locus)).unwrap()
        );
        let other = FindingLocus { path: "src/foo.rs".into(), start_line: 10, end_line: 21 };
        assert_ne!(
            id,
            derive_finding_id("legion-audit/opengrep", "rule-001", Some(&other)).unwrap()
        );
    }

    #[test]
    fn derive_finding_id_rejects_empty_identity_inputs() {
        let locus = FindingLocus { path: "src/foo.rs".into(), start_line: 1, end_line: 2 };
        assert!(derive_finding_id("", "rule-001", Some(&locus)).is_err());
        assert!(derive_finding_id("repo", "", Some(&locus)).is_err());
        assert!(derive_finding_id("repo", "rule-001", None).is_err());
    }
}
