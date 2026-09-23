//! Port of `src/providers/security/contracts.mjs`.
//!
//! Shared security evidence/verdict/path/chain/fact contracts: enum
//! vocabularies, the canonical `stableId`/`digest` hashing, and the
//! binding-freshness assertions every security artifact in this chunk
//! (`candidate-engine.mjs`, `attack-path-synthesis.mjs`,
//! `attack-path-reconcile.mjs`, `evidence-synthesis.mjs`) relies on.
//!
//! `enums.mjs`'s `EVIDENCE_CLASS` / `JUDGMENT_VERDICT` / `PROVIDER_ROLE` /
//! `PROVIDER_STATUS` re-exports are outside this chunk's owned files and are
//! not ported here; none of the five files this module covers reference
//! them directly (only `SECURITY_VERDICTS` etc., which are local to this
//! file in the JS source).
//!
//! Records are represented as `serde_json::Value` rather than fixed Rust
//! structs, matching the loosely-shaped plain-object style of the JS
//! source and the existing wf011 SDK port. The workspace `serde_json` has
//! `preserve_order` enabled, so `canonicalize`'s explicit key sort is what
//! makes `stableId`/`digest` match JS `JSON.stringify` byte-for-byte, not
//! map insertion order.

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Mirrors JS `throw new Error(...)` / `throw new TypeError(...)`: only the
/// message text is observable to callers, exactly as the JS test suite
/// matches on a regex against `.message`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SecurityContractError(pub String);

impl SecurityContractError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Result<T> = std::result::Result<T, SecurityContractError>;

pub const EVIDENCE_STRENGTH: &[&str] = &["possible", "strong-inference", "verified"];

pub fn evidence_rank(strength: &str) -> i64 {
    match strength {
        "possible" => 0,
        "strong-inference" => 1,
        "verified" => 2,
        _ => 0, // JS `EVIDENCE_RANK[x] ?? EVIDENCE_RANK.possible`
    }
}

pub const SECURITY_VERDICTS: &[&str] = &[
    "TRUE_POSITIVE",
    "LIKELY_TRUE_POSITIVE",
    "LIKELY_FALSE_POSITIVE",
    "FALSE_POSITIVE",
    "OUT_OF_SCOPE",
    "HARDENING_GAP",
    "MISUSE_HAZARD",
];

pub const PATH_STATUS: &[&str] = &[
    "PROPOSED",
    "PARTIALLY_SUPPORTED",
    "PROVEN",
    "REFUTED",
    "BLOCKED",
    "UNPROVEN",
];

pub const PATH_PRIORITY: &[&str] = &[
    "DIRECT_CROWN_JEWEL",
    "PRIVILEGE_ESCALATION",
    "CROSS_TENANT",
    "CREDENTIAL_PIVOT",
    "LATERAL_PIVOT",
    "CONTROL_BYPASS",
    "PERSISTENT_COMPROMISE",
    "DATA_EXFILTRATION",
    "INTEGRITY_DESTRUCTION",
    "AVAILABILITY_FAILURE",
    "PARTIAL_PATH",
];

pub const CHAIN_ROLES: &[&str] = &[
    "starter",
    "enabler",
    "pivot",
    "privilege-escalation",
    "control-bypass",
    "impact",
];

pub const FACT_KINDS: &[&str] = &[
    "attacker-position",
    "knowledge",
    "capability",
    "credential-possession",
    "principal-access",
    "network-reachability",
    "data-access",
    "object-access",
    "code-execution",
    "workflow-state",
    "control-bypass",
    "persistence",
    "availability-impact",
    "integrity-impact",
    "confidentiality-impact",
];

/// Alias, matching the JS `export const PRIMITIVE_VERDICTS = SECURITY_VERDICTS;`.
pub const PRIMITIVE_VERDICTS: &[&str] = SECURITY_VERDICTS;

pub const ENTITY_KINDS: &[&str] = &[
    "actor",
    "principal",
    "identity",
    "entrypoint",
    "asset",
    "crown-jewel",
    "trust-boundary",
    "control",
    "source",
    "sink",
    "service",
    "process",
    "repository-artifact",
    "data-store",
    "tool-capability",
    "permission-scope",
    "deployment-context",
    "workflow-state",
];

pub const RELATION_KINDS: &[&str] = &[
    "assumes-role",
    "authenticates-as",
    "authorizes",
    "calls",
    "contains",
    "crosses",
    "delegates-to",
    "derives-from",
    "executes",
    "exposes",
    "flows-to",
    "grants",
    "loads",
    "protects",
    "publishes-to",
    "reaches",
    "reads",
    "retrieves-from",
    "runs-as",
    "stores",
    "trusts",
    "validates",
    "writes",
];

pub const CONTROL_STATES: &[&str] = &[
    "enforced",
    "present-unenforced",
    "misconfigured",
    "absent",
    "unknown",
    "not-applicable",
];

/// Mirrors `SECURITY_SCHEMA_VERSIONS`: `(artifact kind, supported versions)`.
pub const SECURITY_SCHEMA_VERSIONS: &[(&str, &[i64])] = &[
    ("security-binding", &[1]),
    ("security-model", &[1]),
    ("security-candidate", &[2]),
    ("security-verdict", &[1]),
    ("attack-path-hypothesis", &[1]),
    ("security-chain-verdict", &[1]),
    ("security-variant-receipt", &[2]),
    ("security-evidence-synthesis", &[1]),
    ("hazard-model", &[1]),
    ("ai-quality-evaluation-receipt", &[1]),
    ("remediation-sandbox-receipt", &[1]),
    ("remediation-effect-graph", &[1]),
    ("remediation-verification", &[1]),
    ("remediation-apply-receipt", &[1]),
    ("remediation-accepted-risk", &[1]),
    ("untrusted-evidence", &[1]),
];

pub fn assert_enum(label: &str, values: &[&str], value: &str) -> Result<()> {
    if !values.contains(&value) {
        return Err(SecurityContractError::new(format!("unknown {label}: {value}")));
    }
    Ok(())
}

pub fn assert_entity_kind(value: &str) -> Result<()> {
    assert_enum("security entity kind", ENTITY_KINDS, value)
}

pub fn assert_relation_kind(value: &str) -> Result<()> {
    assert_enum("security relation kind", RELATION_KINDS, value)
}

pub fn assert_control_state(value: &str) -> Result<()> {
    assert_enum("security control state", CONTROL_STATES, value)
}

pub fn assert_fact_kind(value: &str) -> Result<()> {
    assert_enum("security fact kind", FACT_KINDS, value)
}

pub fn assert_security_schema_version(kind: &str, version: i64) -> Result<i64> {
    let supported = SECURITY_SCHEMA_VERSIONS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, versions)| *versions)
        .ok_or_else(|| SecurityContractError::new(format!("unknown security artifact kind: {kind}")))?;
    if !supported.contains(&version) {
        return Err(SecurityContractError::new(format!(
            "{kind} unsupported schema version: {version}"
        )));
    }
    Ok(version)
}

/// Faithful port of `canonicalize`: arrays map element-wise, objects have
/// their keys sorted (recursively), scalars pass through unchanged.
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
        other => other.clone(),
    }
}

/// Faithful port of `stableId`: `sha256:<hex(sha256("<namespace>\0<canonical-json>"))>`.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonicalize(value)).expect("canonical JSON never fails to serialize");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Faithful port of `digest`: `stableId('digest', value)`.
pub fn digest(value: &Value) -> String {
    stable_id("digest", value)
}

pub fn require_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| SecurityContractError::new(format!("{label} must be an object")))
}

pub fn require_string<'a>(value: &'a Value, label: &str) -> Result<&'a str> {
    match value.as_str() {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(SecurityContractError::new(format!("{label} must be a non-empty string"))),
    }
}

pub fn require_array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| SecurityContractError::new(format!("{label} must be an array")))
}

const BINDING_STRING_KEYS: &[&str] = &[
    "planDigest",
    "repositoryRevision",
    "blueprintGenerationId",
    "blueprintManifestDigest",
    "registryDigest",
];

/// Faithful port of `assertBinding`.
pub fn assert_binding(binding: &Value) -> Result<&Value> {
    require_object(binding, "binding")?;
    for key in BINDING_STRING_KEYS {
        require_string(&binding[*key], &format!("binding.{key}"))?;
    }
    let dirty = &binding["dirtyPatchDigest"];
    if !dirty.is_null() {
        require_string(dirty, "binding.dirtyPatchDigest")?;
    }
    Ok(binding)
}

/// Faithful port of `bindingFromPlan`.
pub fn binding_from_plan(plan: &Value) -> Result<Value> {
    let plan_digest = plan
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| SecurityContractError::new("plan has no seal digest"))?;
    let binding = serde_json::json!({
        "planDigest": plan_digest,
        "repositoryRevision": plan.pointer("/binding/repositoryRevision").cloned().unwrap_or(Value::Null),
        "dirtyPatchDigest": plan.pointer("/binding/dirtyPatchDigest").cloned().unwrap_or(Value::Null),
        "blueprintGenerationId": plan.pointer("/binding/blueprint/generationId").cloned().unwrap_or(Value::Null),
        "blueprintManifestDigest": plan.pointer("/binding/blueprint/manifestDigest").cloned().unwrap_or(Value::Null),
        "registryDigest": plan.pointer("/binding/registryDigest").cloned().unwrap_or(Value::Null),
    });
    assert_binding(&binding)?;
    Ok(binding)
}

/// Faithful port of `sameBinding`: canonical-JSON string equality.
pub fn same_binding(left: &Value, right: &Value) -> bool {
    serde_json::to_string(&canonicalize(left)).ok() == serde_json::to_string(&canonicalize(right)).ok()
}

/// Faithful port of `assertArtifactBinding`.
pub fn assert_artifact_binding(artifact: &Value, expected_binding: &Value, label: &str) -> Result<()> {
    let binding = artifact.get("binding").cloned().unwrap_or(Value::Null);
    assert_binding(&binding)?;
    if !same_binding(&binding, expected_binding) {
        return Err(SecurityContractError::new(format!(
            "{label} binding does not match the frozen audit plan"
        )));
    }
    Ok(())
}

/// Faithful port of `assertSecurityArtifact`.
pub fn assert_security_artifact<'a>(artifact: &'a Value, kind: &str) -> Result<&'a Value> {
    require_object(artifact, &format!("{kind} artifact"))?;
    let schema_version = artifact
        .get("schemaVersion")
        .and_then(Value::as_i64)
        .ok_or_else(|| SecurityContractError::new(format!("{kind} unsupported schema version: null")))?;
    assert_security_schema_version(kind, schema_version)?;
    assert_binding(&artifact["binding"])?;
    require_string(&artifact["denominatorDigest"], &format!("{kind}.denominatorDigest"))?;
    Ok(artifact)
}

/// Faithful port of `securityArtifactRecord`.
#[allow(clippy::too_many_arguments)]
pub fn security_artifact_record(
    path: &str,
    content_digest: &str,
    bytes: i64,
    producer: &str,
    producer_version: &str,
    media_type: Option<&str>,
    binding: &Value,
    denominator_digest: &str,
) -> Result<Value> {
    if path.is_empty() {
        return Err(SecurityContractError::new("artifact.path must be a non-empty string"));
    }
    if content_digest.is_empty() {
        return Err(SecurityContractError::new("artifact.digest must be a non-empty string"));
    }
    if bytes < 0 {
        return Err(SecurityContractError::new("artifact.bytes must be a non-negative integer"));
    }
    if producer.is_empty() {
        return Err(SecurityContractError::new("artifact.producer must be a non-empty string"));
    }
    if producer_version.is_empty() {
        return Err(SecurityContractError::new("artifact.producerVersion must be a non-empty string"));
    }
    if denominator_digest.is_empty() {
        return Err(SecurityContractError::new(
            "artifact.denominatorDigest must be a non-empty string",
        ));
    }
    let binding = assert_binding(binding)?.clone();
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "kind": "legion-artifact-record",
        "path": path,
        "digest": content_digest,
        "bytes": bytes,
        "producer": producer,
        "producerVersion": producer_version,
        "mediaType": media_type.unwrap_or("application/json"),
        "binding": binding,
        "denominatorDigest": denominator_digest,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan_with() -> Value {
        json!({
            "seal": {"digest": "sha256:plan"},
            "binding": {
                "repositoryRevision": "rev1",
                "dirtyPatchDigest": null,
                "blueprint": {"generationId": "gen1", "manifestDigest": "sha256:manifest"},
                "registryDigest": "sha256:registry",
            },
        })
    }

    #[test]
    fn canonicalize_sorts_object_keys_recursively() {
        let value = json!({"b": 1, "a": {"z": 1, "y": 2}});
        let out = canonicalize(&value);
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
        let nested_keys: Vec<&String> = out["a"].as_object().unwrap().keys().collect();
        assert_eq!(nested_keys, vec!["y", "z"]);
    }

    #[test]
    fn stable_id_is_deterministic_and_order_independent() {
        let a = stable_id("ns", &json!({"x": 1, "y": 2}));
        let b = stable_id("ns", &json!({"y": 2, "x": 1}));
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn stable_id_differs_by_namespace() {
        let a = stable_id("ns1", &json!({"x": 1}));
        let b = stable_id("ns2", &json!({"x": 1}));
        assert_ne!(a, b);
    }

    #[test]
    fn binding_from_plan_round_trips() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        assert_eq!(binding["planDigest"], "sha256:plan");
        assert_eq!(binding["repositoryRevision"], "rev1");
        assert_eq!(binding["blueprintGenerationId"], "gen1");
        assert_eq!(binding["dirtyPatchDigest"], Value::Null);
    }

    #[test]
    fn binding_from_plan_requires_seal_digest() {
        let err = binding_from_plan(&json!({})).unwrap_err();
        assert_eq!(err.0, "plan has no seal digest");
    }

    #[test]
    fn assert_artifact_binding_rejects_mismatch() {
        let plan = plan_with();
        let expected = binding_from_plan(&plan).unwrap();
        let mut other = expected.clone();
        other["repositoryRevision"] = json!("other");
        let artifact = json!({"binding": other});
        let err = assert_artifact_binding(&artifact, &expected, "thing").unwrap_err();
        assert!(err.0.contains("does not match the frozen audit plan"));
    }

    #[test]
    fn assert_artifact_binding_accepts_match() {
        let plan = plan_with();
        let expected = binding_from_plan(&plan).unwrap();
        let artifact = json!({"binding": expected});
        assert!(assert_artifact_binding(&artifact, &expected, "thing").is_ok());
    }

    #[test]
    fn evidence_rank_orders_strength() {
        assert_eq!(evidence_rank("possible"), 0);
        assert_eq!(evidence_rank("strong-inference"), 1);
        assert_eq!(evidence_rank("verified"), 2);
        assert_eq!(evidence_rank("unknown-value"), 0);
    }

    #[test]
    fn assert_security_schema_version_rejects_unknown_kind() {
        let err = assert_security_schema_version("not-a-kind", 1).unwrap_err();
        assert!(err.0.contains("unknown security artifact kind"));
    }

    #[test]
    fn security_artifact_record_requires_non_negative_bytes() {
        let binding = binding_from_plan(&plan_with()).unwrap();
        let err = security_artifact_record(
            "p", "sha256:x", -1, "prod", "1", None, &binding, "sha256:denom",
        )
        .unwrap_err();
        assert!(err.0.contains("non-negative"));
    }
}
