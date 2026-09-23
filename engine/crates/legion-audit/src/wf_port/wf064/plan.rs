//! Port of `tools/audit/audit-plan.mjs`.
//!
//! Scope note: `buildAuditPlan` composes `selectProviders` /
//! `evaluateCoverageFamilies` / `registryDigest` from
//! `src/registry/provider-registry.mjs`, which this chunk (wf064,
//! `tools/audit/audit-*.mjs`) does not own and has no Rust port of in this
//! tree yet. Porting `buildAuditPlan` faithfully needs that registry's Rust
//! types first, so it is left as a gap here. Every other exported function
//! in `audit-plan.mjs` is self-contained (seal/verify/binding/reconciliation
//! over an already-built plan) and is ported below against
//! `serde_json::Value`, matching the open (non-fixed-schema) shape the JS
//! plan/facts objects carry. `writeAuditPlan`'s file I/O is not ported
//! (belongs to whatever native provider-runtime shells out today).

use crate::wf_port::wf064::common::{canonical_json, hmac_sha256_hex, sha256_str, sha256_value};
use serde_json::{json, Map, Value};

/// `SCHEMA_VERSIONS` — the single source of truth for schema versions bound
/// into every plan.
pub fn schema_version_for(label: &str) -> Option<i64> {
    match label {
        "plan" => Some(1),
        "providerResult" => Some(1),
        "securityVerdict" => Some(1),
        _ => None,
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("unknown schema label {0}")]
    UnknownLabel(String),
    #[error("{label} schemaVersion {version} is newer than this Legion build supports ({supported}); refusing to execute")]
    TooNew {
        label: String,
        version: i64,
        supported: i64,
    },
}

/// Faithful port of `assertSupportedSchemaVersion`. The JS `typeof version
/// !== 'number'` guard is subsumed by `version: i64` in the Rust signature.
pub fn assert_supported_schema_version(version: i64, label: &str) -> Result<i64, SchemaError> {
    let supported =
        schema_version_for(label).ok_or_else(|| SchemaError::UnknownLabel(label.to_string()))?;
    if version > supported {
        return Err(SchemaError::TooNew {
            label: label.to_string(),
            version,
            supported,
        });
    }
    Ok(version)
}

/// Faithful port of `normalizedScope`. `scope` is the raw, possibly-partial
/// input object; every field defaults exactly as the JS `??` chain does,
/// including the `base_commit` snake_case fallback the JS also accepts.
pub fn normalized_scope(scope: &Value) -> Value {
    let mode = scope.get("mode").cloned().filter(|v| !v.is_null());
    let kind = scope.get("type").cloned().filter(|v| !v.is_null());
    let base = scope.get("base").cloned().filter(|v| !v.is_null());
    let base_commit = scope
        .get("baseCommit")
        .cloned()
        .filter(|v| !v.is_null())
        .or_else(|| scope.get("base_commit").cloned().filter(|v| !v.is_null()));
    let dir = scope.get("dir").cloned().filter(|v| !v.is_null());
    json!({
        "mode": mode.unwrap_or_else(|| json!("whole-repo")),
        "type": kind.unwrap_or_else(|| json!("all")),
        "base": base.unwrap_or(Value::Null),
        "baseCommit": base_commit.unwrap_or(Value::Null),
        "dir": dir.unwrap_or(Value::Null),
    })
}

fn plan_signature(unsigned: &Value, signing_key: &str) -> String {
    format!(
        "hmac-sha256:{}",
        hmac_sha256_hex(signing_key, &canonical_json(unsigned))
    )
}

/// Faithful port of `signingKeyId`: `sha256(\`audit-plan-key\0${key}\`)`
/// (`"sha256:" + 64 hex chars`), sliced to the first 16 hex chars after the
/// `sha256:` prefix (`.slice(7, 23)`).
fn signing_key_id(signing_key: &str) -> String {
    let full = sha256_str(&format!("audit-plan-key\0{signing_key}"));
    full[7..23].to_string()
}

fn without_seal(plan: &Map<String, Value>) -> Map<String, Value> {
    let mut unsigned = plan.clone();
    unsigned.remove("seal");
    unsigned
}

/// Faithful port of `sealPlan`.
pub fn seal_plan(plan: &Map<String, Value>, signing_key: Option<&str>) -> Map<String, Value> {
    let unsigned = without_seal(plan);
    let unsigned_value = Value::Object(unsigned.clone());
    let digest = sha256_value(&unsigned_value);
    let seal = match signing_key {
        Some(key) => json!({
            "algorithm": "sha256",
            "digest": digest,
            "authenticity": "hmac-sha256",
            "signature": plan_signature(&unsigned_value, key),
            "keyId": signing_key_id(key),
            "semantics": "integrity digest plus key-backed HMAC signature bound to revision, dirty digest, Blueprint packet, registry digest, provider set, and denominators",
        }),
        None => json!({
            "algorithm": "sha256",
            "digest": digest,
            "authenticity": "unsigned",
            "signature": Value::Null,
            "keyId": Value::Null,
            "semantics": "integrity digest only; authenticity is unproven until AUDIT_PLAN_SIGNING_KEY is supplied",
        }),
    };
    let mut sealed = unsigned;
    sealed.insert("seal".to_string(), seal);
    sealed
}

/// Faithful port of `verifyPlanSeal`.
pub fn verify_plan_seal(plan: &Map<String, Value>) -> bool {
    let seal = plan.get("seal");
    let algorithm_ok = seal
        .and_then(|s| s.get("algorithm"))
        .and_then(|a| a.as_str())
        == Some("sha256");
    let digest = seal.and_then(|s| s.get("digest")).and_then(|d| d.as_str());
    let (Some(digest), true) = (digest, algorithm_ok) else {
        return false;
    };
    let unsigned = without_seal(plan);
    sha256_value(&Value::Object(unsigned)) == digest
}

/// Faithful port of `verifyPlanSignature`.
pub fn verify_plan_signature(plan: &Map<String, Value>, signing_key: Option<&str>) -> bool {
    if !verify_plan_seal(plan) {
        return false;
    }
    let Some(signing_key) = signing_key else {
        return false;
    };
    let seal = plan.get("seal");
    let authenticity = seal
        .and_then(|s| s.get("authenticity"))
        .and_then(|a| a.as_str());
    let signature = seal
        .and_then(|s| s.get("signature"))
        .and_then(|s| s.as_str());
    if authenticity != Some("hmac-sha256") || signature.is_none() {
        return false;
    }
    let key_id = seal.and_then(|s| s.get("keyId")).and_then(|k| k.as_str());
    let unsigned = without_seal(plan);
    let expected_signature = plan_signature(&Value::Object(unsigned), signing_key);
    key_id == Some(signing_key_id(signing_key).as_str()) && signature == Some(expected_signature.as_str())
}

/// Faithful port of `verifyPlanBinding`. Returns `{valid, drift}` exactly as
/// the JS object shape does, so callers already reading JSON facts need no
/// remapping.
pub fn verify_plan_binding(
    plan: &Map<String, Value>,
    current_repository_binding: &Value,
    current_blueprint_binding: &Value,
    signing_key: Option<&str>,
) -> Value {
    let mut drift: Vec<Value> = Vec::new();
    let plan_value = Value::Object(plan.clone());
    let seal_digest = plan_value
        .pointer("/seal/digest")
        .cloned()
        .unwrap_or(Value::Null);
    if !verify_plan_seal(plan) {
        drift.push(json!({"field": "seal", "expected": seal_digest, "observed": "invalid"}));
    }
    if !verify_plan_signature(plan, signing_key) {
        let authenticity = plan_value
            .pointer("/seal/authenticity")
            .cloned()
            .unwrap_or(json!("missing"));
        drift.push(json!({"field": "signature", "expected": "valid hmac-sha256", "observed": authenticity}));
    }

    let binding = plan_value.get("binding").cloned().unwrap_or(Value::Null);
    let field_eq = |field: &str, plan_ptr: &str, cur: &Value, drift: &mut Vec<Value>| {
        let expected = binding.pointer(plan_ptr).cloned().unwrap_or(Value::Null);
        if &expected != cur {
            drift.push(json!({"field": field, "expected": expected, "observed": cur}));
        }
    };
    let cur_rev = current_repository_binding
        .get("repositoryRevision")
        .cloned()
        .unwrap_or(Value::Null);
    field_eq("repositoryRevision", "/repositoryRevision", &cur_rev, &mut drift);
    let cur_dirty = current_repository_binding
        .get("dirty")
        .cloned()
        .unwrap_or(Value::Null);
    field_eq("dirty", "/dirty", &cur_dirty, &mut drift);
    let cur_digest = current_repository_binding
        .get("dirtyPatchDigest")
        .cloned()
        .unwrap_or(Value::Null);
    field_eq(
        "dirtyPatchDigest",
        "/dirtyPatchDigest",
        &cur_digest,
        &mut drift,
    );

    let current_state = current_blueprint_binding
        .get("state")
        .and_then(|v| v.as_str());
    if current_state != Some("ready") {
        let observed = current_state.map(Value::from).unwrap_or_else(|| json!("unproven"));
        drift.push(json!({"field": "blueprint", "expected": "ready", "observed": observed}));
    } else {
        let plan_gen_id = binding
            .pointer("/blueprint/generationId")
            .cloned()
            .unwrap_or(Value::Null);
        let cur_gen_id = current_blueprint_binding
            .get("generationId")
            .cloned()
            .unwrap_or(Value::Null);
        if plan_gen_id != cur_gen_id {
            drift.push(json!({"field": "blueprint.generationId", "expected": plan_gen_id, "observed": cur_gen_id}));
        }
        let plan_manifest_digest = binding.pointer("/blueprint/manifestDigest");
        let cur_manifest_digest = current_blueprint_binding.get("manifestDigest");
        if let (Some(p), Some(c)) = (plan_manifest_digest, cur_manifest_digest) {
            if !p.is_null() && !c.is_null() && p != c {
                drift.push(json!({"field": "blueprint.manifestDigest", "expected": p, "observed": c}));
            }
        }
        let plan_status_digest = binding
            .pointer("/blueprint/sourceStatusDigest")
            .cloned()
            .unwrap_or(Value::Null);
        let cur_status_digest = current_blueprint_binding
            .pointer("/sourceObservation/statusDigest")
            .cloned()
            .unwrap_or(Value::Null);
        if plan_status_digest != cur_status_digest {
            drift.push(json!({"field": "blueprint.sourceStatusDigest", "expected": plan_status_digest, "observed": cur_status_digest}));
        }
        let plan_source_head = binding
            .pointer("/blueprint/sourceHead")
            .cloned()
            .unwrap_or(Value::Null);
        let cur_source_head = current_blueprint_binding
            .pointer("/sourceObservation/head")
            .cloned()
            .unwrap_or(Value::Null);
        if plan_source_head != cur_source_head {
            drift.push(json!({"field": "blueprint.sourceHead", "expected": plan_source_head, "observed": cur_source_head}));
        }
    }

    json!({"valid": drift.is_empty(), "drift": drift})
}

/// Faithful port of `reconcilePlanWithFacts`.
pub fn reconcile_plan_with_facts(plan: &Map<String, Value>, facts: &Value) -> Value {
    use std::collections::BTreeSet;

    let expected: BTreeSet<String> = plan
        .pointer("/denominator/expectedChecks")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let checks: Vec<Value> = facts
        .get("checks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let observed: std::collections::BTreeMap<String, &Value> = checks
        .iter()
        .filter_map(|c| c.get("check").and_then(|v| v.as_str()).map(|k| (k.to_string(), c)))
        .collect();
    let mut missing: Vec<String> = expected
        .iter()
        .filter(|c| !observed.contains_key(*c))
        .cloned()
        .collect();
    missing.sort();
    let supplemental: BTreeSet<String> = checks
        .iter()
        .filter(|c| c.get("tier").and_then(|t| t.as_str()) == Some("supplemental"))
        .filter_map(|c| c.get("check").and_then(|v| v.as_str()).map(String::from))
        .collect();
    let mut unplanned: Vec<String> = observed
        .keys()
        .filter(|k| !expected.contains(*k) && !supplemental.contains(*k))
        .cloned()
        .collect();
    unplanned.sort();

    let providers: Vec<Value> = plan
        .get("providers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let provider_results: Vec<Value> = providers
        .iter()
        .map(|provider| {
            let runner_kind = provider.pointer("/runner/kind").and_then(|k| k.as_str());
            let benchmark = provider.get("benchmark").cloned().unwrap_or(Value::Null);
            if runner_kind == Some("legacy-check") {
                let check_name = provider
                    .pointer("/runner/check")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                let result = observed.get(check_name).copied();
                json!({
                    "provider": provider.get("id").cloned().unwrap_or(Value::Null),
                    "phase": provider.get("phase").cloned().unwrap_or(Value::Null),
                    "check": check_name,
                    "status": result.and_then(|r| r.get("status")).cloned().unwrap_or_else(|| json!("missing")),
                    "complete": result
                        .map(|r| r.get("status").and_then(|s| s.as_str()) == Some("ran"))
                        .unwrap_or(false),
                    "findingsCount": result.and_then(|r| r.get("findings_count")).cloned().unwrap_or(Value::Null),
                    "benchmark": benchmark,
                })
            } else {
                json!({
                    "provider": provider.get("id").cloned().unwrap_or(Value::Null),
                    "phase": provider.get("phase").cloned().unwrap_or(Value::Null),
                    "status": "pending",
                    "complete": false,
                    "benchmark": benchmark,
                })
            }
        })
        .collect();

    json!({
        "valid": missing.is_empty() && unplanned.is_empty(),
        "expectedChecks": expected.into_iter().collect::<Vec<_>>(),
        "observedChecks": observed.keys().cloned().collect::<Vec<_>>(),
        "missingChecks": missing,
        "unplannedChecks": unplanned,
        "providerResults": provider_results,
    })
}

/// Faithful port of `stablePlanDigest`: `sha256(canonicalJson(plan))`. `sha256`
/// receives a string here (already-canonicalized JSON), so it hashes those
/// bytes directly rather than re-canonicalizing — same result either way
/// since the input is already canonical.
pub fn stable_plan_digest(plan: &Map<String, Value>) -> String {
    sha256_str(&canonical_json(&Value::Object(plan.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn schema_version_rejects_future_versions() {
        let err = assert_supported_schema_version(2, "plan").unwrap_err();
        assert_eq!(
            err,
            SchemaError::TooNew {
                label: "plan".to_string(),
                version: 2,
                supported: 1
            }
        );
        assert!(err.to_string().contains("refusing to execute"));
        assert_eq!(assert_supported_schema_version(1, "plan").unwrap(), 1);
    }

    #[test]
    fn schema_version_rejects_unknown_label() {
        assert_eq!(
            assert_supported_schema_version(1, "bogus").unwrap_err(),
            SchemaError::UnknownLabel("bogus".to_string())
        );
    }

    #[test]
    fn normalized_scope_defaults_and_base_commit_fallback() {
        let out = normalized_scope(&json!({}));
        assert_eq!(out["mode"], json!("whole-repo"));
        assert_eq!(out["type"], json!("all"));
        assert_eq!(out["base"], Value::Null);

        // snake_case base_commit fallback, matching JS `?? scope.base_commit`.
        let out2 = normalized_scope(&json!({"base_commit": "abc123"}));
        assert_eq!(out2["baseCommit"], json!("abc123"));

        // camelCase takes priority when both are present.
        let out3 = normalized_scope(&json!({"baseCommit": "camel", "base_commit": "snake"}));
        assert_eq!(out3["baseCommit"], json!("camel"));
    }

    #[test]
    fn seal_unsigned_then_signed_round_trip() {
        let plan = obj(json!({"kind": "audit-provider-plan", "root": "/repo"}));
        let sealed = seal_plan(&plan, None);
        assert!(verify_plan_seal(&sealed));
        assert!(!verify_plan_signature(&sealed, None));
        assert_eq!(sealed["seal"]["authenticity"], json!("unsigned"));

        let signed = seal_plan(&plan, Some("secret-key"));
        assert!(verify_plan_seal(&signed));
        assert!(verify_plan_signature(&signed, Some("secret-key")));
        assert!(!verify_plan_signature(&signed, Some("wrong-key")));
        assert!(!verify_plan_signature(&signed, None));
        assert_eq!(signed["seal"]["keyId"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn tampered_plan_fails_seal_verification() {
        let plan = obj(json!({"kind": "audit-provider-plan", "root": "/repo"}));
        let mut sealed = seal_plan(&plan, Some("secret-key"));
        sealed.insert("root".to_string(), json!("/tampered"));
        assert!(!verify_plan_seal(&sealed));
        assert!(!verify_plan_signature(&sealed, Some("secret-key")));
    }

    #[test]
    fn verify_plan_binding_reports_drift() {
        let plan = seal_plan(
            &obj(json!({
                "binding": {
                    "repositoryRevision": "rev1",
                    "dirty": false,
                    "dirtyPatchDigest": null,
                    "blueprint": {"generationId": "gen1", "manifestDigest": "md1", "sourceStatusDigest": "sd1", "sourceHead": "head1"},
                },
            })),
            None,
        );
        let current_repo = json!({"repositoryRevision": "rev2", "dirty": false, "dirtyPatchDigest": null});
        let current_blueprint = json!({
            "state": "ready", "generationId": "gen1", "manifestDigest": "md1",
            "sourceObservation": {"statusDigest": "sd1", "head": "head1"},
        });
        let result = verify_plan_binding(&plan, &current_repo, &current_blueprint, None);
        assert_eq!(result["valid"], json!(false));
        let drift = result["drift"].as_array().unwrap();
        assert!(drift.iter().any(|d| d["field"] == json!("repositoryRevision")));
    }

    #[test]
    fn verify_plan_binding_valid_when_everything_matches() {
        let plan = seal_plan(
            &obj(json!({
                "binding": {
                    "repositoryRevision": "rev1", "dirty": false, "dirtyPatchDigest": null,
                    "blueprint": {"generationId": "gen1", "manifestDigest": "md1", "sourceStatusDigest": "sd1", "sourceHead": "head1"},
                },
            })),
            Some("k"),
        );
        let current_repo = json!({"repositoryRevision": "rev1", "dirty": false, "dirtyPatchDigest": null});
        let current_blueprint = json!({
            "state": "ready", "generationId": "gen1", "manifestDigest": "md1",
            "sourceObservation": {"statusDigest": "sd1", "head": "head1"},
        });
        let result = verify_plan_binding(&plan, &current_repo, &current_blueprint, Some("k"));
        assert_eq!(result["valid"], json!(true));
        assert!(result["drift"].as_array().unwrap().is_empty());
    }

    #[test]
    fn reconcile_plan_with_facts_finds_missing_and_unplanned() {
        let plan = obj(json!({
            "denominator": {"expectedChecks": ["types", "lint"]},
            "providers": [
                {"id": "p.types", "phase": "facts", "runner": {"kind": "legacy-check", "check": "types"}, "benchmark": null},
                {"id": "p.lint", "phase": "facts", "runner": {"kind": "legacy-check", "check": "lint"}, "benchmark": null},
                {"id": "p.reasoning", "phase": "reasoning", "runner": {"kind": "reasoning-contract"}, "benchmark": null},
            ],
        }));
        let facts = json!({"checks": [
            {"check": "types", "status": "ran", "findings_count": 0},
            {"check": "extra_check", "status": "ran"},
        ]});
        let out = reconcile_plan_with_facts(&plan, &facts);
        assert_eq!(out["valid"], json!(false));
        assert_eq!(out["missingChecks"], json!(["lint"]));
        assert_eq!(out["unplannedChecks"], json!(["extra_check"]));
        let providers = out["providerResults"].as_array().unwrap();
        assert_eq!(providers.len(), 3);
        let types_result = providers.iter().find(|p| p["provider"] == json!("p.types")).unwrap();
        assert_eq!(types_result["complete"], json!(true));
        let reasoning_result = providers.iter().find(|p| p["provider"] == json!("p.reasoning")).unwrap();
        assert_eq!(reasoning_result["status"], json!("pending"));
    }

    #[test]
    fn reconcile_plan_with_facts_supplemental_checks_are_not_unplanned() {
        let plan = obj(json!({"denominator": {"expectedChecks": []}, "providers": []}));
        let facts = json!({"checks": [{"check": "extra", "status": "ran", "tier": "supplemental"}]});
        let out = reconcile_plan_with_facts(&plan, &facts);
        assert_eq!(out["unplannedChecks"], json!([]));
        assert_eq!(out["valid"], json!(true));
    }

    #[test]
    fn stable_plan_digest_is_deterministic_and_sha256() {
        let plan = obj(json!({"b": 1, "a": 2}));
        let digest = stable_plan_digest(&plan);
        assert!(digest.starts_with("sha256:"));
        // Key order in the input must not change the digest (canonical JSON).
        let plan2 = obj(json!({"a": 2, "b": 1}));
        assert_eq!(digest, stable_plan_digest(&plan2));
    }
}
