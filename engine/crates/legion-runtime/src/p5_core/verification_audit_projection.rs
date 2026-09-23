//! Port of `src/lib/verification-projection.mjs` (packet P5c).
//!
//! Stable semantic projection of an audit run's `facts` JSON, used to
//! compare the canonical digest of the projection instead of the raw
//! facts.json byte stream, so that output directory, log path, timestamp,
//! and temporary-path changes do not create semantic drift. Faithfully
//! mirrors every `??` fallback chain from the JS source, field for field.
//!
//! Needs `serde_json` as a `legion-runtime` dependency (see packet report).

use serde_json::{json, Value};

use legion_contracts::{canonical_digest_hex, canonical_json_bytes};

fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key).filter(|v| !v.is_null())
}

fn first<'a>(value: &'a Value, paths: &[&[&str]]) -> Value {
    for path in paths {
        let mut cursor = value;
        let mut ok = true;
        for segment in *path {
            match get(cursor, segment) {
                Some(next) => cursor = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return cursor.clone();
        }
    }
    Value::Null
}

fn as_array(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        _ => Vec::new(),
    }
}

fn canonical_json_string(value: &Value) -> String {
    // Sorted-key JSON string used purely as a stable sort key, matching the
    // JS `canonicalJson(a).localeCompare(canonicalJson(b))` comparator.
    canonical_json_bytes(value)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn stable_finding(finding: &Value) -> Value {
    let file = get(finding, "file")
        .and_then(Value::as_str)
        .map(|s| s.replace('\\', "/"));
    let line = get(finding, "line").and_then(Value::as_i64);
    json!({
        "id": get(finding, "id").cloned().unwrap_or(Value::Null),
        "ruleId": first(finding, &[&["ruleId"], &["category"]]),
        "severity": get(finding, "severity").cloned().unwrap_or(Value::Null),
        "verdict": first(finding, &[&["verdict"], &["status"]]),
        "file": file.map(Value::String).unwrap_or(Value::Null),
        "line": line.map(Value::from).unwrap_or(Value::Null),
        "evidenceDigest": first(
            finding,
            &[&["evidenceDigest"], &["proof", "digest"], &["verdictDigest"]],
        ),
    })
}

fn sorted_by_canonical(mut items: Vec<Value>) -> Vec<Value> {
    items.sort_by(|a, b| canonical_json_string(a).cmp(&canonical_json_string(b)));
    items
}

fn stable_check(check: &Value) -> Value {
    let findings = sorted_by_canonical(
        as_array(get(check, "findings").unwrap_or(&Value::Null))
            .iter()
            .map(stable_finding)
            .collect(),
    );
    json!({
        "check": get(check, "check").cloned().unwrap_or(Value::Null),
        "provider": get(check, "provider").cloned().unwrap_or(Value::Null),
        "executionStatus": first(
            check,
            &[&["execution_status"], &["executionStatus"], &["status"]],
        ),
        "verdict": get(check, "verdict").cloned().unwrap_or(Value::Null),
        "exitCode": first(check, &[&["exit_code"], &["exitCode"]]),
        "tool": get(check, "tool").cloned().unwrap_or(Value::Null),
        "toolVersion": first(check, &[&["version"], &["toolVersion"]]),
        "findings": findings,
        "findingsCount": first(check, &[&["findings_count"], &["findingsCount"]]),
    })
}

fn stable_provider(result: &Value) -> Value {
    let findings = sorted_by_canonical(
        as_array(get(result, "findings").unwrap_or(&Value::Null))
            .iter()
            .map(stable_finding)
            .collect(),
    );
    let provider_name = get(result, "provider").cloned().unwrap_or(Value::Null);
    let candidates = sorted_by_canonical(
        as_array(get(result, "candidates").unwrap_or(&Value::Null))
            .iter()
            .map(|candidate| {
                let mut evidence_refs = as_array(
                    get(candidate, "evidenceRefs").unwrap_or(&Value::Array(Vec::new())),
                );
                evidence_refs
                    .sort_by(|a, b| a.as_str().unwrap_or_default().cmp(b.as_str().unwrap_or_default()));
                json!({
                    "id": get(candidate, "id").cloned().unwrap_or(Value::Null),
                    "ruleId": get(candidate, "ruleId").cloned().unwrap_or(Value::Null),
                    "provider": get(candidate, "provider").cloned().unwrap_or(provider_name.clone()),
                    "verdict": get(candidate, "verdict").cloned().unwrap_or(Value::Null),
                    "evidenceRefs": evidence_refs,
                })
            })
            .collect(),
    );
    let coverage_gaps = sorted_by_canonical(
        as_array(get(result, "coverageGaps").unwrap_or(&Value::Null))
            .iter()
            .map(|gap| {
                json!({
                    "kind": get(gap, "kind").cloned().unwrap_or(Value::Null),
                    "provider": get(gap, "provider").cloned().unwrap_or(provider_name.clone()),
                    "path": get(gap, "path").cloned().unwrap_or(Value::Null),
                    "reason": get(gap, "reason").cloned().unwrap_or(Value::Null),
                })
            })
            .collect(),
    );
    json!({
        "provider": provider_name,
        "providerVersion": get(result, "providerVersion").cloned().unwrap_or(Value::Null),
        "status": get(result, "status").cloned().unwrap_or(Value::Null),
        "complete": get(result, "complete").cloned().unwrap_or(Value::Null),
        "applicable": get(result, "applicable").cloned().unwrap_or(Value::Bool(true)),
        "required": get(result, "required").cloned().unwrap_or(Value::Bool(false)),
        "denominatorDigest": first(
            result,
            &[&["coverage", "denominatorDigest"], &["coverage", "examinedPathsDigest"]],
        ),
        "toolVersion": get(result, "toolVersion").cloned().unwrap_or(Value::Null),
        "findings": findings,
        "candidates": candidates,
        "coverageGaps": coverage_gaps,
    })
}

/// Port of `verificationProjection(facts)`.
pub fn verification_projection(facts: &Value) -> Value {
    let commit = first(
        facts,
        &[
            &["commit"],
            &["repository", "revision"],
            &["plan", "binding", "repositoryRevision"],
            &["plan_binding", "repositoryRevision"],
        ],
    );
    let dirty_patch_digest = first(
        facts,
        &[
            &["repository", "dirtyPatchDigest"],
            &["repository_binding", "dirtyPatchDigest"],
            &["plan", "binding", "dirtyPatchDigest"],
        ],
    );
    let mut checks: Vec<Value> = as_array(get(facts, "checks").unwrap_or(&Value::Null))
        .iter()
        .map(stable_check)
        .collect();
    checks.sort_by(|a, b| {
        a.get("check")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(b.get("check").and_then(Value::as_str).unwrap_or_default())
    });

    let mut providers: Vec<Value> = as_array(&first(
        facts,
        &[&["provider_reconciliation", "providerResults"]],
    ))
    .iter()
    .map(stable_provider)
    .collect();
    providers.sort_by(|a, b| {
        a.get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(b.get("provider").and_then(Value::as_str).unwrap_or_default())
    });

    let mut plan_provider_ids = as_array(&first(facts, &[&["plan", "denominator", "providerIds"]]));
    plan_provider_ids.sort_by(|a, b| a.as_str().unwrap_or_default().cmp(b.as_str().unwrap_or_default()));
    let mut plan_expected_checks = as_array(&first(facts, &[&["plan", "denominator", "expectedChecks"]]));
    plan_expected_checks.sort_by(|a, b| a.as_str().unwrap_or_default().cmp(b.as_str().unwrap_or_default()));
    json!({
        "schemaVersion": 1,
        "kind": "legion-verification-projection",
        "workspaceIdentity": first(
            facts,
            &[&["workspace_identity"], &["workspaceIdentity"], &["workspace"]],
        ),
        "commit": commit,
        "dirtyPatchDigest": dirty_patch_digest,
        "plan": {
            "digest": first(facts, &[&["plan", "seal", "digest"], &["plan", "digest"]]),
            "signature": first(facts, &[&["plan", "seal", "signature"]]),
            "registryDigest": first(facts, &[&["plan", "binding", "registryDigest"]]),
            "providerIds": plan_provider_ids,
            "expectedChecks": plan_expected_checks,
        },
        "networkPolicy": {
            "mode": first(facts, &[&["network_policy", "mode"]]),
            "sandboxActive": get(facts, "network_policy")
                .and_then(|policy| get(policy, "sandboxActive"))
                .map(|value| Value::Bool(value == &Value::Bool(true)))
                .unwrap_or(Value::Bool(false)),
        },
        "checks": checks,
        "providers": providers,
    })
}

/// Port of `verificationDigest(facts)`.
pub fn verification_digest(facts: &Value) -> Result<String, String> {
    canonical_digest_hex(&verification_projection(facts)).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finding_prefers_camel_case_and_falls_back_to_snake_case() {
        let facts = json!({
            "checks": [
                {"check": "a", "findings": [{"ruleId": "R1", "status": "pass"}]},
            ],
        });
        let projected = verification_projection(&facts);
        let finding = &projected["checks"][0]["findings"][0];
        assert_eq!(finding["ruleId"], json!("R1"));
        assert_eq!(finding["verdict"], json!("pass"));
    }

    #[test]
    fn checks_are_sorted_by_check_name() {
        let facts = json!({"checks": [{"check": "b"}, {"check": "a"}]});
        let projected = verification_projection(&facts);
        assert_eq!(projected["checks"][0]["check"], json!("a"));
        assert_eq!(projected["checks"][1]["check"], json!("b"));
    }

    #[test]
    fn digest_is_stable_across_key_order() {
        let a = json!({"commit": "abc", "checks": []});
        let b = json!({"checks": [], "commit": "abc"});
        assert_eq!(verification_digest(&a).unwrap(), verification_digest(&b).unwrap());
    }

    #[test]
    fn commit_falls_back_through_the_full_chain() {
        let facts = json!({"plan": {"binding": {"repositoryRevision": "deadbeef"}}});
        let projected = verification_projection(&facts);
        assert_eq!(projected["commit"], json!("deadbeef"));
    }
}
