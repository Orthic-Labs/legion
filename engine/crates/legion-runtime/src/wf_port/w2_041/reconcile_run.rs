//! Port of `src/lib/core/reconcile-run.mjs`.
//!
//! `reconcileRun({ plan, receipts, artifacts }, host)` reconciles only
//! receipts bound to selected providers, sealed repository state, and
//! declared denominators; invalid receipts remain visible but cannot close a
//! run. This is a full, faithful port operating on `serde_json::Value` to
//! mirror the JS source's loosely-typed `plan`/`receipt`/`provider` shapes
//! exactly, including field-presence (`??`, nullish-coalescing) semantics.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Port of `canonicalize(value)` in `binding.mjs`: sorts object keys and
/// replaces `\` with `/` in strings, recursively.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(s.replace('\\', "/")),
        other => other.clone(),
    }
}

/// Port of `digest(value)` in `binding.mjs`: `sha256:<hex>` of the canonical
/// JSON string.
pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Port of `sameBinding(left, right)` in `binding.mjs`.
pub fn same_binding(left: Option<&Value>, right: Option<&Value>) -> bool {
    let l = left.cloned().unwrap_or(Value::Null);
    let r = right.cloned().unwrap_or(Value::Null);
    digest(&l) == digest(&r)
}

/// A `??`-style lookup: `None` when the key is absent *or* explicitly
/// `null`, matching JS nullish coalescing (as opposed to a falsy check).
fn nz(value: &Value, pointer: &str) -> Option<Value> {
    value.pointer(pointer).filter(|v| !v.is_null()).cloned()
}

fn receipt_binding(receipt: &Value) -> Value {
    nz(receipt, "/binding")
        .or_else(|| nz(receipt, "/providerResult/binding"))
        .unwrap_or(Value::Null)
}

fn receipt_denominator(receipt: &Value) -> Value {
    nz(receipt, "/denominatorDigest")
        .or_else(|| nz(receipt, "/providerResult/coverage/denominatorDigest"))
        .unwrap_or(Value::Null)
}

fn expected_denominator(plan: &Value, provider: &Value) -> Value {
    if let Some(v) = nz(provider, "/denominatorDigest") {
        return v;
    }
    if let Some(v) = nz(provider, "/denominator/digest") {
        return v;
    }
    if let Some(id) = provider.get("id").and_then(Value::as_str) {
        if let Some(v) = nz(plan, &format!("/denominator/providerDigests/{id}")) {
            return v;
        }
    }
    Value::Null
}

/// Port of `reconcileRun({ plan, receipts = [], artifacts = null }, host)`.
///
/// `now_iso` stands in for `host.clock.now().toISOString()`.
pub fn reconcile_run(plan: &Value, receipts: &[Value], artifacts: Option<&Value>, now_iso: &str) -> Value {
    let providers = plan
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let planned: std::collections::BTreeMap<String, Value> = providers
        .iter()
        .filter_map(|p| p.get("id").and_then(Value::as_str).map(|id| (id.to_string(), p.clone())))
        .collect();

    // Group receipts by provider id, preserving the original receipt order
    // within each group (only the first receipt of a group is ever used).
    let mut grouped: std::collections::HashMap<String, Vec<&Value>> = std::collections::HashMap::new();
    for receipt in receipts {
        let provider = receipt.get("provider").and_then(Value::as_str).unwrap_or("").to_string();
        grouped.entry(provider).or_default().push(receipt);
    }

    let mut duplicate_checks: Vec<String> = grouped
        .iter()
        .filter(|(id, rows)| rows.len() != 1 && planned.contains_key(id.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    duplicate_checks.sort();

    let mut unplanned_checks: Vec<String> = grouped
        .keys()
        .filter(|id| !planned.contains_key(id.as_str()))
        .cloned()
        .collect();
    unplanned_checks.sort();

    let mut binding_mismatches: Vec<Value> = Vec::new();
    let mut denominator_mismatches: Vec<Value> = Vec::new();
    let plan_binding = plan.get("binding").cloned().unwrap_or(Value::Null);
    for receipt in receipts {
        let provider_id = receipt.get("provider").and_then(Value::as_str).unwrap_or("").to_string();
        let Some(provider) = planned.get(&provider_id) else {
            continue;
        };
        if !plan_binding.is_null() {
            let actual = receipt_binding(receipt);
            if !same_binding(Some(&actual), Some(&plan_binding)) {
                binding_mismatches.push(json!({
                    "provider": provider_id,
                    "expected": plan_binding,
                    "actual": actual,
                }));
            }
        }
        let expected = expected_denominator(plan, provider);
        if !expected.is_null() {
            let actual = receipt_denominator(receipt);
            if actual != expected {
                denominator_mismatches.push(json!({
                    "provider": provider_id,
                    "expected": expected,
                    "actual": actual,
                }));
            }
        }
        if let Some(pr_provider) = nz(receipt, "/providerResult/provider") {
            if pr_provider.as_str() != Some(provider_id.as_str()) {
                binding_mismatches.push(json!({
                    "provider": provider_id,
                    "kind": "provider-result-mismatch",
                    "actual": pr_provider,
                }));
            }
        }
    }

    let mut invalid_providers: BTreeSet<String> = BTreeSet::new();
    invalid_providers.extend(duplicate_checks.iter().cloned());
    invalid_providers.extend(
        binding_mismatches
            .iter()
            .filter_map(|r| r.get("provider").and_then(Value::as_str))
            .map(String::from),
    );
    invalid_providers.extend(
        denominator_mismatches
            .iter()
            .filter_map(|r| r.get("provider").and_then(Value::as_str))
            .map(String::from),
    );

    let provider_results: Vec<Value> = providers
        .iter()
        .map(|provider| {
            let id = provider.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let phase = provider.get("phase").cloned().unwrap_or(Value::Null);
            let benchmark = provider.get("benchmark").cloned().unwrap_or(Value::Null);
            let receipt = grouped.get(&id).and_then(|rows| rows.first()).copied();
            let invalid = invalid_providers.contains(&id);
            if receipt.is_none() || invalid {
                let status = if invalid { "invalid" } else { "missing" };
                let gap_kind = if invalid {
                    "invalid-terminal-receipt"
                } else {
                    "missing-terminal-receipt"
                };
                json!({
                    "provider": id,
                    "phase": phase,
                    "status": status,
                    "complete": false,
                    "benchmark": benchmark,
                    "coverageGaps": [{"kind": gap_kind}],
                })
            } else {
                let receipt = receipt.unwrap();
                let status = nz(receipt, "/providerResult/status").unwrap_or(json!("unproven"));
                let complete = receipt.pointer("/providerResult/complete") == Some(&Value::Bool(true));
                let spawn_status = receipt.get("spawnStatus").cloned().unwrap_or(Value::Null);
                let exit_code = receipt.get("exitCode").cloned().unwrap_or(Value::Null);
                let coverage_gaps = nz(receipt, "/providerResult/coverageGaps").unwrap_or(json!([]));
                json!({
                    "provider": id,
                    "phase": phase,
                    "status": status,
                    "complete": complete,
                    "spawnStatus": spawn_status,
                    "exitCode": exit_code,
                    "benchmark": benchmark,
                    "coverageGaps": coverage_gaps,
                })
            }
        })
        .collect();

    let capability_gaps: Vec<Value> = nz(plan, "/capabilityImpacts")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    let baseline_gaps: Vec<Value> = plan
        .pointer("/controlBaseline/controls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| {
            let unimplemented = c.get("unimplemented").and_then(Value::as_bool).unwrap_or(false);
            let providers_len = c
                .get("providers")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            unimplemented || providers_len == 0
        })
        .map(|c| json!({"kind": "unmapped-control", "controlId": c.get("id").cloned().unwrap_or(Value::Null)}))
        .collect();

    let topology_gaps: Vec<Value> = plan
        .pointer("/productInspection/portfolio/coverage/unknownDeliverables")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|target_id| json!({"kind": "unknown-deliverable", "targetId": target_id}))
        .collect();

    let mut integrity_gaps: Vec<Value> = Vec::new();
    integrity_gaps.extend(
        duplicate_checks
            .iter()
            .map(|provider| json!({"kind": "duplicate-terminal-receipt", "provider": provider})),
    );
    integrity_gaps.extend(
        unplanned_checks
            .iter()
            .map(|provider| json!({"kind": "unplanned-terminal-receipt", "provider": provider})),
    );
    integrity_gaps.extend(binding_mismatches.iter().map(|row| spread_kind("binding-mismatch", row)));
    integrity_gaps.extend(
        denominator_mismatches
            .iter()
            .map(|row| spread_kind("denominator-mismatch", row)),
    );

    let incomplete_providers = provider_results.iter().any(|r| {
        let complete = r.get("complete").and_then(Value::as_bool).unwrap_or(false);
        let status = r.get("status").and_then(Value::as_str).unwrap_or("");
        !complete
            || matches!(
                status,
                "unproven" | "missing" | "invalid" | "error" | "blocked" | "pending" | "skipped"
            )
    });
    let incomplete = incomplete_providers || !integrity_gaps.is_empty();
    let execution_failed = provider_results.iter().any(|r| {
        matches!(r.get("status").and_then(Value::as_str), Some("fail") | Some("error"))
    });

    let checks: Vec<Value> = receipts
        .iter()
        .map(|receipt| {
            let provider = receipt.get("provider").cloned().unwrap_or(Value::Null);
            let provider_id = receipt.get("provider").and_then(Value::as_str).unwrap_or("");
            let provider_result_status = nz(receipt, "/providerResult/status");
            let status = provider_result_status
                .clone()
                .or_else(|| receipt.get("spawnStatus").cloned())
                .unwrap_or(Value::Null);
            let execution_status = receipt.get("spawnStatus").cloned().unwrap_or(Value::Null);
            let verdict = if provider_result_status.as_ref().and_then(Value::as_str) == Some("pass")
                && !invalid_providers.contains(provider_id)
            {
                "pass"
            } else {
                "unproven"
            };
            json!({
                "check": provider,
                "status": status,
                "execution_status": execution_status,
                "verdict": verdict,
                "exit_code": receipt.get("exitCode").cloned().unwrap_or(Value::Null),
                "findings_count": Value::Null,
            })
        })
        .collect();

    let workspace = plan.get("root").cloned().unwrap_or(Value::Null);
    let out_dir = artifacts.and_then(|a| nz(a, "/root")).unwrap_or(Value::Null);

    let missing_checks: Vec<Value> = provider_results
        .iter()
        .filter(|r| r.get("status").and_then(Value::as_str) == Some("missing"))
        .map(|r| r.get("provider").cloned().unwrap_or(Value::Null))
        .collect();

    let mut unresolved_coverage: Vec<Value> = Vec::new();
    unresolved_coverage.extend(capability_gaps.clone());
    unresolved_coverage.extend(baseline_gaps.clone());
    unresolved_coverage.extend(topology_gaps.clone());
    unresolved_coverage.extend(integrity_gaps.clone());

    let overall_incomplete =
        incomplete || !capability_gaps.is_empty() || !baseline_gaps.is_empty() || !topology_gaps.is_empty();

    json!({
        "schemaVersion": 1,
        "kind": "audit-facts",
        "workspace": workspace,
        "out_dir": out_dir,
        "generated_at": now_iso,
        "checks": checks,
        "incomplete": overall_incomplete,
        "executionFailed": execution_failed,
        "provider_reconciliation": {
            "providerResults": provider_results,
            "missingChecks": missing_checks,
            "duplicateChecks": duplicate_checks,
            "unplannedChecks": unplanned_checks,
            "bindingMismatches": binding_mismatches,
            "denominatorMismatches": denominator_mismatches,
            "unresolvedCoverage": unresolved_coverage,
            "missingRuntimeProviders": Value::Array(vec![]),
        },
        "plan": plan,
    })
}

/// `{ kind, ...row }` where a `kind` key already present on `row` wins (JS
/// object-spread semantics: later keys overwrite earlier ones).
fn spread_kind(kind: &str, row: &Value) -> Value {
    let mut out = Map::new();
    out.insert("kind".to_string(), json!(kind));
    if let Some(obj) = row.as_object() {
        for (k, v) in obj {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn digest_matches_known_shape_and_ignores_key_order() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn same_binding_treats_absent_as_null() {
        assert!(same_binding(None, None));
        assert!(same_binding(Some(&Value::Null), None));
    }

    #[test]
    fn missing_and_pass_provider_reconciliation() {
        let plan = json!({
            "root": "/repo",
            "providers": [
                {"id": "p1", "phase": "build", "benchmark": "b1"},
                {"id": "p2", "phase": "build", "benchmark": "b2"}
            ],
        });
        let receipts = vec![json!({
            "provider": "p1",
            "exitCode": 0,
            "providerResult": {"status": "pass", "complete": true, "provider": "p1", "coverageGaps": []},
        })];
        let result = reconcile_run(&plan, &receipts, None, "2026-01-01T00:00:00.000Z");
        assert_eq!(result["schemaVersion"], json!(1));
        assert_eq!(result["kind"], json!("audit-facts"));
        assert_eq!(result["workspace"], json!("/repo"));
        assert_eq!(result["generated_at"], json!("2026-01-01T00:00:00.000Z"));
        let provider_results = result["provider_reconciliation"]["providerResults"].as_array().unwrap();
        assert_eq!(provider_results.len(), 2);
        assert_eq!(provider_results[0]["status"], json!("pass"));
        assert_eq!(provider_results[0]["complete"], json!(true));
        assert_eq!(provider_results[1]["status"], json!("missing"));
        assert_eq!(provider_results[1]["coverageGaps"], json!([{"kind": "missing-terminal-receipt"}]));
        assert_eq!(
            result["provider_reconciliation"]["missingChecks"],
            json!(["p2"])
        );
        assert_eq!(result["incomplete"], json!(true));
        assert_eq!(result["executionFailed"], json!(false));
        assert_eq!(result["checks"][0]["verdict"], json!("pass"));
    }

    #[test]
    fn duplicate_terminal_receipts_are_flagged_and_invalidate_the_provider() {
        let plan = json!({"root": "/repo", "providers": [{"id": "p1", "phase": "build"}]});
        let receipts = vec![
            json!({"provider": "p1", "providerResult": {"status": "pass", "complete": true, "provider": "p1"}}),
            json!({"provider": "p1", "providerResult": {"status": "pass", "complete": true, "provider": "p1"}}),
        ];
        let result = reconcile_run(&plan, &receipts, None, "now");
        assert_eq!(
            result["provider_reconciliation"]["duplicateChecks"],
            json!(["p1"])
        );
        let provider_results = result["provider_reconciliation"]["providerResults"].as_array().unwrap();
        assert_eq!(provider_results[0]["status"], json!("invalid"));
        assert_eq!(provider_results[0]["coverageGaps"], json!([{"kind": "invalid-terminal-receipt"}]));
        assert_eq!(result["incomplete"], json!(true));
    }

    #[test]
    fn unplanned_terminal_receipt_is_flagged_without_touching_planned_providers() {
        let plan = json!({"root": "/repo", "providers": [{"id": "p1", "phase": "build"}]});
        let receipts = vec![
            json!({"provider": "p1", "providerResult": {"status": "pass", "complete": true, "provider": "p1"}}),
            json!({"provider": "ghost", "providerResult": {"status": "pass", "complete": true, "provider": "ghost"}}),
        ];
        let result = reconcile_run(&plan, &receipts, None, "now");
        assert_eq!(
            result["provider_reconciliation"]["unplannedChecks"],
            json!(["ghost"])
        );
        assert_eq!(result["incomplete"], json!(true));
        assert_eq!(
            result["provider_reconciliation"]["providerResults"][0]["status"],
            json!("pass")
        );
    }

    #[test]
    fn binding_mismatch_invalidates_provider_and_provider_result_mismatch_kind_wins() {
        let plan = json!({"root": "/repo", "binding": {"repo": "a"}, "providers": [{"id": "p1", "phase": "build"}]});
        let receipts = vec![json!({
            "provider": "p1",
            "binding": {"repo": "b"},
            "providerResult": {"status": "pass", "complete": true, "provider": "not-p1"},
        })];
        let result = reconcile_run(&plan, &receipts, None, "now");
        let mismatches = result["provider_reconciliation"]["bindingMismatches"].as_array().unwrap();
        // One binding digest mismatch + one provider-result mismatch.
        assert_eq!(mismatches.len(), 2);
        assert!(mismatches
            .iter()
            .any(|m| m.get("kind").and_then(Value::as_str) == Some("provider-result-mismatch")));
        assert_eq!(
            result["provider_reconciliation"]["providerResults"][0]["status"],
            json!("invalid")
        );
    }

    #[test]
    fn denominator_mismatch_is_detected_from_provider_denominator_digest() {
        let plan = json!({"root": "/repo", "providers": [{"id": "p1", "phase": "build", "denominatorDigest": "d1"}]});
        let receipts = vec![json!({
            "provider": "p1",
            "denominatorDigest": "d2",
            "providerResult": {"status": "pass", "complete": true, "provider": "p1"},
        })];
        let result = reconcile_run(&plan, &receipts, None, "now");
        let mismatches = result["provider_reconciliation"]["denominatorMismatches"].as_array().unwrap();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0]["expected"], json!("d1"));
        assert_eq!(mismatches[0]["actual"], json!("d2"));
    }

    #[test]
    fn baseline_and_topology_gaps_force_incomplete_even_with_passing_providers() {
        let plan = json!({
            "root": "/repo",
            "providers": [],
            "controlBaseline": {"controls": [{"id": "c1", "unimplemented": true, "providers": []}]},
            "productInspection": {"portfolio": {"coverage": {"unknownDeliverables": ["t1"]}}},
        });
        let result = reconcile_run(&plan, &[], None, "now");
        assert_eq!(result["incomplete"], json!(true));
        let unresolved = result["provider_reconciliation"]["unresolvedCoverage"].as_array().unwrap();
        assert!(unresolved.iter().any(|g| g["kind"] == json!("unmapped-control")));
        assert!(unresolved.iter().any(|g| g["kind"] == json!("unknown-deliverable")));
    }

    #[test]
    fn execution_failed_when_any_provider_status_is_fail_or_error() {
        let plan = json!({"root": "/repo", "providers": [{"id": "p1", "phase": "build"}]});
        let receipts = vec![json!({
            "provider": "p1",
            "providerResult": {"status": "fail", "complete": false, "provider": "p1"},
        })];
        let result = reconcile_run(&plan, &receipts, None, "now");
        assert_eq!(result["executionFailed"], json!(true));
    }

    #[test]
    fn out_dir_comes_from_artifacts_root_when_present() {
        let plan = json!({"root": "/repo", "providers": []});
        let artifacts = json!({"root": "/repo/.legion/run-1"});
        let result = reconcile_run(&plan, &[], Some(&artifacts), "now");
        assert_eq!(result["out_dir"], json!("/repo/.legion/run-1"));
    }
}
