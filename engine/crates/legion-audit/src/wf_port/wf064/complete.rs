//! Partial port of `tools/audit/audit-complete.mjs`.
//!
//! Scope note: `runCompleteAudit` orchestrates Blueprint discovery,
//! `collect-facts.mjs` as a child process, and five provider-suite modules
//! this chunk (wf064) does not own — that process/IO orchestration is not
//! ported. The pure reconciliation logic (`reconcileCompleteRun` and its
//! `familyCoverage`/`denominatorDrift` helpers) and the deterministic parts
//! of `applyOfflinePolicy` (the network-dependent/project-execution check
//! sets and the resulting skip-set union) are ported faithfully below.

use crate::wf_port::wf064::plan::reconcile_plan_with_facts;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// `NETWORK_DEPENDENT_CHECKS`.
pub fn network_dependent_checks() -> BTreeSet<&'static str> {
    [
        "deps_cve",
        "py_deps_cve",
        "cargo_audit",
        "cargo_deny",
        "outdated",
        "cargo_outdated",
        "binary_pins",
    ]
    .into_iter()
    .collect()
}

/// `PROJECT_EXECUTION_CHECKS`.
pub fn project_execution_checks() -> BTreeSet<&'static str> {
    [
        "types",
        "lint",
        "build",
        "dead_code",
        "duplication",
        "ci_lint",
        "docker",
        "sast",
        "swift_lint",
        "js_licenses",
        "cargo_unsafe",
        "cargo_unused_deps",
    ]
    .into_iter()
    .collect()
}

/// The deterministic core of `applyOfflinePolicy`: given the caller's
/// requested `skip` list and whether the trusted network sandbox is active,
/// returns the sorted, deduped final skip set. Always includes the
/// network-dependent checks; additionally includes every project-execution
/// check when the sandbox is not active (mirrors JS `guardedSkips`). Setting
/// the offline environment variables themselves (`AUDIT_OFFLINE`,
/// `CARGO_NET_OFFLINE`, etc.) is process-environment mutation and is not
/// ported here.
pub fn offline_policy_skip_set(requested_skip: &[String], network_sandbox_active: bool) -> Vec<String> {
    let mut skip: BTreeSet<String> = requested_skip.iter().cloned().collect();
    skip.extend(network_dependent_checks().into_iter().map(String::from));
    if !network_sandbox_active {
        skip.extend(project_execution_checks().into_iter().map(String::from));
    }
    skip.into_iter().collect()
}

fn provider_plan<'a>(plan: &'a Value, id: &str) -> Option<&'a Value> {
    plan.get("providers")
        .and_then(|v| v.as_array())
        .and_then(|providers| providers.iter().find(|p| p.get("id").and_then(|v| v.as_str()) == Some(id)))
}

/// `familyCoverage`.
fn family_coverage(plan: &Value, results: &[Value]) -> (Vec<Value>, Vec<Value>) {
    use std::collections::BTreeMap;
    let mut by_family: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for result in results {
        if let Some(family) = result.get("family").and_then(|v| v.as_str()) {
            by_family.entry(family.to_string()).or_default().push(result);
        }
    }
    let families: Vec<Value> = plan
        .get("coverageFamilies")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|family| {
            let id = family.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let executions = by_family.get(id);
            match executions {
                Some(execs) if !execs.is_empty() => {
                    let mut with_exec = family.clone();
                    let exec_values: Vec<Value> = execs
                        .iter()
                        .map(|e| {
                            json!({
                                "provider": e.get("provider").cloned().unwrap_or(Value::Null),
                                "status": e.get("status").cloned().unwrap_or(Value::Null),
                                "complete": e.get("complete").cloned().unwrap_or(Value::Null),
                                "coverage": e.get("coverage").cloned().unwrap_or(Value::Null),
                            })
                        })
                        .collect();
                    with_exec["executions"] = json!(exec_values);
                    with_exec
                }
                _ => family,
            }
        })
        .collect();
    let unresolved: Vec<Value> = families
        .iter()
        .filter(|family| {
            let executions = family.get("executions").and_then(|v| v.as_array());
            match executions {
                None | Some([]) => {
                    let qualification = family.get("qualification").and_then(|v| v.as_str());
                    let missing_providers = family
                        .get("missingProviders")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
                    qualification != Some("complete") || missing_providers
                }
                Some(execs) => execs.iter().any(|item| {
                    let incomplete = item.get("complete").and_then(|v| v.as_bool()) != Some(true);
                    let bad_status = matches!(
                        item.get("status").and_then(|v| v.as_str()),
                        Some("unproven") | Some("error")
                    );
                    incomplete || bad_status
                }),
            }
        })
        .cloned()
        .collect();
    (families, unresolved)
}

/// `denominatorDrift`.
fn denominator_drift(plan: &Value, provider_results: &[Value]) -> Vec<Value> {
    let mut gaps = Vec::new();
    for result in provider_results {
        let provider_id = match result.get("provider").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let contract = match provider_plan(plan, provider_id) {
            Some(c) => c,
            None => continue,
        };
        let coverage = match result.get("coverage") {
            Some(c) if !c.is_null() => c,
            _ => continue,
        };
        let denominator = match contract.get("denominator") {
            Some(d) if !d.is_null() => d,
            _ => continue,
        };
        let expected_digest = denominator.get("pathDigest");
        let observed_digest = coverage
            .get("pathDigest")
            .or_else(|| coverage.get("denominatorDigest"));
        if let (Some(expected), Some(observed)) = (expected_digest, observed_digest) {
            if !expected.is_null() && !observed.is_null() && expected != observed {
                gaps.push(json!({
                    "provider": provider_id,
                    "kind": "denominator-digest-mismatch",
                    "expectedDigest": expected,
                    "observedDigest": observed,
                }));
                continue;
            }
        }
        let expected = denominator.get("pathCount").cloned().unwrap_or(Value::Null);
        let observed = coverage
            .get("expectedFiles")
            .or_else(|| coverage.get("pathCount"))
            .or_else(|| coverage.get("fileCount"))
            .cloned()
            .or_else(|| {
                coverage
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|a| json!(a.len()))
            });
        if let Some(observed) = observed {
            if !observed.is_null() {
                let observed_num = observed.as_f64();
                let expected_num = expected.as_f64();
                if observed_num != expected_num {
                    gaps.push(json!({
                        "provider": provider_id,
                        "expectedPathCount": expected,
                        "observedPathCount": observed,
                    }));
                }
            }
        }
    }
    gaps
}

/// Faithful port of `reconcileCompleteRun`.
pub fn reconcile_complete_run(
    plan: &Map<String, Value>,
    facts: &Value,
    provider_results: &[Value],
    security_result: &Value,
    projection: &Value,
    binding_verification: &Value,
) -> Value {
    let plan_value = Value::Object(plan.clone());
    let legacy = reconcile_plan_with_facts(plan, facts);
    let (families, unresolved) = family_coverage(&plan_value, provider_results);
    let selected_runtime: BTreeSet<&str> = plan_value
        .get("providers")
        .and_then(|v| v.as_array())
        .map(|providers| {
            providers
                .iter()
                .filter(|p| p.get("phase").and_then(|v| v.as_str()) == Some("runtime"))
                .filter_map(|p| p.get("id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let observed: BTreeSet<&str> = provider_results
        .iter()
        .filter_map(|p| p.get("provider").and_then(|v| v.as_str()))
        .collect();
    let missing_runtime_providers: Vec<&str> = selected_runtime
        .iter()
        .filter(|id| !observed.contains(*id))
        .copied()
        .collect();
    let legacy_provider_results = legacy["providerResults"].as_array().cloned().unwrap_or_default();
    let facts_complete = legacy_provider_results
        .iter()
        .filter(|p| p.get("phase").and_then(|v| v.as_str()) == Some("facts"))
        .all(|p| p.get("complete").and_then(|v| v.as_bool()) == Some(true));
    let provider_incomplete = provider_results.iter().any(|p| {
        p.get("complete").and_then(|v| v.as_bool()) == Some(false)
            || matches!(
                p.get("status").and_then(|v| v.as_str()),
                Some("unproven") | Some("error") | Some("missing") | Some("fail")
            )
    });
    let security_pending = security_result
        .pointer("/candidates")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let plan_incomplete = !plan_value
        .get("coverageGaps")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true)
        || plan_value.pointer("/qualification/state").and_then(|v| v.as_str()) == Some("unproven");
    let denominator_mismatches = denominator_drift(&plan_value, provider_results);
    let binding_valid = binding_verification.get("valid").and_then(|v| v.as_bool()) == Some(true);
    let projection_ready = projection.get("state").and_then(|v| v.as_str()) == Some("ready");
    let legacy_valid = legacy.get("valid").and_then(|v| v.as_bool()) == Some(true);

    let incomplete = facts.get("incomplete").and_then(|v| v.as_bool()) == Some(true)
        || plan_incomplete
        || !projection_ready
        || !legacy_valid
        || !facts_complete
        || !binding_valid
        || provider_incomplete
        || !missing_runtime_providers.is_empty()
        || !unresolved.is_empty()
        || security_pending
        || !denominator_mismatches.is_empty();

    let mut out = facts.clone();
    if let Value::Object(map) = &mut out {
        map.insert("incomplete".to_string(), json!(incomplete));
        map.insert(
            "blueprint".to_string(),
            json!({
                "state": projection.get("state").cloned().unwrap_or(Value::Null),
                "reason": projection.get("reason").cloned().unwrap_or(Value::Null),
                "generationId": projection.get("generationId").cloned().unwrap_or(Value::Null),
                "manifestDigest": projection.get("manifestDigest").cloned().unwrap_or(Value::Null),
                "fileCount": projection.get("fileCount").cloned().unwrap_or(json!(0)),
                "sourceFileCount": projection.get("sourceFileCount").cloned().unwrap_or(json!(0)),
                "parsedExtensions": projection.get("parsedExtensions").cloned().unwrap_or_else(|| json!([])),
                "unsupportedExtensions": projection.get("unsupportedExtensions").cloned().unwrap_or_else(|| json!([])),
            }),
        );
        map.insert(
            "plan".to_string(),
            json!({
                "schemaVersion": plan_value.get("schemaVersion").cloned().unwrap_or(Value::Null),
                "seal": plan_value.get("seal").cloned().unwrap_or(Value::Null),
                "binding": plan_value.get("binding").cloned().unwrap_or(Value::Null),
                "expectedChecks": plan_value.pointer("/denominator/expectedChecks").cloned().unwrap_or_else(|| json!([])),
                "selectedProviderIds": plan_value.pointer("/denominator/providerIds").cloned().unwrap_or_else(|| json!([])),
                "reasoningProviders": plan_value.pointer("/denominator/reasoningProviders").cloned().unwrap_or_else(|| json!([])),
                "coverageGaps": plan_value.get("coverageGaps").cloned().unwrap_or_else(|| json!([])),
            }),
        );
        let mut combined_results: Vec<Value> = legacy_provider_results
            .into_iter()
            .filter(|p| p.get("status").and_then(|v| v.as_str()) != Some("pending"))
            .collect();
        combined_results.extend(provider_results.iter().cloned());
        map.insert(
            "provider_reconciliation".to_string(),
            json!({
                "valid": legacy.get("valid").cloned().unwrap_or(Value::Null),
                "expectedChecks": legacy.get("expectedChecks").cloned().unwrap_or(Value::Null),
                "observedChecks": legacy.get("observedChecks").cloned().unwrap_or(Value::Null),
                "missingChecks": legacy.get("missingChecks").cloned().unwrap_or(Value::Null),
                "unplannedChecks": legacy.get("unplannedChecks").cloned().unwrap_or(Value::Null),
                "providerResults": combined_results,
                "coverageFamilies": families,
                "unresolvedCoverage": unresolved,
                "missingRuntimeProviders": missing_runtime_providers,
                "denominatorMismatches": denominator_mismatches,
            }),
        );
        map.insert(
            "security".to_string(),
            json!({
                "candidatesPath": "security-candidates.json",
                "candidatesCount": security_result.pointer("/candidates").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                "adjudicationRequired": security_pending,
            }),
        );
        map.insert("plan_binding_verification".to_string(), binding_verification.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_policy_always_includes_network_dependent_checks() {
        let skip = offline_policy_skip_set(&[], true);
        assert!(skip.contains(&"deps_cve".to_string()));
        assert!(skip.contains(&"cargo_audit".to_string()));
        // Sandbox active: project-execution checks are NOT force-skipped.
        assert!(!skip.contains(&"lint".to_string()));
    }

    #[test]
    fn offline_policy_without_sandbox_also_skips_project_execution() {
        let skip = offline_policy_skip_set(&["custom_check".to_string()], false);
        assert!(skip.contains(&"lint".to_string()));
        assert!(skip.contains(&"build".to_string()));
        assert!(skip.contains(&"custom_check".to_string()));
        assert!(skip.contains(&"deps_cve".to_string()));
    }

    #[test]
    fn reconcile_complete_run_marks_incomplete_on_provider_failure() {
        let plan = json!({
            "schemaVersion": 1, "coverageGaps": [], "qualification": {"state": "ready"},
            "denominator": {"expectedChecks": [], "providerIds": [], "reasoningProviders": []},
            "providers": [], "coverageFamilies": [],
        })
        .as_object()
        .unwrap()
        .clone();
        let facts = json!({"checks": [], "incomplete": false});
        let provider_results = vec![json!({"provider": "p1", "status": "fail", "complete": true})];
        let security_result = json!({"candidates": []});
        let projection = json!({"state": "ready"});
        let binding_verification = json!({"valid": true});
        let out = reconcile_complete_run(&plan, &facts, &provider_results, &security_result, &projection, &binding_verification);
        assert_eq!(out["incomplete"], json!(true));
    }

    #[test]
    fn reconcile_complete_run_complete_when_everything_passes() {
        let plan = json!({
            "schemaVersion": 1, "coverageGaps": [], "qualification": {"state": "ready"},
            "denominator": {"expectedChecks": [], "providerIds": [], "reasoningProviders": []},
            "providers": [], "coverageFamilies": [],
        })
        .as_object()
        .unwrap()
        .clone();
        let facts = json!({"checks": [], "incomplete": false});
        let provider_results = vec![json!({"provider": "p1", "status": "pass", "complete": true})];
        let security_result = json!({"candidates": []});
        let projection = json!({"state": "ready"});
        let binding_verification = json!({"valid": true});
        let out = reconcile_complete_run(&plan, &facts, &provider_results, &security_result, &projection, &binding_verification);
        assert_eq!(out["incomplete"], json!(false));
    }
}
