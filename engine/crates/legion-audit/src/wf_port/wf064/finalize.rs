//! Port of `tools/audit/audit-finalize.mjs`.
//!
//! Scope note: the CLI `main()` (arg parsing, file I/O, SARIF write via
//! `scripts/report-to-sarif.mjs`) is not ported — it is process/IO glue, not
//! the audited business logic. `finalizeAudit` and every helper it calls are
//! ported faithfully below against `serde_json::Value`, matching the open
//! `facts`/`candidates`/`adjudication` object shapes the JS source consumes.

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

fn as_array<'a>(value: &'a Value, pointer: &str) -> &'a [Value] {
    value
        .pointer(pointer)
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// `requiredLenses`: sorted, deduped `facts.plan.reasoningProviders`.
fn required_lenses(facts: &Value) -> Vec<String> {
    let set: BTreeSet<String> = as_array(facts, "/plan/reasoningProviders")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    set.into_iter().collect()
}

/// `ranLenses`: sorted, deduped `facts.lenses_ran`, `[]` if not an array.
fn ran_lenses(facts: &Value) -> Vec<String> {
    let set: BTreeSet<String> = facts
        .get("lenses_ran")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    set.into_iter().collect()
}

/// `candidateGeneratorIds`: plan providers whose `producesSecurityCandidates`
/// is `true`. Candidate-generator authority comes only from the frozen plan
/// record, never from a provider name prefix.
fn candidate_generator_ids(facts: &Value) -> BTreeSet<String> {
    as_array(facts, "/plan/providers")
        .iter()
        .filter(|p| p.get("producesSecurityCandidates").and_then(|v| v.as_bool()) == Some(true))
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

fn is_candidate_generator(ids: &BTreeSet<String>, provider: &Value) -> bool {
    let provider_id = provider.get("provider").and_then(|v| v.as_str());
    let owner_id = provider.get("ownerProvider").and_then(|v| v.as_str());
    provider_id.map(|id| ids.contains(id)).unwrap_or(false)
        || owner_id.map(|id| ids.contains(id)).unwrap_or(false)
}

fn severity_from_finding(finding: &Value) -> Value {
    if let Some(s) = finding.get("severity") {
        if !s.is_null() {
            return s.clone();
        }
    }
    match finding.get("level").and_then(|v| v.as_str()) {
        Some("error") => json!("high"),
        Some("warning") => json!("medium"),
        _ => json!("low"),
    }
}

/// `providerFindings`: findings from every non-candidate-generator provider,
/// normalized into the report finding shape.
fn provider_findings(facts: &Value) -> Vec<Value> {
    let ids = candidate_generator_ids(facts);
    let mut out = Vec::new();
    for provider in as_array(facts, "/provider_reconciliation/providerResults") {
        if is_candidate_generator(&ids, provider) {
            continue;
        }
        let provider_name = provider.get("provider").cloned().unwrap_or(Value::Null);
        for finding in as_array(provider, "/findings") {
            let rule_id = finding
                .get("ruleId")
                .cloned()
                .unwrap_or_else(|| provider_name.clone());
            let category = rule_id
                .as_str()
                .map(|s| s.split('.').next().unwrap_or(s).to_string())
                .unwrap_or_default();
            let id = finding.get("id").cloned().unwrap_or_else(|| {
                let file_or_surface = finding
                    .get("file")
                    .and_then(|v| v.as_str())
                    .or_else(|| finding.get("surface").and_then(|v| v.as_str()))
                    .unwrap_or("unknown");
                let line = finding.get("line").and_then(|v| v.as_i64()).unwrap_or(1);
                json!(format!(
                    "{}:{}:{}:{}",
                    provider_name.as_str().unwrap_or_default(),
                    rule_id.as_str().unwrap_or_default(),
                    file_or_surface,
                    line
                ))
            });
            let evidence = finding.get("evidence").cloned().unwrap_or_else(|| {
                finding
                    .get("screenshot")
                    .map(|screenshot| {
                        json!([{"screenshot": screenshot, "surface": finding.get("surface").cloned().unwrap_or(Value::Null)}])
                    })
                    .unwrap_or_else(|| json!([]))
            });
            out.push(json!({
                "id": id,
                "category": category,
                "ruleId": rule_id,
                "severity": severity_from_finding(finding),
                "title": finding.get("title").cloned().unwrap_or_else(|| rule_id.clone()).clone(),
                "detail": finding.get("detail").cloned().unwrap_or_else(|| finding.get("message").cloned().unwrap_or_else(|| json!("Provider finding"))),
                "file": finding.get("file").cloned().unwrap_or(Value::Null),
                "line": finding.get("line").cloned().unwrap_or(json!(1)),
                "evidence": evidence,
                "evidence_strength": finding.get("evidence_strength").cloned().unwrap_or_else(|| json!("observed")),
                "status": "open",
                "tier": finding.get("tier").cloned().unwrap_or_else(|| json!("GUIDED")),
                "provider": provider_name.clone(),
            }));
        }
    }
    out
}

/// `redactedSecretCarrier`. JS's key list is `['match', 'secretDigest',
/// 'secretType', 'mode', 'classification', 'validity', 'commit']`.
fn redacted_secret_carrier(candidate: &Value) -> Option<Value> {
    let keys = [
        "match",
        "secretDigest",
        "secretType",
        "mode",
        "classification",
        "validity",
        "commit",
    ];
    let mut carrier = Map::new();
    for key in keys {
        if let Some(v) = candidate.get(key) {
            if !v.is_null() {
                carrier.insert(key.to_string(), v.clone());
            }
        }
    }
    if carrier.is_empty() {
        None
    } else {
        Some(Value::Object(carrier))
    }
}

/// `orphanSecurityVerdicts`: verdicts whose `candidateId` no longer matches
/// any known candidate.
pub fn orphan_security_verdicts(adjudication: &Value, candidates: &Value) -> Vec<Value> {
    let known: BTreeSet<String> = as_array(candidates, "/candidates")
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect();
    as_array(adjudication, "/verdicts")
        .iter()
        .filter(|v| {
            v.get("candidateId")
                .and_then(|id| id.as_str())
                .map(|id| !known.contains(id))
                .unwrap_or(true)
        })
        .map(|v| json!({"candidateId": v.get("candidateId").cloned().unwrap_or(Value::Null)}))
        .collect()
}

const SURVIVING_VERDICTS: [&str; 2] = ["TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"];

fn security_findings(adjudication: &Value, candidates: &Value) -> Vec<Value> {
    let candidate_by_id: std::collections::BTreeMap<String, &Value> = as_array(candidates, "/candidates")
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(|id| (id.to_string(), c)))
        .collect();
    as_array(adjudication, "/verdicts")
        .iter()
        .filter(|v| {
            v.get("verdict")
                .and_then(|s| s.as_str())
                .map(|s| SURVIVING_VERDICTS.contains(&s))
                .unwrap_or(false)
        })
        .map(|verdict| {
            let empty = json!({});
            let candidate = verdict
                .get("candidateId")
                .and_then(|id| id.as_str())
                .and_then(|id| candidate_by_id.get(id))
                .copied()
                .unwrap_or(&empty);
            let location = as_array(candidate, "/evidence").first().cloned().unwrap_or(json!({}));
            let secret_carrier = redacted_secret_carrier(candidate);
            let mut out = json!({
                "id": verdict.get("candidateId").cloned().unwrap_or(Value::Null),
                "category": "security",
                "ruleId": candidate.get("ruleId").cloned().unwrap_or_else(|| candidate.get("allegedRootCause").cloned().unwrap_or_else(|| json!("security.verified"))),
                "severity": verdict.get("severity").cloned().unwrap_or(Value::Null),
                "title": candidate.get("claim").cloned().unwrap_or_else(|| json!("Verified security finding")),
                "detail": verdict.get("rationale").cloned().unwrap_or_else(|| verdict.get("impact").cloned().unwrap_or(Value::Null)),
                "file": location.get("file").cloned().unwrap_or(Value::Null),
                "line": location.get("line").cloned().unwrap_or(json!(1)),
                "evidence": candidate.get("evidence").cloned().unwrap_or_else(|| json!([])),
                "evidence_strength": verdict.get("evidenceStrength").cloned().unwrap_or(Value::Null),
                "status": "open",
                "tier": "GUIDED",
                "provider": verdict.get("candidateProvider").cloned().unwrap_or(Value::Null),
                "security": verdict,
            });
            if let Some(carrier) = secret_carrier {
                out["redacted_secret"] = carrier;
            }
            out
        })
        .collect()
}

/// `nonSecurityGaps`.
fn non_security_gaps(facts: &Value) -> Vec<Value> {
    let mut gaps = Vec::new();
    let reconciliation = facts
        .get("provider_reconciliation")
        .cloned()
        .unwrap_or_else(|| json!({}));

    if facts
        .pointer("/plan_binding_verification/valid")
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        gaps.push(json!({
            "kind": "plan-binding",
            "detail": facts.pointer("/plan_binding_verification/drift").cloned().unwrap_or_else(|| json!([])),
        }));
    }
    for gap in as_array(facts, "/plan/coverageGaps") {
        gaps.push(json!({"kind": "plan-coverage", "detail": gap}));
    }
    for check in as_array(&reconciliation, "/missingChecks") {
        gaps.push(json!({"kind": "missing-check", "check": check}));
    }
    for check in as_array(&reconciliation, "/unplannedChecks") {
        gaps.push(json!({"kind": "unplanned-check", "check": check}));
    }
    for mismatch in as_array(&reconciliation, "/denominatorMismatches") {
        gaps.push(json!({"kind": "provider-denominator-mismatch", "detail": mismatch}));
    }
    for provider in as_array(&reconciliation, "/providerResults") {
        let provider_name = provider.get("provider").and_then(|v| v.as_str());
        if provider_name == Some("security.adjudication") || provider_name == Some("security.variant-analysis") {
            continue;
        }
        let complete_false = provider.get("complete").and_then(|v| v.as_bool()) == Some(false);
        let status = provider.get("status").and_then(|v| v.as_str()).unwrap_or_default();
        if complete_false
            || ["missing", "skipped", "error", "unproven", "pending", "fail"].contains(&status)
        {
            gaps.push(json!({"kind": "provider-incomplete", "provider": provider.get("provider").cloned().unwrap_or(Value::Null), "status": status}));
        }
    }
    for gap in as_array(&reconciliation, "/unresolvedCoverage") {
        gaps.push(json!({"kind": "coverage-family", "family": gap.get("id").cloned().unwrap_or(Value::Null), "detail": gap}));
    }
    for provider in as_array(&reconciliation, "/missingRuntimeProviders") {
        gaps.push(json!({"kind": "missing-runtime-provider", "provider": provider}));
    }
    let ran_lens_set: BTreeSet<String> = ran_lenses(facts).into_iter().collect();
    for lens in required_lenses(facts) {
        if !ran_lens_set.contains(&lens) {
            gaps.push(json!({"kind": "missing-reasoning-lens", "lens": lens}));
        }
    }
    if facts.pointer("/network_policy/mode").and_then(|v| v.as_str()) != Some("deny") {
        gaps.push(json!({"kind": "network-policy", "detail": facts.get("network_policy").cloned().unwrap_or(Value::Null)}));
    }
    if facts.get("incomplete").and_then(|v| v.as_bool()) == Some(true) && gaps.is_empty() {
        gaps.push(json!({"kind": "facts-incomplete", "detail": "facts.json is marked incomplete without a more specific normalized gap"}));
    }
    gaps
}

/// `canonicalCounts`: the one canonical count model shared by JSON, Markdown
/// and SARIF surfaces.
fn canonical_counts(
    facts: &Value,
    findings: &[Value],
    candidates: &Value,
    adjudication: &Value,
    lenses: &[String],
    required_lens_list: &[String],
) -> Value {
    let provider_results = as_array(facts, "/provider_reconciliation/providerResults");
    let mut by_severity = json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0});
    for finding in findings {
        if let Some(sev) = finding.get("severity").and_then(|v| v.as_str()) {
            if let Some(count) = by_severity.get_mut(sev) {
                *count = json!(count.as_i64().unwrap_or(0) + 1);
            }
        }
    }
    let selected_provider_ids: Vec<&str> = as_array(facts, "/plan/selectedProviderIds")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let ran_providers: BTreeSet<&str> = provider_results
        .iter()
        .filter_map(|p| p.get("provider").and_then(|v| v.as_str()))
        .collect();
    json!({
        "schemaVersion": 1,
        "providers_selected": selected_provider_ids.len(),
        "providers_ran": provider_results.iter().filter(|p| p.get("status").and_then(|v| v.as_str()) != Some("pending")).count(),
        "providers_missing": selected_provider_ids.iter().filter(|id| !ran_providers.contains(*id)).count(),
        "findings_total": findings.len(),
        "findings_by_severity": by_severity,
        "findings_open": findings.iter().filter(|f| f.get("status").and_then(|v| v.as_str()) == Some("open")).count(),
        "security_candidates": as_array(candidates, "/candidates").len(),
        "security_verdicts": as_array(adjudication, "/verdicts").len(),
        "security_findings_surviving": findings.iter().filter(|f| f.get("security").map(|v| !v.is_null()).unwrap_or(false)).count(),
        "lenses_required": required_lens_list.len(),
        "lenses_ran": lenses.len(),
    })
}

/// Faithful port of `finalizeAudit`. The `rerun` command block (which shells
/// out to `audit-run.mjs`/`audit-verify.mjs` with `process.execPath`) is not
/// ported — it names process-launch commands, not analysis output.
pub fn finalize_audit(facts: &Value, candidates: &Value, adjudication: &Value) -> Value {
    let mut gaps = non_security_gaps(facts);
    let adjudication_complete = adjudication.get("complete").and_then(|v| v.as_bool()) == Some(true);
    if !adjudication_complete {
        gaps.push(json!({"kind": "security-adjudication", "detail": adjudication}));
    }
    for orphan in orphan_security_verdicts(adjudication, candidates) {
        gaps.push(json!({"kind": "orphan-security-verdict", "candidateId": orphan["candidateId"]}));
    }

    for provider in as_array(facts, "/provider_reconciliation/providerResults") {
        let ids = candidate_generator_ids(facts);
        let findings_count = as_array(provider, "/findings").len();
        if is_candidate_generator(&ids, provider) && findings_count > 0 {
            gaps.push(json!({
                "kind": "candidate-provider-contract-violation",
                "provider": provider.get("provider").cloned().unwrap_or(Value::Null),
                "findingsCount": findings_count,
            }));
        }
    }

    let mut findings = provider_findings(facts);
    findings.extend(security_findings(adjudication, candidates));

    let mut seen_finding_ids = BTreeSet::new();
    let mut duplicate_findings = Vec::new();
    for finding in &findings {
        let id = finding.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if seen_finding_ids.contains(&id) {
            duplicate_findings.push(id.clone());
        }
        seen_finding_ids.insert(id);
    }
    if !duplicate_findings.is_empty() {
        gaps.push(json!({"kind": "duplicate-finding-ids", "ids": duplicate_findings}));
    }

    let mut seen_candidate_ids = BTreeSet::new();
    let mut duplicate_candidates = Vec::new();
    for candidate in as_array(candidates, "/candidates") {
        let id = candidate.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if seen_candidate_ids.contains(&id) {
            duplicate_candidates.push(id.clone());
        }
        seen_candidate_ids.insert(id);
    }
    if !duplicate_candidates.is_empty() {
        gaps.push(json!({"kind": "duplicate-candidate-ids", "ids": duplicate_candidates}));
    }

    let lenses = ran_lenses(facts);
    let required_lens_list = required_lenses(facts);
    let summary = canonical_counts(facts, &findings, candidates, adjudication, &lenses, &required_lens_list);
    let incomplete = facts.get("incomplete").and_then(|v| v.as_bool()) == Some(true) || !gaps.is_empty();
    let execution_failed = as_array(facts, "/checks").iter().any(|check| {
        let verdict = check.get("verdict").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| {
            if check.get("status").and_then(|v| v.as_str()) == Some("ran") {
                "pass".to_string()
            } else {
                "unproven".to_string()
            }
        });
        verdict == "fail"
    });
    let has_findings = !findings.is_empty();
    let audit_status = if incomplete {
        "incomplete"
    } else if execution_failed || has_findings {
        "fail"
    } else {
        "pass"
    };
    let quality_gate = if incomplete {
        "unproven"
    } else if findings.iter().any(|f| {
        matches!(f.get("severity").and_then(|v| v.as_str()), Some("critical") | Some("high"))
    }) {
        "blocked"
    } else if has_findings {
        "attention"
    } else {
        "pass"
    };

    let deterministic_checks_pass = as_array(facts, "/checks").iter().all(|check| {
        let execution_status = check
            .get("execution_status")
            .or_else(|| check.get("status"))
            .and_then(|v| v.as_str());
        let verdict = check.get("verdict").and_then(|v| v.as_str()).unwrap_or("pass");
        execution_status == Some("ran") && verdict == "pass"
    });
    let provider_reconciliation_gate = if gaps.iter().any(|g| g.get("kind").and_then(|v| v.as_str()) != Some("security-adjudication")) {
        "unproven"
    } else {
        "pass"
    };
    let visual_status = as_array(facts, "/provider_reconciliation/providerResults")
        .iter()
        .find(|p| p.get("provider").and_then(|v| v.as_str()) == Some("visual.core"))
        .and_then(|p| p.get("status").cloned())
        .unwrap_or_else(|| json!("not_applicable"));
    let runtime_status = as_array(facts, "/provider_reconciliation/providerResults")
        .iter()
        .find(|p| p.get("provider").and_then(|v| v.as_str()) == Some("runtime.app"))
        .and_then(|p| p.get("status").cloned())
        .unwrap_or_else(|| json!("not_applicable"));

    json!({
        "schemaVersion": 4,
        "kind": "repository-audit-report",
        "workspace": facts.get("workspace").cloned().unwrap_or(Value::Null),
        "commit": facts.pointer("/plan/binding/repositoryRevision").cloned().unwrap_or(Value::Null),
        "audit_status": audit_status,
        "quality_gate": quality_gate,
        "incomplete": incomplete,
        "plan": facts.get("plan").cloned().unwrap_or(Value::Null),
        "blueprint": facts.get("blueprint").cloned().unwrap_or(Value::Null),
        "network_policy": facts.get("network_policy").cloned().unwrap_or(Value::Null),
        "lenses_ran": lenses,
        "lenses": {"required": required_lens_list, "ran": lenses},
        "summary": summary,
        "gates": {
            "deterministic_checks": if deterministic_checks_pass { "pass" } else { "unproven" },
            "provider_reconciliation": provider_reconciliation_gate,
            "security_adjudication": if adjudication_complete { "pass" } else { "unproven" },
            "visual": visual_status,
            "runtime": runtime_status,
        },
        "coverage_gaps": gaps,
        "findings": findings,
        "security": {
            "candidate_count": as_array(candidates, "/candidates").len(),
            "adjudication_complete": adjudication_complete,
            "verdicts": adjudication.get("verdicts").cloned().unwrap_or_else(|| json!([])),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_run_is_pass() {
        let facts = json!({
            "workspace": "/repo", "incomplete": false, "checks": [],
            "plan_binding_verification": {"valid": true, "drift": []},
            "plan": {"coverageGaps": [], "reasoningProviders": [], "selectedProviderIds": []},
            "network_policy": {"mode": "deny"},
            "provider_reconciliation": {
                "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
                "providerResults": [], "unresolvedCoverage": [], "missingRuntimeProviders": [],
            },
        });
        let candidates = json!({"candidates": []});
        let adjudication = json!({"complete": true, "verdicts": []});
        let report = finalize_audit(&facts, &candidates, &adjudication);
        assert_eq!(report["audit_status"], json!("pass"));
        assert_eq!(report["quality_gate"], json!("pass"));
        assert_eq!(report["incomplete"], json!(false));
        assert!(report["coverage_gaps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn incomplete_adjudication_blocks_pass() {
        let facts = json!({
            "workspace": "/repo", "incomplete": false, "checks": [],
            "plan_binding_verification": {"valid": true, "drift": []},
            "plan": {"coverageGaps": [], "reasoningProviders": [], "selectedProviderIds": []},
            "network_policy": {"mode": "deny"},
            "provider_reconciliation": {
                "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
                "providerResults": [], "unresolvedCoverage": [], "missingRuntimeProviders": [],
            },
        });
        let candidates = json!({"candidates": []});
        let adjudication = json!({"complete": false, "verdicts": []});
        let report = finalize_audit(&facts, &candidates, &adjudication);
        assert_eq!(report["audit_status"], json!("incomplete"));
        assert_eq!(report["quality_gate"], json!("unproven"));
        let gaps = report["coverage_gaps"].as_array().unwrap();
        assert!(gaps.iter().any(|g| g["kind"] == json!("security-adjudication")));
    }

    #[test]
    fn candidate_generator_emitting_findings_is_a_contract_violation() {
        let facts = json!({
            "workspace": "/repo", "incomplete": false, "checks": [],
            "plan_binding_verification": {"valid": true, "drift": []},
            "plan": {
                "coverageGaps": [], "reasoningProviders": [], "selectedProviderIds": [],
                "providers": [{"id": "security.secrets", "producesSecurityCandidates": true}],
            },
            "network_policy": {"mode": "deny"},
            "provider_reconciliation": {
                "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
                "providerResults": [{"provider": "security.secrets", "status": "candidates", "complete": true, "findings": [{"ruleId": "x", "id": "f1"}]}],
                "unresolvedCoverage": [], "missingRuntimeProviders": [],
            },
        });
        let candidates = json!({"candidates": []});
        let adjudication = json!({"complete": true, "verdicts": []});
        let report = finalize_audit(&facts, &candidates, &adjudication);
        let gaps = report["coverage_gaps"].as_array().unwrap();
        assert!(gaps.iter().any(|g| g["kind"] == json!("candidate-provider-contract-violation")));
        // A candidate-generator's findings never surface as report findings directly.
        assert!(report["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn surviving_verdict_becomes_a_finding_with_redacted_secret_carrier() {
        let facts = json!({
            "workspace": "/repo", "incomplete": false, "checks": [],
            "plan_binding_verification": {"valid": true, "drift": []},
            "plan": {"coverageGaps": [], "reasoningProviders": [], "selectedProviderIds": []},
            "network_policy": {"mode": "deny"},
            "provider_reconciliation": {
                "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
                "providerResults": [], "unresolvedCoverage": [], "missingRuntimeProviders": [],
            },
        });
        let candidates = json!({"candidates": [
            {"id": "c1", "ruleId": "secret.aws", "claim": "AWS key found", "evidence": [{"file": "a.rs", "line": 5}], "secretDigest": "sha256:xyz", "secretType": "aws-key"},
        ]});
        let adjudication = json!({"complete": true, "verdicts": [
            {"candidateId": "c1", "verdict": "TRUE_POSITIVE", "severity": "high", "candidateProvider": "security.secrets", "evidenceStrength": "verified"},
        ]});
        let report = finalize_audit(&facts, &candidates, &adjudication);
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["file"], json!("a.rs"));
        assert_eq!(findings[0]["redacted_secret"]["secretDigest"], json!("sha256:xyz"));
        assert_eq!(report["summary"]["security_findings_surviving"], json!(1));
    }

    #[test]
    fn orphan_verdict_is_flagged() {
        let candidates = json!({"candidates": [{"id": "c1"}]});
        let adjudication = json!({"verdicts": [{"candidateId": "c1"}, {"candidateId": "c2"}]});
        let orphans = orphan_security_verdicts(&adjudication, &candidates);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0]["candidateId"], json!("c2"));
    }

    #[test]
    fn missing_reasoning_lens_is_a_gap_even_when_facts_report_complete() {
        let facts = json!({
            "workspace": "/repo", "incomplete": false, "checks": [],
            "plan_binding_verification": {"valid": true, "drift": []},
            "plan": {"coverageGaps": [], "reasoningProviders": ["reasoning.security"], "selectedProviderIds": []},
            "network_policy": {"mode": "deny"},
            "lenses_ran": [],
            "provider_reconciliation": {
                "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
                "providerResults": [], "unresolvedCoverage": [], "missingRuntimeProviders": [],
            },
        });
        let candidates = json!({"candidates": []});
        let adjudication = json!({"complete": true, "verdicts": []});
        let report = finalize_audit(&facts, &candidates, &adjudication);
        assert_eq!(report["audit_status"], json!("incomplete"));
        let gaps = report["coverage_gaps"].as_array().unwrap();
        assert!(gaps.iter().any(|g| g["kind"] == json!("missing-reasoning-lens") && g["lens"] == json!("reasoning.security")));
    }
}
