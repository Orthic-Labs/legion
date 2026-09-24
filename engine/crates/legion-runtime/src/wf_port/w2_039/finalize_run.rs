//! Port of `tools/audit/audit-finalize.mjs`'s `finalizeAudit` (272-line
//! legacy file, ported in full except the CLI `main()`/argv/file-I/O
//! entrypoint, which is not portable core logic) and of
//! `src/lib/core/finalize-run.mjs`'s `finalizeRun`/`exitCodeForReport`
//! (packet r44b).
//!
//! `exitCodeForReport` reuses the pre-existing
//! [`crate::p5_core::exit_taxonomy::Exit`] taxonomy rather than re-deriving
//! it, per the "one entry point" rule: `EXIT.INTEGRITY`/`INCOMPLETE`/
//! `POLICY_FAIL`/`PASS`/`INTERNAL_ERROR` map onto
//! `Exit::{Integrity,Incomplete,PolicyFail,Pass,InternalError}`.
//!
//! Not ported: `reportToSarif` (`scripts/report-to-sarif.mjs`) and the CLI
//! `main()` (argv parsing, file reads/writes, `process.exitCode`) — the
//! former is a separate legacy file outside this packet's list, the latter
//! is host I/O by design (see port rules: CLI entrypoints belong in a `run`
//! function, but this packet's only mandate is `finalizeRun`/`finalizeAudit`
//! themselves; the caller in `legion` CLI code is responsible for reading
//! facts/candidates/adjudication JSON and calling [`finalize_audit`]).

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::p5_core::exit_taxonomy::{exit_code_for_report as taxonomy_exit_code_for_report, Exit, ExitReport};

const SURVIVING_VERDICTS: [&str; 2] = ["TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"];

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(key))
}
fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    get(v, key).and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}
fn s(v: &Value) -> Option<&str> {
    v.as_str()
}

/// Mirrors `requiredLenses(facts)`.
fn required_lenses(facts: &Value) -> Vec<String> {
    let plan = get(facts, "plan").cloned().unwrap_or(Value::Null);
    let mut set: BTreeSet<String> =
        arr(&plan, "reasoningProviders").iter().filter_map(|v| s(v).map(|x| x.to_string())).collect();
    let out: Vec<String> = std::mem::take(&mut set).into_iter().collect();
    out
}

/// Mirrors `ranLenses(facts)`.
fn ran_lenses(facts: &Value) -> Vec<String> {
    let mut set: BTreeSet<String> =
        arr(facts, "lenses_ran").iter().filter_map(|v| s(v).map(|x| x.to_string())).collect();
    let out: Vec<String> = std::mem::take(&mut set).into_iter().collect();
    out
}

/// Mirrors `candidateGeneratorIds(facts)`.
fn candidate_generator_ids(facts: &Value) -> BTreeSet<String> {
    let plan = get(facts, "plan").cloned().unwrap_or(Value::Null);
    arr(&plan, "providers")
        .iter()
        .filter(|p| get(p, "producesSecurityCandidates").and_then(|v| v.as_bool()).unwrap_or(false))
        .filter_map(|p| get(p, "id").and_then(s).map(|x| x.to_string()))
        .collect()
}

/// Mirrors `isCandidateGenerator(facts, provider)`.
fn is_candidate_generator(ids: &BTreeSet<String>, provider: &Value) -> bool {
    let by_provider = get(provider, "provider").and_then(s).map(|x| ids.contains(x)).unwrap_or(false);
    let by_owner = get(provider, "ownerProvider").and_then(s).map(|x| ids.contains(x)).unwrap_or(false);
    by_provider || by_owner
}

/// Mirrors `providerFindings(facts)`.
fn provider_findings(facts: &Value) -> Vec<Value> {
    let ids = candidate_generator_ids(facts);
    let reconciliation = get(facts, "provider_reconciliation").cloned().unwrap_or(Value::Null);
    let mut out = Vec::new();
    for provider in arr(&reconciliation, "providerResults") {
        if is_candidate_generator(&ids, provider) {
            continue;
        }
        let provider_name = get(provider, "provider").and_then(s).unwrap_or("");
        for finding in arr(provider, "findings") {
            let rule_id = get(finding, "ruleId").and_then(s);
            let file = get(finding, "file").and_then(s);
            let surface = get(finding, "surface").and_then(s);
            let line = get(finding, "line").and_then(|v| v.as_i64()).unwrap_or(1);
            let id = get(finding, "id").and_then(s).map(|x| x.to_string()).unwrap_or_else(|| {
                format!(
                    "{}:{}:{}:{}",
                    provider_name,
                    rule_id.unwrap_or(provider_name),
                    file.or(surface).unwrap_or("unknown"),
                    line
                )
            });
            let category = rule_id.unwrap_or(provider_name).split('.').next().unwrap_or("").to_string();
            let severity = get(finding, "severity")
                .and_then(s)
                .map(|x| x.to_string())
                .unwrap_or_else(|| match get(finding, "level").and_then(s) {
                    Some("error") => "high".to_string(),
                    Some("warning") => "medium".to_string(),
                    _ => "low".to_string(),
                });
            let title = get(finding, "title").and_then(s).or(rule_id).unwrap_or(provider_name).to_string();
            let detail = get(finding, "detail")
                .and_then(s)
                .or_else(|| get(finding, "message").and_then(s))
                .unwrap_or("Provider finding")
                .to_string();
            let evidence = get(finding, "evidence").cloned().unwrap_or_else(|| {
                if let Some(screenshot) = get(finding, "screenshot") {
                    json!([{"screenshot": screenshot, "surface": surface}])
                } else {
                    json!([])
                }
            });
            let evidence_strength =
                get(finding, "evidence_strength").and_then(s).unwrap_or("observed").to_string();
            let tier = get(finding, "tier").and_then(s).unwrap_or("GUIDED").to_string();
            out.push(json!({
                "id": id, "category": category, "ruleId": rule_id.unwrap_or(provider_name),
                "severity": severity, "title": title, "detail": detail,
                "file": file, "line": line, "evidence": evidence,
                "evidence_strength": evidence_strength, "status": "open",
                "tier": tier, "provider": provider_name,
            }));
        }
    }
    out
}

const SECRET_CARRIER_KEYS: [&str; 6] =
    ["match", "secretDigest", "secretType", "mode", "classification", "validity"];

/// Mirrors `redactedSecretCarrier(candidate)`. Note: the JS `SECRET_CARRIER_KEYS`
/// also includes `'commit'`, kept here too.
fn redacted_secret_carrier(candidate: &Value) -> Option<Value> {
    let mut carrier = Map::new();
    for key in SECRET_CARRIER_KEYS.iter().chain(["commit"].iter()) {
        if let Some(v) = get(candidate, key) {
            if !v.is_null() {
                carrier.insert((*key).to_string(), v.clone());
            }
        }
    }
    if carrier.is_empty() {
        None
    } else {
        Some(Value::Object(carrier))
    }
}

/// Mirrors `orphanSecurityVerdicts(adjudication, candidates)`.
pub fn orphan_security_verdicts(adjudication: &Value, candidates: &Value) -> Vec<Value> {
    let known: BTreeSet<&str> =
        arr(candidates, "candidates").iter().filter_map(|c| get(c, "id").and_then(s)).collect();
    arr(adjudication, "verdicts")
        .iter()
        .filter(|v| get(v, "candidateId").and_then(s).map(|id| !known.contains(id)).unwrap_or(true))
        .map(|v| json!({"candidateId": get(v, "candidateId").cloned().unwrap_or(Value::Null)}))
        .collect()
}

/// Mirrors `securityFindings(adjudication, candidates)`.
fn security_findings(adjudication: &Value, candidates: &Value) -> Vec<Value> {
    let by_id: std::collections::BTreeMap<&str, &Value> = arr(candidates, "candidates")
        .iter()
        .filter_map(|c| get(c, "id").and_then(s).map(|id| (id, c)))
        .collect();
    let surviving: BTreeSet<&str> = SURVIVING_VERDICTS.iter().copied().collect();
    arr(adjudication, "verdicts")
        .iter()
        .filter(|v| get(v, "verdict").and_then(s).map(|x| surviving.contains(x)).unwrap_or(false))
        .map(|verdict| {
            let candidate_id = get(verdict, "candidateId").and_then(s).unwrap_or("");
            let empty = json!({});
            let candidate = by_id.get(candidate_id).copied().unwrap_or(&empty);
            let location = arr(candidate, "evidence").first().cloned().unwrap_or(json!({}));
            let secret_carrier = redacted_secret_carrier(candidate);
            let mut obj = json!({
                "id": candidate_id,
                "category": "security",
                "ruleId": get(candidate, "ruleId").and_then(s).or_else(|| get(candidate, "allegedRootCause").and_then(s)).unwrap_or("security.verified"),
                "severity": get(verdict, "severity").cloned().unwrap_or(Value::Null),
                "title": get(candidate, "claim").and_then(s).unwrap_or("Verified security finding"),
                "detail": get(verdict, "rationale").cloned().or_else(|| get(verdict, "impact").cloned()).unwrap_or(Value::Null),
                "file": get(&location, "file").cloned().unwrap_or(Value::Null),
                "line": get(&location, "line").and_then(|v| v.as_i64()).unwrap_or(1),
                "evidence": get(candidate, "evidence").cloned().unwrap_or(json!([])),
                "evidence_strength": get(verdict, "evidenceStrength").cloned().unwrap_or(Value::Null),
                "status": "open",
                "tier": "GUIDED",
                "provider": get(verdict, "candidateProvider").cloned().unwrap_or(Value::Null),
                "security": verdict.clone(),
            });
            if let Some(sc) = secret_carrier {
                obj.as_object_mut().unwrap().insert("redacted_secret".to_string(), sc);
            }
            obj
        })
        .collect()
}

/// Mirrors `nonSecurityGaps(facts)`.
fn non_security_gaps(facts: &Value) -> Vec<Value> {
    let mut gaps = Vec::new();
    let plan_binding_verification = get(facts, "plan_binding_verification").cloned().unwrap_or(Value::Null);
    if !get(&plan_binding_verification, "valid").and_then(|v| v.as_bool()).unwrap_or(false) {
        gaps.push(json!({
            "kind": "plan-binding",
            "detail": get(&plan_binding_verification, "drift").cloned().unwrap_or(json!([])),
        }));
    }
    let plan = get(facts, "plan").cloned().unwrap_or(Value::Null);
    for gap in arr(&plan, "coverageGaps") {
        gaps.push(json!({"kind": "plan-coverage", "detail": gap}));
    }
    let reconciliation = get(facts, "provider_reconciliation").cloned().unwrap_or(Value::Null);
    for check in arr(&reconciliation, "missingChecks") {
        gaps.push(json!({"kind": "missing-check", "check": check}));
    }
    for check in arr(&reconciliation, "unplannedChecks") {
        gaps.push(json!({"kind": "unplanned-check", "check": check}));
    }
    for mismatch in arr(&reconciliation, "denominatorMismatches") {
        gaps.push(json!({"kind": "provider-denominator-mismatch", "detail": mismatch}));
    }
    for provider in arr(&reconciliation, "providerResults") {
        let name = get(provider, "provider").and_then(s).unwrap_or("");
        if name == "security.adjudication" || name == "security.variant-analysis" {
            continue;
        }
        let complete_false = get(provider, "complete").and_then(|v| v.as_bool()) == Some(false);
        let status = get(provider, "status").and_then(s).unwrap_or("");
        let bad_status = ["missing", "skipped", "error", "unproven", "pending", "fail"].contains(&status);
        if complete_false || bad_status {
            gaps.push(json!({"kind": "provider-incomplete", "provider": name, "status": status}));
        }
    }
    for gap in arr(&reconciliation, "unresolvedCoverage") {
        gaps.push(json!({"kind": "coverage-family", "family": get(gap, "id").cloned().unwrap_or(Value::Null), "detail": gap}));
    }
    for provider in arr(&reconciliation, "missingRuntimeProviders") {
        gaps.push(json!({"kind": "missing-runtime-provider", "provider": provider}));
    }
    let ran: BTreeSet<String> = ran_lenses(facts).into_iter().collect();
    for lens in required_lenses(facts) {
        if !ran.contains(&lens) {
            gaps.push(json!({"kind": "missing-reasoning-lens", "lens": lens}));
        }
    }
    let network_mode = get(facts, "network_policy").and_then(|v| get(v, "mode")).and_then(s);
    if network_mode != Some("deny") {
        gaps.push(json!({"kind": "network-policy", "detail": get(facts, "network_policy").cloned().unwrap_or(Value::Null)}));
    }
    let incomplete = get(facts, "incomplete").and_then(|v| v.as_bool()).unwrap_or(false);
    if incomplete && gaps.is_empty() {
        gaps.push(json!({
            "kind": "facts-incomplete",
            "detail": "facts.json is marked incomplete without a more specific normalized gap",
        }));
    }
    gaps
}

/// Mirrors `canonicalCounts(...)`.
fn canonical_counts(facts: &Value, findings: &[Value], candidates: &Value, adjudication: &Value, lenses: &[String], required_lens_list: &[String]) -> Value {
    let reconciliation = get(facts, "provider_reconciliation").cloned().unwrap_or(Value::Null);
    let provider_results = arr(&reconciliation, "providerResults");
    let mut by_severity = json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0});
    for finding in findings {
        if let Some(sev) = get(finding, "severity").and_then(s) {
            let obj = by_severity.as_object_mut().unwrap();
            let entry = obj.entry(sev.to_string()).or_insert(json!(0));
            *entry = json!(entry.as_i64().unwrap_or(0) + 1);
        }
    }
    let plan = get(facts, "plan").cloned().unwrap_or(Value::Null);
    let selected_provider_ids = arr(&plan, "selectedProviderIds");
    let ran_providers: BTreeSet<&str> =
        provider_results.iter().filter_map(|p| get(p, "provider").and_then(s)).collect();
    let providers_ran = provider_results
        .iter()
        .filter(|p| get(p, "status").and_then(s) != Some("pending"))
        .count();
    let providers_missing = selected_provider_ids
        .iter()
        .filter(|id| id.as_str().map(|x| !ran_providers.contains(x)).unwrap_or(true))
        .count();
    json!({
        "schemaVersion": 1,
        "providers_selected": selected_provider_ids.len(),
        "providers_ran": providers_ran,
        "providers_missing": providers_missing,
        "findings_total": findings.len(),
        "findings_by_severity": by_severity,
        "findings_open": findings.iter().filter(|f| get(f, "status").and_then(s) == Some("open")).count(),
        "security_candidates": arr(candidates, "candidates").len(),
        "security_verdicts": arr(adjudication, "verdicts").len(),
        "security_findings_surviving": findings.iter().filter(|f| get(f, "security").map(|v| !v.is_null()).unwrap_or(false)).count(),
        "lenses_required": required_lens_list.len(),
        "lenses_ran": lenses.len(),
    })
}

/// Mirrors `finalizeAudit({ facts, candidates, adjudication })`. `generated_at`
/// mirrors `new Date().toISOString()` in JS: this port takes it as a caller
/// argument (host clock) rather than reading a wall clock directly, matching
/// how `finalize_run` below supplies `host.clock.now()`.
pub fn finalize_audit(facts: &Value, candidates: &Value, adjudication: &Value, generated_at: &str) -> Value {
    let plan = get(facts, "plan").cloned().unwrap_or(Value::Null);
    let mut gaps = non_security_gaps(facts);
    let adjudication_complete = get(adjudication, "complete").and_then(|v| v.as_bool()).unwrap_or(false);
    if !adjudication_complete {
        gaps.push(json!({"kind": "security-adjudication", "detail": adjudication}));
    }
    for orphan in orphan_security_verdicts(adjudication, candidates) {
        gaps.push(json!({"kind": "orphan-security-verdict", "candidateId": get(&orphan, "candidateId").cloned().unwrap_or(Value::Null)}));
    }

    let ids = candidate_generator_ids(facts);
    let reconciliation = get(facts, "provider_reconciliation").cloned().unwrap_or(Value::Null);
    for provider in arr(&reconciliation, "providerResults") {
        if is_candidate_generator(&ids, provider) {
            let count = arr(provider, "findings").len();
            if count > 0 {
                gaps.push(json!({
                    "kind": "candidate-provider-contract-violation",
                    "provider": get(provider, "provider").cloned().unwrap_or(Value::Null),
                    "findingsCount": count,
                }));
            }
        }
    }

    let mut findings = provider_findings(facts);
    findings.extend(security_findings(adjudication, candidates));

    let mut seen_finding_ids = BTreeSet::new();
    let mut duplicate_findings = Vec::new();
    for f in &findings {
        if let Some(id) = get(f, "id").and_then(s) {
            if !seen_finding_ids.insert(id.to_string()) {
                duplicate_findings.push(id.to_string());
            }
        }
    }
    if !duplicate_findings.is_empty() {
        gaps.push(json!({"kind": "duplicate-finding-ids", "ids": duplicate_findings}));
    }

    let mut seen_candidate_ids = BTreeSet::new();
    let mut duplicate_candidates = Vec::new();
    for c in arr(candidates, "candidates") {
        if let Some(id) = get(c, "id").and_then(s) {
            if !seen_candidate_ids.insert(id.to_string()) {
                duplicate_candidates.push(id.to_string());
            }
        }
    }
    if !duplicate_candidates.is_empty() {
        gaps.push(json!({"kind": "duplicate-candidate-ids", "ids": duplicate_candidates}));
    }

    let lenses = ran_lenses(facts);
    let required_lens_list = required_lenses(facts);
    let summary = canonical_counts(facts, &findings, candidates, adjudication, &lenses, &required_lens_list);

    let incomplete = get(facts, "incomplete").and_then(|v| v.as_bool()).unwrap_or(false) || !gaps.is_empty();
    let execution_failed = arr(facts, "checks").iter().any(|check| {
        let verdict = get(check, "verdict").and_then(s).map(|x| x.to_string()).unwrap_or_else(|| {
            if get(check, "status").and_then(s) == Some("ran") { "pass".to_string() } else { "unproven".to_string() }
        });
        verdict == "fail"
    });
    let audit_status = if incomplete {
        "incomplete"
    } else if execution_failed {
        "fail"
    } else if !findings.is_empty() {
        "fail"
    } else {
        "pass"
    };
    let quality_gate = if incomplete {
        "unproven"
    } else if findings.iter().any(|f| matches!(get(f, "severity").and_then(s), Some("critical") | Some("high"))) {
        "blocked"
    } else if !findings.is_empty() {
        "attention"
    } else {
        "pass"
    };

    let deterministic_checks_pass = arr(facts, "checks").iter().all(|check| {
        let exec = get(check, "execution_status").and_then(s).or_else(|| get(check, "status").and_then(s));
        let verdict = get(check, "verdict").and_then(s).unwrap_or("pass");
        exec == Some("ran") && verdict == "pass"
    });
    let provider_reconciliation_gate = if gaps.iter().any(|g| get(g, "kind").and_then(s) != Some("security-adjudication")) {
        "unproven"
    } else {
        "pass"
    };
    let visual_status = arr(&reconciliation, "providerResults")
        .iter()
        .find(|p| get(p, "provider").and_then(s) == Some("visual.core"))
        .and_then(|p| get(p, "status").and_then(s))
        .unwrap_or("not_applicable")
        .to_string();
    let runtime_status = arr(&reconciliation, "providerResults")
        .iter()
        .find(|p| get(p, "provider").and_then(s) == Some("runtime.app"))
        .and_then(|p| get(p, "status").and_then(s))
        .unwrap_or("not_applicable")
        .to_string();

    json!({
        "schemaVersion": 4,
        "kind": "repository-audit-report",
        "generated_at": generated_at,
        "workspace": get(facts, "workspace").cloned().unwrap_or(Value::Null),
        "commit": get(&plan, "binding").and_then(|b| get(b, "repositoryRevision")).cloned().unwrap_or(Value::Null),
        "audit_status": audit_status,
        "quality_gate": quality_gate,
        "incomplete": incomplete,
        "plan": plan,
        "blueprint": get(facts, "blueprint").cloned().unwrap_or(Value::Null),
        "network_policy": get(facts, "network_policy").cloned().unwrap_or(Value::Null),
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
            "candidate_count": arr(candidates, "candidates").len(),
            "adjudication_complete": adjudication_complete,
            "verdicts": get(adjudication, "verdicts").cloned().unwrap_or(json!([])),
        },
    })
}

/// Mirrors `exitCodeForReport(report)` from `finalize-run.mjs` by adapting
/// the JSON report shape onto the pre-existing native
/// [`crate::p5_core::exit_taxonomy::exit_code_for_report`] — one entry
/// point, not a second reimplementation.
pub fn exit_code_for_report(report: &Value) -> Exit {
    let exit_report = ExitReport {
        integrity_valid: get(report, "integrity").and_then(|i| get(i, "valid")).and_then(|v| v.as_bool()),
        gates_plan_binding: get(report, "gates").and_then(|g| get(g, "plan_binding")).and_then(s).map(|x| x.to_string()),
        incomplete: get(report, "incomplete").and_then(|v| v.as_bool()),
        audit_status: get(report, "audit_status").and_then(s).map(|x| x.to_string()),
        quality_gate: get(report, "quality_gate").and_then(s).map(|x| x.to_string()),
    };
    taxonomy_exit_code_for_report(&exit_report)
}

/// Mirrors `finalizeRun({ plan, facts, results, policy }, host)`.
///
/// `results_security_candidates`/`results_adjudication` mirror
/// `results?.securityCandidates ?? []` / `results?.adjudication ?? {complete:
/// true, verdicts: []}`; `policy` is accepted (matching the JS destructure)
/// but, as in JS, unused by the function body itself.
pub fn finalize_run(
    plan: &Value,
    facts: &Value,
    results_security_candidates: Option<&Value>,
    results_adjudication: Option<&Value>,
    _policy: Option<&Value>,
    now: &str,
) -> Value {
    let mut merged_facts = facts.clone();
    if let Value::Object(obj) = &mut merged_facts {
        obj.insert("plan".to_string(), plan.clone());
    }
    let candidates = json!({"candidates": results_security_candidates.cloned().unwrap_or(json!([]))});
    let adjudication = results_adjudication.cloned().unwrap_or(json!({"complete": true, "verdicts": []}));

    let mut report = finalize_audit(&merged_facts, &candidates, &adjudication, now);
    let exit_code = exit_code_for_report(&report).code();
    if let Value::Object(obj) = &mut report {
        obj.insert("generated_at".to_string(), json!(now));
        obj.insert("exit_code".to_string(), json!(exit_code));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_facts() -> Value {
        json!({
            "workspace": "/repo",
            "network_policy": {"mode": "deny"},
            "checks": [],
            "provider_reconciliation": {"providerResults": []},
            "plan": {"reasoningProviders": [], "selectedProviderIds": [], "binding": {"repositoryRevision": "abc"}},
            // A missing/invalid plan_binding_verification is itself a
            // "plan-binding" gap (fail-closed), so a genuinely clean run
            // must carry an explicit valid verification.
            "plan_binding_verification": {"valid": true},
        })
    }

    #[test]
    fn clean_run_passes() {
        let facts = base_facts();
        let report = finalize_audit(&facts, &json!({"candidates": []}), &json!({"complete": true, "verdicts": []}), "t0");
        assert_eq!(report["audit_status"], "pass");
        assert_eq!(report["quality_gate"], "pass");
        assert_eq!(report["incomplete"], false);
        assert_eq!(exit_code_for_report(&report), Exit::Pass);
    }

    #[test]
    fn open_network_policy_is_a_gap_and_incomplete() {
        let mut facts = base_facts();
        facts["network_policy"] = json!({"mode": "allow"});
        let report = finalize_audit(&facts, &json!({"candidates": []}), &json!({"complete": true, "verdicts": []}), "t0");
        assert_eq!(report["audit_status"], "incomplete");
        assert_eq!(exit_code_for_report(&report), Exit::Incomplete);
    }

    #[test]
    fn incomplete_adjudication_is_a_gap() {
        let facts = base_facts();
        let report = finalize_audit(&facts, &json!({"candidates": []}), &json!({"complete": false, "verdicts": []}), "t0");
        assert_eq!(report["audit_status"], "incomplete");
        assert_eq!(report["gates"]["security_adjudication"], "unproven");
    }

    #[test]
    fn surviving_security_verdict_becomes_finding() {
        let facts = base_facts();
        let candidates = json!({"candidates": [{"id": "c1", "claim": "x", "evidence": []}]});
        let adjudication = json!({"complete": true, "verdicts": [{"candidateId": "c1", "verdict": "TRUE_POSITIVE", "severity": "high", "candidateProvider": "p"}]});
        let report = finalize_audit(&facts, &candidates, &adjudication, "t0");
        assert_eq!(report["summary"]["findings_total"], 1);
        assert_eq!(report["quality_gate"], "blocked");
        assert_eq!(exit_code_for_report(&report), Exit::PolicyFail);
    }

    #[test]
    fn orphan_verdict_is_flagged() {
        let facts = base_facts();
        let candidates = json!({"candidates": []});
        let adjudication = json!({"complete": true, "verdicts": [{"candidateId": "ghost", "verdict": "TRUE_POSITIVE"}]});
        let orphans = orphan_security_verdicts(&adjudication, &candidates);
        assert_eq!(orphans.len(), 1);
        let report = finalize_audit(&facts, &candidates, &adjudication, "t0");
        assert_eq!(report["incomplete"], true);
    }

    #[test]
    fn integrity_gate_takes_priority_over_pass() {
        let report = json!({"integrity": {"valid": false}, "audit_status": "pass"});
        assert_eq!(exit_code_for_report(&report), Exit::Integrity);
    }

    #[test]
    fn finalize_run_sets_generated_at_and_exit_code() {
        let plan = json!({"reasoningProviders": [], "selectedProviderIds": []});
        let facts = json!({"workspace": "/repo", "network_policy": {"mode": "deny"}, "checks": [], "provider_reconciliation": {"providerResults": []}, "plan_binding_verification": {"valid": true}});
        let report = finalize_run(&plan, &facts, None, None, None, "2024-01-01T00:00:00.000Z");
        assert_eq!(report["generated_at"], "2024-01-01T00:00:00.000Z");
        assert_eq!(report["exit_code"], Exit::Pass.code());
    }
}
