//! Partial port of `tools/audit/audit-run.mjs`.
//!
//! Scope note: `runAuditProviders`/`executeUnexecutedProviders`/`main()`
//! orchestrate dynamic module imports, a reasoning-reviewer host callback,
//! and CLI/file I/O; none of that is portable analysis logic and is not
//! ported. The pure, self-contained pieces — `assertRunOwnedOutScope`,
//! `candidateProviderIds`, `aggregateSecurityCandidates`,
//! `onlyWrapperProvidersCausedPriorIncomplete`, and `severityHint` — are
//! ported faithfully below.

use crate::wf_port::wf064::common::sha256_str;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("--out must stay under the run-owned .audit scope ({scope_root}); received {target}")]
pub struct OutScopeError {
    pub scope_root: String,
    pub target: String,
}

/// Faithful port of `assertRunOwnedOutScope`: `--out` must resolve to a path
/// strictly inside `<root>/.audit` (never equal to it, never escaping via
/// `..`). Paths are treated lexically (no filesystem access), mirroring
/// `node:path`'s `resolve`/`relative` on already-absolute inputs; callers
/// must pass absolute `root`/`out_dir`.
pub fn assert_run_owned_out_scope(root: &Path, out_dir: &Path) -> Result<PathBuf, OutScopeError> {
    let scope_root = root.join(".audit");
    let rel = pathdiff_lexical(&scope_root, out_dir);
    let escapes = rel.as_deref().map(|r| r.is_empty() || r.starts_with("..")).unwrap_or(true);
    if escapes {
        return Err(OutScopeError {
            scope_root: scope_root.to_string_lossy().to_string(),
            target: out_dir.to_string_lossy().to_string(),
        });
    }
    Ok(out_dir.to_path_buf())
}

/// Lexical equivalent of Node's `path.relative(from, to)`, sufficient for
/// the containment check above (both inputs are expected already-absolute
/// and lexically normal; no symlink resolution).
fn pathdiff_lexical(from: &Path, to: &Path) -> Option<String> {
    let from_comps: Vec<_> = from.components().collect();
    let to_comps: Vec<_> = to.components().collect();
    let common = from_comps
        .iter()
        .zip(to_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut rel = PathBuf::new();
    for _ in common..from_comps.len() {
        rel.push("..");
    }
    for comp in &to_comps[common..] {
        rel.push(comp.as_os_str());
    }
    Some(rel.to_string_lossy().to_string())
}

/// Faithful port of `candidateProviderIds`: plan providers whose
/// `producesSecurityCandidates` is `true`. Candidate authority comes only
/// from the frozen plan record, never a name prefix or family heuristic.
pub fn candidate_provider_ids(plan: &Value) -> BTreeSet<String> {
    plan.get("providers")
        .and_then(|v| v.as_array())
        .map(|providers| {
            providers
                .iter()
                .filter(|p| p.get("producesSecurityCandidates").and_then(|v| v.as_bool()) == Some(true))
                .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("candidate provider {provider} emitted findings; candidate providers must emit candidates with findings: []")]
pub struct CandidateProviderContractViolation {
    pub provider: String,
}

/// `stableId`.
fn stable_id(seed: &str) -> String {
    sha256_str(seed)
}

/// Faithful port of `aggregateSecurityCandidates`. Returns `Err` exactly
/// where the JS `throw new Error(...)` does: an authorized candidate
/// provider result that also carries findings.
pub fn aggregate_security_candidates(
    plan: &Value,
    internal_report: &Value,
    provider_results: &[Value],
) -> Result<Value, CandidateProviderContractViolation> {
    let allowed = candidate_provider_ids(plan);
    let mut candidates: Vec<Value> = internal_report
        .get("candidates")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for result in provider_results {
        let provider = result.get("provider").and_then(|v| v.as_str());
        let owner = result.get("ownerProvider").and_then(|v| v.as_str());
        let authorized = provider.map(|p| allowed.contains(p)).unwrap_or(false)
            || owner.map(|o| allowed.contains(o)).unwrap_or(false);
        if !authorized {
            continue;
        }
        let findings = result.get("findings").and_then(|v| v.as_array());
        if findings.map(|f| !f.is_empty()).unwrap_or(false) {
            return Err(CandidateProviderContractViolation {
                provider: provider.unwrap_or_default().to_string(),
            });
        }
        for candidate in result.get("candidates").and_then(|v| v.as_array()).into_iter().flatten() {
            let rule_id = candidate.get("ruleId").and_then(|v| v.as_str()).unwrap_or_default();
            let file = candidate.get("file").and_then(|v| v.as_str()).unwrap_or_default();
            let line = candidate.get("line").and_then(|v| v.as_i64()).unwrap_or(1);
            let id = candidate
                .get("id")
                .cloned()
                .filter(|v| !v.is_null())
                .unwrap_or_else(|| {
                    json!(stable_id(&format!(
                        "{}\0{}\0{}\0{}",
                        provider.unwrap_or_default(),
                        rule_id,
                        file,
                        line
                    )))
                });
            let evidence = candidate.get("evidence").cloned().unwrap_or_else(|| {
                candidate
                    .get("file")
                    .filter(|f| !f.is_null())
                    .map(|_| json!([{"file": candidate.get("file").cloned().unwrap_or(Value::Null), "line": line}]))
                    .unwrap_or_else(|| json!([]))
            });
            let mut enriched = candidate.clone();
            if let Value::Object(map) = &mut enriched {
                map.insert("id".to_string(), id);
                map.insert(
                    "provider".to_string(),
                    candidate
                        .get("provider")
                        .cloned()
                        .filter(|v| !v.is_null())
                        .unwrap_or_else(|| json!(provider.unwrap_or_default())),
                );
                map.insert("role".to_string(), json!("candidate-generator"));
                map.insert("evidence".to_string(), evidence);
                map.insert("verdict".to_string(), json!("UNADJUDICATED"));
                map.insert("adjudicationRequired".to_string(), json!(true));
            }
            candidates.push(enriched);
        }
    }

    // `[...new Map(candidates.map(c => [c.id, c])).values()]`: last write per
    // id wins, but the FIRST occurrence's position is kept (a JS `Map` only
    // updates the value on a repeated `set`, not the key's insertion order).
    use std::collections::BTreeMap;
    let mut order: Vec<String> = Vec::new();
    let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
    for candidate in candidates {
        let id = candidate.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if !by_id.contains_key(&id) {
            order.push(id.clone());
        }
        by_id.insert(id, candidate);
    }
    let unique: Vec<Value> = order.into_iter().map(|id| by_id.remove(&id).unwrap()).collect();

    let candidate_providers: BTreeSet<String> = unique
        .iter()
        .filter_map(|c| c.get("provider").and_then(|v| v.as_str()).map(String::from))
        .collect();
    let mut coverage = internal_report.get("coverage").cloned().unwrap_or_else(|| json!({}));
    if let Value::Object(map) = &mut coverage {
        map.insert(
            "candidateProviders".to_string(),
            json!(candidate_providers.into_iter().collect::<Vec<_>>()),
        );
    }

    Ok(json!({
        "schemaVersion": 1,
        "kind": "audit-security-candidates",
        "provider": "security.multi-provider",
        "complete": internal_report.get("complete").and_then(|v| v.as_bool()) != Some(false),
        "coverage": coverage,
        "candidates": unique,
        "coverageGaps": internal_report.get("coverageGaps").cloned().unwrap_or_else(|| json!([])),
    }))
}

/// Faithful port of `onlyWrapperProvidersCausedPriorIncomplete`.
pub fn only_wrapper_providers_caused_prior_incomplete(facts: &Value, added_provider_ids: &BTreeSet<String>) -> bool {
    if facts.get("incomplete").and_then(|v| v.as_bool()) != Some(true) {
        return false;
    }
    let reconciliation = facts.get("provider_reconciliation").cloned().unwrap_or_else(|| json!({}));
    let mut missing: Vec<String> = reconciliation
        .get("missingRuntimeProviders")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    missing.sort();
    let mut expected: Vec<String> = added_provider_ids.iter().cloned().collect();
    expected.sort();
    if missing != expected {
        return false;
    }
    if reconciliation
        .get("unresolvedCoverage")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
    {
        return false;
    }
    if reconciliation
        .get("denominatorMismatches")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
    {
        return false;
    }
    if facts.pointer("/security/adjudicationRequired").and_then(|v| v.as_bool()) == Some(true) {
        return false;
    }
    if facts.pointer("/blueprint/state").and_then(|v| v.as_str()) != Some("ready")
        || facts
            .pointer("/plan_binding_verification/valid")
            .and_then(|v| v.as_bool())
            != Some(true)
    {
        return false;
    }
    reconciliation
        .get("providerResults")
        .and_then(|v| v.as_array())
        .map(|results| {
            results
                .iter()
                .filter(|p| {
                    let id = p.get("provider").and_then(|v| v.as_str()).unwrap_or_default();
                    !added_provider_ids.contains(id) && p.get("status").and_then(|v| v.as_str()) != Some("pending")
                })
                .all(|p| {
                    p.get("complete").and_then(|v| v.as_bool()) != Some(false)
                        && !matches!(
                            p.get("status").and_then(|v| v.as_str()),
                            Some("unproven") | Some("error") | Some("missing")
                        )
                })
        })
        .unwrap_or(true)
}

/// Faithful port of `severityHint`.
pub fn severity_hint(level: &str) -> &'static str {
    if level == "error" || level == "critical" {
        "high"
    } else if level == "warning" {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_scope_rejects_escape_and_root_itself() {
        let root = Path::new("/repo");
        assert!(assert_run_owned_out_scope(root, Path::new("/repo/.audit/run1")).is_ok());
        assert!(assert_run_owned_out_scope(root, Path::new("/repo/.audit")).is_err());
        assert!(assert_run_owned_out_scope(root, Path::new("/repo/other")).is_err());
        assert!(assert_run_owned_out_scope(root, Path::new("/elsewhere")).is_err());
    }

    #[test]
    fn severity_hint_matches_js_mapping() {
        assert_eq!(severity_hint("error"), "high");
        assert_eq!(severity_hint("critical"), "high");
        assert_eq!(severity_hint("warning"), "medium");
        assert_eq!(severity_hint("info"), "low");
        assert_eq!(severity_hint("anything-else"), "low");
    }

    #[test]
    fn candidate_provider_ids_only_from_plan_flag() {
        let plan = json!({"providers": [
            {"id": "security.secrets", "producesSecurityCandidates": true},
            {"id": "security.other", "producesSecurityCandidates": false},
        ]});
        let ids = candidate_provider_ids(&plan);
        assert!(ids.contains("security.secrets"));
        assert!(!ids.contains("security.other"));
    }

    #[test]
    fn aggregate_security_candidates_rejects_findings_from_candidate_provider() {
        let plan = json!({"providers": [{"id": "security.secrets", "producesSecurityCandidates": true}]});
        let internal = json!({"candidates": []});
        let results = vec![json!({"provider": "security.secrets", "findings": [{"ruleId": "x"}], "candidates": []})];
        let err = aggregate_security_candidates(&plan, &internal, &results).unwrap_err();
        assert_eq!(err.provider, "security.secrets");
    }

    #[test]
    fn aggregate_security_candidates_dedupes_by_id() {
        let plan = json!({"providers": [{"id": "security.secrets", "producesSecurityCandidates": true}]});
        let internal = json!({"candidates": [{"id": "c1", "provider": "security.secrets"}]});
        let results = vec![json!({
            "provider": "security.secrets",
            "findings": [],
            "candidates": [{"id": "c1", "ruleId": "dup"}, {"id": "c2", "ruleId": "new"}],
        })];
        let out = aggregate_security_candidates(&plan, &internal, &results).unwrap();
        let candidates = out["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 2);
        let c1 = candidates.iter().find(|c| c["id"] == json!("c1")).unwrap();
        // Later write wins (the reported candidate replaces the internal one).
        assert_eq!(c1["ruleId"], json!("dup"));
    }

    #[test]
    fn aggregate_security_candidates_ignores_unauthorized_providers() {
        let plan = json!({"providers": [{"id": "security.secrets", "producesSecurityCandidates": true}]});
        let internal = json!({"candidates": []});
        let results = vec![json!({"provider": "not-a-candidate-provider", "findings": [{"ruleId":"x"}], "candidates": [{"id": "should-not-appear"}]})];
        let out = aggregate_security_candidates(&plan, &internal, &results).unwrap();
        assert!(out["candidates"].as_array().unwrap().is_empty());
    }

    #[test]
    fn only_wrapper_providers_gate_requires_exact_missing_set() {
        let added: BTreeSet<String> = ["runtime.app".to_string()].into_iter().collect();
        let facts = json!({
            "incomplete": true,
            "blueprint": {"state": "ready"},
            "plan_binding_verification": {"valid": true},
            "security": {"adjudicationRequired": false},
            "provider_reconciliation": {
                "missingRuntimeProviders": ["runtime.app"],
                "unresolvedCoverage": [], "denominatorMismatches": [],
                "providerResults": [{"provider": "other", "status": "pass", "complete": true}],
            },
        });
        assert!(only_wrapper_providers_caused_prior_incomplete(&facts, &added));

        let facts_not_ready = json!({
            "incomplete": true,
            "blueprint": {"state": "unproven"},
            "plan_binding_verification": {"valid": true},
            "security": {"adjudicationRequired": false},
            "provider_reconciliation": {
                "missingRuntimeProviders": ["runtime.app"],
                "unresolvedCoverage": [], "denominatorMismatches": [],
                "providerResults": [],
            },
        });
        assert!(!only_wrapper_providers_caused_prior_incomplete(&facts_not_ready, &added));
    }
}
