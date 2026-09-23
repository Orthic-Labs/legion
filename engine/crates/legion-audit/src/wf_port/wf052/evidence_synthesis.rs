//! Port of `src/providers/security/evidence-synthesis.mjs`.
//!
//! Security evidence synthesis per Security Appendix §43. Materializes
//! final findings only from surviving verdicts plus complete variant
//! receipts; proven paths separately; systemic root causes grouped
//! relationally; effective controls reported.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::contracts::{assert_artifact_binding, binding_from_plan, digest, stable_id, Result};

const SURVIVING: &[&str] = &["TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"];

fn complete_receipt_by_finding(variants: &Value) -> BTreeMap<String, Value> {
    variants
        .get("receipts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|receipt| receipt.get("complete").and_then(Value::as_bool) == Some(true))
        .filter_map(|receipt| {
            receipt
                .get("findingId")
                .and_then(Value::as_str)
                .map(|id| (id.to_string(), receipt.clone()))
        })
        .collect()
}

fn finding_from(candidate: &Value, verdict: &Value, receipt: &Value, paths: &[Value]) -> Value {
    let locations: Vec<Value> = receipt
        .get("matches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| m.get("disposition").and_then(Value::as_str) == Some("CONFIRMED"))
        .map(|m| {
            json!({
                "file": m.get("file").cloned().unwrap_or(Value::Null),
                "line": m.get("line").cloned().unwrap_or(Value::Null),
                "matchId": m.get("id").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    let candidate_id = candidate.get("id").cloned().unwrap_or(Value::Null);
    let mut related_attack_path_ids: Vec<String> = paths
        .iter()
        .filter(|path| {
            path.get("steps")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|step| step.get("candidateId") == Some(&candidate_id))
        })
        .filter_map(|path| {
            path.get("pathId")
                .or_else(|| path.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    related_attack_path_ids.sort();

    let root_cause_signature = verdict.get("rootCauseSignature").cloned().unwrap_or(Value::Null);
    let verdict_kind = verdict.get("verdict").cloned().unwrap_or(Value::Null);
    let content = json!({
        "candidateId": candidate_id,
        "verdict": verdict_kind,
        "rootCauseSignature": root_cause_signature,
        "locations": locations,
    });
    let id = stable_id("security-finding", &content);

    json!({
        "id": id,
        "candidateId": candidate_id,
        "ruleId": candidate.get("ruleId").cloned().unwrap_or(Value::Null),
        "title": verdict.get("title").cloned().unwrap_or_else(|| candidate.get("claim").cloned().unwrap_or(Value::Null)),
        "verdict": verdict_kind,
        "severity": verdict.get("severity").cloned().unwrap_or(Value::Null),
        "evidenceStrength": verdict.get("evidenceStrength").cloned().unwrap_or(Value::Null),
        "threatModel": verdict.get("threatModel").cloned().unwrap_or(Value::Null),
        "attackerControl": verdict.get("attackerControl").cloned().unwrap_or(Value::Null),
        "reachability": verdict.get("reachability").cloned().unwrap_or(Value::Null),
        "impact": verdict.get("impact").cloned().unwrap_or(Value::Null),
        "proof": verdict.get("proof").cloned().unwrap_or(Value::Null),
        "rootCauseSignature": root_cause_signature,
        "variantReceiptId": receipt.get("receiptDigest").cloned().unwrap_or(Value::Null),
        "locations": locations,
        "relatedAttackPathIds": related_attack_path_ids,
        "acceptedRisk": Value::Null,
    })
}

fn materialize_attack_paths(proven_paths: &[Value], findings: &[Value]) -> Vec<Value> {
    proven_paths
        .iter()
        .map(|path| {
            let path_id = path.get("pathId").cloned().unwrap_or(Value::Null);
            let constituent_finding_ids: Vec<Value> = findings
                .iter()
                .filter(|finding| {
                    finding
                        .get("relatedAttackPathIds")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .any(|id| id == &path_id)
                })
                .map(|finding| finding.get("id").cloned().unwrap_or(Value::Null))
                .collect();

            let start = path.get("start").cloned().unwrap_or(Value::Null);
            let start_fact_ids = start
                .pointer("/factIds")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let objective_id = path
                .pointer("/objective/id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            json!({
                "id": path_id,
                "verdict": "PROVEN",
                "severity": path.get("severity").cloned().unwrap_or(Value::Null),
                "priority": path.get("priority").cloned().unwrap_or(Value::Null),
                "start": start,
                "objective": path.get("objective").cloned().unwrap_or(Value::Null),
                "constituentFindingIds": constituent_finding_ids,
                "stepAssessments": path.get("stepAssessments").cloned().unwrap_or_else(|| json!([])),
                "joinAssessments": path.get("joinAssessments").cloned().unwrap_or_else(|| json!([])),
                "controls": path.get("controls").cloned().unwrap_or_else(|| json!([])),
                "terminalImpact": path.get("terminalImpact").cloned().unwrap_or(Value::Null),
                "proof": path.get("proof").cloned().unwrap_or(Value::Null),
                "narrative": format!("Generated from structured fields: {start_fact_ids} → {objective_id}"),
            })
        })
        .collect()
}

struct ClassifiedPaths {
    partially_supported: Vec<Value>,
    blocked: Vec<Value>,
    refuted: Vec<Value>,
    unproven: Vec<Value>,
}

fn classify_non_proven_paths(chain_adjudication: &Value) -> ClassifiedPaths {
    let mut classified = ClassifiedPaths {
        partially_supported: Vec::new(),
        blocked: Vec::new(),
        refuted: Vec::new(),
        unproven: Vec::new(),
    };
    for verdict in chain_adjudication.get("verdicts").and_then(Value::as_array).into_iter().flatten() {
        let kind = verdict.get("verdict").and_then(Value::as_str).unwrap_or("");
        if kind == "PROVEN" {
            continue;
        }
        match kind {
            "PARTIALLY_SUPPORTED" => classified.partially_supported.push(verdict.clone()),
            "BLOCKED" => classified.blocked.push(verdict.clone()),
            "REFUTED" => classified.refuted.push(verdict.clone()),
            "UNPROVEN" => classified.unproven.push(verdict.clone()),
            _ => {}
        }
    }
    classified
}

fn group_root_causes(findings: &[Value]) -> Vec<Value> {
    struct Group {
        root_cause_signature: Value,
        finding_ids: Vec<String>,
    }
    let mut by_signature: BTreeMap<String, Group> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for finding in findings {
        let signature = finding.get("rootCauseSignature").cloned().unwrap_or(Value::Null);
        let key = digest(&signature.clone());
        let key = if signature.is_null() { digest(&json!({})) } else { key };
        let entry = by_signature.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Group {
                root_cause_signature: if signature.is_null() { json!({}) } else { signature.clone() },
                finding_ids: Vec::new(),
            }
        });
        if let Some(id) = finding.get("id").and_then(Value::as_str) {
            entry.finding_ids.push(id.to_string());
        }
    }
    order
        .into_iter()
        .map(|key| {
            let group = by_signature.get_mut(&key).unwrap();
            group.finding_ids.sort();
            json!({
                "id": key,
                "rootCauseSignature": group.root_cause_signature,
                "findingIds": group.finding_ids,
                "confirmedVariantCount": group.finding_ids.len(),
                "affectedComponents": [],
                "breaksAttackPathIds": [],
                "recommendedControl": Value::Null,
            })
        })
        .collect()
}

fn summarize_controls(model: &Value, chain_adjudication: &Value, _findings: &[Value]) -> Vec<Value> {
    let mut controls: BTreeMap<String, Value> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for entity in model.get("entities").and_then(Value::as_array).into_iter().flatten() {
        if entity.get("kind").and_then(Value::as_str) != Some("control") {
            continue;
        }
        if let Some(id) = entity.get("id").and_then(Value::as_str) {
            order.push(id.to_string());
            controls.insert(
                id.to_string(),
                json!({
                    "controlId": id,
                    "status": "UNKNOWN",
                    "supportsFindingIds": [],
                    "blocksAttackPathIds": [],
                    "evidenceRefs": entity.get("evidenceRefs").cloned().unwrap_or_else(|| json!([])),
                }),
            );
        }
    }
    for verdict in chain_adjudication.get("verdicts").and_then(Value::as_array).into_iter().flatten() {
        if verdict.get("verdict").and_then(Value::as_str) != Some("BLOCKED") {
            continue;
        }
        let path_id = verdict.get("pathId").cloned().unwrap_or(Value::Null);
        for assessment in verdict.get("controlAssessments").and_then(Value::as_array).into_iter().flatten() {
            let control_id = assessment.get("controlId").and_then(Value::as_str).unwrap_or("");
            if let Some(control) = controls.get_mut(control_id) {
                control["status"] = assessment.get("status").cloned().unwrap_or(json!("UNKNOWN"));
                control["blocksAttackPathIds"]
                    .as_array_mut()
                    .unwrap()
                    .push(path_id.clone());
            }
        }
    }
    // JS's `for (const ref of finding.rootCauseSignature?.missingControl ? [] : [])`
    // always iterates an empty array (the ternary produces `[]` either way), so
    // `supportsFindingIds` is never populated from findings; this port carries
    // that dead branch's observable no-op behaviour forward faithfully by
    // simply not touching `supportsFindingIds` here.
    order
        .into_iter()
        .filter_map(|id| controls.get(&id).cloned())
        .collect()
}

/// Faithful port of `synthesizeSecurityEvidence`.
pub fn synthesize_security_evidence(
    plan: &Value,
    model: &Value,
    candidates: &Value,
    adjudication: &Value,
    chain_adjudication: &Value,
    variants: &Value,
) -> Result<Value> {
    let binding = binding_from_plan(plan)?;
    for (label, artifact) in [
        ("model", model),
        ("candidates", candidates),
        ("adjudication", adjudication),
        ("chainAdjudication", chain_adjudication),
        ("variants", variants),
    ] {
        assert_artifact_binding(artifact, &binding, label)?;
    }

    let candidate_by_id: BTreeMap<String, Value> = candidates
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item.clone())))
        .collect();
    let receipt_by_finding = complete_receipt_by_finding(variants);
    let proven_paths: Vec<Value> = chain_adjudication
        .get("verdicts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("verdict").and_then(Value::as_str) == Some("PROVEN"))
        .cloned()
        .collect();

    let mut findings: Vec<Value> = Vec::new();
    let mut coverage_gaps: Vec<Value> = Vec::new();

    for verdict in adjudication.get("verdicts").and_then(Value::as_array).into_iter().flatten() {
        let verdict_kind = verdict.get("verdict").and_then(Value::as_str).unwrap_or("");
        if !SURVIVING.contains(&verdict_kind) {
            continue;
        }
        let candidate_id = verdict.get("candidateId").and_then(Value::as_str).unwrap_or("");
        let candidate = candidate_by_id.get(candidate_id);
        let receipt = receipt_by_finding.get(candidate_id);
        match (candidate, receipt) {
            (Some(candidate), Some(receipt)) => {
                findings.push(finding_from(candidate, verdict, receipt, &proven_paths));
            }
            _ => {
                coverage_gaps.push(json!({
                    "kind": "finding-missing-candidate-or-variant-receipt",
                    "candidateId": candidate_id,
                }));
            }
        }
    }

    let attack_paths = materialize_attack_paths(&proven_paths, &findings);
    let hypotheses = classify_non_proven_paths(chain_adjudication);
    let systemic_root_causes = group_root_causes(&findings);
    let controls = summarize_controls(model, chain_adjudication, &findings);

    let variants_complete = variants.get("complete").and_then(Value::as_bool).unwrap_or(false);
    let adjudication_complete = adjudication.get("complete").and_then(Value::as_bool).unwrap_or(false);
    let chain_adjudication_complete = chain_adjudication.get("complete").and_then(Value::as_bool).unwrap_or(false);
    let complete = coverage_gaps.is_empty() && variants_complete && adjudication_complete && chain_adjudication_complete;

    let complete_variant_receipts = variants
        .get("receipts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("complete").and_then(Value::as_bool) == Some(true))
        .count();

    let synthesis_digest = digest(&json!({
        "findings": findings,
        "attackPaths": attack_paths,
        "systemicRootCauses": systemic_root_causes,
        "controls": controls,
        "hypotheses": {
            "partiallySupported": hypotheses.partially_supported,
            "blocked": hypotheses.blocked,
            "refuted": hypotheses.refuted,
            "unproven": hypotheses.unproven,
        },
    }));

    Ok(json!({
        "schemaVersion": 1,
        "kind": "security-evidence-synthesis",
        "provider": "security.evidence-synthesis",
        "providerVersion": "1",
        "binding": binding,
        "complete": complete,
        "findings": findings,
        "attackPaths": attack_paths,
        "systemicRootCauses": systemic_root_causes,
        "controls": controls,
        "hypotheses": {
            "partiallySupported": hypotheses.partially_supported.clone(),
            "blocked": hypotheses.blocked.clone(),
            "refuted": hypotheses.refuted.clone(),
            "unproven": hypotheses.unproven.clone(),
        },
        "coverage": {
            "candidates": candidates.get("candidates").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "survivingCandidateVerdicts": findings.len(),
            "provenPaths": attack_paths.len(),
            "partialPaths": hypotheses.partially_supported.len(),
            "blockedPaths": hypotheses.blocked.len(),
            "refutedPaths": hypotheses.refuted.len(),
            "unprovenPaths": hypotheses.unproven.len(),
            "completeVariantReceipts": complete_variant_receipts,
            "synthesisDigest": synthesis_digest,
        },
        "coverageGaps": coverage_gaps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn artifact(extra: Value) -> Value {
        let binding = binding_from_plan(&plan_with()).unwrap();
        let mut base = json!({"binding": binding, "complete": true});
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        base
    }

    #[test]
    fn surviving_verdict_with_complete_receipt_becomes_a_finding() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let candidates = artifact(json!({"candidates": [{"id": "c1", "ruleId": "r1", "claim": "claim"}]}));
        let adjudication = artifact(json!({"verdicts": [{"candidateId": "c1", "verdict": "TRUE_POSITIVE"}]}));
        let chain_adjudication = artifact(json!({"verdicts": []}));
        let variants = artifact(json!({"receipts": [{"findingId": "c1", "complete": true, "matches": []}]}));

        let out = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap();
        assert_eq!(out["findings"].as_array().unwrap().len(), 1);
        assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn missing_receipt_produces_coverage_gap_not_a_finding() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let candidates = artifact(json!({"candidates": [{"id": "c1", "ruleId": "r1", "claim": "claim"}]}));
        let adjudication = artifact(json!({"verdicts": [{"candidateId": "c1", "verdict": "TRUE_POSITIVE"}]}));
        let chain_adjudication = artifact(json!({"verdicts": []}));
        let variants = artifact(json!({"receipts": []}));

        let out = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap();
        assert_eq!(out["findings"].as_array().unwrap().len(), 0);
        assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 1);
        assert_eq!(out["complete"], false);
    }

    #[test]
    fn non_surviving_verdict_is_never_a_finding() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let candidates = artifact(json!({"candidates": [{"id": "c1", "ruleId": "r1", "claim": "claim"}]}));
        let adjudication = artifact(json!({"verdicts": [{"candidateId": "c1", "verdict": "FALSE_POSITIVE"}]}));
        let chain_adjudication = artifact(json!({"verdicts": []}));
        let variants = artifact(json!({"receipts": [{"findingId": "c1", "complete": true, "matches": []}]}));

        let out = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap();
        assert_eq!(out["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn proven_paths_are_materialized_separately() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let candidates = artifact(json!({"candidates": []}));
        let adjudication = artifact(json!({"verdicts": []}));
        let chain_adjudication = artifact(json!({"verdicts": [{"verdict": "PROVEN", "pathId": "p1", "start": {"factIds": []}, "objective": {"id": "o1"}}]}));
        let variants = artifact(json!({"receipts": []}));

        let out = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap();
        assert_eq!(out["attackPaths"].as_array().unwrap().len(), 1);
        assert_eq!(out["attackPaths"][0]["verdict"], "PROVEN");
    }

    #[test]
    fn root_causes_are_grouped_by_signature() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let candidates = artifact(json!({"candidates": [
            {"id": "c1", "ruleId": "r1", "claim": "claim1"},
            {"id": "c2", "ruleId": "r2", "claim": "claim2"},
        ]}));
        let adjudication = artifact(json!({"verdicts": [
            {"candidateId": "c1", "verdict": "TRUE_POSITIVE", "rootCauseSignature": {"pattern": "x"}},
            {"candidateId": "c2", "verdict": "TRUE_POSITIVE", "rootCauseSignature": {"pattern": "x"}},
        ]}));
        let chain_adjudication = artifact(json!({"verdicts": []}));
        let variants = artifact(json!({"receipts": [
            {"findingId": "c1", "complete": true, "matches": []},
            {"findingId": "c2", "complete": true, "matches": []},
        ]}));

        let out = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap();
        assert_eq!(out["systemicRootCauses"].as_array().unwrap().len(), 1);
        assert_eq!(out["systemicRootCauses"][0]["findingIds"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn binding_mismatch_is_rejected() {
        let plan = plan_with();
        let model = artifact(json!({"entities": []}));
        let mut candidates = artifact(json!({"candidates": []}));
        candidates["binding"]["repositoryRevision"] = json!("other");
        let adjudication = artifact(json!({"verdicts": []}));
        let chain_adjudication = artifact(json!({"verdicts": []}));
        let variants = artifact(json!({"receipts": []}));

        let err = synthesize_security_evidence(&plan, &model, &candidates, &adjudication, &chain_adjudication, &variants).unwrap_err();
        assert!(err.0.contains("does not match"));
    }
}
