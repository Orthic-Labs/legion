//! Port of `src/providers/security/attack-path-reconcile.mjs`.
//!
//! Attack-path reconciliation per Security Appendix §25. Paths become
//! eligible for chain adjudication only when every mandatory primitive
//! survives; a path is never marked `PROVEN` during reconciliation.

use serde_json::{json, Map, Value};

use super::contracts::{assert_artifact_binding, binding_from_plan, Result};

const SURVIVING: &[&str] = &["TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"];
const HARD_REFUTE: &[&str] = &["FALSE_POSITIVE", "OUT_OF_SCOPE"];

/// Faithful port of `reconcileAttackPaths`.
pub fn reconcile_attack_paths(
    plan: &Value,
    hypotheses_artifact: &Value,
    adjudication: &Value,
) -> Result<Value> {
    let binding = binding_from_plan(plan)?;
    assert_artifact_binding(hypotheses_artifact, &binding, "attack paths")?;
    assert_artifact_binding(adjudication, &binding, "security adjudication")?;

    let mut verdict_by_candidate: Map<String, Value> = Map::new();
    for verdict in adjudication
        .get("verdicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(candidate_id) = verdict.get("candidateId").and_then(Value::as_str) {
            verdict_by_candidate.insert(candidate_id.to_string(), verdict);
        }
    }

    let hypotheses_in = hypotheses_artifact
        .get("hypotheses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut hypotheses_out = Vec::with_capacity(hypotheses_in.len());
    for path in hypotheses_in {
        let steps = path.get("steps").and_then(Value::as_array).cloned().unwrap_or_default();

        let step_verdicts: Vec<Value> = steps
            .iter()
            .map(|step| {
                let candidate_id = step.get("candidateId").cloned().unwrap_or(Value::Null);
                let verdict = candidate_id
                    .as_str()
                    .and_then(|id| verdict_by_candidate.get(id))
                    .cloned()
                    .unwrap_or(Value::Null);
                json!({"candidateId": candidate_id, "verdict": verdict})
            })
            .collect();

        let missing: Vec<&Value> = step_verdicts
            .iter()
            .filter(|item| item.get("verdict").map(Value::is_null).unwrap_or(true))
            .collect();
        let refuted: Vec<&Value> = step_verdicts
            .iter()
            .filter(|item| {
                item.pointer("/verdict/verdict")
                    .and_then(Value::as_str)
                    .map(|v| HARD_REFUTE.contains(&v))
                    .unwrap_or(false)
            })
            .collect();
        let unsupported: Vec<&Value> = step_verdicts
            .iter()
            .filter(|item| {
                let verdict_value = item.get("verdict");
                let has_verdict = verdict_value.map(|v| !v.is_null()).unwrap_or(false);
                if !has_verdict {
                    return false;
                }
                let verdict_str = item.pointer("/verdict/verdict").and_then(Value::as_str);
                match verdict_str {
                    Some(v) => !SURVIVING.contains(&v),
                    None => true,
                }
            })
            .collect();

        let (status, reason) = if !missing.is_empty() {
            ("UNPROVEN", "one or more primitive steps have no verdict")
        } else if !refuted.is_empty() {
            ("REFUTED", "one or more mandatory primitive steps were refuted")
        } else if !unsupported.is_empty() {
            ("UNPROVEN", "one or more steps did not survive as vulnerabilities")
        } else {
            (
                "PARTIALLY_SUPPORTED",
                "all primitive steps survived; composition has not been adjudicated",
            )
        };

        let mut out = path
            .as_object()
            .cloned()
            .ok_or_else(|| super::contracts::SecurityContractError::new("hypothesis must be an object"))?;
        out.insert("status".to_string(), json!(status));
        out.insert(
            "reconciliation".to_string(),
            json!({
                "reason": reason,
                "stepVerdicts": step_verdicts,
                "eligibleForChainAdjudication": status == "PARTIALLY_SUPPORTED",
            }),
        );
        hypotheses_out.push(Value::Object(out));
    }

    let mut out = hypotheses_artifact
        .as_object()
        .cloned()
        .ok_or_else(|| super::contracts::SecurityContractError::new("hypothesesArtifact must be an object"))?;
    out.insert("kind".to_string(), json!("reconciled-attack-path-hypotheses"));
    out.insert("hypotheses".to_string(), Value::Array(hypotheses_out));
    let adjudication_complete = adjudication.get("complete").and_then(Value::as_bool).unwrap_or(false);
    let hypotheses_complete = hypotheses_artifact.get("complete").and_then(Value::as_bool).unwrap_or(false);
    out.insert("complete".to_string(), json!(adjudication_complete && hypotheses_complete));

    Ok(Value::Object(out))
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

    fn artifact_with(binding: &Value, extra: Value) -> Value {
        let mut base = json!({
            "binding": binding,
            "complete": true,
        });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base
    }

    #[test]
    fn missing_verdict_is_unproven() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let hypotheses = artifact_with(
            &binding,
            json!({"hypotheses": [{"steps": [{"candidateId": "c1"}]}]}),
        );
        let adjudication = artifact_with(&binding, json!({"verdicts": []}));
        let out = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
        assert_eq!(out["hypotheses"][0]["status"], "UNPROVEN");
        assert_eq!(
            out["hypotheses"][0]["reconciliation"]["eligibleForChainAdjudication"],
            false
        );
    }

    #[test]
    fn refuted_step_refutes_path() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let hypotheses = artifact_with(
            &binding,
            json!({"hypotheses": [{"steps": [{"candidateId": "c1"}]}]}),
        );
        let adjudication = artifact_with(
            &binding,
            json!({"verdicts": [{"candidateId": "c1", "verdict": "FALSE_POSITIVE"}]}),
        );
        let out = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
        assert_eq!(out["hypotheses"][0]["status"], "REFUTED");
    }

    #[test]
    fn all_surviving_is_partially_supported_never_proven() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let hypotheses = artifact_with(
            &binding,
            json!({"hypotheses": [{"steps": [{"candidateId": "c1"}, {"candidateId": "c2"}]}]}),
        );
        let adjudication = artifact_with(
            &binding,
            json!({"verdicts": [
                {"candidateId": "c1", "verdict": "TRUE_POSITIVE"},
                {"candidateId": "c2", "verdict": "LIKELY_TRUE_POSITIVE"},
            ]}),
        );
        let out = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
        assert_eq!(out["hypotheses"][0]["status"], "PARTIALLY_SUPPORTED");
        assert_eq!(
            out["hypotheses"][0]["reconciliation"]["eligibleForChainAdjudication"],
            true
        );
        assert_ne!(out["hypotheses"][0]["status"], "PROVEN");
    }

    #[test]
    fn unsupported_verdict_is_unproven() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let hypotheses = artifact_with(
            &binding,
            json!({"hypotheses": [{"steps": [{"candidateId": "c1"}]}]}),
        );
        let adjudication = artifact_with(
            &binding,
            json!({"verdicts": [{"candidateId": "c1", "verdict": "LIKELY_FALSE_POSITIVE"}]}),
        );
        let out = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
        assert_eq!(out["hypotheses"][0]["status"], "UNPROVEN");
    }

    #[test]
    fn overall_complete_requires_both_inputs_complete() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let mut hypotheses = artifact_with(&binding, json!({"hypotheses": []}));
        hypotheses["complete"] = json!(true);
        let mut adjudication = artifact_with(&binding, json!({"verdicts": []}));
        adjudication["complete"] = json!(false);
        let out = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
        assert_eq!(out["complete"], false);
    }

    #[test]
    fn binding_mismatch_is_rejected() {
        let plan = plan_with();
        let binding = binding_from_plan(&plan).unwrap();
        let mut other = binding.clone();
        other["repositoryRevision"] = json!("other");
        let hypotheses = artifact_with(&other, json!({"hypotheses": []}));
        let adjudication = artifact_with(&binding, json!({"verdicts": []}));
        let err = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap_err();
        assert!(err.0.contains("does not match the frozen audit plan"));
    }
}
