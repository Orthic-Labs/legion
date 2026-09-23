//! Port of `src/adapters/security-chain-adjudication.mjs` (packet P5c).
//!
//! Chain adjudication adapter per Security Appendix §27-28. One fresh
//! context per path; the synthesizer can never adjudicate its own path;
//! `PROVEN` requires verified steps, verified joins, terminal impact, bound
//! proof, a negative control, and a devil's-advocate challenge.
//!
//! `plan`/`path`/`candidates`/`candidateAdjudication`/`model` are modeled as
//! `serde_json::Value` here rather than typed structs: this packet does not
//! own `src/providers/security/contracts.mjs` (the binding/require helpers
//! the JS adapter imports from there), so `binding_from_plan` and
//! `assert_artifact_binding` below are minimal re-implementations of that
//! module's `bindingFromPlan`/`assertArtifactBinding`/`assertBinding`
//! sufficient for this adapter's own needs — not a full port of that file.
//! Flag for reconciliation once `src/providers/security/contracts.mjs` is
//! ported by its owning packet.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use legion_contracts::canonical_json_bytes;

#[derive(Debug, thiserror::Error)]
pub enum ChainAdjudicationError {
    #[error("plan has no seal digest")]
    NoSealDigest,
    #[error("{0} must be an object")]
    NotAnObject(String),
    #[error("{0} must be a non-empty string")]
    NotANonEmptyString(String),
    #[error("{0} must be an array")]
    NotAnArray(String),
    #[error("{0} binding does not match the frozen audit plan")]
    BindingMismatch(String),
    #[error("attack-path synthesizer cannot adjudicate its own path")]
    SelfSynthesis,
    #[error("chain adjudication requires a fresh context")]
    SameContext,
    #[error("missing candidate or verdict for {0}")]
    MissingCandidateOrVerdict(String),
    #[error("chain verdict pathId mismatch")]
    PathIdMismatch,
    #[error("chain verdict contextId mismatch")]
    ContextIdMismatch,
    #[error("unsupported chain verdict {0:?}")]
    UnsupportedVerdict(String),
    #[error("chain verdict must assess every path step exactly once")]
    IncompleteStepAssessments,
    #[error("chain verdict must assess every path join exactly once")]
    IncompleteJoinAssessments,
    #[error("PROVEN chain requires verified evidence")]
    ProvenRequiresVerifiedEvidence,
    #[error("PROVEN chain requires severity")]
    ProvenRequiresSeverity,
    #[error("PROVEN chain requires terminalImpact")]
    ProvenRequiresTerminalImpact,
    #[error("PROVEN chain requires bound proof")]
    ProvenRequiresProof,
    #[error("PROVEN chain requires a negative control")]
    ProvenRequiresNegativeControl,
    #[error("PROVEN chain requires every step to be usable")]
    ProvenRequiresUsableSteps,
    #[error("PROVEN chain requires every join to be verified")]
    ProvenRequiresVerifiedJoins,
    #[error("{0} chain must not carry final severity")]
    UnexpectedSeverity(String),
    #[error("BLOCKED chain requires an effective blocking control")]
    BlockedRequiresEffectiveControl,
    #[error("REFUTED chain requires a refuted join or unusable step")]
    RefutedRequiresRefutation,
}

const CHAIN_VERDICTS: [&str; 5] = ["PROVEN", "PARTIALLY_SUPPORTED", "REFUTED", "BLOCKED", "UNPROVEN"];

fn require_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, ChainAdjudicationError> {
    value
        .as_object()
        .ok_or_else(|| ChainAdjudicationError::NotAnObject(label.to_string()))
}

fn require_string<'a>(value: &'a Value, label: &str) -> Result<&'a str, ChainAdjudicationError> {
    match value.as_str() {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(ChainAdjudicationError::NotANonEmptyString(label.to_string())),
    }
}

fn require_array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>, ChainAdjudicationError> {
    value
        .as_array()
        .ok_or_else(|| ChainAdjudicationError::NotAnArray(label.to_string()))
}

/// Re-implementation of `assertBinding(binding)`.
fn assert_binding(binding: &Value) -> Result<(), ChainAdjudicationError> {
    require_object(binding, "binding")?;
    for key in [
        "planDigest",
        "repositoryRevision",
        "blueprintGenerationId",
        "blueprintManifestDigest",
        "registryDigest",
    ] {
        require_string(&binding[key], &format!("binding.{key}"))?;
    }
    if !binding["dirtyPatchDigest"].is_null() {
        require_string(&binding["dirtyPatchDigest"], "binding.dirtyPatchDigest")?;
    }
    Ok(())
}

/// Re-implementation of `bindingFromPlan(plan)`.
pub fn binding_from_plan(plan: &Value) -> Result<Value, ChainAdjudicationError> {
    let seal_digest = plan.pointer("/seal/digest").and_then(Value::as_str);
    if seal_digest.is_none() {
        return Err(ChainAdjudicationError::NoSealDigest);
    }
    let binding = json!({
        "planDigest": plan["seal"]["digest"],
        "repositoryRevision": plan["binding"]["repositoryRevision"],
        "dirtyPatchDigest": plan["binding"]["dirtyPatchDigest"],
        "blueprintGenerationId": plan["binding"]["blueprint"]["generationId"],
        "blueprintManifestDigest": plan["binding"]["blueprint"]["manifestDigest"],
        "registryDigest": plan["binding"]["registryDigest"],
    });
    assert_binding(&binding)?;
    Ok(binding)
}

fn same_binding(left: &Value, right: &Value) -> bool {
    canonical_json_bytes(left).ok() == canonical_json_bytes(right).ok()
}

/// Re-implementation of `assertArtifactBinding(artifact, expectedBinding, label)`.
pub fn assert_artifact_binding(
    artifact: &Value,
    expected_binding: &Value,
    label: &str,
) -> Result<(), ChainAdjudicationError> {
    let binding = artifact.get("binding").cloned().unwrap_or(Value::Null);
    assert_binding(&binding)?;
    if !same_binding(&binding, expected_binding) {
        return Err(ChainAdjudicationError::BindingMismatch(label.to_string()));
    }
    Ok(())
}

fn ids_from(value: &Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        if let Some(items) = value.get(key).and_then(Value::as_array) {
            for item in items {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

fn slice_model_for_path(model: &Value, step_packets: &[Value]) -> Value {
    use std::collections::HashSet;
    let mut referenced: HashSet<String> = HashSet::new();
    for step in step_packets {
        let candidate = step.get("candidate").cloned().unwrap_or(Value::Null);
        for id in ids_from(
            &candidate,
            &["sources", "sinks", "assets", "requiredControls", "observedControls"],
        ) {
            referenced.insert(id);
        }
    }
    let empty = Vec::new();
    let entities: Vec<Value> = model
        .get("entities")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter(|entity| {
            entity
                .get("id")
                .and_then(Value::as_str)
                .map(|id| referenced.contains(id))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let entity_ids: HashSet<String> = entities
        .iter()
        .filter_map(|entity| entity.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    let relations: Vec<Value> = model
        .get("relations")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter(|relation| {
            let from = relation.get("from").and_then(Value::as_str).unwrap_or_default();
            let to = relation.get("to").and_then(Value::as_str).unwrap_or_default();
            entity_ids.contains(from) || entity_ids.contains(to)
        })
        .cloned()
        .collect();
    let mut referenced_evidence: HashSet<String> = HashSet::new();
    for entity in &entities {
        for id in ids_from(entity, &["evidenceRefs"]) {
            referenced_evidence.insert(id);
        }
    }
    for relation in &relations {
        for id in ids_from(relation, &["evidenceRefs"]) {
            referenced_evidence.insert(id);
        }
    }
    let evidence: Vec<Value> = model
        .get("evidence")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .map(|id| referenced_evidence.contains(id))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    json!({ "entities": entities, "relations": relations, "evidence": evidence })
}

const REQUIRED_ANALYSIS: [&str; 11] = [
    "step usability",
    "identity compatibility",
    "environment compatibility",
    "tenant compatibility",
    "timing and workflow state",
    "join validity",
    "inter-step controls",
    "terminal impact",
    "safe proof",
    "negative control",
    "strongest benign explanation",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAdjudicationPacket(pub Value);

pub struct CreateChainAdjudicationPacketInput<'a> {
    pub plan: &'a Value,
    pub path: &'a Value,
    pub candidates: &'a Value,
    pub candidate_adjudication: &'a Value,
    pub model: &'a Value,
    pub adjudicator: &'a Value,
}

/// Port of `createChainAdjudicationPacket(...)`.
pub fn create_chain_adjudication_packet(
    input: CreateChainAdjudicationPacketInput<'_>,
) -> Result<ChainAdjudicationPacket, ChainAdjudicationError> {
    let binding = binding_from_plan(input.plan)?;

    let path_artifact = json!({ "binding": input.path.get("binding").cloned().unwrap_or(Value::Null) });
    assert_artifact_binding(&path_artifact, &binding, "pathArtifact")?;
    assert_artifact_binding(input.candidates, &binding, "candidates")?;
    assert_artifact_binding(input.candidate_adjudication, &binding, "candidateAdjudication")?;
    assert_artifact_binding(input.model, &binding, "model")?;

    let path_provider = input.path.get("provider").and_then(Value::as_str).unwrap_or_default();
    let adjudicator_provider = input
        .adjudicator
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if path_provider == adjudicator_provider {
        return Err(ChainAdjudicationError::SelfSynthesis);
    }
    let synthesis_context_id = input.path.get("synthesisContextId").and_then(Value::as_str);
    let adjudicator_context_id = input.adjudicator.get("contextId").and_then(Value::as_str);
    if let (Some(a), Some(b)) = (synthesis_context_id, adjudicator_context_id) {
        if a == b {
            return Err(ChainAdjudicationError::SameContext);
        }
    }

    let empty_vec = Vec::new();
    let candidate_list = input
        .candidates
        .get("candidates")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let candidate_by_id: std::collections::HashMap<&str, &Value> = candidate_list
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id, item)))
        .collect();
    let verdict_list = input
        .candidate_adjudication
        .get("verdicts")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let verdict_by_id: std::collections::HashMap<&str, &Value> = verdict_list
        .iter()
        .filter_map(|item| item.get("candidateId").and_then(Value::as_str).map(|id| (id, item)))
        .collect();

    let steps = require_array(&input.path["steps"], "path.steps")?;
    let mut step_packets = Vec::with_capacity(steps.len());
    for step in steps {
        let candidate_id = step.get("candidateId").and_then(Value::as_str).unwrap_or_default();
        let candidate = candidate_by_id.get(candidate_id);
        let verdict = verdict_by_id.get(candidate_id);
        match (candidate, verdict) {
            (Some(candidate), Some(verdict)) => step_packets.push(json!({
                "step": step,
                "candidate": candidate,
                "verdict": verdict,
            })),
            _ => {
                return Err(ChainAdjudicationError::MissingCandidateOrVerdict(
                    candidate_id.to_string(),
                ))
            }
        }
    }

    let path_id = input.path.get("id").cloned().unwrap_or(Value::Null);
    let adjudicator_context_id_value = input.adjudicator.get("contextId").cloned().unwrap_or(Value::Null);
    let packet_id = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json::to_vec(&json!({
                "pathId": path_id,
                "contextId": adjudicator_context_id_value,
                "binding": binding,
            }))
            .unwrap_or_default()
        )
    );

    let model_slice = slice_model_for_path(input.model, &step_packets);

    let packet = json!({
        "schemaVersion": 1,
        "kind": "security-chain-adjudication-packet",
        "packetId": packet_id,
        "pathId": input.path.get("id").cloned().unwrap_or(Value::Null),
        "binding": binding,
        "synthesizer": {
            "provider": path_provider,
            "contextId": synthesis_context_id,
        },
        "adjudicator": input.adjudicator,
        "path": input.path,
        "steps": step_packets,
        "modelSlice": model_slice,
        "requiredAnalysis": REQUIRED_ANALYSIS,
    });
    Ok(ChainAdjudicationPacket(packet))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict(pub Value);

/// Port of `finalizeChainVerdict(packet, rawVerdict)`.
pub fn finalize_chain_verdict(
    packet: &ChainAdjudicationPacket,
    raw_verdict: &Value,
) -> Result<ChainVerdict, ChainAdjudicationError> {
    let packet = &packet.0;
    require_object(raw_verdict, "chain verdict")?;
    if raw_verdict.get("pathId") != packet.get("pathId") {
        return Err(ChainAdjudicationError::PathIdMismatch);
    }
    if raw_verdict.get("contextId") != packet.pointer("/adjudicator/contextId") {
        return Err(ChainAdjudicationError::ContextIdMismatch);
    }
    let verdict = raw_verdict
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !CHAIN_VERDICTS.contains(&verdict) {
        return Err(ChainAdjudicationError::UnsupportedVerdict(verdict.to_string()));
    }

    let step_assessments = require_array(&raw_verdict["stepAssessments"], "stepAssessments")?;
    let join_assessments = require_array(&raw_verdict["joinAssessments"], "joinAssessments")?;

    let expected_steps: std::collections::HashSet<&str> = packet["path"]["steps"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|s| s.get("candidateId").and_then(Value::as_str))
        .collect();
    let expected_joins: std::collections::HashSet<&str> = packet["path"]["joins"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|j| j.get("id").and_then(Value::as_str))
        .collect();

    let step_ids: std::collections::HashSet<&str> = step_assessments
        .iter()
        .filter_map(|item| item.get("candidateId").and_then(Value::as_str))
        .collect();
    if step_ids.len() != expected_steps.len()
        || step_assessments.iter().any(|item| {
            item.get("candidateId")
                .and_then(Value::as_str)
                .map(|id| !expected_steps.contains(id))
                .unwrap_or(true)
        })
    {
        return Err(ChainAdjudicationError::IncompleteStepAssessments);
    }
    let join_ids: std::collections::HashSet<&str> = join_assessments
        .iter()
        .filter_map(|item| item.get("joinId").and_then(Value::as_str))
        .collect();
    if join_ids.len() != expected_joins.len()
        || join_assessments.iter().any(|item| {
            item.get("joinId")
                .and_then(Value::as_str)
                .map(|id| !expected_joins.contains(id))
                .unwrap_or(true)
        })
    {
        return Err(ChainAdjudicationError::IncompleteJoinAssessments);
    }

    require_string(&raw_verdict["rationale"], "rationale")?;
    require_string(&raw_verdict["devilsAdvocate"], "devilsAdvocate")?;

    let mut final_severity = Value::Null;
    if verdict == "PROVEN" {
        if raw_verdict.get("evidenceStrength").and_then(Value::as_str) != Some("verified") {
            return Err(ChainAdjudicationError::ProvenRequiresVerifiedEvidence);
        }
        if raw_verdict.get("severity").map(Value::is_null).unwrap_or(true) {
            return Err(ChainAdjudicationError::ProvenRequiresSeverity);
        }
        if raw_verdict.get("terminalImpact").map(Value::is_null).unwrap_or(true) {
            return Err(ChainAdjudicationError::ProvenRequiresTerminalImpact);
        }
        if raw_verdict.pointer("/proof/digest").is_none() {
            return Err(ChainAdjudicationError::ProvenRequiresProof);
        }
        if raw_verdict
            .pointer("/negativeControl/rationale")
            .is_none()
        {
            return Err(ChainAdjudicationError::ProvenRequiresNegativeControl);
        }
        if step_assessments
            .iter()
            .any(|item| item.get("usableInChain") != Some(&Value::Bool(true)))
        {
            return Err(ChainAdjudicationError::ProvenRequiresUsableSteps);
        }
        if join_assessments
            .iter()
            .any(|item| item.get("verdict").and_then(Value::as_str) != Some("VERIFIED"))
        {
            return Err(ChainAdjudicationError::ProvenRequiresVerifiedJoins);
        }
        final_severity = raw_verdict.get("severity").cloned().unwrap_or(Value::Null);
    } else if raw_verdict
        .get("severity")
        .map(|value| !value.is_null())
        .unwrap_or(false)
    {
        return Err(ChainAdjudicationError::UnexpectedSeverity(verdict.to_string()));
    }

    if verdict == "BLOCKED" {
        let effective = raw_verdict
            .get("controlAssessments")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .any(|item| item.get("status").and_then(Value::as_str) == Some("EFFECTIVE"))
            })
            .unwrap_or(false);
        if !effective {
            return Err(ChainAdjudicationError::BlockedRequiresEffectiveControl);
        }
    }

    if verdict == "REFUTED" {
        let refuted_join = join_assessments
            .iter()
            .any(|item| item.get("verdict").and_then(Value::as_str) == Some("REFUTED"));
        let unusable_step = step_assessments
            .iter()
            .any(|item| item.get("usableInChain") == Some(&Value::Bool(false)));
        if !refuted_join && !unusable_step {
            return Err(ChainAdjudicationError::RefutedRequiresRefutation);
        }
    }

    let result = json!({
        "schemaVersion": 1,
        "kind": "security-chain-verdict",
        "pathId": packet["pathId"],
        "synthesizerProvider": packet["synthesizer"]["provider"],
        "adjudicatorProvider": packet["adjudicator"]["provider"],
        "contextId": packet["adjudicator"]["contextId"],
        "binding": packet["binding"],
        "verdict": verdict,
        "evidenceStrength": raw_verdict.get("evidenceStrength").cloned().unwrap_or(Value::Null),
        "stepAssessments": step_assessments,
        "joinAssessments": join_assessments,
        "controlAssessments": raw_verdict.get("controlAssessments").cloned().unwrap_or_else(|| json!([])),
        "terminalImpact": raw_verdict.get("terminalImpact").cloned().unwrap_or(Value::Null),
        "proof": raw_verdict.get("proof").cloned().unwrap_or(Value::Null),
        "negativeControl": raw_verdict.get("negativeControl").cloned().unwrap_or(Value::Null),
        "devilsAdvocate": raw_verdict["devilsAdvocate"],
        "rationale": raw_verdict["rationale"],
        "severity": final_severity,
    });
    Ok(ChainVerdict(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Value {
        json!({
            "seal": {"digest": "sha256:plan"},
            "binding": {
                "repositoryRevision": "rev1",
                "dirtyPatchDigest": Value::Null,
                "blueprint": {"generationId": "gen1", "manifestDigest": "sha256:manifest"},
                "registryDigest": "sha256:registry",
            },
        })
    }

    #[test]
    fn binding_from_plan_matches_expected_shape() {
        let binding = binding_from_plan(&plan()).unwrap();
        assert_eq!(binding["planDigest"], json!("sha256:plan"));
        assert_eq!(binding["repositoryRevision"], json!("rev1"));
    }

    #[test]
    fn no_seal_digest_is_rejected() {
        let mut bad_plan = plan();
        bad_plan["seal"] = json!({});
        assert!(matches!(
            binding_from_plan(&bad_plan),
            Err(ChainAdjudicationError::NoSealDigest)
        ));
    }

    #[test]
    fn self_synthesis_is_rejected() {
        let binding = binding_from_plan(&plan()).unwrap();
        let artifact = json!({"binding": binding.clone()});
        let path = json!({"id": "path-1", "provider": "same", "binding": binding, "steps": []});
        let adjudicator = json!({"provider": "same", "contextId": "ctx-2"});
        let result = create_chain_adjudication_packet(CreateChainAdjudicationPacketInput {
            plan: &plan(),
            path: &path,
            candidates: &artifact,
            candidate_adjudication: &artifact,
            model: &artifact,
            adjudicator: &adjudicator,
        });
        assert!(matches!(result, Err(ChainAdjudicationError::SelfSynthesis)));
    }

    #[test]
    fn unsupported_verdict_is_rejected() {
        let binding = binding_from_plan(&plan()).unwrap();
        let packet = ChainAdjudicationPacket(json!({
            "pathId": "p1",
            "adjudicator": {"provider": "adj", "contextId": "ctx-2"},
            "path": {"steps": [], "joins": []},
            "binding": binding,
        }));
        let raw = json!({
            "pathId": "p1",
            "contextId": "ctx-2",
            "verdict": "MADE_UP",
            "stepAssessments": [],
            "joinAssessments": [],
            "rationale": "r",
            "devilsAdvocate": "d",
        });
        assert!(matches!(
            finalize_chain_verdict(&packet, &raw),
            Err(ChainAdjudicationError::UnsupportedVerdict(_))
        ));
    }

    #[test]
    fn proven_without_negative_control_is_rejected() {
        let binding = binding_from_plan(&plan()).unwrap();
        let packet = ChainAdjudicationPacket(json!({
            "pathId": "p1",
            "synthesizer": {"provider": "syn"},
            "adjudicator": {"provider": "adj", "contextId": "ctx-2"},
            "path": {
                "steps": [{"candidateId": "c1"}],
                "joins": [{"id": "j1"}],
            },
            "binding": binding,
        }));
        let raw = json!({
            "pathId": "p1",
            "contextId": "ctx-2",
            "verdict": "PROVEN",
            "evidenceStrength": "verified",
            "severity": "high",
            "terminalImpact": "rce",
            "proof": {"digest": "sha256:proof"},
            "stepAssessments": [{"candidateId": "c1", "usableInChain": true}],
            "joinAssessments": [{"joinId": "j1", "verdict": "VERIFIED"}],
            "rationale": "r",
            "devilsAdvocate": "d",
        });
        assert!(matches!(
            finalize_chain_verdict(&packet, &raw),
            Err(ChainAdjudicationError::ProvenRequiresNegativeControl)
        ));
    }

    #[test]
    fn refuted_requires_a_refuted_join_or_unusable_step() {
        let binding = binding_from_plan(&plan()).unwrap();
        let packet = ChainAdjudicationPacket(json!({
            "pathId": "p1",
            "synthesizer": {"provider": "syn"},
            "adjudicator": {"provider": "adj", "contextId": "ctx-2"},
            "path": {"steps": [{"candidateId": "c1"}], "joins": [{"id": "j1"}]},
            "binding": binding,
        }));
        let raw = json!({
            "pathId": "p1",
            "contextId": "ctx-2",
            "verdict": "REFUTED",
            "stepAssessments": [{"candidateId": "c1", "usableInChain": true}],
            "joinAssessments": [{"joinId": "j1", "verdict": "VERIFIED"}],
            "rationale": "r",
            "devilsAdvocate": "d",
        });
        assert!(matches!(
            finalize_chain_verdict(&packet, &raw),
            Err(ChainAdjudicationError::RefutedRequiresRefutation)
        ));
    }
}
