//! Port of `tools/audit/security-chain-pipeline.mjs`'s
//! `prepareChainAdjudicationBundle` / `finalizeChainAdjudicationBundle`. The
//! per-path primitives these two functions wrap
//! (`createChainAdjudicationPacket`, `finalizeChainVerdict`) are already
//! ported at `legion_runtime::p5_core::adapters_chain_adjudication`; this
//! file ports the bundle-level orchestration JS layered on top: one packet
//! per eligible reconciled path, and duplicate-path-verdict rejection during
//! finalization.

use std::collections::HashSet;

use serde_json::{json, Value};

use super::security_pipeline::random_id;
use legion_runtime::p5_core::adapters_chain_adjudication::{
    create_chain_adjudication_packet, finalize_chain_verdict, ChainAdjudicationPacket,
    CreateChainAdjudicationPacketInput,
};

/// A prepared chain bundle: the JSON envelope plus the typed packets kept
/// around (keyed by `pathId`) so `finalize_chain_adjudication_bundle` can
/// re-verify each one without re-parsing the envelope.
#[derive(Debug, Clone)]
pub struct ChainAdjudicationBundle {
    pub envelope: Value,
    pub packets: Vec<(String, ChainAdjudicationPacket)>,
    pub binding: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityChainPipelineError {
    #[error(transparent)]
    Chain(
        #[from]
        legion_runtime::p5_core::adapters_chain_adjudication::ChainAdjudicationError,
    ),
    #[error("hypothesis is missing a path id")]
    MissingPathId,
}

/// Port of `prepareChainAdjudicationBundle({ plan, reconciledPaths, candidates,
/// candidateAdjudication, model, synthesizerContextId })`.
pub fn prepare_chain_adjudication_bundle(
    plan: &Value,
    reconciled_paths: &Value,
    candidates: &Value,
    candidate_adjudication: &Value,
    model: &Value,
    synthesizer_context_id: Option<&str>,
) -> Result<ChainAdjudicationBundle, SecurityChainPipelineError> {
    let synthesizer_context_id = synthesizer_context_id.unwrap_or("attack-path-synthesis");
    let empty = Vec::new();
    let hypotheses = reconciled_paths
        .get("hypotheses")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let eligible: Vec<&Value> = hypotheses
        .iter()
        .filter(|path| {
            path.pointer("/reconciliation/eligibleForChainAdjudication")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .collect();

    let mut packets = Vec::with_capacity(eligible.len());
    let mut packet_values = Vec::with_capacity(eligible.len());
    for path in &eligible {
        let path_id = path.get("id").and_then(Value::as_str).ok_or(SecurityChainPipelineError::MissingPathId)?;
        let mut path_with_synthesis = (*path).clone();
        if let Value::Object(map) = &mut path_with_synthesis {
            map.insert("synthesisContextId".into(), json!(synthesizer_context_id));
        }
        let adjudicator = json!({
            "provider": "security.chain-adjudication",
            "contextId": format!("chain-{}-{}", &path_id[path_id.len().saturating_sub(12)..], random_id()),
            "contextStrategy": "one-context-per-path",
        });
        let packet = create_chain_adjudication_packet(CreateChainAdjudicationPacketInput {
            plan,
            path: &path_with_synthesis,
            candidates,
            candidate_adjudication,
            model,
            adjudicator: &adjudicator,
        })?;
        packet_values.push(packet.0.clone());
        packets.push((path_id.to_string(), packet));
    }

    let binding = reconciled_paths.get("binding").cloned().unwrap_or(Value::Null);
    let envelope = json!({
        "schemaVersion": 1,
        "kind": "security-chain-adjudication-bundle",
        "binding": binding,
        "complete": true,
        "contextStrategy": "one-context-per-path",
        "packets": packet_values,
    });

    Ok(ChainAdjudicationBundle {
        envelope,
        packets,
        binding,
    })
}

/// Port of `finalizeChainAdjudicationBundle(bundle, rawResults)`.
///
/// Note on ordering: JS builds `invalidVerdicts` for duplicate path ids in a
/// first pass over ALL raw verdicts (so a duplicate-path error can appear
/// even when the bundle has no packet for that path), then in the per-packet
/// loop skips any packet whose path already has a "duplicate" entry. This
/// port keeps the same two-pass structure and duplicate-suppression rule.
pub fn finalize_chain_adjudication_bundle(bundle: &ChainAdjudicationBundle, raw_results: &Value) -> Value {
    let empty = Vec::new();
    let raw_verdicts = raw_results
        .get("verdicts")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    let mut result_by_path: std::collections::HashMap<&str, &Value> = std::collections::HashMap::new();
    for raw in raw_verdicts {
        if let Some(path_id) = raw.get("pathId").and_then(Value::as_str) {
            result_by_path.entry(path_id).or_insert(raw);
        }
    }

    let mut verdicts: Vec<Value> = Vec::new();
    let mut missing_verdicts: Vec<String> = Vec::new();
    let mut invalid_verdicts: Vec<Value> = Vec::new();
    let mut seen_paths: HashSet<String> = HashSet::new();

    // Pass 1: duplicate path verdicts are invalid — never let the last value win.
    let mut count_by_path: std::collections::HashMap<Option<&str>, u32> = std::collections::HashMap::new();
    for raw in raw_verdicts {
        let path_id = raw.get("pathId").and_then(Value::as_str);
        *count_by_path.entry(path_id).or_insert(0) += 1;
    }
    let mut duplicate_paths: HashSet<&str> = HashSet::new();
    for (path_id, count) in &count_by_path {
        if *count > 1 {
            if let Some(id) = *path_id {
                duplicate_paths.insert(id);
            }
        }
    }
    for path_id in &duplicate_paths {
        invalid_verdicts.push(json!({ "pathId": path_id, "error": "duplicate path verdict" }));
    }

    // Pass 2: per-packet finalization.
    for (path_id, packet) in &bundle.packets {
        let Some(&raw) = result_by_path.get(path_id.as_str()) else {
            missing_verdicts.push(path_id.clone());
            continue;
        };
        if seen_paths.contains(path_id) {
            invalid_verdicts.push(json!({ "pathId": path_id, "error": "duplicate path verdict" }));
            continue;
        }
        if duplicate_paths.contains(path_id.as_str()) {
            continue;
        }
        seen_paths.insert(path_id.clone());
        match finalize_chain_verdict(packet, raw) {
            Ok(verdict) => verdicts.push(verdict.0),
            Err(error) => invalid_verdicts.push(json!({ "pathId": path_id, "error": error.to_string() })),
        }
    }

    let complete = missing_verdicts.is_empty() && invalid_verdicts.is_empty();
    json!({
        "schemaVersion": 1,
        "kind": "security-chain-adjudication-result",
        "binding": bundle.binding,
        "complete": complete,
        "verdicts": verdicts,
        "missingVerdicts": missing_verdicts,
        "invalidVerdicts": invalid_verdicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Value {
        json!({
            "seal": { "digest": "sha256:seal" },
            "binding": {
                "repositoryRevision": "rev-1",
                "dirtyPatchDigest": Value::Null,
                "blueprint": { "generationId": "gen-1", "manifestDigest": "sha256:manifest" },
                "registryDigest": "sha256:registry",
            },
        })
    }

    fn binding() -> Value {
        json!({
            "planDigest": "sha256:seal",
            "repositoryRevision": "rev-1",
            "dirtyPatchDigest": Value::Null,
            "blueprintGenerationId": "gen-1",
            "blueprintManifestDigest": "sha256:manifest",
            "registryDigest": "sha256:registry",
        })
    }

    fn candidates() -> Value {
        json!({
            "binding": binding(),
            "candidates": [{ "id": "cand-1", "sources": ["src-1"], "sinks": ["sink-1"] }],
        })
    }

    fn candidate_adjudication() -> Value {
        json!({
            "binding": binding(),
            "verdicts": [{ "candidateId": "cand-1", "verdict": "TRUE_POSITIVE" }],
        })
    }

    fn model() -> Value {
        json!({ "binding": binding(), "entities": [], "relations": [], "evidence": [] })
    }

    fn reconciled_paths(eligible: bool) -> Value {
        json!({
            "binding": binding(),
            "hypotheses": [{
                "id": "path-1",
                "provider": "security.attack-path-synthesis",
                "binding": binding(),
                "reconciliation": { "eligibleForChainAdjudication": eligible },
                "steps": [{ "candidateId": "cand-1" }],
                "joins": [],
            }],
        })
    }

    #[test]
    fn prepares_one_packet_per_eligible_path() {
        let bundle = prepare_chain_adjudication_bundle(
            &plan(),
            &reconciled_paths(true),
            &candidates(),
            &candidate_adjudication(),
            &model(),
            None,
        )
        .unwrap();
        assert_eq!(bundle.packets.len(), 1);
        assert_eq!(bundle.packets[0].0, "path-1");
    }

    #[test]
    fn skips_ineligible_paths() {
        let bundle = prepare_chain_adjudication_bundle(
            &plan(),
            &reconciled_paths(false),
            &candidates(),
            &candidate_adjudication(),
            &model(),
            None,
        )
        .unwrap();
        assert!(bundle.packets.is_empty());
    }

    fn proven_raw_verdict() -> Value {
        json!({
            "pathId": "path-1",
            "contextId": null,
            "verdict": "PROVEN",
            "evidenceStrength": "verified",
            "severity": "critical",
            "terminalImpact": "remote code execution",
            "proof": { "digest": "sha256:proof" },
            "negativeControl": { "rationale": "checked benign path" },
            "devilsAdvocate": "considered benign explanation and rejected it",
            "rationale": "chain fully verified",
            "stepAssessments": [{ "candidateId": "cand-1", "usableInChain": true }],
            "joinAssessments": [],
        })
    }

    #[test]
    fn finalize_reports_missing_verdict_for_unmatched_path() {
        let bundle = prepare_chain_adjudication_bundle(
            &plan(),
            &reconciled_paths(true),
            &candidates(),
            &candidate_adjudication(),
            &model(),
            None,
        )
        .unwrap();
        let result = finalize_chain_adjudication_bundle(&bundle, &json!({ "verdicts": [] }));
        assert_eq!(result["complete"], json!(false));
        assert_eq!(result["missingVerdicts"], json!(["path-1"]));
    }

    #[test]
    fn finalize_round_trips_a_matched_verdict_with_correct_context() {
        let bundle = prepare_chain_adjudication_bundle(
            &plan(),
            &reconciled_paths(true),
            &candidates(),
            &candidate_adjudication(),
            &model(),
            None,
        )
        .unwrap();
        let context_id = bundle.packets[0].1 .0["adjudicator"]["contextId"].clone();
        let mut raw = proven_raw_verdict();
        raw["contextId"] = context_id;
        let result = finalize_chain_adjudication_bundle(&bundle, &json!({ "verdicts": [raw] }));
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["verdicts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn finalize_rejects_duplicate_path_verdicts() {
        let bundle = prepare_chain_adjudication_bundle(
            &plan(),
            &reconciled_paths(true),
            &candidates(),
            &candidate_adjudication(),
            &model(),
            None,
        )
        .unwrap();
        let context_id = bundle.packets[0].1 .0["adjudicator"]["contextId"].clone();
        let mut raw_a = proven_raw_verdict();
        raw_a["contextId"] = context_id.clone();
        let mut raw_b = proven_raw_verdict();
        raw_b["contextId"] = context_id;
        let result = finalize_chain_adjudication_bundle(&bundle, &json!({ "verdicts": [raw_a, raw_b] }));
        assert_eq!(result["complete"], json!(false));
        let invalid = result["invalidVerdicts"].as_array().unwrap();
        assert!(invalid.iter().any(|item| item["error"] == json!("duplicate path verdict")));
        // The duplicate suppresses finalization for that path entirely.
        assert!(result["verdicts"].as_array().unwrap().is_empty());
    }
}
