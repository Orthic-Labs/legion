//! Port of `tools/audit/security-pipeline.mjs`'s `prepareAdjudicationBundle`
//! / `finalizeAdjudicationBundle`. The per-candidate primitives these two
//! functions wrap (`createSecurityCandidate`, `createAdjudicationPacket`,
//! `finalizeSecurityVerdict`) are already ported at
//! [`crate::native_providers::reasoning::security_adjudication`]; this file
//! ports the bundle-level orchestration that JS layered on top of them:
//! fresh-context-per-candidate fan-out, duplicate/reused-context rejection,
//! and missing-variant-analysis detection for surviving verdicts.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::native_providers::p11d_quality::security_suite::derive_variant_queries;
use crate::native_providers::reasoning::security_adjudication::{
    create_adjudication_packet, create_security_candidate, finalize_security_verdict,
    EvidenceStrength, NewSecurityCandidate, SecurityAdjudicationPacket, SecurityVerdictInput,
    SecurityVerdictKind,
};

/// Dependency-free stand-in for JS `randomUUID()`. Uniqueness, not RFC 4122
/// compliance, is all the pipeline needs (context ids and generator ids are
/// only ever compared for equality).
pub(crate) fn random_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(now.as_nanos().to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(&digest[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityPipelineError {
    #[error(
        "one adjudicatorContextId may only be supplied for a single candidate; each candidate requires a fresh context"
    )]
    SingleContextForMultipleCandidates,
    #[error("candidate {0} must be adjudicated in a fresh context")]
    SameContext(String),
    #[error("adjudication contexts must be unique per candidate")]
    DuplicateContexts,
    #[error(transparent)]
    Adjudication(
        #[from]
        crate::native_providers::reasoning::security_adjudication::SecurityAdjudicationError,
    ),
}

/// Mirrors JS `normalizeCandidate(candidate, contextId)`.
fn normalize_candidate(
    raw: &Value,
    context_id: &str,
) -> Result<crate::native_providers::reasoning::security_adjudication::SecurityCandidate, SecurityPipelineError>
{
    let id = raw.get("id").and_then(Value::as_str).unwrap_or_default();
    let provider = raw.get("provider").and_then(Value::as_str).unwrap_or_default();
    let claim = raw.get("claim").and_then(Value::as_str).unwrap_or_default();
    let alleged_root_cause = raw
        .get("allegedRootCause")
        .and_then(Value::as_str)
        .or_else(|| raw.get("ruleId").and_then(Value::as_str))
        .map(String::from);
    let alleged_trigger = raw
        .get("allegedTrigger")
        .and_then(Value::as_str)
        .map(String::from);
    let alleged_impact = raw
        .get("allegedImpact")
        .and_then(Value::as_str)
        .or_else(|| raw.get("severityHint").and_then(Value::as_str))
        .map(String::from);
    let evidence = raw
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let generated_at = raw
        .get("generatedAt")
        .and_then(Value::as_str)
        .map(String::from);
    Ok(create_security_candidate(NewSecurityCandidate {
        id,
        provider,
        context_id,
        claim,
        alleged_root_cause,
        alleged_trigger,
        alleged_impact,
        evidence,
        generated_at,
    })?)
}

/// A prepared bundle, kept as the typed packets (for `finalize_adjudication_bundle`)
/// plus the JSON envelope JS callers would see (`schemaVersion`/`kind`/`generator`/
/// `adjudicator`/`packets`/`requiredVerdictCandidateIds`).
#[derive(Debug, Clone)]
pub struct AdjudicationBundle {
    pub envelope: Value,
    pub packets: Vec<SecurityAdjudicationPacket>,
    pub required_verdict_candidate_ids: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct PrepareAdjudicationOptions {
    pub generator_context_id: Option<String>,
    pub adjudicator_provider: Option<String>,
    pub adjudicator_context_id: Option<String>,
}

/// Port of `prepareAdjudicationBundle(candidateReport, options)`.
pub fn prepare_adjudication_bundle(
    candidate_report: &Value,
    options: &PrepareAdjudicationOptions,
) -> Result<AdjudicationBundle, SecurityPipelineError> {
    let generator_context_id = options
        .generator_context_id
        .clone()
        .unwrap_or_else(random_id);
    let adjudicator_provider = options
        .adjudicator_provider
        .clone()
        .unwrap_or_else(|| "security.adjudication".to_string());
    let raw_candidates: Vec<Value> = candidate_report
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if options.adjudicator_context_id.is_some() && raw_candidates.len() > 1 {
        return Err(SecurityPipelineError::SingleContextForMultipleCandidates);
    }

    let mut packets = Vec::with_capacity(raw_candidates.len());
    let mut contexts = Vec::with_capacity(raw_candidates.len());
    for raw in &raw_candidates {
        let candidate = normalize_candidate(raw, &generator_context_id)?;
        let context_id = options
            .adjudicator_context_id
            .clone()
            .unwrap_or_else(random_id);
        if context_id == generator_context_id {
            return Err(SecurityPipelineError::SameContext(candidate.id.clone()));
        }
        let packet = create_adjudication_packet(candidate, &adjudicator_provider, &context_id, None)?;
        contexts.push(json!({
            "candidateId": packet.candidate.id,
            "provider": packet.adjudicator.provider,
            "contextId": packet.adjudicator.context_id,
        }));
        packets.push(packet);
    }

    let unique_contexts: HashSet<&str> = packets
        .iter()
        .map(|packet| packet.adjudicator.context_id.as_str())
        .collect();
    if unique_contexts.len() != packets.len() {
        return Err(SecurityPipelineError::DuplicateContexts);
    }

    let mut required_verdict_candidate_ids: Vec<String> =
        packets.iter().map(|packet| packet.candidate.id.clone()).collect();
    required_verdict_candidate_ids.sort();

    let envelope = json!({
        "schemaVersion": 1,
        "kind": "security-adjudication-bundle",
        "generator": {
            "provider": candidate_report.get("provider").and_then(Value::as_str).unwrap_or("security.internal-suite"),
            "contextId": generator_context_id,
        },
        "adjudicator": {
            "provider": adjudicator_provider,
            "freshContextRequired": true,
            "contextStrategy": "one-context-per-candidate",
            "contexts": contexts,
        },
        "packets": packets.iter().map(|p| serde_json::to_value(p).unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "requiredVerdictCandidateIds": required_verdict_candidate_ids,
    });

    Ok(AdjudicationBundle {
        envelope,
        packets,
        required_verdict_candidate_ids,
    })
}

/// A single submitted raw verdict, as JS `submitted.verdicts[]` carries it.
fn parse_verdict_kind(raw: &str) -> Option<SecurityVerdictKind> {
    Some(match raw {
        "TRUE_POSITIVE" => SecurityVerdictKind::TruePositive,
        "LIKELY_TRUE_POSITIVE" => SecurityVerdictKind::LikelyTruePositive,
        "LIKELY_FALSE_POSITIVE" => SecurityVerdictKind::LikelyFalsePositive,
        "FALSE_POSITIVE" => SecurityVerdictKind::FalsePositive,
        "OUT_OF_SCOPE" => SecurityVerdictKind::OutOfScope,
        "HARDENING_GAP" => SecurityVerdictKind::HardeningGap,
        "MISUSE_HAZARD" => SecurityVerdictKind::MisuseHazard,
        _ => return None,
    })
}

fn parse_evidence_strength(raw: &Value) -> Option<EvidenceStrength> {
    match raw.as_str()? {
        "possible" => Some(EvidenceStrength::Possible),
        "observed" => Some(EvidenceStrength::Observed),
        "verified" => Some(EvidenceStrength::Verified),
        _ => None,
    }
}

fn verdict_input_from_value(raw: &Value) -> SecurityVerdictInput {
    SecurityVerdictInput {
        verdict: raw
            .get("verdict")
            .and_then(Value::as_str)
            .and_then(parse_verdict_kind)
            // finalize_security_verdict will reject an unsupported kind; default to a
            // non-surviving sentinel so an unrecognized string still round-trips as an
            // "unsupported verdict" error via the typed check below rather than panicking.
            .unwrap_or(SecurityVerdictKind::OutOfScope),
        evidence_strength: raw.get("evidenceStrength").and_then(parse_evidence_strength),
        severity: raw.get("severity").and_then(Value::as_str).map(String::from),
        exploitability: raw.get("exploitability").and_then(Value::as_str).map(String::from),
        threat_model: raw.get("threatModel").and_then(Value::as_str).map(String::from),
        attacker_control: raw.get("attackerControl").and_then(Value::as_str).map(String::from),
        reachability: raw.get("reachability").and_then(Value::as_str).map(String::from),
        trust_boundaries: raw
            .get("trustBoundaries")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        sink: raw.get("sink").and_then(Value::as_str).map(String::from),
        primary_controls: raw
            .get("primaryControls")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        mitigations: raw
            .get("mitigations")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        proof: raw.get("proof").and_then(Value::as_str).map(String::from),
        impact: raw.get("impact").and_then(Value::as_str).map(String::from),
        rationale: raw.get("rationale").and_then(Value::as_str).map(String::from),
        devils_advocate: raw.get("devilsAdvocate").and_then(Value::as_str).map(String::from),
    }
}

/// Port of `finalizeAdjudicationBundle(bundle, submitted, variantReceipts)`.
///
/// Note: unlike JS's exception-swallowing `try { finalizeSecurityVerdict… }
/// catch { invalidVerdicts.push(...) }`, a raw `verdict` string this module
/// does not recognize is surfaced as an `UnsupportedVerdict` error from
/// `finalize_security_verdict` itself (via a harmless `OutOfScope`
/// placeholder plus a string re-check), landing in `invalidVerdicts` exactly
/// as JS's catch block would.
pub fn finalize_adjudication_bundle(
    bundle: &AdjudicationBundle,
    submitted: &Value,
    variant_receipts: &[Value],
) -> Value {
    let submitted_by_id: HashMap<String, Value> = submitted
        .get("verdicts")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.get("candidateId")
                        .and_then(Value::as_str)
                        .map(|id| (id.to_string(), v.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    let receipts_by_finding: HashMap<String, Value> = variant_receipts
        .iter()
        .filter_map(|receipt| {
            receipt
                .get("findingId")
                .and_then(Value::as_str)
                .map(|id| (id.to_string(), receipt.clone()))
        })
        .collect();

    let mut verdicts: Vec<Value> = Vec::new();
    let mut missing_verdicts: Vec<String> = Vec::new();
    let mut invalid_verdicts: Vec<Value> = Vec::new();
    let mut missing_variant_analysis: Vec<Value> = Vec::new();
    let mut context_ids: HashSet<String> = HashSet::new();

    for packet in &bundle.packets {
        let candidate_id = packet.candidate.id.clone();
        if context_ids.contains(&packet.adjudicator.context_id) {
            invalid_verdicts.push(json!({
                "candidateId": candidate_id,
                "error": "adjudicator context was reused across candidates",
            }));
            continue;
        }
        context_ids.insert(packet.adjudicator.context_id.clone());

        let Some(raw) = submitted_by_id.get(&candidate_id) else {
            missing_verdicts.push(candidate_id);
            continue;
        };

        let raw_verdict_str = raw.get("verdict").and_then(Value::as_str).unwrap_or("");
        if parse_verdict_kind(raw_verdict_str).is_none() {
            invalid_verdicts.push(json!({
                "candidateId": candidate_id,
                "error": format!("unsupported security verdict {raw_verdict_str:?}"),
            }));
            continue;
        }

        let input = verdict_input_from_value(raw);
        match finalize_security_verdict(packet, input) {
            Ok(verdict) => {
                let surviving = verdict.verdict.is_surviving();
                let verdict_value = serde_json::to_value(&verdict).unwrap_or(Value::Null);
                if surviving {
                    let receipt = receipts_by_finding.get(&verdict.candidate_id);
                    let receipt_complete = receipt
                        .and_then(|r| r.get("complete"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let receipt_rule_id = receipt.and_then(|r| r.get("ruleId")).and_then(Value::as_str);
                    let candidate_root_cause = packet.candidate.alleged_root_cause.as_deref();
                    if !receipt_complete || receipt_rule_id != candidate_root_cause {
                        let finding_value = json!({
                            "id": verdict.candidate_id,
                            "ruleId": packet.candidate.alleged_root_cause,
                            "evidence": packet.candidate.evidence,
                        });
                        let required_plan = derive_variant_queries(&finding_value)
                            .unwrap_or_else(|error| json!({ "error": error }));
                        missing_variant_analysis.push(json!({
                            "candidateId": verdict.candidate_id,
                            "requiredPlan": required_plan,
                        }));
                    }
                }
                verdicts.push(verdict_value);
            }
            Err(error) => {
                invalid_verdicts.push(json!({
                    "candidateId": candidate_id,
                    "error": error.to_string(),
                }));
            }
        }
    }

    let required: HashSet<&str> = bundle
        .required_verdict_candidate_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut unplanned_verdicts: Vec<String> = submitted_by_id
        .keys()
        .filter(|id| !required.contains(id.as_str()))
        .cloned()
        .collect();
    unplanned_verdicts.sort();

    let complete = missing_verdicts.is_empty()
        && invalid_verdicts.is_empty()
        && unplanned_verdicts.is_empty()
        && missing_variant_analysis.is_empty();
    let any_surviving = verdicts.iter().any(|v| {
        matches!(
            v.get("verdict").and_then(Value::as_str),
            Some("TRUE_POSITIVE") | Some("LIKELY_TRUE_POSITIVE")
        )
    });
    let status = if !complete {
        "unproven"
    } else if any_surviving {
        "findings"
    } else {
        "pass"
    };

    json!({
        "schemaVersion": 1,
        "kind": "security-adjudication-result",
        "complete": complete,
        "status": status,
        "verdicts": verdicts,
        "missingVerdicts": missing_verdicts,
        "invalidVerdicts": invalid_verdicts,
        "unplannedVerdicts": unplanned_verdicts,
        "missingVariantAnalysis": missing_variant_analysis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_report() -> Value {
        json!({
            "provider": "security.internal-suite",
            "candidates": [
                {
                    "id": "cand-1",
                    "provider": "reasoning.security",
                    "claim": "possible SQL injection",
                    "ruleId": "sql.injection",
                    "evidence": [{"path": "src/x.rs", "line": 10}],
                    "generatedAt": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "cand-2",
                    "provider": "reasoning.security",
                    "claim": "possible XSS",
                    "ruleId": "xss.reflected",
                    "evidence": [{"path": "src/y.rs", "line": 20}],
                    "generatedAt": "2026-01-01T00:00:00Z",
                },
            ],
        })
    }

    #[test]
    fn prepares_one_fresh_context_per_candidate() {
        let bundle = prepare_adjudication_bundle(&candidate_report(), &PrepareAdjudicationOptions::default())
            .unwrap();
        assert_eq!(bundle.packets.len(), 2);
        assert_eq!(bundle.required_verdict_candidate_ids, vec!["cand-1", "cand-2"]);
        let contexts: HashSet<&str> = bundle
            .packets
            .iter()
            .map(|p| p.adjudicator.context_id.as_str())
            .collect();
        assert_eq!(contexts.len(), 2);
    }

    #[test]
    fn single_shared_context_rejected_for_multiple_candidates() {
        let options = PrepareAdjudicationOptions {
            adjudicator_context_id: Some("ctx-shared".into()),
            ..Default::default()
        };
        let error = prepare_adjudication_bundle(&candidate_report(), &options).unwrap_err();
        assert!(matches!(
            error,
            SecurityPipelineError::SingleContextForMultipleCandidates
        ));
    }

    fn surviving_verdict_json(candidate_id: &str) -> Value {
        json!({
            "candidateId": candidate_id,
            "verdict": "TRUE_POSITIVE",
            "evidenceStrength": "observed",
            "severity": "high",
            "threatModel": "remote unauthenticated attacker",
            "attackerControl": "full",
            "reachability": "reachable from public endpoint",
            "proof": "reproduced with curl PoC",
            "impact": "data exfiltration",
            "devilsAdvocate": "checked for parameterization; none found",
        })
    }

    #[test]
    fn finalize_reports_missing_variant_analysis_for_surviving_verdict() {
        let bundle = prepare_adjudication_bundle(&candidate_report(), &PrepareAdjudicationOptions::default())
            .unwrap();
        let submitted = json!({ "verdicts": [surviving_verdict_json("cand-1")] });
        let result = finalize_adjudication_bundle(&bundle, &submitted, &[]);
        assert_eq!(result["complete"], json!(false));
        assert_eq!(result["missingVerdicts"], json!(["cand-2"]));
        assert_eq!(result["missingVariantAnalysis"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["missingVariantAnalysis"][0]["candidateId"],
            json!("cand-1")
        );
    }

    #[test]
    fn finalize_is_complete_when_variant_receipt_matches() {
        let bundle = prepare_adjudication_bundle(&candidate_report(), &PrepareAdjudicationOptions::default())
            .unwrap();
        let submitted = json!({
            "verdicts": [
                surviving_verdict_json("cand-1"),
                {
                    "candidateId": "cand-2",
                    "verdict": "FALSE_POSITIVE",
                    "threatModel": "n/a",
                    "reachability": "unreachable",
                    "impact": "none",
                },
            ],
        });
        let receipts = vec![json!({
            "findingId": "cand-1",
            "complete": true,
            "ruleId": "sql.injection",
        })];
        let result = finalize_adjudication_bundle(&bundle, &submitted, &receipts);
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["status"], json!("findings"));
        assert!(result["missingVariantAnalysis"].as_array().unwrap().is_empty());
    }

    #[test]
    fn finalize_rejects_reused_adjudicator_context() {
        let bundle = prepare_adjudication_bundle(&candidate_report(), &PrepareAdjudicationOptions::default())
            .unwrap();
        let mut bundle = bundle;
        // Force a reused context to exercise the duplicate-context branch,
        // mirroring the JS `contextIds.has(...)` guard.
        let shared = bundle.packets[0].adjudicator.context_id.clone();
        bundle.packets[1].adjudicator.context_id = shared;
        let submitted = json!({
            "verdicts": [surviving_verdict_json("cand-1"), surviving_verdict_json("cand-2")],
        });
        let result = finalize_adjudication_bundle(&bundle, &submitted, &[]);
        assert_eq!(result["complete"], json!(false));
        let invalid = result["invalidVerdicts"].as_array().unwrap();
        assert!(invalid
            .iter()
            .any(|item| item["error"] == json!("adjudicator context was reused across candidates")));
    }

    #[test]
    fn finalize_reports_unplanned_verdicts() {
        let bundle = prepare_adjudication_bundle(&candidate_report(), &PrepareAdjudicationOptions::default())
            .unwrap();
        let submitted = json!({
            "verdicts": [
                surviving_verdict_json("cand-1"),
                surviving_verdict_json("cand-2"),
                surviving_verdict_json("cand-does-not-exist"),
            ],
        });
        let result = finalize_adjudication_bundle(&bundle, &submitted, &[]);
        assert_eq!(result["unplannedVerdicts"], json!(["cand-does-not-exist"]));
        assert_eq!(result["complete"], json!(false));
    }
}
