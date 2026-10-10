//! Port of `src/adapters/security-adjudication.mjs`.
//!
//! Enforces the independence rule for the security lens: no generator may
//! close its own finding.  A candidate raised by provider P and context C
//! must be adjudicated by a different provider in a different context, and
//! a surviving verdict (`TRUE_POSITIVE` / `LIKELY_TRUE_POSITIVE`) must carry
//! the same evidentiary bar the JS adapter required: threat model,
//! reachability, impact, attacker control above `unproven`, proof, evidence
//! strength above `possible`, and a devil's-advocate false-positive
//! challenge.  Digests are computed the same way the rest of the reasoning
//! protocol computes them: canonical JSON over the object with the digest
//! field itself excluded.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use legion_contracts::{canonical_digest, ProviderResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The provider that adjudicates scanner candidates. It is never a candidate
/// generator, so adjudication is independent of generation by construction.
pub const ADJUDICATOR_PROVIDER_ID: &str = "legacy.security.adjudication";

/// Verdicts a security adjudication may reach. Mirrors the JS `VERDICTS` set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityVerdictKind {
    TruePositive,
    LikelyTruePositive,
    LikelyFalsePositive,
    FalsePositive,
    OutOfScope,
    HardeningGap,
    MisuseHazard,
}

impl SecurityVerdictKind {
    /// Verdicts that keep the finding alive and require variant analysis.
    pub fn is_surviving(self) -> bool {
        matches!(
            self,
            SecurityVerdictKind::TruePositive | SecurityVerdictKind::LikelyTruePositive
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceStrength {
    Possible,
    Observed,
    Verified,
}

impl EvidenceStrength {
    fn rank(self) -> u8 {
        match self {
            EvidenceStrength::Possible => 0,
            EvidenceStrength::Observed => 1,
            EvidenceStrength::Verified => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCandidate {
    pub schema_version: u32,
    pub kind: String,
    pub id: String,
    pub provider: String,
    pub context_id: String,
    pub claim: String,
    #[serde(default)]
    pub alleged_root_cause: Option<String>,
    #[serde(default)]
    pub alleged_trigger: Option<String>,
    #[serde(default)]
    pub alleged_impact: Option<String>,
    pub evidence: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityAdjudicationError {
    #[error("security candidate requires id, provider, contextId, and exact claim")]
    IncompleteCandidate,
    #[error("security candidate {0} requires evidence")]
    MissingEvidence(String),
    #[error("adjudication requires a security candidate")]
    NotACandidate,
    #[error("adjudication provider is required")]
    MissingAdjudicator,
    #[error("provider {0} may not adjudicate its own candidate {1}")]
    SelfAdjudication(String, String),
    #[error("candidate {0} must be adjudicated in a fresh context")]
    SameContext(String),
    #[error("invalid or self-adjudicated security packet")]
    InvalidPacket,
    #[error("unsupported security verdict {0:?}")]
    UnsupportedVerdict(String),
    #[error("security verdict requires threatModel, reachability, and impact")]
    IncompleteVerdict,
    #[error("surviving security verdict {0:?} requires severity")]
    MissingSeverity(SecurityVerdictKind),
    #[error("non-surviving security verdict {0:?} must not carry vulnerability severity")]
    UnexpectedSeverity(SecurityVerdictKind),
    #[error("surviving security verdict {0:?} requires attackerControl above unproven")]
    WeakAttackerControl(SecurityVerdictKind),
    #[error("surviving security verdict {0:?} requires proof (reproduction, trace, PoC, or mathematical proof)")]
    MissingProof(SecurityVerdictKind),
    #[error("surviving security verdict {0:?} requires evidenceStrength above possible")]
    WeakEvidenceStrength(SecurityVerdictKind),
    #[error("surviving security verdict {0:?} requires devilsAdvocate false-positive challenge")]
    MissingDevilsAdvocate(SecurityVerdictKind),
    #[error("digest computation failed: {0}")]
    Digest(String),
}

pub struct NewSecurityCandidate<'a> {
    pub id: &'a str,
    pub provider: &'a str,
    pub context_id: &'a str,
    pub claim: &'a str,
    pub alleged_root_cause: Option<String>,
    pub alleged_trigger: Option<String>,
    pub alleged_impact: Option<String>,
    pub evidence: Vec<Value>,
    pub generated_at: Option<String>,
}

pub fn create_security_candidate(
    input: NewSecurityCandidate<'_>,
) -> Result<SecurityCandidate, SecurityAdjudicationError> {
    if input.id.trim().is_empty()
        || input.provider.trim().is_empty()
        || input.context_id.trim().is_empty()
        || input.claim.trim().is_empty()
    {
        return Err(SecurityAdjudicationError::IncompleteCandidate);
    }
    if input.evidence.is_empty() {
        return Err(SecurityAdjudicationError::MissingEvidence(
            input.id.to_string(),
        ));
    }
    Ok(SecurityCandidate {
        schema_version: 1,
        kind: "security-candidate".into(),
        id: input.id.to_string(),
        provider: input.provider.to_string(),
        context_id: input.context_id.to_string(),
        claim: input.claim.to_string(),
        alleged_root_cause: input.alleged_root_cause,
        alleged_trigger: input.alleged_trigger,
        alleged_impact: input.alleged_impact,
        evidence: input.evidence,
        generated_at: input.generated_at.unwrap_or_else(|| chrono_now_rfc3339()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Adjudicator {
    pub provider: String,
    pub context_id: String,
    pub context_started_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAdjudicationPacket {
    pub schema_version: u32,
    pub kind: String,
    pub candidate: SecurityCandidate,
    pub adjudicator: Adjudicator,
    pub required_evidence: Vec<String>,
    pub packet_digest: String,
}

const REQUIRED_EVIDENCE: [&str; 9] = [
    "threat model and attacker capability",
    "attacker-controlled source",
    "trust-boundary trace",
    "validation and authorization between source and sink",
    "reachability",
    "primary controls and environmental mitigations",
    "real security impact",
    "reproduction, trace, PoC sketch, or mathematical proof",
    "devils-advocate false-positive challenge",
];

/// Bind a candidate to an independent adjudicator. Rejects self-adjudication
/// (same provider) and context reuse (same contextId) at construction time,
/// exactly as the JS adapter does — no generator may close its own finding.
pub fn create_adjudication_packet(
    candidate: SecurityCandidate,
    adjudicator_provider: &str,
    adjudicator_context_id: &str,
    context_started_at: Option<String>,
) -> Result<SecurityAdjudicationPacket, SecurityAdjudicationError> {
    if candidate.kind != "security-candidate" {
        return Err(SecurityAdjudicationError::NotACandidate);
    }
    if adjudicator_provider.trim().is_empty() {
        return Err(SecurityAdjudicationError::MissingAdjudicator);
    }
    if adjudicator_provider == candidate.provider {
        return Err(SecurityAdjudicationError::SelfAdjudication(
            adjudicator_provider.to_string(),
            candidate.id.clone(),
        ));
    }
    if adjudicator_context_id == candidate.context_id {
        return Err(SecurityAdjudicationError::SameContext(candidate.id.clone()));
    }
    let adjudicator = Adjudicator {
        provider: adjudicator_provider.to_string(),
        context_id: adjudicator_context_id.to_string(),
        context_started_at: context_started_at.unwrap_or_else(chrono_now_rfc3339),
    };
    let unsigned = SecurityAdjudicationPacket {
        schema_version: 1,
        kind: "security-adjudication-packet".into(),
        candidate,
        adjudicator,
        required_evidence: REQUIRED_EVIDENCE.iter().map(|s| s.to_string()).collect(),
        packet_digest: String::new(),
    };
    let digest = canonical_digest(&unsigned)
        .map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))?;
    Ok(SecurityAdjudicationPacket {
        packet_digest: digest,
        ..unsigned
    })
}

/// Recompute the packet digest with `packetDigest` cleared, exactly the way
/// `verifyAdjudicationPacket` in the JS adapter does, then check independence.
pub fn verify_adjudication_packet(packet: &SecurityAdjudicationPacket) -> bool {
    if packet.kind != "security-adjudication-packet" {
        return false;
    }
    let unsigned = SecurityAdjudicationPacket {
        packet_digest: String::new(),
        ..packet.clone()
    };
    let recomputed = match canonical_digest(&unsigned) {
        Ok(digest) => digest,
        Err(_) => return false,
    };
    recomputed == packet.packet_digest
        && packet.candidate.provider != packet.adjudicator.provider
        && packet.candidate.context_id != packet.adjudicator.context_id
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityVerdictInput {
    pub verdict: SecurityVerdictKind,
    #[serde(default)]
    pub evidence_strength: Option<EvidenceStrength>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub exploitability: Option<String>,
    pub threat_model: Option<String>,
    #[serde(default)]
    pub attacker_control: Option<String>,
    pub reachability: Option<String>,
    #[serde(default)]
    pub trust_boundaries: Vec<String>,
    #[serde(default)]
    pub sink: Option<String>,
    #[serde(default)]
    pub primary_controls: Vec<String>,
    #[serde(default)]
    pub mitigations: Vec<String>,
    #[serde(default)]
    pub proof: Option<String>,
    pub impact: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub devils_advocate: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityVerdict {
    pub schema_version: u32,
    pub kind: String,
    pub candidate_id: String,
    pub candidate_provider: String,
    pub adjudicator_provider: String,
    pub adjudicator_context_id: String,
    pub evidence_strength: EvidenceStrength,
    pub verdict: SecurityVerdictKind,
    pub severity: Option<String>,
    pub exploitability: Option<String>,
    pub threat_model: String,
    pub attacker_control: String,
    pub reachability: String,
    pub trust_boundaries: Vec<String>,
    pub sink: Option<String>,
    pub primary_controls: Vec<String>,
    pub mitigations: Vec<String>,
    pub proof: Option<String>,
    pub impact: String,
    pub rationale: Option<String>,
    pub devils_advocate: Option<String>,
    pub variant_analysis_required: bool,
    pub verdict_digest: String,
}

/// Close a candidate. Requires an independently-verified packet
/// (`verify_adjudication_packet`) and enforces the same evidentiary bar the
/// JS `finalizeSecurityVerdict` enforced for a surviving verdict.
pub fn finalize_security_verdict(
    packet: &SecurityAdjudicationPacket,
    result: SecurityVerdictInput,
) -> Result<SecurityVerdict, SecurityAdjudicationError> {
    if !verify_adjudication_packet(packet) {
        return Err(SecurityAdjudicationError::InvalidPacket);
    }
    let threat_model = result
        .threat_model
        .clone()
        .ok_or(SecurityAdjudicationError::IncompleteVerdict)?;
    let reachability = result
        .reachability
        .clone()
        .ok_or(SecurityAdjudicationError::IncompleteVerdict)?;
    let impact = result
        .impact
        .clone()
        .ok_or(SecurityAdjudicationError::IncompleteVerdict)?;

    let surviving = result.verdict.is_surviving();
    if surviving && result.severity.is_none() {
        return Err(SecurityAdjudicationError::MissingSeverity(result.verdict));
    }
    if !surviving && result.severity.is_some() {
        return Err(SecurityAdjudicationError::UnexpectedSeverity(
            result.verdict,
        ));
    }
    let attacker_control = result
        .attacker_control
        .clone()
        .unwrap_or_else(|| "unproven".to_string());
    if surviving {
        if attacker_control.trim().is_empty() || attacker_control == "unproven" {
            return Err(SecurityAdjudicationError::WeakAttackerControl(
                result.verdict,
            ));
        }
        if result.proof.is_none() {
            return Err(SecurityAdjudicationError::MissingProof(result.verdict));
        }
        let strength = result
            .evidence_strength
            .unwrap_or(EvidenceStrength::Possible);
        if strength.rank() == 0 {
            return Err(SecurityAdjudicationError::WeakEvidenceStrength(
                result.verdict,
            ));
        }
        if result.devils_advocate.is_none() {
            return Err(SecurityAdjudicationError::MissingDevilsAdvocate(
                result.verdict,
            ));
        }
    }

    let unsigned = SecurityVerdict {
        schema_version: 1,
        kind: "security-verdict".into(),
        candidate_id: packet.candidate.id.clone(),
        candidate_provider: packet.candidate.provider.clone(),
        adjudicator_provider: packet.adjudicator.provider.clone(),
        adjudicator_context_id: packet.adjudicator.context_id.clone(),
        evidence_strength: result
            .evidence_strength
            .unwrap_or(EvidenceStrength::Possible),
        verdict: result.verdict,
        severity: result.severity,
        exploitability: result.exploitability,
        threat_model,
        attacker_control,
        reachability,
        trust_boundaries: result.trust_boundaries,
        sink: result.sink,
        primary_controls: result.primary_controls,
        mitigations: result.mitigations,
        proof: result.proof,
        impact,
        rationale: result.rationale,
        devils_advocate: result.devils_advocate,
        variant_analysis_required: surviving,
        verdict_digest: String::new(),
    };
    let digest = canonical_digest(&unsigned)
        .map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))?;
    Ok(SecurityVerdict {
        verdict_digest: digest,
        ..unsigned
    })
}

/// One scanner (candidate-generator) result carried into the adjudication
/// packet so a lens can reach a verdict per candidate instead of re-deriving
/// scanner output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerCandidate {
    pub finding_id: String,
    pub provider: String,
    pub rule: String,
    pub severity: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub line: Option<u64>,
    pub message: String,
    /// The anchored source line, bounded and redacted.
    #[serde(default)]
    pub evidence_excerpt: Option<String>,
}

/// Splits a `path:line` / `path:start-end` location.
fn parse_location(location: &str) -> (String, Option<u64>) {
    if let Some((path, range)) = location.rsplit_once(':') {
        let start = range.split_once('-').map_or(range, |(start, _)| start);
        if let Ok(line) = start.parse::<u64>() {
            return (path.to_owned(), Some(line));
        }
    }
    (location.to_owned(), None)
}

fn excerpt_line(root: &Path, path: &str, line: u64) -> Option<String> {
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let bytes = std::fs::read(root.join(relative)).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let index = usize::try_from(line.checked_sub(1)?).ok()?;
    let source = text.lines().nth(index)?;
    let (redacted, _) = super::excerpts::redact_secrets(source.trim());
    Some(redacted.chars().take(240).collect())
}

fn detail_entry<'a>(result: &'a ProviderResult, key: &str, id: &str) -> Option<&'a Value> {
    result.details.get(key)?.as_object()?.get(id)
}

/// Candidates a candidate-generator `result` raised, in finding-id order.
pub fn scanner_candidates(
    root: &Path,
    provider: &str,
    result: &ProviderResult,
) -> Vec<ScannerCandidate> {
    let mut candidates = result
        .findings
        .iter()
        .map(|finding| {
            let id = finding.id.as_str();
            let location = detail_entry(result, "findingLocations", id)
                .and_then(Value::as_array)
                .and_then(|locations| locations.iter().find_map(Value::as_str))
                .map(parse_location);
            let rule = detail_entry(result, "findingEvidence", id)
                .and_then(Value::as_object)
                .and_then(|evidence| {
                    ["ruleId", "rule", "checkId"]
                        .iter()
                        .find_map(|key| evidence.get(*key).and_then(Value::as_str))
                })
                .unwrap_or(provider)
                .to_owned();
            let message = ["findingMessages", "findingTitles"]
                .iter()
                .find_map(|key| detail_entry(result, key, id).and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned();
            let (path, line) = match location {
                Some((path, line)) => (Some(path), line),
                None => (None, None),
            };
            let evidence_excerpt = path
                .as_deref()
                .zip(line)
                .and_then(|(path, line)| excerpt_line(root, path, line));
            ScannerCandidate {
                finding_id: id.to_owned(),
                provider: provider.to_owned(),
                rule,
                severity: finding.severity.clone(),
                path,
                line,
                message,
                evidence_excerpt,
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    candidates
}

/// A confirmed (surviving) verdict reduced to what variant analysis needs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmedSecurityFinding {
    pub candidate_id: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub line: Option<u64>,
    pub verdict: SecurityVerdictKind,
    #[serde(default)]
    pub severity: Option<String>,
    pub verdict_digest: String,
}

/// Closes every scanner candidate with exactly one verdict from an
/// independent adjudicator: unknown, duplicate and missing candidate ids are
/// rejected, and each verdict must clear the evidentiary bar for its kind
/// (`finalize_security_verdict`). `verdicts` items are `SecurityVerdictInput`
/// objects plus `candidateId`.
pub fn adjudicate_scanner_candidates(
    candidates: &[ScannerCandidate],
    verdicts: &[Value],
    packet_digest: &str,
) -> Result<Vec<SecurityVerdict>, String> {
    let by_id = candidates
        .iter()
        .map(|candidate| (candidate.finding_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut closed = BTreeMap::new();
    for (index, value) in verdicts.iter().enumerate() {
        let id = value
            .get("candidateId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("verdict {index}: `candidateId` is required"))?;
        let candidate = by_id
            .get(id)
            .ok_or_else(|| format!("verdict {index}: {id} is not a candidate in this packet"))?;
        if closed.contains_key(id) {
            return Err(format!("verdict {index}: duplicate verdict for {id}"));
        }
        let input: SecurityVerdictInput = serde_json::from_value(value.clone())
            .map_err(|error| format!("verdict for {id}: {error}"))?;
        let claim = if candidate.message.trim().is_empty() {
            candidate.rule.clone()
        } else {
            format!("{}: {}", candidate.rule, candidate.message)
        };
        let stamp = format!("frozen:{packet_digest}");
        let security_candidate = create_security_candidate(NewSecurityCandidate {
            id,
            provider: &candidate.provider,
            context_id: &format!("scanner:{}", candidate.provider),
            claim: &claim,
            alleged_root_cause: None,
            alleged_trigger: None,
            alleged_impact: None,
            evidence: vec![json!({
                "findingId": id,
                "path": candidate.path,
                "line": candidate.line,
                "excerpt": candidate.evidence_excerpt,
            })],
            generated_at: Some(stamp.clone()),
        })
        .map_err(|error| format!("candidate {id}: {error}"))?;
        let packet = create_adjudication_packet(
            security_candidate,
            ADJUDICATOR_PROVIDER_ID,
            &format!("adjudicator:{packet_digest}"),
            Some(stamp),
        )
        .map_err(|error| format!("candidate {id}: {error}"))?;
        let verdict = finalize_security_verdict(&packet, input)
            .map_err(|error| format!("verdict for {id}: {error}"))?;
        closed.insert(id, verdict);
    }
    let missing = by_id
        .keys()
        .filter(|id| !closed.contains_key(*id))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "every scanner candidate needs exactly one verdict; missing: {}",
            missing.join(", ")
        ));
    }
    Ok(candidates
        .iter()
        .filter_map(|candidate| closed.remove(candidate.finding_id.as_str()))
        .collect())
}

/// The surviving (`TRUE_POSITIVE` / `LIKELY_TRUE_POSITIVE`) verdicts with the
/// scanner location they confirm.
pub fn confirmed_findings(
    candidates: &[ScannerCandidate],
    verdicts: &[SecurityVerdict],
) -> Vec<ConfirmedSecurityFinding> {
    verdicts
        .iter()
        .filter(|verdict| verdict.verdict.is_surviving())
        .map(|verdict| {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.finding_id == verdict.candidate_id);
            ConfirmedSecurityFinding {
                candidate_id: verdict.candidate_id.clone(),
                path: candidate.and_then(|candidate| candidate.path.clone()),
                line: candidate.and_then(|candidate| candidate.line),
                verdict: verdict.verdict,
                severity: verdict.severity.clone(),
                verdict_digest: verdict.verdict_digest.clone(),
            }
        })
        .collect()
}

/// Sorted, unique paths of confirmed findings: the input to the
/// `confirmedSecurityFinding` selector.
pub fn confirmed_paths(confirmed: &[ConfirmedSecurityFinding]) -> Vec<String> {
    confirmed
        .iter()
        .filter_map(|finding| finding.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn chrono_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Dependency-free RFC3339-ish timestamp (seconds resolution) so this
    // module needs no extra crate; callers that need calendar precision
    // should pass generated_at/context_started_at explicitly.
    format!("1970-01-01T00:00:00Z+{}s", now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Vec<Value> {
        vec![serde_json::json!({"path": "src/x.rs", "line": 10})]
    }

    fn candidate(provider: &str, context: &str) -> SecurityCandidate {
        create_security_candidate(NewSecurityCandidate {
            id: "cand-1",
            provider,
            context_id: context,
            claim: "possible SQL injection",
            alleged_root_cause: None,
            alleged_trigger: None,
            alleged_impact: None,
            evidence: evidence(),
            generated_at: Some("2026-01-01T00:00:00Z".into()),
        })
        .unwrap()
    }

    #[test]
    fn candidate_requires_evidence() {
        let error = create_security_candidate(NewSecurityCandidate {
            id: "cand-1",
            provider: "reasoning.security",
            context_id: "ctx-1",
            claim: "claim",
            alleged_root_cause: None,
            alleged_trigger: None,
            alleged_impact: None,
            evidence: Vec::new(),
            generated_at: None,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            SecurityAdjudicationError::MissingEvidence(_)
        ));
    }

    #[test]
    fn same_provider_cannot_adjudicate_its_own_candidate() {
        let c = candidate("reasoning.security", "ctx-1");
        let error = create_adjudication_packet(c, "reasoning.security", "ctx-2", None).unwrap_err();
        assert!(matches!(
            error,
            SecurityAdjudicationError::SelfAdjudication(_, _)
        ));
    }

    #[test]
    fn same_context_is_rejected_even_for_a_different_provider() {
        let c = candidate("reasoning.security", "ctx-1");
        let error = create_adjudication_packet(c, "legacy.security.adjudication", "ctx-1", None)
            .unwrap_err();
        assert!(matches!(error, SecurityAdjudicationError::SameContext(_)));
    }

    #[test]
    fn independent_packet_round_trips_and_verifies() {
        let c = candidate("reasoning.security", "ctx-1");
        let packet = create_adjudication_packet(
            c,
            "legacy.security.adjudication",
            "ctx-2",
            Some("2026-01-01T00:00:01Z".into()),
        )
        .unwrap();
        assert!(verify_adjudication_packet(&packet));
    }

    #[test]
    fn tampered_packet_fails_verification() {
        let c = candidate("reasoning.security", "ctx-1");
        let mut packet = create_adjudication_packet(
            c,
            "legacy.security.adjudication",
            "ctx-2",
            Some("2026-01-01T00:00:01Z".into()),
        )
        .unwrap();
        packet.candidate.claim = "tampered claim".into();
        assert!(!verify_adjudication_packet(&packet));
    }

    fn surviving_result() -> SecurityVerdictInput {
        SecurityVerdictInput {
            verdict: SecurityVerdictKind::TruePositive,
            evidence_strength: Some(EvidenceStrength::Observed),
            severity: Some("high".into()),
            exploitability: None,
            threat_model: Some("remote unauthenticated attacker".into()),
            attacker_control: Some("full".into()),
            reachability: Some("reachable from public endpoint".into()),
            trust_boundaries: vec!["network".into()],
            sink: Some("sql.execute".into()),
            primary_controls: Vec::new(),
            mitigations: Vec::new(),
            proof: Some("reproduced with curl PoC".into()),
            impact: Some("data exfiltration".into()),
            rationale: None,
            devils_advocate: Some("checked for parameterization; none found".into()),
        }
    }

    #[test]
    fn surviving_verdict_requires_full_evidentiary_bar() {
        let c = candidate("reasoning.security", "ctx-1");
        let packet = create_adjudication_packet(
            c,
            "legacy.security.adjudication",
            "ctx-2",
            Some("2026-01-01T00:00:01Z".into()),
        )
        .unwrap();

        let mut missing_proof = surviving_result();
        missing_proof.proof = None;
        assert!(matches!(
            finalize_security_verdict(&packet, missing_proof).unwrap_err(),
            SecurityAdjudicationError::MissingProof(_)
        ));

        let mut missing_devils_advocate = surviving_result();
        missing_devils_advocate.devils_advocate = None;
        assert!(matches!(
            finalize_security_verdict(&packet, missing_devils_advocate).unwrap_err(),
            SecurityAdjudicationError::MissingDevilsAdvocate(_)
        ));

        let mut weak_attacker_control = surviving_result();
        weak_attacker_control.attacker_control = Some("unproven".into());
        assert!(matches!(
            finalize_security_verdict(&packet, weak_attacker_control).unwrap_err(),
            SecurityAdjudicationError::WeakAttackerControl(_)
        ));

        let mut weak_strength = surviving_result();
        weak_strength.evidence_strength = Some(EvidenceStrength::Possible);
        assert!(matches!(
            finalize_security_verdict(&packet, weak_strength).unwrap_err(),
            SecurityAdjudicationError::WeakEvidenceStrength(_)
        ));

        let mut missing_severity = surviving_result();
        missing_severity.severity = None;
        assert!(matches!(
            finalize_security_verdict(&packet, missing_severity).unwrap_err(),
            SecurityAdjudicationError::MissingSeverity(_)
        ));

        let ok = finalize_security_verdict(&packet, surviving_result()).unwrap();
        assert!(ok.variant_analysis_required);
        assert_eq!(ok.candidate_provider, "reasoning.security");
        assert_eq!(ok.adjudicator_provider, "legacy.security.adjudication");
    }

    #[test]
    fn non_surviving_verdict_rejects_severity() {
        let c = candidate("reasoning.security", "ctx-1");
        let packet = create_adjudication_packet(
            c,
            "legacy.security.adjudication",
            "ctx-2",
            Some("2026-01-01T00:00:01Z".into()),
        )
        .unwrap();
        let mut result = surviving_result();
        result.verdict = SecurityVerdictKind::FalsePositive;
        // Non-surviving path does not require proof/devilsAdvocate, but
        // severity must be absent.
        assert!(matches!(
            finalize_security_verdict(&packet, result).unwrap_err(),
            SecurityAdjudicationError::UnexpectedSeverity(_)
        ));
    }

    #[test]
    fn tampered_packet_cannot_be_finalized() {
        let c = candidate("reasoning.security", "ctx-1");
        let mut packet = create_adjudication_packet(
            c,
            "legacy.security.adjudication",
            "ctx-2",
            Some("2026-01-01T00:00:01Z".into()),
        )
        .unwrap();
        packet.packet_digest = "sha256:deadbeef".into();
        assert!(matches!(
            finalize_security_verdict(&packet, surviving_result()).unwrap_err(),
            SecurityAdjudicationError::InvalidPacket
        ));
    }

    fn scanner_fixture() -> (std::path::PathBuf, ProviderResult) {
        use legion_contracts::{FindingId, FindingRef, ProviderId, ProviderStatus};
        let root = std::env::temp_dir().join(format!(
            "legion-adjudication-candidates-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/db.rs"),
            "fn run(q: &str) {\n    db.execute(&format!(\"select {q}\"));\n}\n",
        )
        .unwrap();
        let finding = |id: &str| FindingRef {
            id: FindingId::new(id).unwrap(),
            severity: "high".into(),
        };
        let result = ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("legacy.security.sast").unwrap(),
            applicable: true,
            required: false,
            status: ProviderStatus::Ok,
            complete: false,
            coverage: None,
            findings: vec![finding("cand-sql"), finding("cand-doc")],
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::from([
                (
                    "findingLocations".to_owned(),
                    json!({"cand-sql": ["src/db.rs:2"], "cand-doc": ["docs/x.md:1"]}),
                ),
                (
                    "findingMessages".to_owned(),
                    json!({"cand-sql": "query built by concatenation", "cand-doc": "doc note"}),
                ),
                (
                    "findingEvidence".to_owned(),
                    json!({"cand-sql": {"ruleId": "sql-concat"}}),
                ),
            ]),
        };
        (root, result)
    }

    fn tp_verdict(id: &str) -> Value {
        json!({
            "candidateId": id,
            "verdict": "TRUE_POSITIVE",
            "evidenceStrength": "observed",
            "severity": "high",
            "threatModel": "remote unauthenticated attacker",
            "attackerControl": "full",
            "reachability": "reachable from a public handler",
            "proof": "trace from handler to execute",
            "impact": "data exfiltration",
            "devilsAdvocate": "no parameterization found"
        })
    }

    fn fp_verdict(id: &str) -> Value {
        json!({
            "candidateId": id,
            "verdict": "FALSE_POSITIVE",
            "threatModel": "none",
            "reachability": "documentation only",
            "impact": "none"
        })
    }

    #[test]
    fn scanner_candidates_carry_rule_location_and_excerpt() {
        let (root, result) = scanner_fixture();
        let candidates = scanner_candidates(&root, "legacy.security.sast", &result);
        assert_eq!(candidates.len(), 2);
        let sql = candidates
            .iter()
            .find(|candidate| candidate.finding_id == "cand-sql")
            .unwrap();
        assert_eq!(sql.rule, "sql-concat");
        assert_eq!(sql.path.as_deref(), Some("src/db.rs"));
        assert_eq!(sql.line, Some(2));
        assert!(sql
            .evidence_excerpt
            .as_deref()
            .is_some_and(|excerpt| excerpt.contains("db.execute")));
        let doc = candidates
            .iter()
            .find(|candidate| candidate.finding_id == "cand-doc")
            .unwrap();
        // No rule id in the evidence: falls back to the generating provider.
        assert_eq!(doc.rule, "legacy.security.sast");
        assert_eq!(doc.evidence_excerpt, None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn candidate_to_verdict_to_variant_selection() {
        use crate::inventory::{InventoryEntry, InventoryEnvelope};
        let (root, result) = scanner_fixture();
        let candidates = scanner_candidates(&root, "legacy.security.sast", &result);

        // A candidate left without a verdict, or closed twice, is rejected.
        let missing =
            adjudicate_scanner_candidates(&candidates, &[tp_verdict("cand-sql")], "d").unwrap_err();
        assert!(missing.contains("missing: cand-doc"), "{missing}");
        let duplicate = adjudicate_scanner_candidates(
            &candidates,
            &[tp_verdict("cand-sql"), tp_verdict("cand-sql")],
            "d",
        )
        .unwrap_err();
        assert!(duplicate.contains("duplicate"), "{duplicate}");
        let unknown =
            adjudicate_scanner_candidates(&candidates, &[tp_verdict("nope")], "d").unwrap_err();
        assert!(unknown.contains("not a candidate"), "{unknown}");

        // A surviving verdict without proof does not clear the evidentiary bar.
        let mut unproven = tp_verdict("cand-sql");
        unproven.as_object_mut().unwrap().remove("proof");
        let weak =
            adjudicate_scanner_candidates(&candidates, &[unproven, fp_verdict("cand-doc")], "d")
                .unwrap_err();
        assert!(weak.contains("requires proof"), "{weak}");

        let verdicts = adjudicate_scanner_candidates(
            &candidates,
            &[tp_verdict("cand-sql"), fp_verdict("cand-doc")],
            "d",
        )
        .unwrap();
        assert_eq!(verdicts.len(), 2);
        let confirmed = confirmed_findings(&candidates, &verdicts);
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].candidate_id, "cand-sql");
        let paths = confirmed_paths(&confirmed);
        assert_eq!(paths, vec!["src/db.rs".to_owned()]);

        // The confirmed verdict, and only it, triggers variant analysis.
        let entry = |path: &str| InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        };
        let inventory = InventoryEnvelope::new(
            "repo",
            "generation",
            vec![entry("src/db.rs"), entry("src/other.rs")],
        )
        .unwrap();
        let selector = json!({"op": "confirmedSecurityFinding"});
        assert!(inventory
            .denominator_entries(&selector)
            .unwrap()
            .entries
            .is_empty());
        let selected = inventory
            .denominator_entries_with_security_context(&selector, &[], &paths)
            .unwrap();
        assert_eq!(selected.entries.len(), 1);
        assert_eq!(selected.entries[0].path, "src/db.rs");
        let _ = std::fs::remove_dir_all(root);
    }
}
