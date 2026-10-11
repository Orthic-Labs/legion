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
//!
//! ## Isolation and content integrity
//!
//! Presence of a field is not an assessment. A batch of scanner candidates is
//! adjudicated as one work item per candidate ([`adjudication_work_items`]):
//! each item is its own packet, identified by a digest of the batch packet
//! digest and the candidate id, carrying only that candidate's evidence, and
//! bound to its own adjudicator context (`adjudicator:{itemId}`). A verdict
//! records the context it was reached in; one that shares a context with
//! another candidate, or equals the generator's context, is rejected. The
//! batch entry point only fans out to those per-candidate items.
//!
//! Verdict text must be meaningful ([`SecurityAdjudicationError`] variants
//! `EmptyField`, `PlaceholderContent`, `ThinContent`, `DuplicateContent`), and a
//! surviving verdict must reference the candidate's path or sink and cite an
//! evidence location inside the candidate's file.

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
    #[error("candidate {candidate}: `{field}` is empty")]
    EmptyField {
        candidate: String,
        field: &'static str,
    },
    #[error("candidate {candidate}: `{field}` is placeholder content ({text:?})")]
    PlaceholderContent {
        candidate: String,
        field: &'static str,
        text: String,
    },
    #[error("candidate {candidate}: `{field}` is too thin to be an assessment (needs at least 12 characters and 2 words)")]
    ThinContent {
        candidate: String,
        field: &'static str,
    },
    #[error("candidate {candidate}: `{field}` repeats candidate {other}'s text verbatim")]
    DuplicateContent {
        candidate: String,
        other: String,
        field: &'static str,
    },
    #[error("surviving verdict for {candidate} does not reference the candidate's path ({path}) or sink")]
    MissingCandidateReference { candidate: String, path: String },
    #[error("surviving verdict for {0} must cite at least one evidence location (file and line)")]
    MissingEvidenceCitation(String),
    #[error("surviving verdict for {candidate} cites no evidence inside the candidate's file {expected} (cited {cited})")]
    EvidenceOutsideCandidateFile {
        candidate: String,
        expected: String,
        cited: String,
    },
    #[error(
        "verdict for {candidate}: adjudicator context {context} is shared with candidate {other}"
    )]
    SharedContext {
        candidate: String,
        other: String,
        context: String,
    },
    #[error("verdict for {0}: adjudicator context equals the generator's context")]
    GeneratorContext(String),
    #[error("verdict for {candidate}: context {actual} is not the isolated context {expected} issued for this candidate")]
    UnexpectedContext {
        candidate: String,
        expected: String,
        actual: String,
    },
    #[error("verdict for {0}: the adjudicator context attestation (`contextId`) is required")]
    MissingContextAttestation(String),
    #[error("verdict {0}: `candidateId` is required")]
    MissingCandidateId(usize),
    #[error("verdict {index}: {id} is not a candidate in this packet")]
    UnknownCandidate { index: usize, id: String },
    #[error("verdict {index}: duplicate verdict for {id}")]
    DuplicateVerdict { index: usize, id: String },
    #[error("verdict for {id}: {reason}")]
    MalformedVerdict { id: String, reason: String },
    #[error("candidate {id}: {reason}")]
    CandidateSetup { id: String, reason: String },
    #[error("every scanner candidate needs exactly one verdict; missing: {0}")]
    MissingVerdicts(String),
    #[error("verdict for {id}: {source}")]
    Verdict {
        id: String,
        source: Box<SecurityAdjudicationError>,
    },
}

/// Shortest verdict text that can be an assessment rather than a stub.
pub const MIN_CONTENT_CHARS: usize = 12;
/// Fewest words in such a text.
pub const MIN_CONTENT_WORDS: usize = 2;

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
    /// Evidence locations the adjudicator cited (`{file, line}`); a surviving
    /// verdict from the batch path always carries at least one in the
    /// candidate's file.
    #[serde(default)]
    pub cited_evidence: Vec<Value>,
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
    finalize_with_evidence(packet, result, Vec::new())
}

fn non_blank(text: &Option<String>) -> bool {
    text.as_deref().is_some_and(|text| !text.trim().is_empty())
}

fn finalize_with_evidence(
    packet: &SecurityAdjudicationPacket,
    result: SecurityVerdictInput,
    cited_evidence: Vec<Value>,
) -> Result<SecurityVerdict, SecurityAdjudicationError> {
    if !verify_adjudication_packet(packet) {
        return Err(SecurityAdjudicationError::InvalidPacket);
    }
    // A blank string is no more an assessment than an absent one.
    if !non_blank(&result.threat_model)
        || !non_blank(&result.reachability)
        || !non_blank(&result.impact)
    {
        return Err(SecurityAdjudicationError::IncompleteVerdict);
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
    if surviving && !non_blank(&result.severity) {
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
        if !non_blank(&result.proof) {
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
        if !non_blank(&result.devils_advocate) {
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
        cited_evidence,
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
    // Candidate generators may not emit findings (`validate_result`); the
    // native scanners carry theirs in `details.candidates` instead.
    let raised = result
        .details
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|candidate| {
            let id = candidate.get("id").and_then(Value::as_str)?;
            let evidence = candidate
                .get("evidence")
                .and_then(Value::as_array)
                .and_then(|items| items.first());
            let path = evidence
                .and_then(|item| item.get("file"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let line = evidence
                .and_then(|item| item.get("line"))
                .and_then(Value::as_u64);
            // A generator that already stored a redacted excerpt (the heuristic
            // security packs) is trusted over re-reading the source line, so a
            // matched secret is never copied into the adjudication packet.
            let evidence_excerpt = candidate
                .get("redactedExcerpt")
                .and_then(Value::as_str)
                .filter(|excerpt| !excerpt.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    path.as_deref()
                        .zip(line)
                        .and_then(|(path, line)| excerpt_line(root, path, line))
                });
            Some(ScannerCandidate {
                finding_id: id.to_owned(),
                provider: provider.to_owned(),
                rule: candidate
                    .get("ruleId")
                    .and_then(Value::as_str)
                    .unwrap_or(provider)
                    .to_owned(),
                severity: candidate
                    .get("severityHint")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                path,
                line,
                message: candidate
                    .get("claim")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                evidence_excerpt,
            })
        });
    candidates.extend(raised);
    candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    candidates.dedup_by(|left, right| left.finding_id == right.finding_id);
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

/// The generator-side context a scanner candidate was raised in.
fn generator_context_id(candidate: &ScannerCandidate) -> String {
    format!("scanner:{}", candidate.provider)
}

/// The isolated adjudicator context issued for one candidate of a batch: a
/// digest of the batch packet digest and the candidate id. Distinct for every
/// candidate, deterministic for a given batch, and never the generator's.
pub fn adjudication_item_id(
    packet_digest: &str,
    candidate_id: &str,
) -> Result<String, SecurityAdjudicationError> {
    canonical_digest(&json!({
        "kind": "security-adjudication-item",
        "packetDigest": packet_digest,
        "candidateId": candidate_id,
    }))
    .map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))
}

/// The adjudicator context id issued for `candidate_id` in the batch.
pub fn adjudication_context_id(
    packet_digest: &str,
    candidate_id: &str,
) -> Result<String, SecurityAdjudicationError> {
    Ok(format!(
        "adjudicator:{}",
        adjudication_item_id(packet_digest, candidate_id)?
    ))
}

/// One candidate's isolated adjudication work item: its own packet, holding
/// only that candidate's evidence, bound to its own adjudicator context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateAdjudicationItem {
    /// `sha256` of (batch packet digest, candidate id).
    pub item_id: String,
    /// The fresh context the verdict for this candidate must be reached in.
    pub context_id: String,
    pub packet: SecurityAdjudicationPacket,
}

fn build_item(
    candidate: &ScannerCandidate,
    packet_digest: &str,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    let id = candidate.finding_id.as_str();
    let setup = |error: SecurityAdjudicationError| SecurityAdjudicationError::CandidateSetup {
        id: id.to_owned(),
        reason: error.to_string(),
    };
    let item_id = adjudication_item_id(packet_digest, id)?;
    let context_id = format!("adjudicator:{item_id}");
    let claim = if candidate.message.trim().is_empty() {
        candidate.rule.clone()
    } else {
        format!("{}: {}", candidate.rule, candidate.message)
    };
    let stamp = format!("frozen:{packet_digest}");
    let security_candidate = create_security_candidate(NewSecurityCandidate {
        id,
        provider: &candidate.provider,
        context_id: &generator_context_id(candidate),
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
    .map_err(setup)?;
    let packet = create_adjudication_packet(
        security_candidate,
        ADJUDICATOR_PROVIDER_ID,
        &context_id,
        Some(stamp),
    )
    .map_err(setup)?;
    Ok(CandidateAdjudicationItem {
        item_id,
        context_id,
        packet,
    })
}

/// Fans a batch out into one isolated work item per candidate, in candidate
/// order. A host runs each item in its own fresh adjudicator context.
pub fn adjudication_work_items(
    candidates: &[ScannerCandidate],
    packet_digest: &str,
) -> Result<Vec<CandidateAdjudicationItem>, SecurityAdjudicationError> {
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();
    for candidate in candidates {
        if seen.insert(candidate.finding_id.as_str()) {
            items.push(build_item(candidate, packet_digest)?);
        }
    }
    Ok(items)
}

/// How a verdict's adjudicator context is established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextPolicy {
    /// The context is the one issued for the candidate; a verdict that names a
    /// different one (`contextId`) is rejected. A verdict that names none is
    /// accepted, which proves nothing about how it was reached: use only where
    /// the host cannot yet attest.
    Derived,
    /// Every verdict must name the context it was reached in, and it must be
    /// the one issued for its candidate.
    Attested,
}

/// A location a verdict cites as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Citation {
    file: String,
    line: u64,
}

fn normalize_cited_path(path: &str) -> String {
    let path = path.trim().replace('\\', "/");
    path.strip_prefix("./").unwrap_or(&path).to_owned()
}

fn parse_citations(value: &Value) -> Vec<Citation> {
    value
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| match item {
            Value::String(location) => {
                let (file, line) = parse_location(location);
                Some(Citation {
                    file: normalize_cited_path(&file),
                    line: line.filter(|line| *line > 0)?,
                })
            }
            Value::Object(_) => {
                let file = item
                    .get("file")
                    .or_else(|| item.get("path"))
                    .and_then(Value::as_str)?;
                let line = item
                    .get("line")
                    .and_then(Value::as_u64)
                    .filter(|l| *l > 0)?;
                Some(Citation {
                    file: normalize_cited_path(file),
                    line,
                })
            }
            _ => None,
        })
        .filter(|citation| !citation.file.is_empty())
        .collect()
}

/// Lowercased alphanumerics only: the comparison form for placeholder and
/// verbatim-duplicate checks.
fn normal_form(text: &str) -> String {
    text.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

const PLACEHOLDER_TEXTS: &[&str] = &[
    "none",
    "na",
    "nil",
    "null",
    "undefined",
    "unknown",
    "tbd",
    "todo",
    "wip",
    "placeholder",
    "notapplicable",
    "yes",
    "no",
    "ok",
    "true",
    "false",
    "same",
    "seeabove",
    "asabove",
    "default",
    "test",
    "example",
    "sample",
    "string",
    "text",
    "lorem",
    "loremipsum",
];

/// Rejects empty, field-name, stock-placeholder (and, unless `short_ok`, thin)
/// text. Returns the comparison form on success.
fn check_text(
    candidate: &str,
    field: &'static str,
    text: &str,
    short_ok: bool,
) -> Result<String, SecurityAdjudicationError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(SecurityAdjudicationError::EmptyField {
            candidate: candidate.to_owned(),
            field,
        });
    }
    let form = normal_form(trimmed);
    if form.is_empty() || form == normal_form(field) || PLACEHOLDER_TEXTS.contains(&form.as_str()) {
        return Err(SecurityAdjudicationError::PlaceholderContent {
            candidate: candidate.to_owned(),
            field,
            text: trimmed.chars().take(40).collect(),
        });
    }
    if !short_ok
        && (trimmed.chars().count() < MIN_CONTENT_CHARS
            || trimmed.split_whitespace().count() < MIN_CONTENT_WORDS)
    {
        return Err(SecurityAdjudicationError::ThinContent {
            candidate: candidate.to_owned(),
            field,
        });
    }
    Ok(form)
}

/// The text fields of a verdict that must be meaningful, with whether they
/// are mandatory for this verdict kind. `attackerControl` is an assessment
/// level ("full", "partial") and so is exempt from the length floor.
fn content_fields<'a>(
    input: &'a SecurityVerdictInput,
    surviving: bool,
) -> Vec<(&'static str, Option<&'a str>, bool, bool)> {
    // (field, text, mandatory, short_ok)
    vec![
        ("threatModel", input.threat_model.as_deref(), true, false),
        ("reachability", input.reachability.as_deref(), true, false),
        ("impact", input.impact.as_deref(), true, false),
        ("proof", input.proof.as_deref(), surviving, false),
        (
            "devilsAdvocate",
            input.devils_advocate.as_deref(),
            surviving,
            false,
        ),
        (
            "attackerControl",
            if surviving {
                input.attacker_control.as_deref()
            } else {
                None
            },
            surviving,
            true,
        ),
        ("rationale", input.rationale.as_deref(), false, false),
    ]
}

/// Content validation that does not depend on the rest of the batch. Returns
/// the comparison forms of the verbatim-comparable fields.
fn validate_content(
    candidate: &ScannerCandidate,
    input: &SecurityVerdictInput,
    citations: &[Citation],
) -> Result<Vec<(&'static str, String)>, SecurityAdjudicationError> {
    let id = candidate.finding_id.as_str();
    let surviving = input.verdict.is_surviving();
    let mut forms = Vec::new();
    for (field, text, mandatory, short_ok) in content_fields(input, surviving) {
        match text {
            Some(text) => {
                let form = check_text(id, field, text, short_ok)?;
                if !short_ok {
                    forms.push((field, form));
                }
            }
            None if mandatory => {
                return Err(SecurityAdjudicationError::EmptyField {
                    candidate: id.to_owned(),
                    field,
                })
            }
            None => {}
        }
    }
    if !surviving {
        return Ok(forms);
    }
    let Some(path) = candidate.path.as_deref().map(normalize_cited_path) else {
        // Nothing to anchor a surviving verdict to.
        return Err(SecurityAdjudicationError::MissingCandidateReference {
            candidate: id.to_owned(),
            path: "<none>".to_owned(),
        });
    };
    // The verdict must talk about this candidate: its path or file name, or a
    // sink that actually appears on the anchored line.
    let discussion = [
        input.threat_model.as_deref(),
        input.reachability.as_deref(),
        input.proof.as_deref(),
        input.rationale.as_deref(),
        input.sink.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(input.trust_boundaries.iter().map(String::as_str))
    .chain(input.primary_controls.iter().map(String::as_str))
    .collect::<Vec<_>>()
    .join("\n")
    .to_lowercase();
    let lower_path = path.to_lowercase();
    let file_name = lower_path.rsplit('/').next().unwrap_or(&lower_path);
    let names_path = discussion.contains(&lower_path)
        || (!file_name.is_empty() && discussion.contains(file_name));
    let names_sink = input
        .sink
        .as_deref()
        .map(|sink| sink.trim().to_lowercase())
        .filter(|sink| sink.chars().count() >= 3)
        .is_some_and(|sink| {
            [
                candidate.evidence_excerpt.as_deref(),
                Some(candidate.message.as_str()),
            ]
            .into_iter()
            .flatten()
            .any(|anchored| anchored.to_lowercase().contains(&sink))
        });
    if !names_path && !names_sink {
        return Err(SecurityAdjudicationError::MissingCandidateReference {
            candidate: id.to_owned(),
            path,
        });
    }
    if citations.is_empty() {
        return Err(SecurityAdjudicationError::MissingEvidenceCitation(
            id.to_owned(),
        ));
    }
    if !citations.iter().any(|citation| citation.file == path) {
        return Err(SecurityAdjudicationError::EvidenceOutsideCandidateFile {
            candidate: id.to_owned(),
            expected: path,
            cited: citations
                .iter()
                .map(|citation| format!("{}:{}", citation.file, citation.line))
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    Ok(forms)
}

fn wrap(id: &str, error: SecurityAdjudicationError) -> SecurityAdjudicationError {
    SecurityAdjudicationError::Verdict {
        id: id.to_owned(),
        source: Box::new(error),
    }
}

/// Closes every scanner candidate with exactly one verdict, each reached in
/// the candidate's own isolated context.
///
/// * Unknown, duplicate and missing candidate ids are rejected.
/// * Each candidate is finalized against its own packet
///   ([`adjudication_work_items`]) holding only its evidence.
/// * A verdict that names a context (`contextId`) must name the one issued
///   for its candidate; one shared with another candidate, or equal to the
///   generator's, is rejected. With [`ContextPolicy::Attested`] naming it is
///   mandatory.
/// * Verdict text must be meaningful and not copied between candidates; a
///   surviving verdict must reference the candidate's path or sink and cite
///   an evidence location in the candidate's file (`evidence`: `[{file,line}]`).
///
/// `verdicts` items are `SecurityVerdictInput` objects plus `candidateId`,
/// optional `contextId` and `evidence`.
pub fn adjudicate_scanner_candidates_isolated(
    candidates: &[ScannerCandidate],
    verdicts: &[Value],
    packet_digest: &str,
    policy: ContextPolicy,
) -> Result<Vec<SecurityVerdict>, SecurityAdjudicationError> {
    let mut by_id: BTreeMap<&str, &ScannerCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_id
            .entry(candidate.finding_id.as_str())
            .or_insert(candidate);
    }
    let items = adjudication_work_items(candidates, packet_digest)?
        .into_iter()
        .map(|item| (item.packet.candidate.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    // Which candidate each issued context belongs to, to name the other party
    // when a verdict claims a context that is not its own.
    let issued = items
        .iter()
        .map(|(id, item)| (item.context_id.clone(), id.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut closed: BTreeMap<String, SecurityVerdict> = BTreeMap::new();
    let mut claimed_contexts: BTreeMap<String, String> = BTreeMap::new();
    // normal form of a text -> (candidate that wrote it first)
    let mut seen_text: BTreeMap<String, String> = BTreeMap::new();
    for (index, value) in verdicts.iter().enumerate() {
        let id = value
            .get("candidateId")
            .and_then(Value::as_str)
            .ok_or(SecurityAdjudicationError::MissingCandidateId(index))?;
        let candidate =
            by_id
                .get(id)
                .copied()
                .ok_or_else(|| SecurityAdjudicationError::UnknownCandidate {
                    index,
                    id: id.to_owned(),
                })?;
        if closed.contains_key(id) {
            return Err(SecurityAdjudicationError::DuplicateVerdict {
                index,
                id: id.to_owned(),
            });
        }
        let item = &items[id];
        let input: SecurityVerdictInput =
            serde_json::from_value(value.clone()).map_err(|error| {
                SecurityAdjudicationError::MalformedVerdict {
                    id: id.to_owned(),
                    reason: error.to_string(),
                }
            })?;

        // Context isolation.
        let attested = value.get("contextId").and_then(Value::as_str);
        match attested {
            Some(context) => {
                if context == generator_context_id(candidate) {
                    return Err(SecurityAdjudicationError::GeneratorContext(id.to_owned()));
                }
                if let Some(other) = issued.get(context).filter(|other| other.as_str() != id) {
                    return Err(SecurityAdjudicationError::SharedContext {
                        candidate: id.to_owned(),
                        other: other.clone(),
                        context: context.to_owned(),
                    });
                }
                if let Some(other) = claimed_contexts.get(context) {
                    return Err(SecurityAdjudicationError::SharedContext {
                        candidate: id.to_owned(),
                        other: other.clone(),
                        context: context.to_owned(),
                    });
                }
                if context != item.context_id {
                    return Err(SecurityAdjudicationError::UnexpectedContext {
                        candidate: id.to_owned(),
                        expected: item.context_id.clone(),
                        actual: context.to_owned(),
                    });
                }
                claimed_contexts.insert(context.to_owned(), id.to_owned());
            }
            None if policy == ContextPolicy::Attested => {
                return Err(SecurityAdjudicationError::MissingContextAttestation(
                    id.to_owned(),
                ))
            }
            None => {}
        }

        // The evidentiary bar for the verdict kind, then meaningful content.
        let citations = parse_citations(value);
        let cited = citations
            .iter()
            .map(|citation| json!({"file": citation.file, "line": citation.line}))
            .collect::<Vec<_>>();
        let verdict = finalize_with_evidence(&item.packet, input.clone(), cited)
            .map_err(|error| wrap(id, error))?;
        let forms =
            validate_content(candidate, &input, &citations).map_err(|error| wrap(id, error))?;
        for (field, form) in forms {
            match seen_text.get(&form) {
                Some(other) if other != id => {
                    return Err(wrap(
                        id,
                        SecurityAdjudicationError::DuplicateContent {
                            candidate: id.to_owned(),
                            other: other.clone(),
                            field,
                        },
                    ))
                }
                Some(_) => {}
                None => {
                    seen_text.insert(form, id.to_owned());
                }
            }
        }
        closed.insert(id.to_owned(), verdict);
    }
    let missing = by_id
        .keys()
        .filter(|id| !closed.contains_key(**id))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(SecurityAdjudicationError::MissingVerdicts(
            missing.join(", "),
        ));
    }
    Ok(candidates
        .iter()
        .filter_map(|candidate| closed.remove(candidate.finding_id.as_str()))
        .collect())
}

/// Batch entry point kept for compatibility. It fans out to the per-candidate
/// contexts of [`adjudicate_scanner_candidates_isolated`] under
/// [`ContextPolicy::Derived`]: the isolation and content checks apply, but a
/// verdict that names no context is accepted. Hosts that can attest the
/// context each verdict was reached in should call the isolated entry point
/// with [`ContextPolicy::Attested`].
pub fn adjudicate_scanner_candidates(
    candidates: &[ScannerCandidate],
    verdicts: &[Value],
    packet_digest: &str,
) -> Result<Vec<SecurityVerdict>, String> {
    adjudicate_scanner_candidates_isolated(
        candidates,
        verdicts,
        packet_digest,
        ContextPolicy::Derived,
    )
    .map_err(|error| error.to_string())
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
        // Parallel tests share the process id; the counter keeps fixtures apart.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "legion-adjudication-candidates-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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
            "threatModel": "remote unauthenticated attacker supplying the query fragment",
            "attackerControl": "full",
            "reachability": "reachable from a public handler that calls run() in src/db.rs",
            "sink": "db.execute",
            "proof": "trace from the handler argument q to db.execute in src/db.rs line 2",
            "impact": "data exfiltration through the interpolated query",
            "devilsAdvocate": "no parameterization or allowlist found between q and the query text",
            "evidence": [{"file": "src/db.rs", "line": 2}]
        })
    }

    fn fp_verdict(id: &str) -> Value {
        json!({
            "candidateId": id,
            "verdict": "FALSE_POSITIVE",
            "threatModel": "documentation marker, not executable code",
            "reachability": "documentation only; nothing here reaches a runtime sink",
            "impact": "no security impact because the line is prose"
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
