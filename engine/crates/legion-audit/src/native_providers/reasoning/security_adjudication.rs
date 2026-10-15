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
//! exposed as one work item per candidate ([`adjudication_work_items`]): each
//! child packet carries only that candidate's evidence and is bound to a
//! deterministic batch/candidate digest. Its `contextId` is a requested label,
//! not evidence that a host actually created a fresh context. Verdicts that
//! name a context are checked against the issued label; that check does not
//! attest context isolation. The batch entry point only fans out to those
//! per-candidate items.
//!
//! Verdict text must be meaningful ([`SecurityAdjudicationError`] variants
//! `EmptyField`, `PlaceholderContent`, `ThinContent`, `DuplicateContent`), and a
//! surviving verdict must reference the candidate's path or sink and cite an
//! evidence location inside the candidate's file.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use legion_contracts::{canonical_digest, canonical_json_bytes, ProviderResult};
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

    /// Verdicts that keep a candidate alive in any form: every one of them
    /// needs a second, single-candidate fresh-context confirmation before it
    /// counts (scaled adjudication, D1).
    pub fn needs_confirmation(self) -> bool {
        matches!(
            self,
            SecurityVerdictKind::TruePositive
                | SecurityVerdictKind::LikelyTruePositive
                | SecurityVerdictKind::HardeningGap
                | SecurityVerdictKind::MisuseHazard
        )
    }

    /// Verdicts that dismiss a candidate.
    pub fn is_dismissal(self) -> bool {
        matches!(
            self,
            SecurityVerdictKind::FalsePositive
                | SecurityVerdictKind::LikelyFalsePositive
                | SecurityVerdictKind::OutOfScope
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
    #[error(
        "surviving security verdict {0:?} requires proof (reproduction, trace, PoC, or mathematical proof)"
    )]
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
    #[error(
        "candidate {candidate}: `{field}` is too thin to be an assessment (needs at least 12 characters and 2 words)"
    )]
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
    #[error(
        "surviving verdict for {candidate} does not reference the candidate's path ({path}) or sink"
    )]
    MissingCandidateReference { candidate: String, path: String },
    #[error("surviving verdict for {0} must cite at least one evidence location (file and line)")]
    MissingEvidenceCitation(String),
    #[error(
        "surviving verdict for {candidate} cites no evidence inside the candidate's file {expected} (cited {cited})"
    )]
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
    #[error(
        "verdict for {candidate}: context {actual} is not the isolated context {expected} issued for this candidate"
    )]
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
    let required_evidence = domain_required_evidence(
        candidate
            .evidence
            .first()
            .and_then(|item| item.get("domain"))
            .and_then(Value::as_str)
            .filter(|domain| !domain.is_empty())
            .unwrap_or("security"),
    );
    let unsigned = SecurityAdjudicationPacket {
        schema_version: 1,
        kind: "security-adjudication-packet".into(),
        candidate,
        adjudicator,
        required_evidence,
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

/// Nonsecurity findings bind a concrete invariant & trigger to their domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateDomainProof {
    pub domain: String,
    pub invariant: String,
    pub trigger: String,
}

fn default_verdict_domain() -> String {
    "security".into()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityVerdict {
    #[serde(default = "default_verdict_domain")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_proof: Option<CandidateDomainProof>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub threat_model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
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
    /// The cluster this row was expanded from, when it was adjudicated through
    /// a cluster representative. Absent for single-candidate verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
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
    finalize_for_domain(packet, result, cited_evidence, None)
}

fn finalize_for_domain(
    packet: &SecurityAdjudicationPacket,
    result: SecurityVerdictInput,
    cited_evidence: Vec<Value>,
    domain_proof: Option<CandidateDomainProof>,
) -> Result<SecurityVerdict, SecurityAdjudicationError> {
    let domain = packet
        .candidate
        .evidence
        .first()
        .and_then(|item| item.get("domain"))
        .and_then(Value::as_str)
        .filter(|domain| !domain.is_empty())
        .unwrap_or("security");
    if !matches!(domain, "security" | "data" | "reliability" | "release") {
        return Err(SecurityAdjudicationError::CandidateSetup {
            id: packet.candidate.id.clone(),
            reason: "candidate domain is unknown; no applicable proof contract".into(),
        });
    }
    let security = domain == "security";
    if !security {
        let proof = domain_proof
            .as_ref()
            .filter(|proof| proof.domain == domain)
            .ok_or_else(|| SecurityAdjudicationError::CandidateSetup {
                id: packet.candidate.id.clone(),
                reason: format!("{domain} verdict requires matching domainProof"),
            })?;
        check_text(&packet.candidate.id, "invariant", &proof.invariant, false)?;
        check_text(&packet.candidate.id, "trigger", &proof.trigger, false)?;
        if !non_blank(&result.proof) {
            return Err(SecurityAdjudicationError::MissingProof(result.verdict));
        }
        if !non_blank(&result.devils_advocate) {
            return Err(SecurityAdjudicationError::MissingDevilsAdvocate(
                result.verdict,
            ));
        }
    } else if domain_proof.is_some() {
        return Err(SecurityAdjudicationError::CandidateSetup { id: packet.candidate.id.clone(), reason: "security verdict uses threatModel and attackerControl, not a nonsecurity domainProof".into() });
    }
    if !verify_adjudication_packet(packet) {
        return Err(SecurityAdjudicationError::InvalidPacket);
    }
    // A blank string is no more an assessment than an absent one.
    if (security && !non_blank(&result.threat_model))
        || !non_blank(&result.reachability)
        || !non_blank(&result.impact)
    {
        return Err(SecurityAdjudicationError::IncompleteVerdict);
    }
    let threat_model = if security {
        result
            .threat_model
            .clone()
            .ok_or(SecurityAdjudicationError::IncompleteVerdict)?
    } else {
        String::new()
    };
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
    let attacker_control = if security {
        result
            .attacker_control
            .clone()
            .unwrap_or_else(|| "unproven".to_string())
    } else {
        String::new()
    };
    if surviving {
        if security && (attacker_control.trim().is_empty() || attacker_control == "unproven") {
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
        domain: domain.into(),
        domain_proof,
        schema_version: 1,
        kind: if security {
            "security-verdict"
        } else {
            "candidate-verdict"
        }
        .into(),
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
        cluster_id: None,
        variant_analysis_required: surviving && security,
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
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub end_line: Option<u64>,
    /// Known, unknown, invalid, or conflicting. Unknown anchors stay live.
    #[serde(default)]
    pub location_status: String,
    /// Original adapter location/evidence, recursively secret-redacted.
    #[serde(default)]
    pub source_mapping: Value,
    #[serde(default)]
    pub evidence_digest: String,
    #[serde(default)]
    pub domain: String,
}

/// Repository-relative anchors only; never turn traversal into a safe path.
fn normalized_candidate_path(root: &Path, path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let relative = if Path::new(&normalized).is_absolute() {
        Path::new(&normalized)
            .strip_prefix(root)
            .ok()?
            .to_str()?
            .to_owned()
    } else {
        normalized
    };
    if relative.contains(':') || relative.chars().any(char::is_control) {
        return None;
    }
    let mut parts = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            _ => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn parse_location(location: &str) -> (String, Option<u64>, Option<u64>) {
    if let Some((path, range)) = location.rsplit_once(':') {
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        if let Ok(line) = start.parse::<u64>() {
            let end = end
                .parse::<u64>()
                .ok()
                .filter(|end| line > 0 && *end >= line);
            return (path.to_owned(), (line > 0).then_some(line), end);
        }
    }
    (location.to_owned(), None, None)
}

fn safe_source_mapping(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(super::excerpts::redact_secrets(text).0),
        Value::Array(items) => Value::Array(items.iter().map(safe_source_mapping).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, value)| {
                    let safe = match value {
                        Value::String(text)
                            if super::excerpts::redact_secrets(&format!("{key}={text}")).1 =>
                        {
                            Value::String("[REDACTED]".into())
                        }
                        _ => safe_source_mapping(value),
                    };
                    (key.clone(), safe)
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn candidate_anchor(
    root: &Path,
    raw: &Value,
) -> (Option<String>, Option<u64>, Option<u64>, String) {
    let path = raw
        .get("file")
        .or_else(|| raw.get("path"))
        .and_then(Value::as_str);
    let line = raw
        .get("line")
        .or_else(|| raw.get("startLine"))
        .and_then(Value::as_u64)
        .filter(|line| *line > 0);
    let end = raw.get("endLine").and_then(Value::as_u64).or(line);
    let normalized = path.and_then(|path| normalized_candidate_path(root, path));
    let status = if path.is_some() && normalized.is_none()
        || raw
            .get("line")
            .or_else(|| raw.get("startLine"))
            .is_some_and(|value| !value.is_null())
            && line.is_none()
        || raw
            .get("endLine")
            .is_some_and(|value| !value.is_null() && value.as_u64().is_none())
        || end.zip(line).is_some_and(|(end, start)| end < start)
    {
        "invalid"
    } else if normalized.is_some() && line.is_some() {
        "known"
    } else {
        "unknown"
    };
    if status == "invalid" {
        (None, None, None, status.into())
    } else {
        (normalized, line, end, status.into())
    }
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
    let canonical_root = root.canonicalize().ok()?;
    let canonical_file = root.join(relative).canonicalize().ok()?;
    if !canonical_file.starts_with(&canonical_root) {
        return None;
    }
    let bytes = std::fs::read(canonical_file).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let index = usize::try_from(line.checked_sub(1)?).ok()?;
    let source = text.lines().nth(index)?;
    let (redacted, _) = super::excerpts::redact_secrets(source.trim());
    Some(redacted.chars().take(240).collect())
}

fn detail_entry<'a>(result: &'a ProviderResult, key: &str, id: &str) -> Option<&'a Value> {
    result.details.get(key)?.as_object()?.get(id)
}

/// Routing remains explicit: unknown families do not become security claims.
pub fn candidate_domain(provider: &str, rule: &str) -> &'static str {
    for identity in [rule, provider] {
        let family = identity.to_ascii_lowercase();
        if family.starts_with("data.") || family.contains(".data.") {
            return "data";
        }
        if family.starts_with("release.") || family.contains(".release.") {
            return "release";
        }
        if ["reliability", "resilience"]
            .iter()
            .any(|prefix| family.starts_with(prefix) || family.contains(&format!(".{prefix}.")))
        {
            return "reliability";
        }
        if ["security", "secrets", "credentials"]
            .iter()
            .any(|prefix| family.starts_with(prefix) || family.contains(&format!(".{prefix}.")))
        {
            return "security";
        }
    }
    "unknown"
}

pub fn effective_candidate_domain(candidate: &ScannerCandidate) -> &str {
    if candidate.domain.is_empty() {
        candidate_domain(&candidate.provider, &candidate.rule)
    } else {
        &candidate.domain
    }
}

fn domain_required_evidence(domain: &str) -> Vec<String> {
    if domain == "security" {
        return REQUIRED_EVIDENCE
            .iter()
            .map(|text| (*text).into())
            .collect();
    }
    vec![
        format!("domainProof.domain must equal {domain}"),
        "domainProof.invariant: concrete data, reliability, or release invariant".into(),
        "domainProof.trigger: executable trigger that violates or falsifies that invariant".into(),
        "reachability and impact supported by source anchors".into(),
        "proof: source trace or reproduction; uncertainty remains unresolved".into(),
        "devilsAdvocate: counterevidence and false-positive challenge".into(),
    ]
}

/// Candidates a candidate-generator `result` raised, in finding-id order.
pub fn scanner_candidates(
    root: &Path,
    provider: &str,
    result: &ProviderResult,
) -> Vec<ScannerCandidate> {
    let mut raw = result.findings.iter().map(|finding| {
        let id = finding.id.as_str();
        let locations = detail_entry(result, "findingLocations", id).cloned().unwrap_or(Value::Null);
        let evidence = detail_entry(result, "findingEvidence", id).cloned().unwrap_or(Value::Null);
        let location = locations.as_array().and_then(|items| items.first()).and_then(Value::as_str);
        let (file, line, end) = location.map(parse_location).unwrap_or_default();
        let rule = ["ruleId", "rule", "checkId"].iter()
            .find_map(|key| evidence.get(*key).and_then(Value::as_str)).unwrap_or(provider);
        let message = ["findingMessages", "findingTitles"].iter()
            .find_map(|key| detail_entry(result, key, id).and_then(Value::as_str)).unwrap_or_default();
        json!({"id": id, "ruleId": rule, "severityHint": finding.severity,
            "claim": message, "file": if file.is_empty() { None } else { Some(file) },
            "line": line, "endLine": if line.is_some() && end.is_none() { Some(0) } else { end }, "adapterLocations": locations, "adapterEvidence": evidence})
    }).collect::<Vec<_>>();
    raw.extend(
        result
            .details
            .get("candidates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .cloned(),
    );
    let mut candidates = raw
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            let evidence = candidate
                .get("evidence")
                .and_then(Value::as_array)
                .and_then(|items| items.first());
            let top_present = ["file", "path", "line", "startLine"]
                .iter()
                .any(|key| candidate.get(*key).is_some_and(|value| !value.is_null()));
            let mut top = candidate_anchor(root, &candidate);
            let nested = evidence.map(|item| candidate_anchor(root, item));
            if candidate.get("endLine").is_none_or(Value::is_null) {
                if let Some(nested) = nested
                    .as_ref()
                    .filter(|nested| nested.0 == top.0 && nested.1 == top.1)
                {
                    top.2 = nested.2;
                }
            }
            let (path, line, end_line, location_status) = match (top_present, nested) {
                (true, Some(nested))
                    if top.3 == "known" && nested.3 == "known" && top != nested =>
                {
                    (None, None, None, "conflicting".into())
                }
                (true, Some(nested)) if top.3 == "unknown" && nested.3 == "known" => {
                    if top
                        .0
                        .as_ref()
                        .zip(nested.0.as_ref())
                        .is_some_and(|(left, right)| left != right)
                        || top
                            .1
                            .zip(nested.1)
                            .is_some_and(|(left, right)| left != right)
                    {
                        (None, None, None, "conflicting".into())
                    } else {
                        nested
                    }
                }
                (true, _) => top,
                (false, Some(nested)) => nested,
                (false, None) => top,
            };
            let source_mapping = safe_source_mapping(&candidate);
            let evidence_digest = canonical_digest(&candidate).unwrap_or_default();
            let id = candidate
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("unknown-id:{provider}:{index}:{evidence_digest}"));
            let evidence_excerpt = candidate
                .get("redactedExcerpt")
                .and_then(Value::as_str)
                .filter(|excerpt| !excerpt.is_empty())
                .map(|excerpt| super::excerpts::redact_secrets(excerpt).0)
                .or_else(|| {
                    path.as_deref()
                        .zip(line)
                        .and_then(|(path, line)| excerpt_line(root, path, line))
                });
            ScannerCandidate {
                finding_id: id,
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
                end_line,
                location_status,
                source_mapping,
                evidence_digest,
                message: super::excerpts::redact_secrets(
                    candidate
                        .get("claim")
                        .or_else(|| candidate.get("title"))
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
                .0,
                domain: candidate
                    .get("domain")
                    .and_then(Value::as_str)
                    .filter(|domain| {
                        matches!(
                            *domain,
                            "security" | "data" | "reliability" | "release" | "unknown"
                        )
                    })
                    .unwrap_or_else(|| {
                        candidate_domain(
                            provider,
                            candidate
                                .get("ruleId")
                                .and_then(Value::as_str)
                                .unwrap_or(provider),
                        )
                    })
                    .into(),
                evidence_excerpt,
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    candidates
}

fn validate_candidate_ids(
    candidates: &[ScannerCandidate],
) -> Result<(), SecurityAdjudicationError> {
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if candidate.finding_id.trim().is_empty() || !seen.insert(candidate.finding_id.as_str()) {
            return Err(SecurityAdjudicationError::CandidateSetup {
                id: candidate.finding_id.clone(),
                reason: "candidate IDs must be nonempty and unique".into(),
            });
        }
    }
    Ok(())
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
/// only that candidate's evidence, bound to its requested context label.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateAdjudicationItem {
    /// `sha256` of (batch packet digest, candidate id).
    pub item_id: String,
    /// Requested context label. It does not prove a fresh host context exists.
    pub context_id: String,
    pub packet: SecurityAdjudicationPacket,
}

/// Digest the parent adjudication packet before its derived child work items
/// are attached. The child work is itself carried by the parent packet, so
/// excluding that field avoids a circular digest while still binding every
/// child to the complete batch evidence and frozen invocation context.
pub fn adjudication_parent_packet_digest(
    packet: &Value,
) -> Result<String, SecurityAdjudicationError> {
    let mut parent = packet.clone();
    let object = parent
        .as_object_mut()
        .ok_or(SecurityAdjudicationError::InvalidPacket)?;
    object.remove("candidateWorkItems");
    canonical_digest(&parent).map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))
}

fn build_item(
    candidate: &ScannerCandidate,
    packet_digest: &str,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    let item_id = adjudication_item_id(packet_digest, candidate.finding_id.as_str())?;
    let context_id = format!("adjudicator:{item_id}");
    build_item_with(candidate, packet_digest, item_id, context_id)
}

fn build_item_with(
    candidate: &ScannerCandidate,
    packet_digest: &str,
    item_id: String,
    context_id: String,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    let id = candidate.finding_id.as_str();
    let setup = |error: SecurityAdjudicationError| SecurityAdjudicationError::CandidateSetup {
        id: id.to_owned(),
        reason: error.to_string(),
    };
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
            "endLine": candidate.end_line,
            "locationStatus": candidate.location_status,
            "sourceMapping": candidate.source_mapping,
            "evidenceDigest": candidate.evidence_digest,
            "domain": effective_candidate_domain(candidate),
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

/// Fans a batch out into one isolated evidence packet per candidate, in
/// candidate order. A host should dispatch each packet in a fresh context;
/// this helper cannot observe or attest that host behavior.
pub fn adjudication_work_items(
    candidates: &[ScannerCandidate],
    packet_digest: &str,
) -> Result<Vec<CandidateAdjudicationItem>, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    candidates
        .iter()
        .map(|candidate| build_item(candidate, packet_digest))
        .collect()
}

/// How a verdict's adjudicator context is established.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextPolicy {
    /// The context is the one issued for the candidate; a verdict that names a
    /// different one (`contextId`) is rejected. A verdict that names none is
    /// accepted, which proves nothing about how it was reached: use only where
    /// the host cannot yet attest.
    Derived,
    /// Every verdict must name the context it claims to have used, and it must
    /// be the one issued for its candidate. This checks labels only; a trusted
    /// host must separately attest actual context identity and freshness.
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
                let (file, line, end) = parse_location(location);
                end?;
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
    domain_proof: Option<&CandidateDomainProof>,
) -> Result<Vec<(&'static str, String)>, SecurityAdjudicationError> {
    let id = candidate.finding_id.as_str();
    let surviving = input.verdict.is_surviving();
    let mut forms = Vec::new();
    let security = effective_candidate_domain(candidate) == "security";
    let fields = content_fields(input, surviving || !security)
        .into_iter()
        .filter(|(field, _, _, _)| {
            security || !matches!(*field, "threatModel" | "attackerControl")
        });
    for (field, text, mandatory, short_ok) in fields {
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
                });
            }
            None => {}
        }
    }
    if let Some(proof) = domain_proof {
        forms.push((
            "invariant",
            check_text(id, "invariant", &proof.invariant, false)?,
        ));
        forms.push(("trigger", check_text(id, "trigger", &proof.trigger, false)?));
    }
    if !surviving && security {
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

/// Closes every scanner candidate with exactly one verdict, each assigned its
/// own isolated work packet and requested context label.
///
/// * Unknown, duplicate and missing candidate ids are rejected.
/// * Each candidate is finalized against its own packet
///   ([`adjudication_work_items`]) holding only its evidence.
/// * A verdict that names a context (`contextId`) must name the one issued
///   for its candidate; one shared with another candidate, or equal to the
///   generator's, is rejected. With [`ContextPolicy::Attested`] naming it is
///   mandatory, but that policy validates only the label and is not trusted
///   host evidence that the context was actually fresh.
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
    adjudicate_scanner_candidates_scoped(
        candidates,
        verdicts,
        packet_digest,
        policy,
        &AdjudicationScope::PerCandidate,
    )
}

/// What a set of verdicts is scoped to, and so which adjudicator context each
/// verdict must name.
#[derive(Clone, Copy, Debug)]
pub enum AdjudicationScope<'a> {
    /// One isolated context per candidate (the original contract).
    PerCandidate,
    /// One isolated context per candidate, in a named stage
    /// (`confirmation`, `spotCheck`, `individual`). The stage is part of the
    /// context derivation, so a candidate's contexts differ between stages.
    Stage(&'a str),
    /// One context for the whole batch, shared by its cluster representatives.
    /// Only representatives carry verdicts; each is expanded to every cluster
    /// member, which keeps its own row (with `cluster_id`).
    Batch {
        batch: &'a Batch,
        clusters: &'a [Cluster],
    },
}

fn scoped_item(
    scope: &AdjudicationScope<'_>,
    candidate: &ScannerCandidate,
    packet_digest: &str,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    match scope {
        AdjudicationScope::PerCandidate => build_item(candidate, packet_digest),
        AdjudicationScope::Stage(stage) => {
            let item_id =
                adjudication_item_id(packet_digest, &format!("{stage}:{}", candidate.finding_id))?;
            let context_id = format!("adjudicator:{item_id}");
            build_item_with(candidate, packet_digest, item_id, context_id)
        }
        AdjudicationScope::Batch { batch, .. } => build_item_with(
            candidate,
            packet_digest,
            batch.item_id.clone(),
            batch.context_id.clone(),
        ),
    }
}

/// [`adjudicate_scanner_candidates_isolated`] generalized over
/// [`AdjudicationScope`]. Under [`AdjudicationScope::Batch`] `candidates` are
/// every member of the batch's clusters and `verdicts` cover the cluster
/// representatives only; the result has one row per member.
pub fn adjudicate_scanner_candidates_scoped(
    candidates: &[ScannerCandidate],
    verdicts: &[Value],
    packet_digest: &str,
    policy: ContextPolicy,
    scope: &AdjudicationScope<'_>,
) -> Result<Vec<SecurityVerdict>, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    let mut by_id: BTreeMap<&str, &ScannerCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_id
            .entry(candidate.finding_id.as_str())
            .or_insert(candidate);
    }
    if let AdjudicationScope::Batch { batch, clusters } = scope {
        let computed = cluster_candidates(candidates)?;
        let mut assigned = BTreeSet::new();
        for cluster in *clusters {
            if !batch.cluster_ids.contains(&cluster.cluster_id)
                || !computed.iter().any(|expected| expected == cluster)
                || cluster
                    .member_ids
                    .iter()
                    .any(|member| !assigned.insert(member.as_str()))
            {
                return Err(SecurityAdjudicationError::CandidateSetup {
                    id: cluster.representative_id.clone(),
                    reason:
                        "batch clusters must preserve evidenced equivalence and unique assignment"
                            .into(),
                });
            }
        }
    }
    // The candidates that need a verdict of their own.
    let adjudicated: Vec<ScannerCandidate> = match scope {
        AdjudicationScope::Batch { clusters, .. } => clusters
            .iter()
            .map(|cluster| {
                by_id
                    .get(cluster.representative_id.as_str())
                    .map(|candidate| (*candidate).clone())
                    .ok_or_else(|| SecurityAdjudicationError::CandidateSetup {
                        id: cluster.representative_id.clone(),
                        reason: format!(
                            "representative of cluster {} is not among the batch candidates",
                            cluster.cluster_id
                        ),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => candidates.to_vec(),
    };
    let shared_context = matches!(scope, AdjudicationScope::Batch { .. });
    let mut items: BTreeMap<String, CandidateAdjudicationItem> = BTreeMap::new();
    for candidate in &adjudicated {
        if !items.contains_key(&candidate.finding_id) {
            items.insert(
                candidate.finding_id.clone(),
                scoped_item(scope, candidate, packet_digest)?,
            );
        }
    }
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
        let candidate = by_id
            .get(id)
            .copied()
            .filter(|_| items.contains_key(id))
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
                if !shared_context {
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
                ));
            }
            None => {}
        }

        // The evidentiary bar for the verdict kind, then meaningful content.
        let citations = parse_citations(value);
        let cited = citations
            .iter()
            .map(|citation| json!({"file": citation.file, "line": citation.line}))
            .collect::<Vec<_>>();
        let domain_proof = value
            .get("domainProof")
            .cloned()
            .map(serde_json::from_value::<CandidateDomainProof>)
            .transpose()
            .map_err(|error| SecurityAdjudicationError::MalformedVerdict {
                id: id.into(),
                reason: error.to_string(),
            })?;
        let verdict = finalize_for_domain(&item.packet, input.clone(), cited, domain_proof.clone())
            .map_err(|error| wrap(id, error))?;
        let forms = validate_content(candidate, &input, &citations, domain_proof.as_ref())
            .map_err(|error| wrap(id, error))?;
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
                    ));
                }
                Some(_) => {}
                None => {
                    seen_text.insert(form, id.to_owned());
                }
            }
        }
        closed.insert(id.to_owned(), verdict);
    }
    let missing = items
        .keys()
        .filter(|id| !closed.contains_key(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(SecurityAdjudicationError::MissingVerdicts(
            missing.join(", "),
        ));
    }
    match scope {
        AdjudicationScope::Batch { clusters, .. } => expand_clusters(candidates, clusters, &closed),
        _ => Ok(candidates
            .iter()
            .filter_map(|candidate| closed.remove(candidate.finding_id.as_str()))
            .collect()),
    }
}

/// One row per candidate, copied from its cluster representative's verdict.
/// Every row records its own candidate and `cluster_id` and carries its own
/// digest, so no location is lost to clustering.
fn expand_clusters(
    candidates: &[ScannerCandidate],
    clusters: &[Cluster],
    closed: &BTreeMap<String, SecurityVerdict>,
) -> Result<Vec<SecurityVerdict>, SecurityAdjudicationError> {
    let mut cluster_of: BTreeMap<&str, &Cluster> = BTreeMap::new();
    for cluster in clusters {
        for member in &cluster.member_ids {
            cluster_of.insert(member.as_str(), cluster);
        }
    }
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if !seen.insert(candidate.finding_id.as_str()) {
            continue;
        }
        let cluster = cluster_of
            .get(candidate.finding_id.as_str())
            .copied()
            .ok_or_else(|| SecurityAdjudicationError::CandidateSetup {
                id: candidate.finding_id.clone(),
                reason: "candidate is not a member of any cluster in this batch".to_owned(),
            })?;
        let representative = closed
            .get(cluster.representative_id.as_str())
            .ok_or_else(|| SecurityAdjudicationError::CandidateSetup {
                id: cluster.representative_id.clone(),
                reason: "cluster representative has no verdict".to_owned(),
            })?;
        let mut row = representative.clone();
        row.candidate_id = candidate.finding_id.clone();
        row.candidate_provider = candidate.provider.clone();
        row.cluster_id = Some(cluster.cluster_id.clone());
        row.verdict_digest = String::new();
        row.verdict_digest = canonical_digest(&row)
            .map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))?;
        rows.push(row);
    }
    Ok(rows)
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
        .filter(|verdict| verdict.verdict.is_surviving() && verdict.domain == "security")
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

// ---------------------------------------------------------------------
// Scaled adjudication: triage, clusters, batches, confirmations, spot-checks
// ---------------------------------------------------------------------
//
// At ~1.4k candidates one fresh context per candidate is not affordable, so
// adjudication is staged. Nothing here weakens what a verdict must prove; it
// moves where the per-candidate rigor is spent:
//
// 1. `triage_candidates` closes only provable non-issues, typed
//    `deterministic`, reported as `autoTriaged`, never counted as adjudicated.
// 2. `cluster_candidates` groups identical sinks; every member keeps its own
//    verdict row (`clusterId`).
// 3. `adjudication_batches` groups clusters (rule family, then file locality,
//    at most `MAX_CLUSTERS_PER_BATCH` clusters and `MAX_BATCH_TOKENS`) into one
//    fresh context per batch.
// 4. Every surviving verdict is re-adjudicated alone (`confirmation_items`),
//    a seeded 5% of routine dismissals is re-adjudicated alone
//    (`spot_check_items`; any disagreement voids the batch and reruns it one
//    candidate per context), and high-risk or uncertain dismissals go straight
//    to individual review.
//
// Context identity is host-attested. The context ids issued here are labels a
// host is asked to honour; a verdict echoing one proves nothing about how it
// was reached, so ingest keeps recording the derived-context gap.

/// Most clusters one batch may carry.
pub const MAX_CLUSTERS_PER_BATCH: usize = 25;
/// Estimated-token bound for one batch packet (4 characters per token).
pub const MAX_BATCH_TOKENS: usize = 24_000;
/// Share of routine dismissals re-adjudicated alone, rounded up, at least one
/// per batch that has any.
pub const SPOT_CHECK_PERCENT: usize = 5;
/// Verdict basis of a deterministic triage closure.
pub const DETERMINISTIC_BASIS: &str = "deterministic";

pub const STAGE_BATCH: &str = "batch";
pub const STAGE_CONFIRMATION: &str = "confirmation";
pub const STAGE_SPOT_CHECK: &str = "spotCheck";
pub const STAGE_INDIVIDUAL: &str = "individual";

pub const TRIAGE_RULE_PATH_EXCLUDED: &str = "triage.path-excluded";
pub const TRIAGE_RULE_PLACEHOLDER: &str = "triage.placeholder-value";
pub const TRIAGE_RULE_NATIVE_RESOLVED: &str = "triage.native-resolved";

fn digest_of<T: Serialize>(value: &T) -> Result<String, SecurityAdjudicationError> {
    canonical_digest(value).map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))
}

fn short_digest(digest: &str) -> String {
    digest
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect()
}

fn estimate_tokens(text: &str) -> usize {
    text.chars().count() / 4 + 1
}

/// Host-supplied facts triage may rely on. Both sets are frozen into the
/// packet, so ingest re-derives triage from exactly what the packet declares.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageContext {
    /// Paths the lens denominators exclude (the host's own classification).
    #[serde(default)]
    pub excluded_paths: BTreeSet<String>,
    /// [`location_fingerprint`]s a native provider already resolved.
    #[serde(default)]
    pub resolved_fingerprints: BTreeSet<String>,
}

/// A candidate closed by a deterministic rule. It is not an adjudication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoTriaged {
    pub candidate_id: String,
    pub rule_id: String,
    pub scanner_rule: String,
    pub verdict: SecurityVerdictKind,
    pub basis: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub line: Option<u64>,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct TriageOutcome {
    pub auto_triaged: Vec<AutoTriaged>,
    pub remaining: Vec<ScannerCandidate>,
}

fn lower_path(path: &str) -> String {
    path.trim().replace('\\', "/").to_lowercase()
}

/// Test and fixture paths are never auto-closed: real secrets leak there.
fn path_is_test_or_fixture(path: &str) -> bool {
    let lower = lower_path(path);
    let mut parts = lower.split('/').collect::<Vec<_>>();
    let name = parts.pop().unwrap_or_default();
    parts.iter().any(|part| {
        matches!(
            *part,
            "test"
                | "tests"
                | "__tests__"
                | "spec"
                | "specs"
                | "fixture"
                | "fixtures"
                | "__fixtures__"
                | "testdata"
                | "mocks"
                | "__mocks__"
                | "e2e"
        )
    }) || name.starts_with("test_")
        || [
            "_test.go",
            "_test.rs",
            "_test.py",
            ".test.js",
            ".test.ts",
            ".test.tsx",
            ".spec.js",
            ".spec.ts",
            ".spec.tsx",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Generated, vendored, minified or lock files: what the lens denominators
/// leave out.
fn excluded_path_kind(path: &str) -> Option<&'static str> {
    let lower = lower_path(path);
    let mut parts = lower.split('/').collect::<Vec<_>>();
    let name = parts.pop().unwrap_or_default();
    if parts.iter().any(|part| {
        matches!(
            *part,
            "node_modules" | "vendor" | "vendored" | "third_party" | "third-party"
        )
    }) {
        return Some("vendored");
    }
    if parts
        .iter()
        .any(|part| matches!(*part, "generated" | "__generated__"))
        || name.contains(".generated.")
        || name.contains("_generated.")
        || name.ends_with(".pb.go")
        || name.ends_with("_pb2.py")
    {
        return Some("generated");
    }
    if name.ends_with(".min.js") || name.ends_with(".min.css") {
        return Some("minified");
    }
    if name.ends_with(".lock")
        || matches!(
            name,
            "package-lock.json" | "pnpm-lock.yaml" | "npm-shrinkwrap.json" | "go.sum"
        )
    {
        return Some("lock file");
    }
    None
}

fn rule_is_secret_like(rule: &str) -> bool {
    let lower = rule.to_lowercase();
    [
        "secret",
        "credential",
        "password",
        "passwd",
        "token",
        "api-key",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Exact, stock placeholder literals. Deliberately narrow: `changeme`,
/// `password` and `secret` are default credentials, not placeholders.
const STRICT_PLACEHOLDERS: &[&str] = &[
    "example",
    "sample",
    "dummy",
    "placeholder",
    "notasecret",
    "yourapikey",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourpassword",
];

fn quoted_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut quote: Option<char> = None;
    let mut current = String::new();
    for character in text.chars() {
        match quote {
            Some(open) if character == open => {
                literals.push(std::mem::take(&mut current));
                quote = None;
            }
            Some(_) => current.push(character),
            None if character == '"' || character == '\'' => quote = Some(character),
            None => {}
        }
    }
    literals
}

/// True only when the anchored line assigns a secret-shaped rule's value to
/// nothing but stock placeholder literals. A redacted excerpt can hide a real
/// value, so any redaction marker disables the rule.
fn placeholder_value(candidate: &ScannerCandidate) -> bool {
    if !rule_is_secret_like(&candidate.rule) {
        return false;
    }
    let Some(excerpt) = candidate.evidence_excerpt.as_deref() else {
        return false;
    };
    if excerpt.to_lowercase().contains("redacted") {
        return false;
    }
    let literals = quoted_literals(excerpt);
    !literals.is_empty()
        && literals.iter().all(|literal| {
            let form = normal_form(literal);
            STRICT_PLACEHOLDERS.contains(&form.as_str())
                || (form.len() >= 4 && form.chars().all(|character| character == 'x'))
        })
}

fn normalized_excerpt(candidate: &ScannerCandidate) -> String {
    candidate
        .evidence_excerpt
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Identity of one candidate location: scanner rule, path, line and the
/// normalized anchored text. Native providers record resolutions under it.
pub fn location_fingerprint(candidate: &ScannerCandidate) -> String {
    // A failed digest yields "", which no resolved set contains: triage then
    // leaves the candidate alone.
    digest_of(&json!({
        "kind": "candidate-location",
        "provider": candidate.provider,
        "endLine": candidate.end_line,
        "rule": candidate.rule,
        "path": candidate.path,
        "line": candidate.line,
        "excerpt": normalized_excerpt(candidate),
    }))
    .unwrap_or_default()
}

fn resolved_by_native(candidate: &ScannerCandidate, context: &TriageContext) -> bool {
    let fingerprint = location_fingerprint(candidate);
    !fingerprint.is_empty() && context.resolved_fingerprints.contains(&fingerprint)
}

/// Close only provable non-issues. Each closure carries the verdict basis
/// `deterministic` and its rule id; none is an adjudication.
pub fn triage_candidates(
    candidates: &[ScannerCandidate],
    context: &TriageContext,
) -> TriageOutcome {
    let mut outcome = TriageOutcome::default();
    for candidate in candidates {
        let path = candidate.path.as_deref();
        let closure = if path.is_some_and(path_is_test_or_fixture) {
            None
        } else if let Some(kind) = path.and_then(|path| {
            excluded_path_kind(path).or_else(|| {
                context
                    .excluded_paths
                    .contains(&normalize_cited_path(path))
                    .then_some("excluded from the lens denominators")
            })
        }) {
            Some((
                TRIAGE_RULE_PATH_EXCLUDED,
                SecurityVerdictKind::OutOfScope,
                format!("path is a {kind} file, outside the lens denominators"),
            ))
        } else if placeholder_value(candidate) {
            Some((
                TRIAGE_RULE_PLACEHOLDER,
                SecurityVerdictKind::FalsePositive,
                "the matched value is a stock placeholder literal".to_owned(),
            ))
        } else if resolved_by_native(candidate, context) {
            Some((
                TRIAGE_RULE_NATIVE_RESOLVED,
                SecurityVerdictKind::FalsePositive,
                "a native provider already resolved this fingerprint".to_owned(),
            ))
        } else {
            None
        };
        match closure {
            Some((rule_id, verdict, reason)) => outcome.auto_triaged.push(AutoTriaged {
                candidate_id: candidate.finding_id.clone(),
                rule_id: rule_id.to_owned(),
                scanner_rule: candidate.rule.clone(),
                verdict,
                basis: DETERMINISTIC_BASIS.to_owned(),
                path: candidate.path.clone(),
                line: candidate.line,
                reason,
            }),
            None => outcome.remaining.push(candidate.clone()),
        }
    }
    outcome
}

/// Rule family: the first dotted/slashed segment of the scanner rule id.
fn rule_family(rule: &str) -> String {
    rule.split(['.', '/', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(rule)
        .to_lowercase()
}

/// Duplicate observations with identical provider, source anchor & evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cluster {
    pub cluster_id: String,
    pub fingerprint: String,
    pub rule: String,
    pub family: String,
    /// The one member that is adjudicated for the cluster.
    pub representative_id: String,
    /// Every member, representative included, in id order.
    pub member_ids: Vec<String>,
}

fn equivalence_source_mapping(mapping: &Value) -> Value {
    let mut context = mapping.clone();
    if let Some(object) = context.as_object_mut() {
        object.remove("id");
    }
    context
}

/// Merge only duplicate observations of the same anchored source instance.
/// Missing evidence or location never establishes semantic equivalence.
pub fn cluster_candidates(
    candidates: &[ScannerCandidate],
) -> Result<Vec<Cluster>, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    let mut groups: BTreeMap<String, Vec<&ScannerCandidate>> = BTreeMap::new();
    for candidate in candidates {
        let excerpt = normalized_excerpt(candidate);
        let anchored = candidate.path.as_deref().is_some_and(|path| {
            normalized_candidate_path(Path::new(""), path).as_deref() == Some(path)
        }) && candidate.line.is_some_and(|line| line > 0)
            && !excerpt.is_empty()
            && !matches!(
                candidate.location_status.as_str(),
                "invalid" | "conflicting"
            );
        let fingerprint = digest_of(&json!({
            "kind": "candidate-cluster-v2",
            "provider": candidate.provider,
            "rule": candidate.rule,
            "path": candidate.path,
            "line": candidate.line,
            "endLine": candidate.end_line,
            "excerpt": excerpt,
            "sourceContext": equivalence_source_mapping(&candidate.source_mapping),
            "sourceEvidenceDigest": candidate.evidence_digest,
            "instanceId": if anchored { None } else { Some(&candidate.finding_id) },
        }))?;
        groups.entry(fingerprint).or_default().push(candidate);
    }
    let mut clusters = Vec::new();
    for (fingerprint, mut members) in groups {
        members.sort_by(|left, right| {
            (&left.path, left.line, &left.finding_id).cmp(&(
                &right.path,
                right.line,
                &right.finding_id,
            ))
        });
        let representative = members[0];
        let mut member_ids = members
            .iter()
            .map(|member| member.finding_id.clone())
            .collect::<Vec<_>>();
        member_ids.sort();
        clusters.push(Cluster {
            cluster_id: format!("cluster-{}", short_digest(&fingerprint)),
            fingerprint,
            rule: representative.rule.clone(),
            family: rule_family(&representative.rule),
            representative_id: representative.finding_id.clone(),
            member_ids,
        });
    }
    clusters.sort_by(|left, right| left.cluster_id.cmp(&right.cluster_id));
    Ok(clusters)
}

/// One fresh-context batch of clusters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub batch_id: String,
    pub item_id: String,
    /// Requested context label shared by the batch's representatives. It does
    /// not prove a fresh host context exists.
    pub context_id: String,
    pub context_policy: ContextPolicy,
    pub family: String,
    pub cluster_ids: Vec<String>,
    pub estimated_tokens: usize,
    /// The batch work packet a host hands to one fresh adjudicator context.
    pub packet: Value,
}

fn cluster_entry(cluster: &Cluster, by_id: &BTreeMap<&str, &ScannerCandidate>) -> Value {
    let representative = by_id.get(cluster.representative_id.as_str()).copied();
    let locations = cluster
        .member_ids
        .iter()
        .map(|member| {
            let candidate = by_id.get(member.as_str()).copied();
            json!({
                "findingId": member,
                "path": candidate.and_then(|candidate| candidate.path.clone()),
                "line": candidate.and_then(|candidate| candidate.line),
                "endLine": candidate.and_then(|candidate| candidate.end_line),
                "sourceMapping": candidate.map(|candidate| &candidate.source_mapping),
                "evidenceDigest": candidate.map(|candidate| &candidate.evidence_digest),
                "locationStatus": candidate.map(|candidate| &candidate.location_status),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "clusterId": cluster.cluster_id,
        "rule": cluster.rule,
        "memberCount": cluster.member_ids.len(),
        "representative": {
            "findingId": cluster.representative_id,
            "provider": representative.map(|candidate| candidate.provider.clone()),
            "rule": representative.map(|candidate| candidate.rule.clone()),
            "severity": representative.map(|candidate| candidate.severity.clone()),
            "path": representative.and_then(|candidate| candidate.path.clone()),
            "line": representative.and_then(|candidate| candidate.line),
            "message": representative.map(|candidate| candidate.message.clone()),
            "excerpt": representative.and_then(|candidate| candidate.evidence_excerpt.clone()),
            "endLine": representative.and_then(|candidate| candidate.end_line),
            "sourceMapping": representative.map(|candidate| &candidate.source_mapping),
            "evidenceDigest": representative.map(|candidate| &candidate.evidence_digest),
            "locationStatus": representative.map(|candidate| &candidate.location_status),
            "domain": representative.map(|candidate| effective_candidate_domain(candidate)),
            "requiredEvidence": representative.map(|candidate| domain_required_evidence(effective_candidate_domain(candidate))),
        },
        "memberLocations": locations,
    })
}

fn cluster_tokens(cluster: &Cluster, by_id: &BTreeMap<&str, &ScannerCandidate>) -> usize {
    estimate_tokens(&cluster_entry(cluster, by_id).to_string())
}

/// Group clusters by rule family, then file locality, into batches of at most
/// [`MAX_CLUSTERS_PER_BATCH`] clusters and [`MAX_BATCH_TOKENS`] estimated
/// tokens. A single oversize cluster gets a batch of its own. Batches are
/// homogeneous in rule family.
pub fn adjudication_batches(
    clusters: &[Cluster],
    candidates: &[ScannerCandidate],
    packet_digest: &str,
) -> Result<Vec<Batch>, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    let mut by_id: BTreeMap<&str, &ScannerCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_id
            .entry(candidate.finding_id.as_str())
            .or_insert(candidate);
    }
    let representative_path = |cluster: &Cluster| {
        by_id
            .get(cluster.representative_id.as_str())
            .and_then(|candidate| candidate.path.clone())
            .unwrap_or_default()
    };
    let mut ordered = clusters.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (
            &left.family,
            representative_path(*left),
            &left.rule,
            &left.cluster_id,
        )
            .cmp(&(
                &right.family,
                representative_path(*right),
                &right.rule,
                &right.cluster_id,
            ))
    });
    let mut groups: Vec<(String, Vec<&Cluster>, usize)> = Vec::new();
    for cluster in ordered {
        let cost = cluster_tokens(cluster, &by_id);
        let fits = groups.last().is_some_and(|(family, members, tokens)| {
            *family == cluster.family
                && members.len() < MAX_CLUSTERS_PER_BATCH
                && tokens + cost <= MAX_BATCH_TOKENS
        });
        if fits {
            if let Some((_, members, tokens)) = groups.last_mut() {
                members.push(cluster);
                *tokens += cost;
            }
        } else {
            groups.push((cluster.family.clone(), vec![cluster], cost));
        }
    }
    let mut batches = Vec::with_capacity(groups.len());
    for (index, (family, members, tokens)) in groups.into_iter().enumerate() {
        let batch_id = format!("batch-{:04}", index + 1);
        let item_id = adjudication_item_id(packet_digest, &format!("{STAGE_BATCH}:{batch_id}"))?;
        let context_id = format!("adjudicator:{item_id}");
        let packet = json!({
            "schemaVersion": 1,
            "kind": "security-batch-adjudication-packet",
            "parentPacketDigest": packet_digest,
            "batchId": batch_id,
            "family": family,
            "adjudicator": {
                "provider": ADJUDICATOR_PROVIDER_ID,
                "contextId": context_id,
            },
            "requiredEvidenceByCandidateDomain": {"security":domain_required_evidence("security"),"data":domain_required_evidence("data"),"reliability":domain_required_evidence("reliability"),"release":domain_required_evidence("release")},
            "note": "one verdict per cluster representative; it is expanded to every member, which is then confirmed or spot-checked alone",
            "clusters": members
                .iter()
                .map(|cluster| cluster_entry(cluster, &by_id))
                .collect::<Vec<_>>(),
        });
        batches.push(Batch {
            batch_id,
            item_id,
            context_id,
            context_policy: ContextPolicy::Attested,
            family,
            cluster_ids: members
                .iter()
                .map(|cluster| cluster.cluster_id.clone())
                .collect(),
            estimated_tokens: tokens,
            packet,
        });
    }
    Ok(batches)
}

/// Everything derivable from the scanner candidates before any verdict
/// exists. Ingest rebuilds it from the packet and requires equality.
#[derive(Clone, Debug)]
pub struct AdjudicationPlan {
    pub parent_packet_digest: String,
    pub triage_context: TriageContext,
    pub auto_triaged: Vec<AutoTriaged>,
    pub clusters: Vec<Cluster>,
    pub batches: Vec<Batch>,
}

pub fn build_adjudication_plan(
    candidates: &[ScannerCandidate],
    context: &TriageContext,
    parent_packet_digest: &str,
) -> Result<AdjudicationPlan, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    let triage = triage_candidates(candidates, context);
    let clusters = cluster_candidates(&triage.remaining)?;
    let batches = adjudication_batches(&clusters, &triage.remaining, parent_packet_digest)?;
    Ok(AdjudicationPlan {
        parent_packet_digest: parent_packet_digest.to_owned(),
        triage_context: context.clone(),
        auto_triaged: triage.auto_triaged,
        clusters,
        batches,
    })
}

impl AdjudicationPlan {
    /// The `candidateWorkItems` packet value. Confirmations and spot-checks
    /// depend on batch verdicts, so the packet carries their rules and the
    /// host derives the items with [`required_items`] once batches return.
    pub fn to_value(&self) -> Value {
        json!({
            "parentPacketDigest": self.parent_packet_digest,
            "triage": {
                "basis": DETERMINISTIC_BASIS,
                "context": self.triage_context,
                "autoTriagedCount": self.auto_triaged.len(),
                "autoTriaged": self.auto_triaged,
                "note": "deterministic closures are reported as autoTriaged and never counted as adjudicated",
            },
            "clusters": self.clusters,
            "batches": self.batches,
            "confirmations": {
                "status": "derived-after-batch-stage",
                "rule": "every surviving TRUE_POSITIVE, LIKELY_TRUE_POSITIVE, HARDENING_GAP and MISUSE_HAZARD verdict is re-adjudicated alone in a fresh context before it counts",
                "stage": STAGE_CONFIRMATION,
            },
            "spotChecks": {
                "status": "derived-after-batch-stage",
                "rule": "ceil(5% x routine dismissals) per non-empty batch, digest-seeded, re-adjudicated alone; any disagreement voids the batch and reruns it one candidate per context",
                "percent": SPOT_CHECK_PERCENT,
                "stage": STAGE_SPOT_CHECK,
                "individualStage": STAGE_INDIVIDUAL,
            },
            "limits": {
                "maxClustersPerBatch": MAX_CLUSTERS_PER_BATCH,
                "maxBatchTokens": MAX_BATCH_TOKENS,
            },
        })
    }
}

/// One required single-candidate adjudication, with its isolated work item.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageItem {
    pub stage: String,
    pub reason: String,
    pub batch_id: Option<String>,
    /// A verdict for this item has already been ingested and validated.
    pub satisfied: bool,
    pub item: CandidateAdjudicationItem,
}

#[derive(Clone, Debug)]
struct Requirement {
    stage: &'static str,
    candidate_id: String,
    reason: String,
    batch_id: Option<String>,
    satisfied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageCount {
    pub expected: usize,
    pub ingested: usize,
}

/// What was required and what was ingested, per stage. Passing
/// `security_adjudication` requires `complete`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdjudicationLedger {
    pub batches: StageCount,
    pub confirmations: StageCount,
    pub spot_checks: StageCount,
    pub individual_reviews: StageCount,
    pub auto_triaged: usize,
    /// Candidates holding a final adjudicated row.
    pub adjudicated: usize,
    pub voided_batches: Vec<String>,
    /// Confirmations that disagreed with the verdict they confirm.
    pub contested: Vec<String>,
    /// Submitted items that were not required and so were ignored.
    pub superseded: Vec<String>,
    pub outstanding: Vec<String>,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct AdjudicationOutcome {
    /// Final rows, one per resolved candidate, in candidate order. Candidates
    /// that are provisional, unconfirmed, contested or unresolved have none.
    pub verdicts: Vec<SecurityVerdict>,
    pub auto_triaged: Vec<AutoTriaged>,
    pub ledger: AdjudicationLedger,
}

fn high_risk(candidate: &ScannerCandidate) -> bool {
    let severity = candidate.severity.to_lowercase();
    if matches!(severity.as_str(), "critical" | "high" | "error") {
        return true;
    }
    let rule = candidate.rule.to_lowercase();
    rule_is_secret_like(&rule)
        || [
            "inject",
            "rce",
            "exec",
            "deserial",
            "auth",
            "crypto",
            "private-key",
            "privatekey",
        ]
        .iter()
        .any(|marker| rule.contains(marker))
}

/// Ledger `outstanding` entry formats. The `audit next` driver
/// (`crate::next`) parses these strings, so they are produced only here and
/// pinned by `outstanding_formats_are_stable`.
pub(crate) fn outstanding_batch(batch_id: &str, missing: usize) -> String {
    format!("batch:{batch_id}:{missing} cluster representative verdicts missing")
}

/// `spotCheck:<candidateId>` or `confirmation:<candidateId>`.
pub(crate) fn outstanding_stage(stage: &str, candidate_id: &str) -> String {
    format!("{stage}:{candidate_id}")
}

/// `individual:<candidateId>:<reason>`; the reason never contains `:`.
pub(crate) fn outstanding_individual(candidate_id: &str, reason: &str) -> String {
    format!("{STAGE_INDIVIDUAL}:{candidate_id}:{reason}")
}

pub(crate) fn outstanding_contested(candidate_id: &str) -> String {
    format!("contested:{candidate_id}")
}

/// Why a batch dismissal may not stand on the batch verdict alone.
fn individual_reason(
    candidate: &ScannerCandidate,
    verdict: SecurityVerdictKind,
) -> Option<&'static str> {
    if !verdict.is_dismissal() {
        None
    } else if high_risk(candidate) {
        Some("high-risk-dismissal")
    } else if verdict == SecurityVerdictKind::LikelyFalsePositive {
        Some("uncertain-dismissal")
    } else {
        None
    }
}

fn spot_check_selection(
    parent: &str,
    batch_id: &str,
    rows: &[&SecurityVerdict],
    pool: &[String],
) -> Result<Vec<String>, SecurityAdjudicationError> {
    if pool.is_empty() {
        return Ok(Vec::new());
    }
    let seed = digest_of(&json!({
        "kind": "spot-check-seed",
        "parentPacketDigest": parent,
        "batchId": batch_id,
        "verdicts": rows
            .iter()
            .map(|row| json!([row.candidate_id, row.verdict_digest]))
            .collect::<Vec<_>>(),
    }))?;
    let wanted = (pool.len() * SPOT_CHECK_PERCENT).div_ceil(100).max(1);
    let mut keyed = pool
        .iter()
        .map(|id| {
            Ok((
                digest_of(&json!({"seed": seed, "candidateId": id}))?,
                id.clone(),
            ))
        })
        .collect::<Result<Vec<_>, SecurityAdjudicationError>>()?;
    keyed.sort();
    Ok(keyed.into_iter().take(wanted).map(|(_, id)| id).collect())
}

fn check_binding(
    value: &Value,
    id: &str,
    item_id: &str,
    packet_digest: &str,
) -> Result<(), SecurityAdjudicationError> {
    if value.get("workItemId").and_then(Value::as_str) != Some(item_id)
        || value.get("workPacketDigest").and_then(Value::as_str) != Some(packet_digest)
    {
        return Err(SecurityAdjudicationError::MalformedVerdict {
            id: id.to_owned(),
            reason: "verdict is not bound to its isolated work item".to_owned(),
        });
    }
    Ok(())
}

/// The isolated work item for one candidate in a named single-candidate stage
/// (`confirmation`, `spotCheck`, `individual`): the same item
/// [`required_items`] derives, built without re-evaluating a submission. Used
/// by the `audit next` driver, which learns which candidates a stage requires
/// from the ingested adjudication ledger.
pub fn stage_work_item(
    candidate: &ScannerCandidate,
    parent_packet_digest: &str,
    stage: &str,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    scoped_item(
        &AdjudicationScope::Stage(stage),
        candidate,
        parent_packet_digest,
    )
}

fn stage_item(
    candidate: &ScannerCandidate,
    parent: &str,
    stage: &'static str,
) -> Result<CandidateAdjudicationItem, SecurityAdjudicationError> {
    scoped_item(&AdjudicationScope::Stage(stage), candidate, parent)
}

fn observation_error(id: &str, reason: &str) -> SecurityAdjudicationError {
    SecurityAdjudicationError::CandidateSetup {
        id: id.into(),
        reason: reason.into(),
    }
}

fn observation_string<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a str, SecurityAdjudicationError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| observation_error(key, "host stage observation field missing"))
}

fn candidate_evidence_identity(
    candidate: &ScannerCandidate,
) -> Result<String, SecurityAdjudicationError> {
    if !candidate.evidence_digest.is_empty() {
        Ok(candidate.evidence_digest.clone())
    } else {
        digest_of(candidate)
    }
}

/// Derive only identities physically present in the delivered child packet.
fn stage_packet_identities(
    stage_packet: &Value,
) -> Result<(String, String, Vec<String>, Vec<String>), SecurityAdjudicationError> {
    if stage_packet.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || stage_packet.get("kind").and_then(Value::as_str)
            != Some("legion-audit-adjudication-seat")
    {
        return Err(observation_error(
            "stage",
            "unsupported adjudication seat packet",
        ));
    }
    let stage = observation_string(stage_packet, "stage")?;
    if !matches!(
        stage,
        STAGE_BATCH | STAGE_CONFIRMATION | STAGE_SPOT_CHECK | STAGE_INDIVIDUAL
    ) {
        return Err(observation_error(
            stage,
            "unsupported host adjudication stage",
        ));
    }
    let item = observation_string(stage_packet, "itemId")?;
    let packet = stage_packet
        .get("packet")
        .ok_or_else(|| observation_error(item, "delivered child packet missing"))?;
    let mut representatives = Vec::new();
    let mut members = Vec::new();
    if stage == STAGE_BATCH {
        let clusters = packet
            .get("clusters")
            .and_then(Value::as_array)
            .ok_or_else(|| observation_error(item, "delivered batch clusters missing"))?;
        for cluster in clusters {
            representatives.push(
                observation_string(
                    cluster.get("representative").unwrap_or(&Value::Null),
                    "findingId",
                )?
                .to_owned(),
            );
            for location in cluster
                .get("memberLocations")
                .and_then(Value::as_array)
                .ok_or_else(|| observation_error(item, "delivered cluster members missing"))?
            {
                members.push(observation_string(location, "findingId")?.to_owned());
            }
        }
    } else {
        let candidate = packet
            .get("candidate")
            .ok_or_else(|| observation_error(item, "delivered candidate missing"))?;
        let id = observation_string(candidate, "id")?;
        if stage_packet.get("candidateId").and_then(Value::as_str) != Some(id) {
            return Err(observation_error(item, "stage candidate identity mismatch"));
        }
        representatives.push(id.to_owned());
        members.push(id.to_owned());
    }
    for ids in [&mut representatives, &mut members] {
        ids.sort();
        if ids.is_empty() || ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(observation_error(
                item,
                "delivered stage identities must be nonempty and unique",
            ));
        }
    }
    Ok((stage.into(), item.into(), representatives, members))
}

fn candidate_source_side(candidate: &ScannerCandidate) -> &str {
    candidate
        .source_mapping
        .get("sourceSide")
        .or_else(|| candidate.source_mapping.pointer("/evidence/0/sourceSide"))
        .and_then(Value::as_str)
        .unwrap_or("selected")
}

fn delivered_inline(packet: &Value, candidate: &ScannerCandidate) -> bool {
    let Some(excerpt) = candidate
        .evidence_excerpt
        .as_deref()
        .filter(|text| !text.trim().is_empty())
    else {
        return false;
    };
    let matches = |value: &Value| {
        value.get("path").and_then(Value::as_str) == candidate.path.as_deref()
            && value.get("line").and_then(Value::as_u64) == candidate.line
            && value.get("excerpt").and_then(Value::as_str) == Some(excerpt)
    };
    if packet.pointer("/candidate/id").and_then(Value::as_str)
        == Some(candidate.finding_id.as_str())
    {
        return packet
            .pointer("/candidate/evidence")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(matches));
    }
    packet
        .get("clusters")
        .and_then(Value::as_array)
        .is_some_and(|clusters| {
            clusters.iter().any(|cluster| {
                let contains = cluster
                    .get("memberLocations")
                    .and_then(Value::as_array)
                    .is_some_and(|members| {
                        members.iter().any(|member| {
                            member.get("findingId").and_then(Value::as_str)
                                == Some(candidate.finding_id.as_str())
                        })
                    });
                contains && cluster.get("representative").is_some_and(matches)
            })
        })
}

/// Trusted runtime helper. `host` must be process/transport observations from
/// the host, never copied from model JSON. It derives a child-only receipt;
/// signing/authentication belongs to ingest's per-run epoch sidecar.
pub fn stage_observation(
    stage_packet: &Value,
    verdicts: &[Value],
    host: &Value,
    parent_candidates: &[ScannerCandidate],
) -> Result<Value, SecurityAdjudicationError> {
    validate_candidate_ids(parent_candidates)?;
    let (stage, item, representatives, members) = stage_packet_identities(stage_packet)?;
    if host.get("sent").and_then(Value::as_bool) != Some(true)
        || host.get("processCreated").and_then(Value::as_bool) != Some(true)
        || host.get("error").is_some_and(|value| !value.is_null())
    {
        return Err(observation_error(
            &item,
            "successful observed process and transport required",
        ));
    }
    let context = observation_string(host, "contextId")?;
    let pid = host
        .get("processId")
        .and_then(Value::as_u64)
        .filter(|pid| *pid > 0)
        .ok_or_else(|| observation_error(&item, "observed process ID missing"))?;
    let response = observation_string(host, "responseDigest")?;
    let packet = stage_packet
        .get("packet")
        .ok_or_else(|| observation_error(&item, "child packet missing"))?;
    let mut verdict_digests = serde_json::Map::new();
    for row in verdicts {
        let id = observation_string(row, "candidateId")?;
        if !representatives.iter().any(|expected| expected == id)
            || row.get("stage").and_then(Value::as_str) != Some(stage.as_str())
            || row.get("workItemId").and_then(Value::as_str) != Some(item.as_str())
            || row.get("workPacketDigest").and_then(Value::as_str)
                != Some(digest_of(packet)?.as_str())
        {
            return Err(observation_error(
                id,
                "observed verdict is not bound to the delivered stage",
            ));
        }
        if verdict_digests
            .insert(id.into(), json!(digest_of(row)?))
            .is_some()
        {
            return Err(observation_error(id, "duplicate observed verdict"));
        }
    }
    let mut sources = Vec::new();
    for id in &members {
        let candidate = parent_candidates
            .iter()
            .find(|candidate| &candidate.finding_id == id)
            .ok_or_else(|| observation_error(id, "delivered candidate absent from parent"))?;
        let Some((path, line)) = candidate.path.as_deref().zip(candidate.line) else {
            continue;
        };
        if line == 0
            || matches!(
                candidate.location_status.as_str(),
                "invalid" | "conflicting" | "unknown"
            )
        {
            continue;
        }
        let end = candidate.end_line.unwrap_or(line);
        let raw = host
            .get("deliveredExcerpts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|excerpt| {
                excerpt.get("path").and_then(Value::as_str) == Some(path)
                    && excerpt
                        .get("sourceSide")
                        .and_then(Value::as_str)
                        .unwrap_or("selected")
                        == candidate_source_side(candidate)
                    && excerpt.get("mode").and_then(Value::as_str) == Some("raw")
                    && excerpt.get("truncated").and_then(Value::as_bool) != Some(true)
                    && excerpt
                        .get("redactedRanges")
                        .and_then(Value::as_array)
                        .is_none_or(Vec::is_empty)
                    && excerpt
                        .get("content")
                        .and_then(Value::as_str)
                        .is_some_and(|content| {
                            excerpt
                                .get("startLine")
                                .and_then(Value::as_u64)
                                .zip(excerpt.get("endLine").and_then(Value::as_u64))
                                .is_some_and(|(start, last)| {
                                    last >= start
                                        && content.lines().count() as u64 >= last - start + 1
                                })
                        })
                    && excerpt
                        .get("startLine")
                        .and_then(Value::as_u64)
                        .is_some_and(|start| start > 0 && start <= line)
                    && excerpt
                        .get("endLine")
                        .and_then(Value::as_u64)
                        .is_some_and(|last| last >= end)
            });
        let (last, delivery_kind, content_digest) = if let Some(raw) = raw {
            (end, "raw-excerpt", digest_of(raw)?)
        } else if delivered_inline(packet, candidate) {
            (
                line,
                "inline-evidence",
                digest_of(&candidate.evidence_excerpt)?,
            )
        } else {
            continue;
        };
        sources.push(json!({"candidateId":id,"path":path,"sourceSide":candidate_source_side(candidate),"startLine":line,"endLine":last,
            "evidenceDigest":candidate_evidence_identity(candidate)?,"deliveryKind":delivery_kind,"contentDigest":content_digest}));
    }
    Ok(
        json!({"schemaVersion":1,"kind":"legion-adjudication-stage-observation","stage":stage,
        "workItemId":item,"workPacketDigest":digest_of(packet)?,"candidateIds":representatives,
        "deliveredCandidateIds":members,"observedContextId":context,"processId":pid,"processCreated":true,
        "processCreationTicks":host.get("processCreationTicks"),"responseDigest":response,"verdictDigests":verdict_digests,
        "deliveredPacketBytes":canonical_json_bytes(packet).map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))?.len(),
        "complete":true,"truncated":false,"sourceDelivery":sources}),
    )
}

/// Consume only observations authenticated by ingest's host epoch sidecar.
/// Missing transport/source receipts are explicit gaps; mismatched identities,
/// tampering, replay, or real context/process reuse are errors. Model context
/// labels remain routing fields and confer no delivery/isolation authority.
pub fn validate_stage_observations(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
    observations: &[Value],
) -> Result<Vec<String>, SecurityAdjudicationError> {
    validate_candidate_ids(candidates)?;
    let mut gaps = BTreeSet::new();
    let mut seen_observations = BTreeSet::new();
    let mut contexts = BTreeSet::new();
    let mut processes = BTreeSet::new();
    let mut matched = BTreeSet::new();
    for observation in observations {
        let item = observation_string(observation, "workItemId")?;
        let stage = observation_string(observation, "stage")?;
        if observation.get("schemaVersion").and_then(Value::as_u64) != Some(1)
            || observation.get("kind").and_then(Value::as_str)
                != Some("legion-adjudication-stage-observation")
            || observation.get("complete").and_then(Value::as_bool) != Some(true)
            || observation.get("truncated").and_then(Value::as_bool) != Some(false)
            || observation.get("processCreated").and_then(Value::as_bool) != Some(true)
        {
            return Err(observation_error(
                item,
                "incomplete or malformed authenticated stage observation",
            ));
        }
        let context = observation_string(observation, "observedContextId")?;
        let pid = observation
            .get("processId")
            .and_then(Value::as_u64)
            .filter(|pid| *pid > 0)
            .ok_or_else(|| observation_error(item, "observed process ID missing"))?;
        let response_digest = observation_string(observation, "responseDigest")?;
        if !seen_observations.insert((stage, item, context, response_digest))
            || !contexts.insert(context)
            || !processes.insert((
                pid,
                observation
                    .get("processCreationTicks")
                    .and_then(Value::as_u64),
            ))
        {
            return Err(observation_error(
                item,
                "stage observation replay or actual host context/process reuse",
            ));
        }
        let (packet, mut expected_ids, mut members) = if stage == STAGE_BATCH {
            let batch = plan
                .batches
                .iter()
                .find(|batch| batch.item_id == item)
                .ok_or_else(|| observation_error(item, "observed batch is not in frozen plan"))?;
            let clusters = plan
                .clusters
                .iter()
                .filter(|cluster| batch.cluster_ids.contains(&cluster.cluster_id));
            let mut representatives = Vec::new();
            let mut members = Vec::new();
            for cluster in clusters {
                representatives.push(cluster.representative_id.clone());
                members.extend(cluster.member_ids.clone());
            }
            (batch.packet.clone(), representatives, members)
        } else if matches!(
            stage,
            STAGE_CONFIRMATION | STAGE_SPOT_CHECK | STAGE_INDIVIDUAL
        ) {
            let mut found = None;
            for candidate in candidates {
                let work = stage_work_item(candidate, &plan.parent_packet_digest, stage)?;
                if work.item_id == item {
                    found = Some((
                        serde_json::to_value(work.packet).map_err(|error| {
                            SecurityAdjudicationError::Digest(error.to_string())
                        })?,
                        vec![candidate.finding_id.clone()],
                        vec![candidate.finding_id.clone()],
                    ));
                    break;
                }
            }
            found.ok_or_else(|| {
                observation_error(item, "observed individual stage is not in frozen plan")
            })?
        } else {
            return Err(observation_error(item, "unknown authenticated stage"));
        };
        expected_ids.sort();
        members.sort();
        if observation.get("candidateIds") != Some(&json!(expected_ids))
            || observation.get("deliveredCandidateIds") != Some(&json!(members))
            || observation.get("workPacketDigest").and_then(Value::as_str)
                != Some(digest_of(&packet)?.as_str())
            || observation
                .get("deliveredPacketBytes")
                .and_then(Value::as_u64)
                != Some(
                    canonical_json_bytes(&packet)
                        .map_err(|error| SecurityAdjudicationError::Digest(error.to_string()))?
                        .len() as u64,
                )
        {
            return Err(observation_error(
                item,
                "authenticated delivery differs from exact frozen stage packet",
            ));
        }
        let verdicts = observation
            .get("verdictDigests")
            .and_then(Value::as_object)
            .ok_or_else(|| observation_error(item, "host verdict digest ledger missing"))?;
        let mut active = false;
        for (id, digest) in verdicts {
            if !expected_ids.contains(id) {
                return Err(observation_error(
                    id,
                    "observed nonrepresentative or foreign verdict",
                ));
            }
            let row = submitted.iter().find(|row| {
                row.get("stage").and_then(Value::as_str) == Some(stage)
                    && row.get("workItemId").and_then(Value::as_str) == Some(item)
                    && row.get("candidateId").and_then(Value::as_str) == Some(id.as_str())
            });
            // Prior physical attempts remain authenticated history. Only the
            // exact currently submitted row may supply completion evidence.
            if let Some(row) = row {
                if digest.as_str() == Some(digest_of(row)?.as_str()) {
                    matched.insert((stage.to_owned(), item.to_owned(), id.clone()));
                    active = true;
                }
            }
        }
        if !active {
            continue;
        }
        let source_rows = observation
            .get("sourceDelivery")
            .and_then(Value::as_array)
            .ok_or_else(|| observation_error(item, "host source delivery ledger missing"))?;
        let mut source_ids = BTreeSet::new();
        for source in source_rows {
            let id = observation_string(source, "candidateId")?;
            if !source_ids.insert(id) || !members.iter().any(|member| member == id) {
                return Err(observation_error(
                    id,
                    "duplicate or foreign source delivery",
                ));
            }
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.finding_id == id)
                .ok_or_else(|| observation_error(id, "source candidate absent"))?;
            if source.get("path").and_then(Value::as_str) != candidate.path.as_deref()
                || source.get("sourceSide").and_then(Value::as_str)
                    != Some(candidate_source_side(candidate))
                || source.get("startLine").and_then(Value::as_u64) != candidate.line
                || source.get("evidenceDigest").and_then(Value::as_str)
                    != Some(candidate_evidence_identity(candidate)?.as_str())
            {
                return Err(observation_error(
                    id,
                    "source delivery does not match frozen candidate evidence",
                ));
            }
            observation_string(source, "contentDigest")?;
            if source
                .get("endLine")
                .and_then(Value::as_u64)
                .zip(candidate.end_line.or(candidate.line))
                .is_none_or(|(delivered, required)| delivered < required)
            {
                gaps.insert(format!(
                    "adjudication-source-unread:{stage}:{item}:{id}:required range not delivered"
                ));
            }
        }
        for id in &members {
            let candidate = candidates
                .iter()
                .find(|candidate| &candidate.finding_id == id)
                .ok_or_else(|| observation_error(id, "stage member absent"))?;
            if context == generator_context_id(candidate) {
                return Err(observation_error(
                    id,
                    "actual adjudicator context equals generator context",
                ));
            }
            if !source_ids.contains(id.as_str()) {
                gaps.insert(format!(
                    "adjudication-source-unread:{stage}:{item}:{id}:source evidence not delivered"
                ));
            }
        }
    }
    for row in submitted {
        let stage = observation_string(row, "stage")?;
        let item = observation_string(row, "workItemId")?;
        let id = observation_string(row, "candidateId")?;
        if !matched.contains(&(stage.into(), item.into(), id.into())) {
            gaps.insert(format!("adjudication-host-unverified:{stage}:{item}:{id}:missing authenticated host observation"));
        }
    }
    Ok(gaps.into_iter().collect())
}

/// Validate every submitted verdict of one single-candidate stage that is
/// required; verdicts for candidates that are not required are ignored and
/// recorded as superseded.
fn validate_stage(
    stage: &'static str,
    wanted: &BTreeSet<String>,
    values: &[&Value],
    by_id: &BTreeMap<&str, &ScannerCandidate>,
    parent: &str,
    superseded: &mut Vec<String>,
) -> Result<BTreeMap<String, SecurityVerdict>, SecurityAdjudicationError> {
    let mut candidates = Vec::new();
    let mut accepted = Vec::new();
    for (index, value) in values.iter().enumerate() {
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
        if !wanted.contains(id) {
            superseded.push(format!("{stage}:{id}"));
            continue;
        }
        let item = stage_item(candidate, parent, stage)?;
        check_binding(value, id, &item.item_id, &digest_of(&item.packet)?)?;
        candidates.push(candidate.clone());
        accepted.push((*value).clone());
    }
    let rows = adjudicate_scanner_candidates_scoped(
        &candidates,
        &accepted,
        parent,
        ContextPolicy::Attested,
        &AdjudicationScope::Stage(stage),
    )?;
    Ok(rows
        .into_iter()
        .map(|row| (row.candidate_id.clone(), row))
        .collect())
}

/// Evaluate a full submission (all stages, any order) against the plan.
///
/// Hard errors mean the submission is invalid (forged binding, wrong context,
/// thin or copied text, unknown candidates). A submission that is merely
/// incomplete is not an error: its gaps are in the ledger and the affected
/// candidates have no final row, so they can never count as adjudicated.
pub fn evaluate_adjudication(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<AdjudicationOutcome, SecurityAdjudicationError> {
    evaluate_internal(plan, candidates, submitted).map(|(outcome, _)| outcome)
}

fn evaluate_internal(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<(AdjudicationOutcome, Vec<Requirement>), SecurityAdjudicationError> {
    let parent = plan.parent_packet_digest.as_str();
    validate_candidate_ids(candidates)?;
    let mut by_id: BTreeMap<&str, &ScannerCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_id
            .entry(candidate.finding_id.as_str())
            .or_insert(candidate);
    }
    let clusters: BTreeMap<&str, &Cluster> = plan
        .clusters
        .iter()
        .map(|cluster| (cluster.cluster_id.as_str(), cluster))
        .collect();
    let mut batch_of: BTreeMap<&str, &str> = BTreeMap::new();
    for batch in &plan.batches {
        for cluster_id in &batch.cluster_ids {
            if let Some(cluster) = clusters.get(cluster_id.as_str()) {
                for member in &cluster.member_ids {
                    batch_of.insert(member.as_str(), batch.batch_id.as_str());
                }
            }
        }
    }

    // Partition the submission by stage.
    let mut batch_values: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    let mut spot_values: Vec<&Value> = Vec::new();
    let mut individual_values: Vec<&Value> = Vec::new();
    let mut confirmation_values: Vec<&Value> = Vec::new();
    let mut submitted_keys = BTreeSet::new();
    for (index, value) in submitted.iter().enumerate() {
        let id = value
            .get("candidateId")
            .and_then(Value::as_str)
            .ok_or(SecurityAdjudicationError::MissingCandidateId(index))?
            .to_owned();
        if !by_id.contains_key(id.as_str()) {
            return Err(SecurityAdjudicationError::UnknownCandidate { index, id });
        }
        let malformed = |reason: &str| SecurityAdjudicationError::MalformedVerdict {
            id: id.clone(),
            reason: reason.to_owned(),
        };
        let stage = value.get("stage").and_then(Value::as_str);
        if !submitted_keys.insert((stage, id.clone())) {
            return Err(SecurityAdjudicationError::DuplicateVerdict { index, id });
        }
        match stage {
            Some(STAGE_BATCH) => {
                let batch_id = value
                    .get("batchId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("batch verdict requires batchId"))?;
                let batch = plan
                    .batches
                    .iter()
                    .find(|batch| batch.batch_id == batch_id)
                    .ok_or_else(|| malformed("batch verdict names an unknown batch"))?;
                let representatives = batch
                    .cluster_ids
                    .iter()
                    .filter_map(|id| clusters.get(id.as_str()))
                    .map(|cluster| cluster.representative_id.as_str())
                    .collect::<BTreeSet<_>>();
                if !representatives.contains(id.as_str()) {
                    return Err(malformed(
                        "batch verdict must name a representative in this batch",
                    ));
                }
                if batch_values
                    .get(batch.batch_id.as_str())
                    .is_some_and(|values| {
                        values.iter().any(|value| {
                            value.get("candidateId").and_then(Value::as_str) == Some(id.as_str())
                        })
                    })
                {
                    return Err(SecurityAdjudicationError::DuplicateVerdict { index, id });
                }
                batch_values
                    .entry(batch.batch_id.as_str())
                    .or_default()
                    .push(value);
            }
            Some(STAGE_SPOT_CHECK) => spot_values.push(value),
            Some(STAGE_INDIVIDUAL) => individual_values.push(value),
            Some(STAGE_CONFIRMATION) => confirmation_values.push(value),
            Some(_) => return Err(malformed("unknown adjudication stage")),
            None => return Err(malformed("verdict requires its stage")),
        }
    }

    let mut outstanding: Vec<String> = Vec::new();
    let mut superseded: Vec<String> = Vec::new();
    let mut requirements: Vec<Requirement> = Vec::new();

    // Stage 1: batches. A batch is adjudicated only once every cluster
    // representative has its verdict.
    let mut batch_rows: BTreeMap<&str, Vec<SecurityVerdict>> = BTreeMap::new();
    let mut batches_ingested = 0usize;
    for batch in &plan.batches {
        let batch_digest = digest_of(&batch.packet)?;
        let batch_clusters = batch
            .cluster_ids
            .iter()
            .filter_map(|id| clusters.get(id.as_str()).copied().cloned())
            .collect::<Vec<_>>();
        let values = batch_values
            .get(batch.batch_id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut present = BTreeSet::new();
        for value in &values {
            if let Some(id) = value.get("candidateId").and_then(Value::as_str) {
                check_binding(value, id, &batch.item_id, &batch_digest)?;
                present.insert(id.to_owned());
            }
        }
        let missing = batch_clusters
            .iter()
            .filter(|cluster| !present.contains(&cluster.representative_id))
            .count();
        if missing > 0 {
            outstanding.push(outstanding_batch(&batch.batch_id, missing));
            continue;
        }
        let members = batch_clusters
            .iter()
            .flat_map(|cluster| cluster.member_ids.iter())
            .filter_map(|id| by_id.get(id.as_str()).copied().cloned())
            .collect::<Vec<_>>();
        let verdicts = values
            .iter()
            .map(|value| (*value).clone())
            .collect::<Vec<_>>();
        let rows = adjudicate_scanner_candidates_scoped(
            &members,
            &verdicts,
            parent,
            batch.context_policy,
            &AdjudicationScope::Batch {
                batch,
                clusters: &batch_clusters,
            },
        )?;
        batches_ingested += 1;
        batch_rows.insert(batch.batch_id.as_str(), rows);
    }

    // Stage 2a: spot-checks of routine dismissals, per batch.
    let mut spot_required: BTreeMap<String, String> = BTreeMap::new();
    for batch in &plan.batches {
        let Some(rows) = batch_rows.get(batch.batch_id.as_str()) else {
            continue;
        };
        let mut pool = Vec::new();
        for row in rows {
            let Some(candidate) = by_id.get(row.candidate_id.as_str()).copied() else {
                continue;
            };
            if row.verdict.is_dismissal() && individual_reason(candidate, row.verdict).is_none() {
                pool.push(row.candidate_id.clone());
            }
        }
        pool.sort();
        let all = rows.iter().collect::<Vec<_>>();
        for id in spot_check_selection(parent, &batch.batch_id, &all, &pool)? {
            spot_required.insert(id, batch.batch_id.clone());
        }
    }
    let spot_wanted = spot_required.keys().cloned().collect::<BTreeSet<_>>();
    let spot_rows = validate_stage(
        STAGE_SPOT_CHECK,
        &spot_wanted,
        &spot_values,
        &by_id,
        parent,
        &mut superseded,
    )?;
    let mut voided: BTreeSet<String> = BTreeSet::new();
    for (id, batch_id) in &spot_required {
        match spot_rows.get(id) {
            Some(row) if !row.verdict.is_dismissal() => {
                voided.insert(batch_id.clone());
            }
            Some(_) => {}
            None => {}
        }
        requirements.push(Requirement {
            stage: STAGE_SPOT_CHECK,
            candidate_id: id.clone(),
            reason: "seeded spot-check of a routine dismissal".to_owned(),
            batch_id: Some(batch_id.clone()),
            satisfied: spot_rows.contains_key(id),
        });
        if !spot_rows.contains_key(id) {
            outstanding.push(outstanding_stage(STAGE_SPOT_CHECK, id));
        }
    }

    // Stage 2b: individual review of high-risk or uncertain dismissals, and a
    // one-candidate-per-context rerun of every voided batch.
    let mut individual_required: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    for batch in &plan.batches {
        let Some(rows) = batch_rows.get(batch.batch_id.as_str()) else {
            continue;
        };
        let void = voided.contains(&batch.batch_id);
        for row in rows {
            let Some(candidate) = by_id.get(row.candidate_id.as_str()).copied() else {
                continue;
            };
            let reason = if void {
                Some("voided-batch")
            } else {
                individual_reason(candidate, row.verdict)
            };
            if let Some(reason) = reason {
                individual_required.insert(
                    row.candidate_id.clone(),
                    (reason.to_owned(), Some(batch.batch_id.clone())),
                );
            }
        }
    }
    let individual_wanted = individual_required.keys().cloned().collect::<BTreeSet<_>>();
    let individual_rows = validate_stage(
        STAGE_INDIVIDUAL,
        &individual_wanted,
        &individual_values,
        &by_id,
        parent,
        &mut superseded,
    )?;
    for (id, (reason, batch_id)) in &individual_required {
        let satisfied = individual_rows.contains_key(id);
        requirements.push(Requirement {
            stage: STAGE_INDIVIDUAL,
            candidate_id: id.clone(),
            reason: reason.clone(),
            batch_id: batch_id.clone(),
            satisfied,
        });
        if !satisfied {
            outstanding.push(outstanding_individual(id, reason));
        }
    }

    // Stage 3: confirmation of every surviving verdict, wherever it came from.
    // `first` is the verdict a candidate stands on before confirmation.
    let mut first: BTreeMap<String, SecurityVerdict> = BTreeMap::new();
    // Rows that stand on the batch verdict alone, and so only count once the
    // batch's spot-checks are all in.
    let mut batch_standing: BTreeSet<String> = BTreeSet::new();
    for batch in &plan.batches {
        let Some(rows) = batch_rows.get(batch.batch_id.as_str()) else {
            continue;
        };
        for row in rows {
            if let Some(individual) = individual_rows.get(&row.candidate_id) {
                let mut individual = individual.clone();
                individual.cluster_id = row.cluster_id.clone();
                individual.verdict_digest = String::new();
                individual.verdict_digest = digest_of(&individual)?;
                first.insert(row.candidate_id.clone(), individual);
            } else if !individual_required.contains_key(&row.candidate_id) {
                first.insert(row.candidate_id.clone(), row.clone());
                batch_standing.insert(row.candidate_id.clone());
            }
        }
    }
    let confirmation_wanted = first
        .iter()
        .filter(|(_, row)| row.verdict.needs_confirmation())
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let confirmation_rows = validate_stage(
        STAGE_CONFIRMATION,
        &confirmation_wanted,
        &confirmation_values,
        &by_id,
        parent,
        &mut superseded,
    )?;
    let mut contested = Vec::new();
    for id in &confirmation_wanted {
        let satisfied = confirmation_rows.contains_key(id);
        requirements.push(Requirement {
            stage: STAGE_CONFIRMATION,
            candidate_id: id.clone(),
            reason: "single-candidate confirmation of a surviving verdict".to_owned(),
            batch_id: batch_of.get(id.as_str()).map(|batch| (*batch).to_owned()),
            satisfied,
        });
        match confirmation_rows.get(id) {
            None => outstanding.push(outstanding_stage(STAGE_CONFIRMATION, id)),
            Some(row) if !row.verdict.needs_confirmation() => {
                contested.push(id.clone());
                outstanding.push(outstanding_contested(id));
            }
            Some(_) => {}
        }
    }

    // Final rows: a candidate counts only through a verdict that has passed
    // every stage it requires.
    let unchecked_batches = requirements
        .iter()
        .filter(|requirement| requirement.stage == STAGE_SPOT_CHECK && !requirement.satisfied)
        .filter_map(|requirement| requirement.batch_id.clone())
        .collect::<BTreeSet<_>>();
    let mut finals: BTreeMap<String, SecurityVerdict> = BTreeMap::new();
    for (id, row) in &first {
        let unchecked = batch_standing.contains(id)
            && batch_of
                .get(id.as_str())
                .is_some_and(|batch| unchecked_batches.contains(*batch));
        if unchecked {
            continue;
        }
        if confirmation_wanted.contains(id) {
            if let Some(confirmed) = confirmation_rows
                .get(id)
                .filter(|confirmed| confirmed.verdict.needs_confirmation())
            {
                let mut confirmed = confirmed.clone();
                confirmed.cluster_id = row.cluster_id.clone();
                confirmed.verdict_digest = String::new();
                confirmed.verdict_digest = digest_of(&confirmed)?;
                finals.insert(id.clone(), confirmed);
            }
        } else {
            finals.insert(id.clone(), row.clone());
        }
    }
    let ordered = candidates
        .iter()
        .filter_map(|candidate| finals.remove(candidate.finding_id.as_str()))
        .collect::<Vec<_>>();

    let triaged = plan
        .auto_triaged
        .iter()
        .map(|entry| entry.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut accounted = ordered
        .iter()
        .map(|row| row.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    accounted.extend(triaged.iter().copied());
    let unaccounted = candidates
        .iter()
        .filter(|candidate| !accounted.contains(candidate.finding_id.as_str()))
        .count();
    let expected_count = |stage: &str| {
        requirements
            .iter()
            .filter(|requirement| requirement.stage == stage)
            .count()
    };
    let ingested_count = |stage: &str| {
        requirements
            .iter()
            .filter(|requirement| requirement.stage == stage && requirement.satisfied)
            .count()
    };
    let voided_batches = voided.into_iter().collect::<Vec<_>>();
    let ledger = AdjudicationLedger {
        batches: StageCount {
            expected: plan.batches.len(),
            ingested: batches_ingested,
        },
        confirmations: StageCount {
            expected: expected_count(STAGE_CONFIRMATION),
            ingested: ingested_count(STAGE_CONFIRMATION),
        },
        spot_checks: StageCount {
            expected: expected_count(STAGE_SPOT_CHECK),
            ingested: ingested_count(STAGE_SPOT_CHECK),
        },
        individual_reviews: StageCount {
            expected: expected_count(STAGE_INDIVIDUAL),
            ingested: ingested_count(STAGE_INDIVIDUAL),
        },
        auto_triaged: plan.auto_triaged.len(),
        adjudicated: ordered.len(),
        voided_batches,
        contested,
        superseded,
        complete: outstanding.is_empty() && unaccounted == 0,
        outstanding,
    };
    Ok((
        AdjudicationOutcome {
            verdicts: ordered,
            auto_triaged: plan.auto_triaged.clone(),
            ledger,
        },
        requirements,
    ))
}

/// Every single-candidate adjudication the submission so far requires, with
/// its isolated work item. Batches come first; call again after each round of
/// verdicts, because spot-check disagreements and survivors from individual
/// reviews create more required items.
pub fn required_items(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<Vec<StageItem>, SecurityAdjudicationError> {
    let (_, requirements) = evaluate_internal(plan, candidates, submitted)?;
    validate_candidate_ids(candidates)?;
    let mut by_id: BTreeMap<&str, &ScannerCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_id
            .entry(candidate.finding_id.as_str())
            .or_insert(candidate);
    }
    requirements
        .into_iter()
        .map(|requirement| {
            let candidate = by_id
                .get(requirement.candidate_id.as_str())
                .copied()
                .ok_or_else(|| SecurityAdjudicationError::CandidateSetup {
                    id: requirement.candidate_id.clone(),
                    reason: "required item names an unknown candidate".to_owned(),
                })?;
            Ok(StageItem {
                stage: requirement.stage.to_owned(),
                reason: requirement.reason,
                batch_id: requirement.batch_id,
                satisfied: requirement.satisfied,
                item: stage_item(candidate, &plan.parent_packet_digest, requirement.stage)?,
            })
        })
        .collect()
}

fn items_of_stage(
    stage: &str,
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<Vec<StageItem>, SecurityAdjudicationError> {
    Ok(required_items(plan, candidates, submitted)?
        .into_iter()
        .filter(|item| item.stage == stage)
        .collect())
}

/// Single-candidate confirmations of every surviving batch or individual verdict.
pub fn confirmation_items(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<Vec<StageItem>, SecurityAdjudicationError> {
    items_of_stage(STAGE_CONFIRMATION, plan, candidates, submitted)
}

/// The digest-seeded spot-checks of routine dismissals.
pub fn spot_check_items(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<Vec<StageItem>, SecurityAdjudicationError> {
    items_of_stage(STAGE_SPOT_CHECK, plan, candidates, submitted)
}

/// Individual review: high-risk or uncertain dismissals and voided-batch reruns.
pub fn individual_review_items(
    plan: &AdjudicationPlan,
    candidates: &[ScannerCandidate],
    submitted: &[Value],
) -> Result<Vec<StageItem>, SecurityAdjudicationError> {
    items_of_stage(STAGE_INDIVIDUAL, plan, candidates, submitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outstanding_formats_are_stable() {
        // `crate::next` parses these exact shapes from the ledger.
        assert_eq!(
            outstanding_batch("batch-0001", 3),
            "batch:batch-0001:3 cluster representative verdicts missing"
        );
        assert_eq!(outstanding_stage(STAGE_SPOT_CHECK, "c:1"), "spotCheck:c:1");
        assert_eq!(
            outstanding_stage(STAGE_CONFIRMATION, "c:1"),
            "confirmation:c:1"
        );
        assert_eq!(
            outstanding_individual("c:1", "voided-batch"),
            "individual:c:1:voided-batch"
        );
        assert_eq!(outstanding_contested("c:1"), "contested:c:1");
        assert_eq!(STAGE_SPOT_CHECK, "spotCheck");
        assert_eq!(STAGE_INDIVIDUAL, "individual");
        assert_eq!(STAGE_CONFIRMATION, "confirmation");
    }

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

#[cfg(test)]
mod scaled_tests {
    use super::*;

    const PARENT: &str = "sha256:test-parent-packet";

    fn candidate(index: usize, rule: &str, path: &str, excerpt: &str) -> ScannerCandidate {
        ScannerCandidate {
            finding_id: format!("cand-{index:05}"),
            provider: "security.pack".into(),
            rule: rule.into(),
            severity: "medium".into(),
            path: Some(path.into()),
            line: Some(10 + (index % 50) as u64),
            message: format!("{rule} matched"),
            evidence_excerpt: Some(excerpt.into()),
            ..ScannerCandidate::default()
        }
    }

    /// 1,400 candidates: 1,300 ordinary (7 rule families x 40 sinks), 80 in
    /// vendored code, 20 in lock files.
    fn synthetic() -> Vec<ScannerCandidate> {
        let mut candidates = Vec::new();
        for index in 0..1300 {
            let family = index % 7;
            let mut observation = candidate(
                index,
                &format!("fam{family}.check"),
                &format!("src/family{family}/sink{}.rs", (index / 7) % 40),
                &format!("call_sink_{}(input)", (index / 7) % 40),
            );
            observation.line = Some(10);
            candidates.push(observation);
        }
        for index in 1300..1380 {
            candidates.push(candidate(
                index,
                "fam0.check",
                &format!("vendor/lib/file{index}.js"),
                "eval(input)",
            ));
        }
        for index in 1380..1400 {
            candidates.push(candidate(
                index,
                "fam1.check",
                &format!("deps/dir{index}/Cargo.lock"),
                "checksum = \"abc\"",
            ));
        }
        candidates
    }

    fn verdict_json(candidate: &ScannerCandidate, kind: SecurityVerdictKind, tag: &str) -> Value {
        let id = &candidate.finding_id;
        let path = candidate.path.clone().unwrap();
        let mut verdict = json!({
            "candidateId": id,
            "verdict": kind,
            "threatModel": format!("{tag} {id}: attacker model for {path}"),
            "reachability": format!("{tag} {id}: reachable only through {path} wiring"),
            "impact": format!("{tag} {id}: bounded impact assessed here"),
        });
        if kind.is_surviving() {
            let object = verdict.as_object_mut().unwrap();
            object.insert("severity".into(), json!("high"));
            object.insert("attackerControl".into(), json!("full"));
            object.insert("evidenceStrength".into(), json!("observed"));
            object.insert(
                "proof".into(),
                json!(format!("{tag} {id}: trace into {path}")),
            );
            object.insert(
                "devilsAdvocate".into(),
                json!(format!("{tag} {id}: no sanitizer found on the path")),
            );
            object.insert(
                "evidence".into(),
                json!([{"file": path, "line": candidate.line.unwrap()}]),
            );
        }
        verdict
    }

    fn bind(
        mut verdict: Value,
        stage: &str,
        item_id: &str,
        context: &str,
        packet: &impl Serialize,
    ) -> Value {
        let object = verdict.as_object_mut().unwrap();
        object.insert("stage".into(), json!(stage));
        object.insert("workItemId".into(), json!(item_id));
        object.insert(
            "workPacketDigest".into(),
            json!(canonical_digest(packet).unwrap()),
        );
        object.insert("contextId".into(), json!(context));
        verdict
    }

    fn batch_submission(
        plan: &AdjudicationPlan,
        candidates: &[ScannerCandidate],
        decide: &dyn Fn(&str, &ScannerCandidate) -> SecurityVerdictKind,
    ) -> Vec<Value> {
        let by_id = candidates
            .iter()
            .map(|c| (c.finding_id.as_str(), c))
            .collect::<BTreeMap<_, _>>();
        let mut values = Vec::new();
        for batch in &plan.batches {
            for cluster_id in &batch.cluster_ids {
                let cluster = plan
                    .clusters
                    .iter()
                    .find(|cluster| &cluster.cluster_id == cluster_id)
                    .unwrap();
                let rep = by_id[cluster.representative_id.as_str()];
                let mut verdict = verdict_json(rep, decide(STAGE_BATCH, rep), "batch");
                verdict["batchId"] = json!(batch.batch_id);
                verdict["clusterId"] = json!(cluster.cluster_id);
                values.push(bind(
                    verdict,
                    STAGE_BATCH,
                    &batch.item_id,
                    &batch.context_id,
                    &batch.packet,
                ));
            }
        }
        values
    }

    /// Drive the staged protocol to a fixed point. `decide(stage, candidate)`
    /// picks every verdict.
    fn run(
        plan: &AdjudicationPlan,
        candidates: &[ScannerCandidate],
        decide: &dyn Fn(&str, &ScannerCandidate) -> SecurityVerdictKind,
    ) -> (Vec<Value>, AdjudicationOutcome) {
        let by_id = candidates
            .iter()
            .map(|c| (c.finding_id.as_str(), c))
            .collect::<BTreeMap<_, _>>();
        let mut submitted = batch_submission(plan, candidates, decide);
        for _ in 0..8 {
            let pending = required_items(plan, candidates, &submitted)
                .unwrap()
                .into_iter()
                .filter(|item| !item.satisfied)
                .collect::<Vec<_>>();
            if pending.is_empty() {
                break;
            }
            for item in pending {
                let candidate = by_id[item.item.packet.candidate.id.as_str()];
                let kind = decide(item.stage.as_str(), candidate);
                let verdict = verdict_json(candidate, kind, &item.stage);
                submitted.push(bind(
                    verdict,
                    &item.stage,
                    &item.item.item_id,
                    &item.item.context_id,
                    &item.item.packet,
                ));
            }
        }
        let outcome = evaluate_adjudication(plan, candidates, &submitted).unwrap();
        (submitted, outcome)
    }

    fn plan_for(candidates: &[ScannerCandidate]) -> AdjudicationPlan {
        build_adjudication_plan(candidates, &TriageContext::default(), PARENT).unwrap()
    }

    #[test]
    fn plan_bounds_batches_and_types_triage_as_deterministic() {
        let candidates = synthetic();
        assert_eq!(candidates.len(), 1400);
        let plan = plan_for(&candidates);

        assert_eq!(plan.auto_triaged.len(), 100);
        assert!(plan
            .auto_triaged
            .iter()
            .all(|entry| entry.basis == "deterministic"
                && entry.rule_id == TRIAGE_RULE_PATH_EXCLUDED));
        let clustered = plan
            .clusters
            .iter()
            .map(|cluster| cluster.member_ids.len())
            .sum::<usize>();
        assert_eq!(clustered, 1300);
        assert_eq!(plan.clusters.len(), 7 * 40);

        assert!(!plan.batches.is_empty());
        let families = plan
            .batches
            .iter()
            .map(|batch| batch.family.clone())
            .collect::<BTreeSet<_>>();
        assert!(
            plan.batches.len()
                <= plan.clusters.len().div_ceil(MAX_CLUSTERS_PER_BATCH) + families.len()
        );
        for batch in &plan.batches {
            assert!(batch.cluster_ids.len() <= MAX_CLUSTERS_PER_BATCH);
            assert!(batch.estimated_tokens <= MAX_BATCH_TOKENS);
            for cluster_id in &batch.cluster_ids {
                let cluster = plan
                    .clusters
                    .iter()
                    .find(|c| &c.cluster_id == cluster_id)
                    .unwrap();
                assert_eq!(cluster.family, batch.family);
            }
        }
        // Every cluster lands in exactly one batch.
        let batched = plan
            .batches
            .iter()
            .map(|batch| batch.cluster_ids.len())
            .sum::<usize>();
        assert_eq!(batched, plan.clusters.len());
        // Deterministic.
        assert_eq!(plan.to_value(), plan_for(&candidates).to_value());
    }

    #[test]
    fn test_and_fixture_paths_and_redacted_placeholders_are_not_auto_closed() {
        let mut test_secret = candidate(
            1,
            "secrets.api-key",
            "tests/fixtures/vendor/a.rs",
            "k = \"example\"",
        );
        test_secret.finding_id = "cand-test".into();
        let redacted = candidate(2, "secrets.api-key", "src/a.rs", "k = \"[REDACTED]\"");
        let placeholder = candidate(3, "secrets.api-key", "src/b.rs", "k = \"example\"");
        let default_password = candidate(4, "secrets.password", "src/c.rs", "p = \"changeme\"");
        let outcome = triage_candidates(
            &[test_secret, redacted, placeholder, default_password],
            &TriageContext::default(),
        );
        assert_eq!(outcome.auto_triaged.len(), 1);
        assert_eq!(outcome.auto_triaged[0].rule_id, TRIAGE_RULE_PLACEHOLDER);
        assert_eq!(
            outcome.auto_triaged[0].verdict,
            SecurityVerdictKind::FalsePositive
        );
        assert_eq!(outcome.remaining.len(), 3);
    }

    #[test]
    fn native_resolved_fingerprints_close_only_that_location() {
        let resolved = candidate(1, "fam0.check", "src/a.rs", "sink(input)");
        let other = candidate(2, "fam0.check", "src/b.rs", "sink(input)");
        let mut context = TriageContext::default();
        context
            .resolved_fingerprints
            .insert(location_fingerprint(&resolved));
        let outcome = triage_candidates(&[resolved, other], &context);
        assert_eq!(outcome.auto_triaged.len(), 1);
        assert_eq!(outcome.auto_triaged[0].rule_id, TRIAGE_RULE_NATIVE_RESOLVED);
        assert_eq!(outcome.remaining.len(), 1);
    }

    #[test]
    fn cluster_expansion_keeps_every_location() {
        let candidates = synthetic();
        let plan = plan_for(&candidates);
        let dismiss = |_: &str, _: &ScannerCandidate| SecurityVerdictKind::FalsePositive;
        let (_, outcome) = run(&plan, &candidates, &dismiss);
        assert!(outcome.ledger.complete, "{:?}", outcome.ledger.outstanding);
        assert_eq!(outcome.ledger.auto_triaged, 100);
        assert_eq!(outcome.verdicts.len(), 1300);
        let ids = outcome
            .verdicts
            .iter()
            .map(|row| row.candidate_id.clone())
            .collect::<BTreeSet<_>>();
        let expected = candidates[..1300]
            .iter()
            .map(|c| c.finding_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids, expected);
        assert!(outcome.verdicts.iter().all(|row| row.cluster_id.is_some()));
        // Rows of one cluster share a cluster id but keep their own digest.
        let cluster = plan
            .clusters
            .iter()
            .find(|c| c.member_ids.len() > 1)
            .unwrap();
        let rows = outcome
            .verdicts
            .iter()
            .filter(|row| row.cluster_id.as_deref() == Some(cluster.cluster_id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), cluster.member_ids.len());
        let digests = rows
            .iter()
            .map(|row| row.verdict_digest.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(digests.len(), rows.len());
        // Spot-checks ran: at least one per non-empty batch.
        assert!(outcome.ledger.spot_checks.expected >= plan.batches.len());
        assert_eq!(
            outcome.ledger.spot_checks.expected,
            outcome.ledger.spot_checks.ingested
        );
        // Triaged candidates are never counted as adjudicated.
        assert!(outcome.verdicts.iter().all(|row| !outcome
            .auto_triaged
            .iter()
            .any(|t| t.candidate_id == row.candidate_id)));
    }

    #[test]
    fn unconfirmed_survivor_leaves_adjudication_unproven() {
        let candidates = (0..6)
            .map(|i| {
                candidate(
                    i,
                    "fam0.check",
                    &format!("src/m{i}.rs"),
                    &format!("sink_{i}(x)"),
                )
            })
            .collect::<Vec<_>>();
        let plan = plan_for(&candidates);
        let survive = |_: &str, _: &ScannerCandidate| SecurityVerdictKind::TruePositive;
        let batch_only = batch_submission(&plan, &candidates, &survive);
        let outcome = evaluate_adjudication(&plan, &candidates, &batch_only).unwrap();
        assert!(!outcome.ledger.complete);
        assert!(
            outcome.verdicts.is_empty(),
            "an unconfirmed survivor must not count"
        );
        assert!(outcome
            .ledger
            .outstanding
            .iter()
            .any(|entry| entry.starts_with("confirmation:")));
        assert_eq!(outcome.ledger.confirmations.expected, 6);
        assert_eq!(outcome.ledger.confirmations.ingested, 0);
        assert!(confirmed_findings(&candidates, &outcome.verdicts).is_empty());

        let (_, confirmed) = run(&plan, &candidates, &survive);
        assert!(
            confirmed.ledger.complete,
            "{:?}",
            confirmed.ledger.outstanding
        );
        assert_eq!(confirmed.verdicts.len(), 6);
        assert_eq!(
            confirmed_findings(&candidates, &confirmed.verdicts).len(),
            6
        );
    }

    #[test]
    fn confirmation_that_dismisses_a_survivor_is_contested_not_counted() {
        let candidates = vec![candidate(0, "fam0.check", "src/a.rs", "sink(x)")];
        let plan = plan_for(&candidates);
        let decide = |stage: &str, _: &ScannerCandidate| {
            if stage == STAGE_CONFIRMATION {
                SecurityVerdictKind::FalsePositive
            } else {
                SecurityVerdictKind::TruePositive
            }
        };
        let (_, outcome) = run(&plan, &candidates, &decide);
        assert!(!outcome.ledger.complete);
        assert_eq!(outcome.ledger.contested, vec!["cand-00000".to_owned()]);
        assert!(outcome.verdicts.is_empty());
    }

    #[test]
    fn spot_check_disagreement_voids_the_batch_and_reruns_it_per_candidate() {
        // Forty observations of four actual source instances fit one batch.
        // Each equivalence group shares provider, source path, range & excerpt.
        let candidates = (0..40)
            .map(|i| {
                let mut observation = candidate(
                    i,
                    "fam0.check",
                    &format!("src/sink{}.rs", i % 4),
                    &format!("sink_{}(x)", i % 4),
                );
                observation.line = Some(10);
                observation
            })
            .collect::<Vec<_>>();
        let plan = plan_for(&candidates);
        assert_eq!(plan.clusters.len(), 4);
        assert!(plan
            .clusters
            .iter()
            .all(|cluster| cluster.member_ids.len() == 10));
        assert_eq!(plan.batches.len(), 1);
        let dismiss = |_: &str, _: &ScannerCandidate| SecurityVerdictKind::FalsePositive;
        let mut submitted = batch_submission(&plan, &candidates, &dismiss);

        // The seeded spot-check disagrees with the batch.
        let spot = spot_check_items(&plan, &candidates, &submitted).unwrap();
        assert_eq!(spot.len(), 2, "ceil(5% x 40) spot-checks");
        let by_id = candidates
            .iter()
            .map(|c| (c.finding_id.as_str(), c))
            .collect::<BTreeMap<_, _>>();
        for item in &spot {
            let candidate = by_id[item.item.packet.candidate.id.as_str()];
            let kind = if item.item.packet.candidate.id == spot[0].item.packet.candidate.id {
                SecurityVerdictKind::TruePositive
            } else {
                SecurityVerdictKind::FalsePositive
            };
            submitted.push(bind(
                verdict_json(candidate, kind, "spot"),
                STAGE_SPOT_CHECK,
                &item.item.item_id,
                &item.item.context_id,
                &item.item.packet,
            ));
        }
        let outcome = evaluate_adjudication(&plan, &candidates, &submitted).unwrap();
        assert_eq!(outcome.ledger.voided_batches, vec!["batch-0001".to_owned()]);
        assert!(!outcome.ledger.complete);
        assert!(
            outcome.verdicts.is_empty(),
            "a voided batch yields no accepted rows"
        );
        let individual = individual_review_items(&plan, &candidates, &submitted).unwrap();
        assert_eq!(individual.len(), 40, "one candidate per context");
        assert!(individual.iter().all(|item| item.reason == "voided-batch"));
        let batch_context = &plan.batches[0].context_id;
        assert!(individual
            .iter()
            .all(|item| &item.item.context_id != batch_context));

        // Rerun alone: dismissals stand on their own contexts.
        for item in individual {
            let candidate = by_id[item.item.packet.candidate.id.as_str()];
            submitted.push(bind(
                verdict_json(candidate, SecurityVerdictKind::FalsePositive, "indiv"),
                STAGE_INDIVIDUAL,
                &item.item.item_id,
                &item.item.context_id,
                &item.item.packet,
            ));
        }
        let rerun = evaluate_adjudication(&plan, &candidates, &submitted).unwrap();
        assert!(rerun.ledger.complete, "{:?}", rerun.ledger.outstanding);
        assert_eq!(rerun.verdicts.len(), 40);
        assert!(rerun
            .verdicts
            .iter()
            .all(|row| &row.adjudicator_context_id != batch_context));
    }

    #[test]
    fn high_risk_and_uncertain_dismissals_go_straight_to_individual_review() {
        let mut high = candidate(0, "fam0.check", "src/a.rs", "sink_a(x)");
        high.severity = "high".into();
        let uncertain = candidate(1, "fam0.check", "src/b.rs", "sink_b(x)");
        let routine = candidate(2, "fam0.check", "src/c.rs", "sink_c(x)");
        let candidates = vec![high, uncertain, routine];
        let plan = plan_for(&candidates);
        let decide = |stage: &str, c: &ScannerCandidate| {
            if stage == STAGE_BATCH && c.finding_id == "cand-00001" {
                SecurityVerdictKind::LikelyFalsePositive
            } else {
                SecurityVerdictKind::FalsePositive
            }
        };
        let submitted = batch_submission(&plan, &candidates, &decide);
        let individual = individual_review_items(&plan, &candidates, &submitted).unwrap();
        let reasons = individual
            .iter()
            .map(|item| (item.item.packet.candidate.id.clone(), item.reason.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(reasons["cand-00000"], "high-risk-dismissal");
        assert_eq!(reasons["cand-00001"], "uncertain-dismissal");
        assert_eq!(reasons.len(), 2);
        // The routine dismissal is the only spot-check candidate.
        let spot = spot_check_items(&plan, &candidates, &submitted).unwrap();
        assert_eq!(spot.len(), 1);
        assert_eq!(spot[0].item.packet.candidate.id, "cand-00002");
        let outcome = evaluate_adjudication(&plan, &candidates, &submitted).unwrap();
        assert!(!outcome.ledger.complete);
        assert!(
            outcome.verdicts.is_empty(),
            "a batch with a pending spot-check withholds its routine dismissals"
        );
    }

    #[test]
    fn echoed_or_missing_context_ids_never_satisfy_isolation() {
        let candidates = vec![candidate(0, "fam0.check", "src/a.rs", "sink(x)")];
        let plan = plan_for(&candidates);
        let dismiss = |_: &str, _: &ScannerCandidate| SecurityVerdictKind::FalsePositive;
        let good = batch_submission(&plan, &candidates, &dismiss);

        let mut wrong = good.clone();
        wrong[0]["contextId"] = json!("adjudicator:sha256:forged");
        assert!(matches!(
            evaluate_adjudication(&plan, &candidates, &wrong).unwrap_err(),
            SecurityAdjudicationError::UnexpectedContext { .. }
        ));
        let mut missing = good.clone();
        missing[0].as_object_mut().unwrap().remove("contextId");
        assert!(matches!(
            evaluate_adjudication(&plan, &candidates, &missing).unwrap_err(),
            SecurityAdjudicationError::MissingContextAttestation(_)
        ));
        // The generator's context is never acceptable.
        let mut generator = good.clone();
        generator[0]["contextId"] = json!("scanner:security.pack");
        assert!(matches!(
            evaluate_adjudication(&plan, &candidates, &generator).unwrap_err(),
            SecurityAdjudicationError::GeneratorContext(_)
        ));
        // A spot-check/confirmation context may not be the batch context.
        let spot = spot_check_items(&plan, &candidates, &good).unwrap();
        assert!(spot
            .iter()
            .all(|item| item.item.context_id != plan.batches[0].context_id));
    }

    #[test]
    fn unbound_or_unstaged_verdicts_are_rejected() {
        let candidates = vec![candidate(0, "fam0.check", "src/a.rs", "sink(x)")];
        let plan = plan_for(&candidates);
        let dismiss = |_: &str, _: &ScannerCandidate| SecurityVerdictKind::FalsePositive;
        let mut forged = batch_submission(&plan, &candidates, &dismiss);
        forged[0]["workItemId"] = json!("sha256:forged");
        assert!(evaluate_adjudication(&plan, &candidates, &forged)
            .unwrap_err()
            .to_string()
            .contains("not bound to its isolated work item"));
        let mut unstaged = batch_submission(&plan, &candidates, &dismiss);
        unstaged[0].as_object_mut().unwrap().remove("stage");
        assert!(evaluate_adjudication(&plan, &candidates, &unstaged).is_err());
    }

    #[test]
    fn batch_scope_expands_every_member_and_validates_representatives_only() {
        let candidates = (0..3)
            .map(|i| {
                let mut observation = candidate(i, "fam0.check", "src/shared.rs", "same_sink(x)");
                observation.line = Some(10);
                observation
            })
            .collect::<Vec<_>>();
        let plan = plan_for(&candidates);
        assert_eq!(plan.clusters.len(), 1);
        // Identical scanner text in another source file is a separate instance.
        let mut other_source = candidates[0].clone();
        other_source.finding_id = "cand-other-source".into();
        other_source.path = Some("src/unrelated.rs".into());
        let mut with_other_source = candidates.clone();
        with_other_source.push(other_source);
        let distinct_plan = plan_for(&with_other_source);
        assert_eq!(distinct_plan.clusters.len(), 2);
        assert!(distinct_plan
            .clusters
            .iter()
            .any(|cluster| cluster.member_ids == ["cand-other-source"]));
        let batch = &plan.batches[0];
        let rep = candidates
            .iter()
            .find(|c| c.finding_id == plan.clusters[0].representative_id)
            .unwrap();
        let verdict = bind(
            verdict_json(rep, SecurityVerdictKind::FalsePositive, "batch"),
            STAGE_BATCH,
            &batch.item_id,
            &batch.context_id,
            &batch.packet,
        );
        let rows = adjudicate_scanner_candidates_scoped(
            &candidates,
            &[verdict.clone()],
            PARENT,
            ContextPolicy::Attested,
            &AdjudicationScope::Batch {
                batch,
                clusters: &plan.clusters,
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row.cluster_id.as_deref() == Some(plan.clusters[0].cluster_id.as_str())));
        // A verdict for a non-representative member is not a batch verdict.
        let other = candidates
            .iter()
            .find(|c| c.finding_id != rep.finding_id)
            .unwrap();
        let mut stray = verdict;
        stray["candidateId"] = json!(other.finding_id);
        assert!(matches!(
            adjudicate_scanner_candidates_scoped(
                &candidates,
                &[stray],
                PARENT,
                ContextPolicy::Attested,
                &AdjudicationScope::Batch {
                    batch,
                    clusters: &plan.clusters,
                },
            )
            .unwrap_err(),
            SecurityAdjudicationError::UnknownCandidate { .. }
        ));
    }
}
