//! Bounded interpretation of imported quality evidence. Native structure/test providers remain
//! the measurement owners; this module neither executes tools nor attests imported claims.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const QUALITY_OBSERVATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_QUALITY_OBSERVATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 10_000;
const MAX_TEXT: usize = 4096;
const MAX_COUNT: u64 = 1_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityObservationInput {
    pub schema_version: u32,
    pub subject: QualitySubject,
    pub report: ImportedQualityReport,
    pub coverage: CoverageObservation,
    pub duplication_candidates: Vec<DuplicationCandidate>,
    pub mutation: MutationObservation,
    #[serde(default)]
    pub thresholds: Option<ScopedQualityThresholds>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualitySubject {
    pub repository: String,
    pub source_digest: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedQualityReport {
    pub provider: String,
    pub provider_version: String,
    pub report_digest: String,
    pub evidence_ref: String,
    pub source_digest: String,
    pub execution_status: QualityExecutionStatus,
    pub completeness: ObservationCompleteness,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum QualityExecutionStatus {
    Succeeded,
    Failed,
    TimedOut,
    InfrastructureFailure,
    NotRun,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ObservationCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CoverageObservation {
    Measured {
        covered: u64,
        total: u64,
        evidence_ref: String,
    },
    Unavailable {
        reason: String,
    },
    NotRequested,
}

/// Candidate similarity is a prompt for investigation, never proof of needless duplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DuplicationCandidate {
    pub id: String,
    pub first_path: String,
    pub second_path: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MutationObservation {
    Measured {
        baseline_status: QualityExecutionStatus,
        outcomes: Vec<MutationOutcome>,
        /// Exactly assertionDetected + survived + uncovered. Invalid, timeout, infrastructure,
        /// not-run and unclassified upstream kills are explicitly excluded.
        declared_denominator: u64,
    },
    Unavailable {
        reason: String,
    },
    NotRequested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationOutcome {
    pub id: String,
    pub path: String,
    pub category: MutationCategory,
    pub upstream_label: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MutationCategory {
    AssertionDetected,
    Survived,
    Uncovered,
    InvalidCompilation,
    Timeout,
    InfrastructureFailure,
    NotRun,
    UpstreamKilledCauseUnclassified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopedQualityThresholds {
    /// Must exactly match subject.paths: a repository aggregate cannot decide a narrower scope.
    pub paths: Vec<String>,
    pub min_coverage_percent: Option<f64>,
    pub min_mutation_detection_percent: Option<f64>,
    pub max_duplication_candidates: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum QualityObservationState {
    Measured,
    Partial,
    Unavailable,
    PolicyAttention,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityObservationSummary {
    pub schema_version: u32,
    pub origin: QualityEvidenceOrigin,
    pub authoritative: bool,
    pub subject: QualitySubject,
    pub report: ImportedQualityReport,
    pub state: QualityObservationState,
    pub coverage: CoverageSummary,
    pub duplication_candidates: Vec<DuplicationCandidate>,
    pub mutation: MutationSummary,
    pub policy_attention: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum QualityEvidenceOrigin {
    Imported,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSummary {
    pub state: QualityObservationState,
    pub covered: Option<u64>,
    pub total: Option<u64>,
    pub percent: Option<f64>,
    pub evidence_ref: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationSummary {
    pub state: QualityObservationState,
    pub baseline_status: Option<QualityExecutionStatus>,
    /// Imported category count, not a validated score numerator when state is unavailable.
    pub assertion_detected: u64,
    pub denominator: u64,
    pub denominator_definition: String,
    pub detection_percent: Option<f64>,
    pub outcomes: Vec<MutationOutcome>,
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid imported quality observation: {0}")]
pub struct QualityObservationError(pub String);

fn invalid(message: impl Into<String>) -> QualityObservationError {
    QualityObservationError(message.into())
}

fn text(value: &str, field: &str) -> Result<(), QualityObservationError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} must be nonempty bounded text without controls"
        )));
    }
    Ok(())
}

fn digest(value: &str, field: &str) -> Result<(), QualityObservationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid(format!(
            "{field} must be a lowercase 64-hex SHA-256 digest"
        )));
    }
    Ok(())
}

/// Portable lexical relative paths only; opening files and defending symlinks belongs to callers.
fn path(value: &str, field: &str) -> Result<(), QualityObservationError> {
    text(value, field)?;
    if value.contains(['\\', ':'])
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(format!(
            "{field} must be a safe relative slash-separated path"
        )));
    }
    Ok(())
}

fn paths(values: &[String], field: &str) -> Result<BTreeSet<String>, QualityObservationError> {
    if values.is_empty() || values.len() > MAX_ITEMS {
        return Err(invalid(format!("{field} has invalid length")));
    }
    let mut result = BTreeSet::new();
    for value in values {
        path(value, field)?;
        if !result.insert(value.clone()) {
            return Err(invalid(format!("{field} contains duplicate paths")));
        }
    }
    Ok(result)
}

fn scoped_path(value: &str, scope: &BTreeSet<String>) -> Result<(), QualityObservationError> {
    path(value, "candidate path")?;
    if !scope.contains(value) {
        return Err(invalid("candidate path is outside subject.paths"));
    }
    Ok(())
}

/// Validate and interpret imported claims. Success means the envelope is internally consistent,
/// never that an external provider, evidence reference, or digest was independently verified.
pub fn summarize_quality(
    input: &QualityObservationInput,
) -> Result<QualityObservationSummary, QualityObservationError> {
    if input.schema_version != QUALITY_OBSERVATION_SCHEMA_VERSION {
        return Err(invalid("unsupported schemaVersion"));
    }
    // Bound every collection before visiting it; bound aggregate serialized bytes without allocating
    // a second large input buffer. CLI callers should also cap bytes before deserialization.
    if input.subject.paths.len() > MAX_ITEMS
        || input
            .thresholds
            .as_ref()
            .is_some_and(|value| value.paths.len() > MAX_ITEMS)
    {
        return Err(invalid("too many scoped paths"));
    }
    if input.duplication_candidates.len() > MAX_ITEMS {
        return Err(invalid("too many duplication candidates"));
    }
    if let MutationObservation::Measured { outcomes, .. } = &input.mutation {
        if outcomes.len() > MAX_ITEMS {
            return Err(invalid("too many mutation outcomes"));
        }
    }
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, input)
        .map_err(|_| invalid("input exceeds byte bound or cannot be represented as JSON"))?;
    text(&input.subject.repository, "subject.repository")?;
    digest(&input.subject.source_digest, "subject.sourceDigest")?;
    let scope = paths(&input.subject.paths, "subject.paths")?;
    let report = &input.report;
    text(&report.provider, "report.provider")?;
    text(&report.provider_version, "report.providerVersion")?;
    digest(&report.report_digest, "report.reportDigest")?;
    digest(&report.source_digest, "report.sourceDigest")?;
    path(&report.evidence_ref, "report.evidenceRef")?;
    if report.source_digest != input.subject.source_digest {
        return Err(invalid(
            "report sourceDigest does not match current subject",
        ));
    }
    let mut ids = BTreeSet::new();
    for candidate in &input.duplication_candidates {
        text(&candidate.id, "duplication candidate id")?;
        if !ids.insert(candidate.id.clone()) {
            return Err(invalid("duplicate evidence id"));
        }
        scoped_path(&candidate.first_path, &scope)?;
        scoped_path(&candidate.second_path, &scope)?;
        path(&candidate.evidence_ref, "duplication evidenceRef")?;
    }
    let succeeded = report.execution_status == QualityExecutionStatus::Succeeded;
    let complete = report.completeness == ObservationCompleteness::Complete;
    let coverage = match &input.coverage {
        CoverageObservation::Measured {
            covered,
            total,
            evidence_ref,
        } => {
            path(evidence_ref, "coverage.evidenceRef")?;
            if covered > total || *total > MAX_COUNT {
                return Err(invalid("invalid coverage denominator"));
            }
            let available = succeeded && *total > 0;
            CoverageSummary {
                state: if !succeeded {
                    QualityObservationState::Unavailable
                } else if !complete || *total == 0 {
                    QualityObservationState::Partial
                } else {
                    QualityObservationState::Measured
                },
                covered: Some(*covered),
                total: Some(*total),
                percent: available.then(|| *covered as f64 * 100.0 / *total as f64),
                evidence_ref: Some(evidence_ref.clone()),
                reason: if !succeeded {
                    Some("report command did not succeed; supplied counts are unverified".into())
                } else if *total == 0 {
                    Some("zero denominator; no coverage percentage".into())
                } else {
                    None
                },
            }
        }
        CoverageObservation::Unavailable { reason } => {
            text(reason, "coverage.reason")?;
            CoverageSummary {
                state: QualityObservationState::Unavailable,
                covered: None,
                total: None,
                percent: None,
                evidence_ref: None,
                reason: Some(reason.clone()),
            }
        }
        CoverageObservation::NotRequested => CoverageSummary {
            state: QualityObservationState::Unavailable,
            covered: None,
            total: None,
            percent: None,
            evidence_ref: None,
            reason: Some("not requested".into()),
        },
    };
    let mut mutation = MutationSummary {
        state: QualityObservationState::Unavailable,
        baseline_status: None,
        assertion_detected: 0,
        denominator: 0,
        denominator_definition:
            "assertionDetected + survived + uncovered; all other categories excluded".into(),
        detection_percent: None,
        outcomes: Vec::new(),
        reason: None,
    };
    match &input.mutation {
        MutationObservation::Measured {
            baseline_status,
            outcomes,
            declared_denominator,
        } => {
            mutation.baseline_status = Some(*baseline_status);
            let mut eligible = 0_u64;
            let mut excluded = false;
            for outcome in outcomes {
                text(&outcome.id, "mutation id")?;
                if !ids.insert(outcome.id.clone()) {
                    return Err(invalid("duplicate evidence id"));
                }
                scoped_path(&outcome.path, &scope)?;
                text(&outcome.upstream_label, "mutation upstreamLabel")?;
                path(&outcome.evidence_ref, "mutation evidenceRef")?;
                match outcome.category {
                    MutationCategory::AssertionDetected => {
                        mutation.assertion_detected += 1;
                        eligible += 1;
                    }
                    MutationCategory::Survived | MutationCategory::Uncovered => eligible += 1,
                    _ => excluded = true,
                }
            }
            if *declared_denominator != eligible {
                return Err(invalid("mutation declaredDenominator must equal assertionDetected + survived + uncovered"));
            }
            mutation.denominator = eligible;
            mutation.outcomes = outcomes.clone();
            if !succeeded || *baseline_status != QualityExecutionStatus::Succeeded {
                mutation.reason = Some("successful report command and passing baseline required; outcomes are unverified".into());
            } else {
                mutation.state = if !complete || excluded || eligible == 0 {
                    QualityObservationState::Partial
                } else {
                    QualityObservationState::Measured
                };
                if eligible > 0 {
                    mutation.detection_percent =
                        Some(mutation.assertion_detected as f64 * 100.0 / eligible as f64);
                }
                if excluded || eligible == 0 {
                    mutation.reason = Some(
                        "excluded or absent outcomes prevent a complete effectiveness measurement"
                            .into(),
                    );
                }
            }
        }
        MutationObservation::Unavailable { reason } => {
            text(reason, "mutation.reason")?;
            mutation.reason = Some(reason.clone());
        }
        MutationObservation::NotRequested => mutation.reason = Some("not requested".into()),
    }
    let mut policy_attention = Vec::new();
    if let Some(thresholds) = &input.thresholds {
        if paths(&thresholds.paths, "thresholds.paths")? != scope {
            return Err(invalid("threshold scope must exactly match subject.paths"));
        }
        for (minimum, actual, name) in [
            (
                thresholds.min_coverage_percent,
                coverage.percent,
                "coverage",
            ),
            (
                thresholds.min_mutation_detection_percent,
                mutation.detection_percent,
                "mutation assertion detection",
            ),
        ] {
            if let Some(minimum) = minimum {
                if !minimum.is_finite() || !(0.0..=100.0).contains(&minimum) {
                    return Err(invalid(
                        "percent thresholds must be finite and within 0..=100",
                    ));
                }
                match actual {
                    Some(value) if value < minimum => policy_attention.push(format!(
                        "{name} {value:.2}% is below scoped minimum {minimum:.2}%"
                    )),
                    None => policy_attention.push(format!(
                        "{name} threshold cannot be evaluated from available evidence"
                    )),
                    _ => {}
                }
            }
        }
        if let Some(maximum) = thresholds.max_duplication_candidates {
            if maximum > MAX_COUNT {
                return Err(invalid("duplication threshold exceeds bound"));
            }
            if !succeeded {
                policy_attention
                    .push("duplication threshold cannot be evaluated after command failure".into());
            } else if input.duplication_candidates.len() as u64 > maximum {
                policy_attention.push("imported duplication candidates exceed scoped investigation threshold; candidates are not proven defects".into());
            }
        }
    }
    // A missing requested measure degrades an otherwise measured result. NotRequested does not.
    let coverage_requested = !matches!(input.coverage, CoverageObservation::NotRequested);
    let mutation_requested = !matches!(input.mutation, MutationObservation::NotRequested);
    let has_measurement = coverage.percent.is_some() || mutation.detection_percent.is_some();
    let incomplete = !complete
        || (coverage_requested && coverage.state != QualityObservationState::Measured)
        || (mutation_requested && mutation.state != QualityObservationState::Measured);
    let state = if !policy_attention.is_empty() {
        QualityObservationState::PolicyAttention
    } else if !succeeded || !has_measurement {
        QualityObservationState::Unavailable
    } else if incomplete {
        QualityObservationState::Partial
    } else {
        QualityObservationState::Measured
    };
    Ok(QualityObservationSummary {
        schema_version: QUALITY_OBSERVATION_SCHEMA_VERSION, origin: QualityEvidenceOrigin::Imported,
        authoritative: false, subject: input.subject.clone(), report: report.clone(), state, coverage,
        duplication_candidates: input.duplication_candidates.clone(), mutation, policy_attention,
        limitations: vec!["Imported evidence is not independently verified; no repository quality verdict is implied.".into(), "Duplication pairs are investigation candidates; mutation assertion detection excludes unclassified upstream kills.".into()],
    })
}

struct ByteCounter(usize);
impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > MAX_QUALITY_OBSERVATION_BYTES {
            return Err(std::io::Error::other("quality observation too large"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Identity comparison permits reuse only under a caller-supplied complete fingerprint. Equality
/// never verifies that hashes were computed honestly or that cached results are true.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityReuseFingerprint {
    pub source_digest: String,
    pub tests_digest: String,
    pub fixtures_digest: String,
    pub toolchain_digest: String,
    pub dependencies_digest: String,
    pub command_digest: String,
    pub config_digest: String,
    pub environment_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityReuseDecision {
    pub reuse_permitted: bool,
    pub verified: bool,
    pub changed_inputs: Vec<String>,
}

pub fn quality_reuse_compatibility(
    cached: &QualityReuseFingerprint,
    current: &QualityReuseFingerprint,
) -> Result<QualityReuseDecision, QualityObservationError> {
    let mut changed_inputs = Vec::new();
    for (name, before, after) in [
        ("source", &cached.source_digest, &current.source_digest),
        ("tests", &cached.tests_digest, &current.tests_digest),
        (
            "fixtures",
            &cached.fixtures_digest,
            &current.fixtures_digest,
        ),
        (
            "toolchain",
            &cached.toolchain_digest,
            &current.toolchain_digest,
        ),
        (
            "dependencies",
            &cached.dependencies_digest,
            &current.dependencies_digest,
        ),
        ("command", &cached.command_digest, &current.command_digest),
        ("config", &cached.config_digest, &current.config_digest),
        (
            "environment",
            &cached.environment_digest,
            &current.environment_digest,
        ),
    ] {
        digest(before, name)?;
        digest(after, name)?;
        if before != after {
            changed_inputs.push(name.into());
        }
    }
    Ok(QualityReuseDecision {
        reuse_permitted: changed_inputs.is_empty(),
        verified: false,
        changed_inputs,
    })
}
