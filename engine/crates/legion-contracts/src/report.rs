use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::source_anchor::{
    build_evidence, line_byte_range, validate_evidence_claims, AnchorValidation,
    SourceAnchorEvidence, SourceSide, SOURCE_ANCHOR_EVIDENCE_KEY,
};
use crate::{
    canonical_digest,
    id::{FindingId, ReportId},
    require_version, ContractError,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: FindingId,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub provider: Option<String>,
    pub locations: Vec<String>,
    pub evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Clean,
    Findings,
    Incomplete,
    Failed,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Report {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub report_id: ReportId,
    pub status: ReportStatus,
    pub findings: Vec<Finding>,
    pub gaps: Vec<String>,
    pub claims: BTreeMap<String, serde_json::Value>,
    pub targets: Vec<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl Report {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        let mut ids = std::collections::BTreeSet::new();
        for finding in &self.findings {
            if !ids.insert(&finding.id) {
                return Err(ContractError::InvalidContract {
                    path: "findings.id".into(),
                    reason: "duplicate finding id".into(),
                });
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
    /// Raw `auditAssuranceV1` extension, if present. Uninterpreted JSON: the
    /// absent, malformed and future-version cases are the caller's to refuse.
    pub fn assurance_extension(&self) -> Option<&Value> {
        self.extensions.get(AUDIT_ASSURANCE_EXTENSION_KEY)
    }
}

// ---------------------------------------------------------------------------
// Report schema v2 (Audit v2 ADR-8 / Council C4)
// ---------------------------------------------------------------------------

pub const REPORT_SCHEMA_V1: u32 = 1;
pub const REPORT_SCHEMA_V2: u32 = 2;

/// Reserved `finding.evidence` key carrying v2-only finding fields in a v1
/// projection (`Finding` denies unknown fields, `evidence` is a map).
pub const V2_FINDING_EVIDENCE_KEY: &str = "legionV2";
/// Reserved report extension key carrying v2-only report fields in a v1
/// projection.
pub const V2_REPORT_EXTENSION_KEY: &str = "legionV2Report";
/// Additive, versioned Audit production-assurance report extension. Reports
/// that lack it stay readable but can never carry release eligibility;
/// malformed or future-versioned content is never interpreted as a pass.
pub const AUDIT_ASSURANCE_EXTENSION_KEY: &str = "auditAssuranceV1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Proven,
    Likely,
    Possible,
    LegacyUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attribution {
    Introduced,
    RegressedElsewhere,
    PreExisting,
    Unresolved,
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Executed,
    Reused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorState {
    /// Positioned in the scoped bytes (no diff tagging requested).
    Resolved,
    InDiff,
    BeyondDiff,
    PositionFailed,
}

/// Diff-mode tag for a positioned anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffTag {
    InDiff,
    BeyondDiff,
}

/// 1-based inclusive line range. A failed anchor may carry `0` or an
/// out-of-range value exactly as claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub path: String,
    pub range: LineRange,
    #[serde(rename = "lineHash")]
    pub line_hash: String,
    pub state: AnchorState,
}

impl Anchor {
    pub fn failed(&self) -> bool {
        self.state == AnchorState::PositionFailed
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingV2 {
    pub id: FindingId,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub provider: Option<String>,
    pub locations: Vec<String>,
    pub evidence: BTreeMap<String, Value>,
    pub confidence: Confidence,
    #[serde(rename = "confidenceBasis")]
    pub confidence_basis: String,
    pub anchor: Option<Anchor>,
    pub attribution: Attribution,
    pub disposition: Disposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportScope {
    pub spec: String,
    #[serde(
        rename = "baseRefOid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub base_ref_oid: Option<String>,
    #[serde(
        rename = "mergeBaseOid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub merge_base_oid: Option<String>,
    pub head: String,
    #[serde(
        rename = "snapshotKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub snapshot_key: Option<String>,
    #[serde(
        rename = "indexSchemaVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub index_schema_version: Option<u32>,
}

impl ReportScope {
    /// Scope of a report read from a v1 document (no scope was recorded).
    pub fn legacy() -> Self {
        Self {
            spec: "legacy-v1".into(),
            base_ref_oid: None,
            merge_base_oid: None,
            head: "unknown".into(),
            snapshot_key: None,
            index_schema_version: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningBudgetUsed {
    pub judgment: u64,
    pub specialist: u64,
    pub mechanical: u64,
    pub seats: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReportV2 {
    #[serde(deserialize_with = "crate::deserialize_schema_version_2")]
    pub schema_version: u32,
    pub report_id: ReportId,
    pub status: ReportStatus,
    pub findings: Vec<FindingV2>,
    pub gaps: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub targets: Vec<String>,
    pub scope: ReportScope,
    #[serde(rename = "unresolvedPossible")]
    pub unresolved_possible: u32,
    #[serde(rename = "reasoningBudgetUsed")]
    pub reasoning_budget_used: ReasoningBudgetUsed,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

fn invalid(path: &str, reason: impl Into<String>) -> ContractError {
    ContractError::InvalidContract {
        path: path.into(),
        reason: reason.into(),
    }
}

// ----- deterministic positioning (P-pos; no model) --------------------------

/// Parses `path:start[-end]` (an optional trailing `:col` is ignored). Returns
/// `None` for a location without a numeric line (a file-level location).
pub fn parse_location(location: &str) -> Option<(String, u32, u32)> {
    let normalized = location.replace('\\', "/");
    let (head, tail) = normalized.rsplit_once(':')?;
    let (path, span) = if tail.chars().all(|c| c.is_ascii_digit()) && !tail.is_empty() {
        match head.rsplit_once(':') {
            // `path:line:col`
            Some((path, line)) if !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()) => {
                (path.to_owned(), line.to_owned())
            }
            _ => (head.to_owned(), tail.to_owned()),
        }
    } else {
        (head.to_owned(), tail.to_owned())
    };
    if path.is_empty() {
        return None;
    }
    let (start, end) = span
        .split_once('-')
        .unwrap_or((span.as_str(), span.as_str()));
    let start: u32 = start.parse().ok()?;
    let end: u32 = end.parse().ok()?;
    Some((path, start, end))
}

fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines
}

fn hash_lines(lines: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            hasher.update(b"\n");
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        hasher.update(line);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Resolves an anchor against the scoped bytes of `path`. `bytes` is `None`
/// when the path is not in scope. A claimed line hash must match. Line 0, a
/// reversed range, a range past the end of the file, a missing file or a hash
/// mismatch yields `PositionFailed`.
pub fn position_anchor(
    path: &str,
    start: u32,
    end: u32,
    claimed_hash: Option<&str>,
    bytes: Option<&[u8]>,
    diff: Option<DiffTag>,
) -> Anchor {
    let failed = |hash: Option<&str>| Anchor {
        path: path.to_owned(),
        range: LineRange { start, end },
        line_hash: hash.unwrap_or_default().to_owned(),
        state: AnchorState::PositionFailed,
    };
    let Some(bytes) = bytes else {
        return failed(claimed_hash);
    };
    let lines = split_lines(bytes);
    if start == 0 || end < start || (end as usize) > lines.len() {
        return failed(claimed_hash);
    }
    let computed = hash_lines(&lines[(start as usize - 1)..(end as usize)]);
    if claimed_hash.is_some_and(|claimed| claimed != computed) {
        return failed(claimed_hash);
    }
    Anchor {
        path: path.to_owned(),
        range: LineRange { start, end },
        line_hash: computed,
        state: match diff {
            None => AnchorState::Resolved,
            Some(DiffTag::InDiff) => AnchorState::InDiff,
            Some(DiffTag::BeyondDiff) => AnchorState::BeyondDiff,
        },
    }
}

/// Positions an anchor exactly as [`position_anchor`] & additionally builds
/// canonical byte-exact evidence (see `source_anchor`) when positioning
/// succeeds against the scoped bytes. A failed position yields `None`
/// evidence; it is never repaired by searching for similar text. Evidence
/// byte range covers the anchored lines' content in the original bytes
/// (BOM excluded from line 1 content, CRLF retained between lines).
pub fn position_anchor_canonical(
    path: &str,
    start: u32,
    end: u32,
    claimed_hash: Option<&str>,
    bytes: Option<&[u8]>,
    diff: Option<DiffTag>,
    side: SourceSide,
    repository: Option<&str>,
    snapshot_key: Option<&str>,
) -> (Anchor, Option<SourceAnchorEvidence>) {
    let anchor = position_anchor(path, start, end, claimed_hash, bytes, diff);
    if anchor.failed() {
        return (anchor, None);
    }
    let Some(bytes) = bytes else {
        return (anchor, None);
    };
    let evidence = line_byte_range(bytes, anchor.range).and_then(|byte_range| {
        build_evidence(path, side, repository, snapshot_key, bytes, byte_range).ok()
    });
    (anchor, evidence)
}

// ----- confidence (C4) ------------------------------------------------------

/// Whether the provider declares exact results for the finding's rule class
/// (compiler error, exact advisory version match, verified secret).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exactness {
    Exact,
    Heuristic,
}

/// Phase-4 seam: the verification (reflection) outcome for a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReflectionOutcome {
    NotRun,
    UpheldWithConcreteCase,
    UpheldWithoutCase,
    Disputed,
}

/// An anchored tool hit is never `proven` on location alone.
pub fn classify_confidence(
    anchor: Option<&Anchor>,
    exactness: Exactness,
    reflection: ReflectionOutcome,
) -> (Confidence, &'static str) {
    if anchor.is_some_and(Anchor::failed) {
        return (Confidence::Possible, "position-failed");
    }
    if reflection == ReflectionOutcome::Disputed {
        return (Confidence::Possible, "reflection-disputed");
    }
    if reflection == ReflectionOutcome::UpheldWithConcreteCase && anchor.is_some() {
        return (Confidence::Proven, "reflection-concrete-case");
    }
    if exactness == Exactness::Exact {
        return if anchor.is_some() {
            (Confidence::Proven, "provider-exact-anchor-verified")
        } else {
            (Confidence::Likely, "provider-exact-unanchored")
        };
    }
    if reflection == ReflectionOutcome::UpheldWithoutCase {
        return (Confidence::Likely, "reflection-upheld-without-case");
    }
    if anchor.is_some() {
        (Confidence::Likely, "anchored-tool-hit")
    } else {
        (Confidence::Likely, "unanchored-finding")
    }
}

// ----- status rules (ADR-4 / C4) ---------------------------------------------

fn is_security(finding: &FindingV2) -> bool {
    finding
        .provider
        .as_deref()
        .is_some_and(|provider| provider.split('.').any(|part| part == "security"))
}

/// Unknown severity labels fail closed (treated as at least medium).
fn at_least_medium(severity: &str) -> bool {
    !matches!(
        severity.to_ascii_lowercase().as_str(),
        "low" | "info" | "note" | "none"
    )
}

fn high_or_critical(severity: &str) -> bool {
    matches!(
        severity.to_ascii_lowercase().as_str(),
        "high" | "critical" | "error"
    )
}

impl FindingV2 {
    /// A failed anchor is blocking when the finding is at medium or above, or is
    /// a security finding.
    pub fn required_anchor_failed(&self) -> bool {
        self.anchor.as_ref().is_some_and(Anchor::failed)
            && (at_least_medium(&self.severity) || is_security(self))
    }

    /// Canonical byte-exact anchor evidence carried under the reserved
    /// `sourceAnchor` evidence key, when present. `None` means the finding
    /// has only a legacy anchor (or none); that state is preserved as-is and
    /// is never upgraded by guessing. A present-but-malformed value is an
    /// error, not an absence.
    pub fn source_anchor_evidence(&self) -> Option<Result<SourceAnchorEvidence, ContractError>> {
        let value = self.evidence.get(SOURCE_ANCHOR_EVIDENCE_KEY)?;
        Some(
            serde_json::from_value(value.clone())
                .map_err(|error| invalid("findings.evidence.sourceAnchor", error.to_string())),
        )
    }

    /// Records canonical anchor evidence under the reserved evidence key.
    /// The v1 projection carries `evidence` verbatim, so the extension
    /// round-trips through schema 1 without new top-level fields.
    pub fn set_source_anchor_evidence(
        &mut self,
        evidence: &SourceAnchorEvidence,
    ) -> Result<(), ContractError> {
        let value = serde_json::to_value(evidence)
            .map_err(|error| invalid("findings.evidence.sourceAnchor", error.to_string()))?;
        self.evidence
            .insert(SOURCE_ANCHOR_EVIDENCE_KEY.into(), value);
        Ok(())
    }

    fn v2_fields(&self) -> Value {
        json!({
            "confidence": self.confidence,
            "confidenceBasis": self.confidence_basis,
            "anchor": self.anchor,
            "attribution": self.attribution,
            "disposition": self.disposition,
        })
    }

    /// The v1 `Finding` without any v2 information.
    pub fn v1_core(&self) -> Finding {
        Finding {
            id: self.id.clone(),
            severity: self.severity.clone(),
            title: self.title.clone(),
            message: self.message.clone(),
            provider: self.provider.clone(),
            locations: self.locations.clone(),
            evidence: self.evidence.clone(),
        }
    }
}

pub struct StatusInputs<'a> {
    /// The status computed by the writer before the v2 rules (never weakened
    /// below `Failed`/`Blocked`/`Incomplete`).
    pub base: ReportStatus,
    pub findings: &'a [FindingV2],
    /// Findings that never block (advisory providers).
    pub advisory: &'a BTreeSet<String>,
    /// High/critical findings disputed by reflection or adjudication and not
    /// closed within the round limits.
    pub unresolved_disputes: &'a BTreeSet<FindingId>,
    /// Any mandatory coverage-ledger gap.
    pub mandatory_gap: bool,
    /// Whether a report whose only findings are `possible` may drop to `clean`.
    /// Phase 2 writers pass `false` (monotone strengthening only).
    pub allow_possible_demotion: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusDecision {
    pub status: ReportStatus,
    /// Gap entries that explain a forced `incomplete`.
    pub reasons: Vec<String>,
    pub unresolved_possible: u32,
}

pub fn derive_status(inputs: &StatusInputs<'_>) -> StatusDecision {
    let unresolved_possible = inputs
        .findings
        .iter()
        .filter(|finding| finding.confidence == Confidence::Possible)
        .count() as u32;
    if matches!(inputs.base, ReportStatus::Failed | ReportStatus::Blocked) {
        return StatusDecision {
            status: inputs.base,
            reasons: Vec::new(),
            unresolved_possible,
        };
    }
    let mut reasons = BTreeSet::new();
    for finding in inputs.findings {
        if inputs.advisory.contains(finding.id.as_str()) {
            continue;
        }
        if finding.required_anchor_failed() {
            reasons.insert(format!("anchor-failed:{}", finding.id));
        }
    }
    for id in inputs.unresolved_disputes {
        let material = inputs
            .findings
            .iter()
            .find(|finding| &finding.id == id)
            .is_none_or(|finding| high_or_critical(&finding.severity));
        if material {
            reasons.insert(format!("material-dispute-unresolved:{id}"));
        }
    }
    let forced =
        !reasons.is_empty() || inputs.mandatory_gap || inputs.base == ReportStatus::Incomplete;
    let status = if forced {
        ReportStatus::Incomplete
    } else if inputs.findings.iter().any(|finding| {
        !inputs.advisory.contains(finding.id.as_str()) && finding.confidence != Confidence::Possible
    }) {
        ReportStatus::Findings
    } else if inputs.base == ReportStatus::Findings && !inputs.allow_possible_demotion {
        ReportStatus::Findings
    } else {
        ReportStatus::Clean
    };
    StatusDecision {
        status,
        reasons: reasons.into_iter().collect(),
        unresolved_possible,
    }
}

// ----- ReportV2 ---------------------------------------------------------------

/// Inputs for lifting a writer's v1 report into v2.
pub struct LiftContext<'a> {
    pub scope: ReportScope,
    /// Scoped bytes of a repository-relative path; the closure returns `None`
    /// when the path is not in scope. `None` here means positioning is
    /// unavailable (no scoped bytes): anchors are not attempted and are never
    /// reported as failed.
    pub resolve: Option<&'a dyn Fn(&str) -> Option<Vec<u8>>>,
    /// Diff tag for an anchor (diff modes); `None` when not in a diff mode.
    pub diff_tag: Option<&'a dyn Fn(&str, u32, u32) -> DiffTag>,
    /// Provider-declared exactness for a finding's rule class. Absent means
    /// every finding is heuristic.
    pub exactness: Option<&'a dyn Fn(&Finding) -> Exactness>,
    pub disputes: BTreeSet<FindingId>,
    pub reused: BTreeSet<FindingId>,
    pub reasoning_budget_used: ReasoningBudgetUsed,
}

impl<'a> LiftContext<'a> {
    pub fn new(scope: ReportScope, resolve: &'a dyn Fn(&str) -> Option<Vec<u8>>) -> Self {
        Self::with_resolver(scope, Some(resolve))
    }

    /// A context with no scoped bytes (positioning unavailable).
    pub fn without_bytes(scope: ReportScope) -> Self {
        Self::with_resolver(scope, None)
    }

    fn with_resolver(
        scope: ReportScope,
        resolve: Option<&'a dyn Fn(&str) -> Option<Vec<u8>>>,
    ) -> Self {
        Self {
            scope,
            resolve,
            diff_tag: None,
            exactness: None,
            disputes: BTreeSet::new(),
            reused: BTreeSet::new(),
            reasoning_budget_used: ReasoningBudgetUsed::default(),
        }
    }
}

fn safe_relative(path: &str) -> bool {
    !path.starts_with('/') && !path.contains(':') && !path.split('/').any(|part| part == "..")
}

fn attribution_of(finding: &Finding) -> Attribution {
    match finding
        .evidence
        .get("changeAttribution")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
    {
        Some("introduced") => Attribution::Introduced,
        Some("regressed-elsewhere") => Attribution::RegressedElsewhere,
        Some("pre-existing") | Some("preexisting") => Attribution::PreExisting,
        _ => Attribution::Unresolved,
    }
}

fn advisory_ids(extensions: &BTreeMap<String, Value>) -> BTreeSet<String> {
    extensions
        .get("advisoryFindings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

impl ReportV2 {
    /// Lifts a v1 report produced by a writer into v2: positions every
    /// line-anchored location deterministically, classifies confidence, and
    /// applies the status rules (monotone: it can force `incomplete`, never
    /// weaken a writer's status).
    pub fn from_v1_with(report: &Report, ctx: &LiftContext<'_>) -> Result<Self, ContractError> {
        let mut findings = Vec::with_capacity(report.findings.len());
        for finding in &report.findings {
            let mut chosen: Option<Anchor> = None;
            let mut unpositioned = false;
            for location in &finding.locations {
                let Some((path, start, end)) = parse_location(location) else {
                    continue;
                };
                let Some(resolve) = ctx.resolve else {
                    unpositioned = true;
                    continue;
                };
                let bytes = if safe_relative(&path) {
                    resolve(&path)
                } else {
                    None
                };
                let tag = ctx.diff_tag.map(|tag| tag(&path, start, end));
                let anchor = position_anchor(&path, start, end, None, bytes.as_deref(), tag);
                let replace = match &chosen {
                    None => true,
                    Some(current) => !current.failed() && anchor.failed(),
                };
                if replace {
                    chosen = Some(anchor);
                }
            }
            let exactness = ctx
                .exactness
                .map_or(Exactness::Heuristic, |classify| classify(finding));
            let (confidence, basis) =
                classify_confidence(chosen.as_ref(), exactness, ReflectionOutcome::NotRun);
            let basis = if unpositioned && chosen.is_none() {
                "positioning-unavailable"
            } else {
                basis
            };
            findings.push(FindingV2 {
                id: finding.id.clone(),
                severity: finding.severity.clone(),
                title: finding.title.clone(),
                message: finding.message.clone(),
                provider: finding.provider.clone(),
                locations: finding.locations.clone(),
                evidence: finding.evidence.clone(),
                confidence,
                confidence_basis: basis.to_owned(),
                anchor: chosen,
                attribution: attribution_of(finding),
                disposition: if ctx.reused.contains(&finding.id) {
                    Disposition::Reused
                } else {
                    Disposition::Executed
                },
            });
        }
        let mut report_v2 = ReportV2 {
            schema_version: REPORT_SCHEMA_V2,
            report_id: report.report_id.clone(),
            status: report.status,
            findings,
            gaps: report.gaps.clone(),
            claims: report.claims.clone(),
            targets: report.targets.clone(),
            scope: ctx.scope.clone(),
            unresolved_possible: 0,
            reasoning_budget_used: ctx.reasoning_budget_used.clone(),
            extensions: report.extensions.clone(),
        };
        report_v2.apply_status_rules(&ctx.disputes, false);
        Ok(report_v2)
    }

    /// Applies the ADR-4 status rules in place. Reasons for a forced
    /// `incomplete` are recorded as gaps; this is idempotent.
    pub fn apply_status_rules(
        &mut self,
        unresolved_disputes: &BTreeSet<FindingId>,
        allow_possible_demotion: bool,
    ) {
        let advisory = advisory_ids(&self.extensions);
        let decision = derive_status(&StatusInputs {
            base: self.status,
            findings: &self.findings,
            advisory: &advisory,
            unresolved_disputes,
            mandatory_gap: !self.gaps.is_empty(),
            allow_possible_demotion,
        });
        self.gaps.extend(decision.reasons);
        self.gaps.sort();
        self.gaps.dedup();
        self.status = decision.status;
        self.unresolved_possible = decision.unresolved_possible;
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, REPORT_SCHEMA_V2)?;
        let mut ids = BTreeSet::new();
        let mut possible = 0u32;
        let advisory = advisory_ids(&self.extensions);
        let mut required_failed = false;
        for finding in &self.findings {
            if !ids.insert(&finding.id) {
                return Err(invalid("findings.id", "duplicate finding id"));
            }
            if let Some(anchor) = &finding.anchor {
                if anchor.failed() {
                    if finding.confidence != Confidence::Possible {
                        return Err(invalid(
                            "findings.confidence",
                            "a position-failed anchor requires confidence possible",
                        ));
                    }
                } else if anchor.range.start == 0
                    || anchor.range.end < anchor.range.start
                    || anchor.line_hash.is_empty()
                {
                    return Err(invalid(
                        "findings.anchor",
                        "a resolved anchor needs a 1-based range and a line hash",
                    ));
                }
            }
            // Additive canonical evidence (A14): when present it must parse,
            // be structurally valid, belong to this report's snapshot when
            // both record one, & agree with the legacy anchor it refines.
            // Absent evidence (legacy / unknown anchors) is untouched.
            // Byte-level truth is checked against scoped bytes by ingest /
            // verification via `validate_evidence_against_bytes`; a stored
            // report alone cannot re-derive it.
            if let Some(evidence) = finding.source_anchor_evidence() {
                let evidence = evidence?;
                let claims = validate_evidence_claims(&evidence, None);
                if claims != AnchorValidation::Validated {
                    return Err(invalid(
                        "findings.evidence.sourceAnchor",
                        format!("canonical anchor evidence is {}", claims.code()),
                    ));
                }
                if let (Some(recorded), Some(scoped)) = (
                    evidence.snapshot_key.as_deref(),
                    self.scope.snapshot_key.as_deref(),
                ) {
                    if recorded != scoped {
                        return Err(invalid(
                            "findings.evidence.sourceAnchor",
                            "canonical anchor snapshot differs from report scope snapshot",
                        ));
                    }
                }
                if let Some(anchor) = &finding.anchor {
                    if !anchor.failed()
                        && (evidence.path != anchor.path || evidence.lines != anchor.range)
                    {
                        return Err(invalid(
                            "findings.evidence.sourceAnchor",
                            "canonical anchor path/lines disagree with the resolved anchor",
                        ));
                    }
                }
            }
            if finding.confidence == Confidence::Proven && finding.anchor.is_none() {
                // Proven needs a semantic justification and a verified anchor.
                return Err(invalid(
                    "findings.confidence",
                    "proven requires a verified anchor",
                ));
            }
            if finding.confidence == Confidence::Possible {
                possible += 1;
            }
            if finding.required_anchor_failed() && !advisory.contains(finding.id.as_str()) {
                required_failed = true;
            }
        }
        if possible != self.unresolved_possible {
            return Err(invalid(
                "unresolvedPossible",
                "must equal the number of possible findings",
            ));
        }
        if required_failed && matches!(self.status, ReportStatus::Clean | ReportStatus::Findings) {
            return Err(invalid(
                "status",
                "a failed required anchor forces incomplete",
            ));
        }
        Ok(())
    }

    /// Raw `auditAssuranceV1` extension, if present (uninterpreted JSON).
    pub fn assurance_extension(&self) -> Option<&Value> {
        self.extensions.get(AUDIT_ASSURANCE_EXTENSION_KEY)
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }

    fn report_v2_fields(&self) -> Value {
        json!({
            "scope": self.scope,
            "unresolvedPossible": self.unresolved_possible,
            "reasoningBudgetUsed": self.reasoning_budget_used,
        })
    }

    /// Digest over exactly the v2-only fields (per-finding confidence, basis,
    /// anchor, attribution, disposition; report scope, unresolvedPossible,
    /// reasoningBudgetUsed). Stable across a v1 projection round trip.
    pub fn v2_only_digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|finding| {
                let mut fields = finding.v2_fields();
                fields["id"] = json!(finding.id.as_str());
                fields
            })
            .collect();
        canonical_digest(&json!({
            "findings": findings,
            "report": self.report_v2_fields(),
        }))
    }

    /// The v1 report without any v2 information (status, gaps, claims and
    /// findings exactly as a v1 writer would hold them).
    pub fn v1_core(&self) -> Report {
        Report {
            schema_version: REPORT_SCHEMA_V1,
            report_id: self.report_id.clone(),
            status: self.status,
            findings: self.findings.iter().map(FindingV2::v1_core).collect(),
            gaps: self.gaps.clone(),
            claims: self.claims.clone(),
            targets: self.targets.clone(),
            extensions: self.extensions.clone(),
        }
    }

    /// `--report-schema 1`: a v1 report for consumers pinned to v1. v2-only
    /// fields travel under reserved `evidence` / extension keys. Status is
    /// identical in both schemas.
    pub fn to_v1_projection(&self) -> Result<Report, ContractError> {
        let mut report = self.v1_core();
        for (core, v2) in report.findings.iter_mut().zip(&self.findings) {
            if core.evidence.contains_key(V2_FINDING_EVIDENCE_KEY) {
                return Err(invalid(
                    "findings.evidence",
                    format!("evidence key {V2_FINDING_EVIDENCE_KEY} is reserved"),
                ));
            }
            core.evidence
                .insert(V2_FINDING_EVIDENCE_KEY.into(), v2.v2_fields());
        }
        if report.extensions.contains_key(V2_REPORT_EXTENSION_KEY) {
            return Err(invalid(
                "extensions",
                format!("extension key {V2_REPORT_EXTENSION_KEY} is reserved"),
            ));
        }
        report
            .extensions
            .insert(V2_REPORT_EXTENSION_KEY.into(), self.report_v2_fields());
        report.validate()?;
        Ok(report)
    }

    /// Serializes at the requested schema: 2 natively, 1 as a projection.
    pub fn to_value_for_schema(&self, schema: u32) -> Result<Value, ContractError> {
        match schema {
            REPORT_SCHEMA_V2 => {
                self.validate()?;
                serde_json::to_value(self).map_err(|error| invalid("report", error.to_string()))
            }
            REPORT_SCHEMA_V1 => serde_json::to_value(self.to_v1_projection()?)
                .map_err(|error| invalid("report", error.to_string())),
            other => Err(ContractError::UnsupportedVersion(other)),
        }
    }

    /// Reads a v1 report as a v2 view. A v1 projection written by
    /// [`ReportV2::to_v1_projection`] restores its v2-only fields; any other v1
    /// report becomes `legacy-unknown` / `legacy` with its status preserved.
    pub fn from_v1_view(report: &Report) -> Result<Self, ContractError> {
        let mut extensions = report.extensions.clone();
        let report_fields = extensions.remove(V2_REPORT_EXTENSION_KEY);
        let (scope, unresolved_possible, reasoning_budget_used, projected) = match report_fields {
            Some(value) => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields {
                    scope: ReportScope,
                    #[serde(rename = "unresolvedPossible")]
                    unresolved_possible: u32,
                    #[serde(rename = "reasoningBudgetUsed")]
                    reasoning_budget_used: ReasoningBudgetUsed,
                }
                let fields: Fields = serde_json::from_value(value)
                    .map_err(|error| invalid(V2_REPORT_EXTENSION_KEY, error.to_string()))?;
                (
                    fields.scope,
                    fields.unresolved_possible,
                    fields.reasoning_budget_used,
                    true,
                )
            }
            None => (
                ReportScope::legacy(),
                0,
                ReasoningBudgetUsed::default(),
                false,
            ),
        };
        let mut findings = Vec::with_capacity(report.findings.len());
        for finding in &report.findings {
            let mut evidence = finding.evidence.clone();
            let marker = evidence.remove(V2_FINDING_EVIDENCE_KEY);
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Fields {
                confidence: Confidence,
                #[serde(rename = "confidenceBasis")]
                confidence_basis: String,
                anchor: Option<Anchor>,
                attribution: Attribution,
                disposition: Disposition,
            }
            let (confidence, confidence_basis, anchor, attribution, disposition) = match marker {
                Some(value) => {
                    let fields: Fields = serde_json::from_value(value)
                        .map_err(|error| invalid(V2_FINDING_EVIDENCE_KEY, error.to_string()))?;
                    (
                        fields.confidence,
                        fields.confidence_basis,
                        fields.anchor,
                        fields.attribution,
                        fields.disposition,
                    )
                }
                None => (
                    Confidence::LegacyUnknown,
                    "legacy-v1".to_owned(),
                    None,
                    Attribution::Legacy,
                    Disposition::Executed,
                ),
            };
            findings.push(FindingV2 {
                id: finding.id.clone(),
                severity: finding.severity.clone(),
                title: finding.title.clone(),
                message: finding.message.clone(),
                provider: finding.provider.clone(),
                locations: finding.locations.clone(),
                evidence,
                confidence,
                confidence_basis,
                anchor,
                attribution,
                disposition,
            });
        }
        let unresolved_possible = if projected { unresolved_possible } else { 0 };
        Ok(ReportV2 {
            schema_version: REPORT_SCHEMA_V2,
            report_id: report.report_id.clone(),
            status: report.status,
            findings,
            gaps: report.gaps.clone(),
            claims: report.claims.clone(),
            targets: report.targets.clone(),
            scope,
            unresolved_possible,
            reasoning_budget_used,
            extensions,
        })
    }

    /// Reads a stored report of schema 1 or 2 as a v2 view (ADR-8).
    pub fn read_any(value: &Value) -> Result<Self, ContractError> {
        #[derive(Deserialize)]
        struct Probe {
            #[serde(deserialize_with = "crate::deserialize_schema_version_1_or_2")]
            schema_version: u32,
        }
        match value.get("schema_version").and_then(Value::as_u64) {
            Some(1) | Some(2) => {}
            Some(other) => {
                return Err(ContractError::UnsupportedVersion(
                    u32::try_from(other).unwrap_or(u32::MAX),
                ))
            }
            None => return Err(invalid("schema_version", "missing or not an integer")),
        }
        let probe: Probe = serde_json::from_value(value.clone())
            .map_err(|error| invalid("schema_version", error.to_string()))?;
        if probe.schema_version == REPORT_SCHEMA_V1 {
            let report: Report = serde_json::from_value(value.clone())
                .map_err(|error| invalid("report", error.to_string()))?;
            Self::from_v1_view(&report)
        } else {
            let report: ReportV2 = serde_json::from_value(value.clone())
                .map_err(|error| invalid("report", error.to_string()))?;
            report.validate()?;
            Ok(report)
        }
    }
}

impl Report {
    /// Reads any supported report schema as a v2 view (ADR-8).
    pub fn read_any(value: &Value) -> Result<ReportV2, ContractError> {
        ReportV2::read_any(value)
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    const GOLDEN_V1: &str = r#"{
      "schema_version": 1,
      "report_id": "audit-golden",
      "status": "findings",
      "findings": [{
        "id": "f-1", "severity": "high", "title": "t", "message": "m",
        "provider": "security.source", "locations": ["src/a.rs:2"],
        "evidence": {"sourceQuote": "x"}
      }],
      "gaps": [],
      "claims": {"planDigest": "sha256:aa"},
      "targets": ["repo"],
      "providerResults": []
    }"#;

    const SOURCE: &[u8] = b"fn a() {}\nlet x = 1;\nlet y = 2;\n";

    fn ctx_with<'a>(resolve: &'a dyn Fn(&str) -> Option<Vec<u8>>) -> LiftContext<'a> {
        LiftContext::new(
            ReportScope {
                spec: "whole".into(),
                base_ref_oid: None,
                merge_base_oid: None,
                head: "abc".into(),
                snapshot_key: Some("snap".into()),
                index_schema_version: Some(1),
            },
            resolve,
        )
    }

    fn v1_report(severity: &str, provider: &str, location: &str) -> Report {
        Report {
            schema_version: 1,
            report_id: ReportId::new("audit-x").unwrap(),
            status: ReportStatus::Findings,
            findings: vec![Finding {
                id: FindingId::new("f-1").unwrap(),
                severity: severity.into(),
                title: "t".into(),
                message: "m".into(),
                provider: Some(provider.into()),
                locations: vec![location.into()],
                evidence: BTreeMap::new(),
            }],
            gaps: Vec::new(),
            claims: BTreeMap::new(),
            targets: vec!["repo".into()],
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn golden_v1_reads_as_legacy_v2_view() {
        let value: Value = serde_json::from_str(GOLDEN_V1).unwrap();
        let view = Report::read_any(&value).unwrap();
        assert_eq!(view.schema_version, 2);
        assert_eq!(view.status, ReportStatus::Findings);
        assert_eq!(view.findings[0].confidence, Confidence::LegacyUnknown);
        assert_eq!(view.findings[0].attribution, Attribution::Legacy);
        assert!(view.findings[0].anchor.is_none());
        assert_eq!(view.extensions["providerResults"], json!([]));
        view.validate().unwrap();
        // The v1 core of the view is the original v1 report.
        let original: Report = serde_json::from_value(value).unwrap();
        assert_eq!(view.v1_core(), original);
    }

    #[test]
    fn unsupported_schema_versions_are_rejected() {
        let mut value: Value = serde_json::from_str(GOLDEN_V1).unwrap();
        value["schema_version"] = json!(3);
        assert!(matches!(
            Report::read_any(&value),
            Err(ContractError::UnsupportedVersion(3))
        ));
        // A v2 struct never deserializes a schema 1 document.
        let v1: Value = serde_json::from_str(GOLDEN_V1).unwrap();
        assert!(serde_json::from_value::<ReportV2>(v1).is_err());
        // Validation pins the v2 version.
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut v2 =
            ReportV2::from_v1_with(&v1_report("low", "x.y", "src/a.rs:1"), &ctx_with(&resolve))
                .unwrap();
        v2.schema_version = 1;
        assert!(v2.validate().is_err());
    }

    #[test]
    fn v2_projects_to_v1_that_validates_and_round_trips_v2_only_fields() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut context = ctx_with(&resolve);
        context.reasoning_budget_used.seats = 3;
        context.reused.insert(FindingId::new("f-1").unwrap());
        let v2 = ReportV2::from_v1_with(
            &v1_report("high", "security.source", "src/a.rs:2-3"),
            &context,
        )
        .unwrap();
        v2.validate().unwrap();
        let v1 = v2.to_v1_projection().unwrap();
        v1.validate().unwrap();
        assert_eq!(v1.status, v2.status);
        assert!(v1.findings[0]
            .evidence
            .contains_key(V2_FINDING_EVIDENCE_KEY));
        let wire = serde_json::to_value(&v1).unwrap();
        let back = Report::read_any(&wire).unwrap();
        assert_eq!(back.v2_only_digest().unwrap(), v2.v2_only_digest().unwrap());
        assert_eq!(back, v2);
        assert_eq!(back.status, v2.status);
        // The native v2 wire form round-trips too.
        let native = v2.to_value_for_schema(2).unwrap();
        assert_eq!(Report::read_any(&native).unwrap(), v2);
        assert_eq!(v2.to_value_for_schema(1).unwrap(), wire);
    }

    #[test]
    fn reserved_evidence_key_collision_is_refused() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut report = v1_report("low", "x.y", "src/a.rs:1");
        report.findings[0]
            .evidence
            .insert(V2_FINDING_EVIDENCE_KEY.into(), json!({}));
        let v2 = ReportV2::from_v1_with(&report, &ctx_with(&resolve)).unwrap();
        assert!(v2.to_v1_projection().is_err());
    }

    #[test]
    fn failed_medium_anchor_never_yields_clean_or_findings() {
        let missing = |_: &str| -> Option<Vec<u8>> { None };
        let present = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        for location in ["src/a.rs:0", "src/a.rs:99", "src/a.rs:2"] {
            let resolve: &dyn Fn(&str) -> Option<Vec<u8>> = if location.ends_with(":2") {
                &missing
            } else {
                &present
            };
            let v2 = ReportV2::from_v1_with(
                &v1_report("medium", "quality.lint", location),
                &ctx_with(resolve),
            )
            .unwrap();
            assert_eq!(v2.status, ReportStatus::Incomplete, "{location}");
            assert!(v2.gaps.contains(&"anchor-failed:f-1".to_owned()));
            assert_eq!(v2.findings[0].confidence, Confidence::Possible);
            assert_eq!(
                v2.findings[0].anchor.as_ref().unwrap().state,
                AnchorState::PositionFailed
            );
            assert_eq!(v2.unresolved_possible, 1);
            v2.validate().unwrap();
            // A hand-edited clean/findings status is refused.
            for status in [ReportStatus::Clean, ReportStatus::Findings] {
                let mut forged = v2.clone();
                forged.status = status;
                assert!(forged.validate().is_err());
            }
        }
    }

    #[test]
    fn failed_security_anchor_forces_incomplete_even_when_low() {
        let missing = |_: &str| -> Option<Vec<u8>> { None };
        let v2 = ReportV2::from_v1_with(
            &v1_report("low", "reasoning.security", "src/a.rs:2"),
            &ctx_with(&missing),
        )
        .unwrap();
        assert_eq!(v2.status, ReportStatus::Incomplete);
    }

    #[test]
    fn failed_low_non_security_anchor_is_possible_but_not_blocking() {
        let missing = |_: &str| -> Option<Vec<u8>> { None };
        let v2 = ReportV2::from_v1_with(
            &v1_report("low", "quality.lint", "src/a.rs:2"),
            &ctx_with(&missing),
        )
        .unwrap();
        assert_eq!(v2.findings[0].confidence, Confidence::Possible);
        assert_eq!(v2.status, ReportStatus::Findings); // monotone phase-2 writer
        assert!(v2.gaps.is_empty());
        v2.validate().unwrap();
        // The possibles-only demotion is available to phase-4 callers.
        let mut demoted = v2.clone();
        demoted.apply_status_rules(&BTreeSet::new(), true);
        assert_eq!(demoted.status, ReportStatus::Clean);
        assert_eq!(demoted.unresolved_possible, 1);
    }

    #[test]
    fn unresolved_material_dispute_forces_incomplete() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut context = ctx_with(&resolve);
        context.disputes.insert(FindingId::new("f-1").unwrap());
        let v2 =
            ReportV2::from_v1_with(&v1_report("critical", "x.y", "src/a.rs:1"), &context).unwrap();
        assert_eq!(v2.status, ReportStatus::Incomplete);
        assert!(v2
            .gaps
            .contains(&"material-dispute-unresolved:f-1".to_owned()));
        // A disputed low finding is not material.
        let mut context = ctx_with(&resolve);
        context.disputes.insert(FindingId::new("f-1").unwrap());
        let v2 = ReportV2::from_v1_with(&v1_report("low", "x.y", "src/a.rs:1"), &context).unwrap();
        assert_eq!(v2.status, ReportStatus::Findings);
    }

    #[test]
    fn writer_gaps_and_failed_status_are_preserved() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut report = v1_report("low", "x.y", "src/a.rs:1");
        report.status = ReportStatus::Incomplete;
        report.gaps.push("unsigned-plan".into());
        let v2 = ReportV2::from_v1_with(&report, &ctx_with(&resolve)).unwrap();
        assert_eq!(v2.status, ReportStatus::Incomplete);
        report.status = ReportStatus::Failed;
        let v2 = ReportV2::from_v1_with(&report, &ctx_with(&resolve)).unwrap();
        assert_eq!(v2.status, ReportStatus::Failed);
    }

    #[test]
    fn anchored_non_exact_hit_is_likely_and_exact_is_proven() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let report = v1_report("high", "security.source", "src/a.rs:2");
        let v2 = ReportV2::from_v1_with(&report, &ctx_with(&resolve)).unwrap();
        assert_eq!(v2.findings[0].confidence, Confidence::Likely);
        assert_eq!(v2.findings[0].confidence_basis, "anchored-tool-hit");
        let exact = |_: &Finding| Exactness::Exact;
        let mut context = ctx_with(&resolve);
        context.exactness = Some(&exact);
        let v2 = ReportV2::from_v1_with(&report, &context).unwrap();
        assert_eq!(v2.findings[0].confidence, Confidence::Proven);
        // Exact without a verified anchor is not proven.
        let (confidence, _) =
            classify_confidence(None, Exactness::Exact, ReflectionOutcome::NotRun);
        assert_eq!(confidence, Confidence::Likely);
        // Reflection seam.
        let anchor = position_anchor("src/a.rs", 1, 1, None, Some(SOURCE), None);
        assert_eq!(
            classify_confidence(
                Some(&anchor),
                Exactness::Heuristic,
                ReflectionOutcome::UpheldWithConcreteCase
            )
            .0,
            Confidence::Proven
        );
        assert_eq!(
            classify_confidence(
                Some(&anchor),
                Exactness::Heuristic,
                ReflectionOutcome::Disputed
            )
            .0,
            Confidence::Possible
        );
    }

    #[test]
    fn positioning_is_deterministic_and_fails_closed() {
        let ok = position_anchor("a", 2, 3, None, Some(SOURCE), Some(DiffTag::InDiff));
        assert_eq!(ok.state, AnchorState::InDiff);
        let again = position_anchor("a", 2, 3, Some(&ok.line_hash), Some(SOURCE), None);
        assert_eq!(again.state, AnchorState::Resolved);
        assert_eq!(again.line_hash, ok.line_hash);
        let crlf = b"fn a() {}\r\nlet x = 1;\r\nlet y = 2;\r\n";
        assert_eq!(
            position_anchor("a", 2, 3, None, Some(crlf), None).line_hash,
            ok.line_hash
        );
        for anchor in [
            position_anchor("a", 0, 0, None, Some(SOURCE), None),
            position_anchor("a", 4, 4, None, Some(SOURCE), None),
            position_anchor("a", 3, 2, None, Some(SOURCE), None),
            position_anchor("a", 1, 1, Some("sha256:bad"), Some(SOURCE), None),
            position_anchor("a", 1, 1, None, None, None),
        ] {
            assert!(anchor.failed());
        }
    }

    #[test]
    fn unavailable_positioning_is_not_a_failed_anchor() {
        let v2 = ReportV2::from_v1_with(
            &v1_report("high", "security.source", "src/a.rs:2"),
            &LiftContext::without_bytes(ReportScope::legacy()),
        )
        .unwrap();
        assert!(v2.findings[0].anchor.is_none());
        assert_eq!(v2.findings[0].confidence_basis, "positioning-unavailable");
        assert_eq!(v2.status, ReportStatus::Findings);
    }

    #[test]
    fn location_parsing() {
        assert_eq!(
            parse_location("src/a.rs:3-5"),
            Some(("src/a.rs".into(), 3, 5))
        );
        assert_eq!(
            parse_location("src/a.rs:7"),
            Some(("src/a.rs".into(), 7, 7))
        );
        assert_eq!(
            parse_location("src/a.rs:7:9"),
            Some(("src/a.rs".into(), 7, 7))
        );
        assert_eq!(parse_location("src/a.rs"), None);
        assert_eq!(
            parse_location("src\\a.rs:2"),
            Some(("src/a.rs".into(), 2, 2))
        );
    }

    #[test]
    fn canonical_positioning_builds_agreeing_evidence_and_round_trips() {
        use crate::source_anchor::{validate_evidence_against_bytes, AnchorValidation};
        let (anchor, evidence) = position_anchor_canonical(
            "src/a.rs",
            2,
            3,
            None,
            Some(SOURCE),
            Some(DiffTag::InDiff),
            crate::source_anchor::SourceSide::Selected,
            Some("repo"),
            Some("snap"),
        );
        assert_eq!(anchor.state, AnchorState::InDiff);
        let evidence = evidence.expect("resolved position carries canonical evidence");
        assert_eq!(evidence.lines, anchor.range);
        assert_eq!(evidence.path, anchor.path);
        assert_eq!(
            validate_evidence_against_bytes(&evidence, Some("snap"), Some(SOURCE)),
            AnchorValidation::Validated
        );
        // A failed position never invents canonical evidence.
        let (failed, none) = position_anchor_canonical(
            "src/a.rs",
            99,
            99,
            None,
            Some(SOURCE),
            None,
            crate::source_anchor::SourceSide::Selected,
            None,
            None,
        );
        assert!(failed.failed());
        assert!(none.is_none());

        // Evidence rides the v1 projection & native v2 wire form unchanged.
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        let mut v2 = ReportV2::from_v1_with(
            &v1_report("high", "security.source", "src/a.rs:2-3"),
            &ctx_with(&resolve),
        )
        .unwrap();
        v2.findings[0]
            .set_source_anchor_evidence(&evidence)
            .unwrap();
        v2.validate().unwrap();
        let wire = v2.to_value_for_schema(1).unwrap();
        let back = Report::read_any(&wire).unwrap();
        assert_eq!(back, v2);
        assert_eq!(
            back.findings[0].source_anchor_evidence().unwrap().unwrap(),
            evidence
        );
        let native = v2.to_value_for_schema(2).unwrap();
        assert_eq!(Report::read_any(&native).unwrap(), v2);

        // Scope snapshot disagreement & anchor disagreement are refused;
        // ctx scope records snapshot "snap", matching the evidence above.
        let mut wrong_snapshot = v2.clone();
        wrong_snapshot.scope.snapshot_key = Some("other".into());
        assert!(wrong_snapshot.validate().is_err());
        let mut wrong_lines = v2.clone();
        let mut moved = evidence.clone();
        moved.lines = LineRange { start: 1, end: 1 };
        wrong_lines.findings[0]
            .set_source_anchor_evidence(&moved)
            .unwrap();
        assert!(wrong_lines.validate().is_err());
        // Malformed canonical evidence is an error, not a legacy anchor.
        let mut malformed = v2;
        malformed.findings[0]
            .evidence
            .insert("sourceAnchor".into(), json!({"path": "src/a.rs"}));
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn traversal_and_absolute_paths_fail_to_position() {
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(SOURCE.to_vec()) };
        for location in ["../a.rs:1", "/etc/passwd:1"] {
            let v2 =
                ReportV2::from_v1_with(&v1_report("high", "x.y", location), &ctx_with(&resolve))
                    .unwrap();
            assert_eq!(v2.status, ReportStatus::Incomplete, "{location}");
        }
    }
}
