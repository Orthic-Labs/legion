//! A16: production journey, performance and release-artifact obligations.
//!
//! This module never drives a browser, device, simulator or server. Journeys
//! are *declared* here, discharged only by evidence that a qualified
//! execution owner (browser / native UI / Android / Apple / isolated HTTP or
//! database) produced and that A03 authenticated into an
//! [`ImportedEvidenceRecord`]. Missing, stale, replayed (when denied),
//! fixture-only, differently-bound or incomplete evidence leaves the
//! obligation `unmet`; nothing here converts absence into a pass.
//!
//! Identity rules:
//! * A journey is satisfied only by evidence bound to the exact packaged
//!   artifact digest, build configuration, target, variant, scheme /
//!   destination / application id and (for server journeys) server revision.
//! * Paired scenarios (duplicate delivery vs. cancellation/state-restoration)
//!   are separate journeys; each carries its own outcome, the pair is only as
//!   good as its weakest declared member.
//! * Performance is comparable only when workload, warm/cold state, dataset,
//!   traffic mix, concurrency, excluded routes, hardware/OS, environment and
//!   measurement method all match. A budget is product-declared; an absent
//!   budget is reported as missing, never invented.
//! * Source, build, functional, visual, a11y, load and artifact-security
//!   outcomes stay separate ([`OutcomeAxis`], [`AxisReport`]).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::artifact_evidence::{
    is_rfc3339_utc_second, CommandBinding, EvidenceOutcome, ExpectedEvidence, ImportKind,
    ImportedEvidenceRecord, ReplayPolicy, RepositoryBinding,
};
use crate::assurance::{EvidenceKind, ObligationCandidate, ObligationStatus};
use crate::error::AuditError;
use crate::profiles::AuditProfile;

pub const RUNTIME_OBLIGATIONS_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Stacks, axes, producers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stack {
    NodeCommerce,
    ReactAdmin,
    QwikStorefront,
    Postgres,
    Nginx,
    RustCore,
    TauriReact,
    NativeGui,
    SwiftMacos,
    SwiftIos,
    KotlinAndroid,
}

impl Stack {
    pub fn label(self) -> &'static str {
        match self {
            Self::NodeCommerce => "node-commerce",
            Self::ReactAdmin => "react-admin",
            Self::QwikStorefront => "qwik-storefront",
            Self::Postgres => "postgres",
            Self::Nginx => "nginx",
            Self::RustCore => "rust-core",
            Self::TauriReact => "tauri-react",
            Self::NativeGui => "native-gui",
            Self::SwiftMacos => "swift-macos",
            Self::SwiftIos => "swift-ios",
            Self::KotlinAndroid => "kotlin-android",
        }
    }
}

/// Separate outcome axes. One axis never stands in for another.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeAxis {
    Source,
    Build,
    Functional,
    Visual,
    A11y,
    Load,
    ArtifactSecurity,
}

impl OutcomeAxis {
    pub const ALL: [OutcomeAxis; 7] = [
        Self::Source,
        Self::Build,
        Self::Functional,
        Self::Visual,
        Self::A11y,
        Self::Load,
        Self::ArtifactSecurity,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Build => "build",
            Self::Functional => "functional",
            Self::Visual => "visual",
            Self::A11y => "a11y",
            Self::Load => "load",
            Self::ArtifactSecurity => "artifact-security",
        }
    }

    /// A02 evidence kind that can discharge an obligation on this axis.
    pub fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Source => EvidenceKind::ProviderExecution,
            Self::Build => EvidenceKind::Build,
            Self::Functional | Self::Visual | Self::A11y | Self::Load => EvidenceKind::Runtime,
            Self::ArtifactSecurity => EvidenceKind::Artifact,
        }
    }

    /// A03 import kind the authenticated record must carry. `Source` has
    /// none: source outcomes come from providers, not journey imports.
    pub fn import_kind(self) -> Option<ImportKind> {
        match self {
            Self::Source => None,
            Self::Build => Some(ImportKind::Build),
            Self::Functional | Self::Visual | Self::A11y => Some(ImportKind::Runtime),
            Self::Load => Some(ImportKind::Performance),
            Self::ArtifactSecurity => Some(ImportKind::Artifact),
        }
    }
}

/// Qualified execution owners. Audit owns no automation driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionOwner {
    BrowserJourney,
    NativeUi,
    AndroidDevice,
    AppleSimulatorOrDevice,
    IsolatedHttp,
    IsolatedDatabase,
}

/// Who produces the evidence for a declared journey, or the explicit gap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum EvidenceProducer {
    /// A qualified owner executes it; `qualified_owner_id` names the A01
    /// owner/admission, consumed as an opaque id.
    Owner {
        owner: ExecutionOwner,
        #[serde(rename = "qualifiedOwnerId")]
        qualified_owner_id: String,
    },
    /// Authenticated A03 receipt from application CI / host broker.
    ImportedReceipt {
        #[serde(rename = "issuerId")]
        issuer_id: String,
    },
    /// No producer exists yet. The obligation stays unmet.
    Gap { reason: String },
}

impl EvidenceProducer {
    pub fn is_gap(&self) -> bool {
        match self {
            Self::Gap { .. } => true,
            Self::Owner {
                qualified_owner_id, ..
            } => qualified_owner_id.trim().is_empty(),
            Self::ImportedReceipt { issuer_id } => issuer_id.trim().is_empty(),
        }
    }
}

// ---------------------------------------------------------------------------
// Subject identity
// ---------------------------------------------------------------------------

/// Exact runtime subject. Wrong binary/scheme/variant/server revision must
/// not satisfy a journey, so every field is compared for equality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectIdentity {
    /// `sha256:` digest of the packaged binary / bundle / APK / server image
    /// the journey ran against.
    pub artifact_digest: String,
    pub build_config_digest: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Xcode scheme / Gradle flavor selection, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Simulator/device/browser destination identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Bundle id / Android application id / Tauri identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Deployed server revision for server-side journeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_revision: Option<String>,
    /// Exact cargo/build feature selection (sorted by [`normalized_features`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Isolated environment id (never a production URL).
    pub environment_id: String,
}

impl SubjectIdentity {
    pub fn normalized_features(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.features.iter().collect();
        set.into_iter().cloned().collect()
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        for (name, value) in [
            ("artifactDigest", &self.artifact_digest),
            ("buildConfigDigest", &self.build_config_digest),
        ] {
            if !value.starts_with("sha256:") || value.len() <= "sha256:".len() {
                return Err(AuditError::Invalid(format!(
                    "runtime subject {name} must be a sha256: digest"
                )));
            }
        }
        if self.target.trim().is_empty() || self.environment_id.trim().is_empty() {
            return Err(AuditError::Invalid(
                "runtime subject requires target and environmentId".into(),
            ));
        }
        Ok(())
    }
}

/// Named differences between expected and observed subject; empty = equal.
pub fn subject_mismatches(expected: &SubjectIdentity, observed: &SubjectIdentity) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(format!("{name}-mismatch"));
        }
    };
    check(
        "artifact-digest",
        expected.artifact_digest == observed.artifact_digest,
    );
    check(
        "build-config",
        expected.build_config_digest == observed.build_config_digest,
    );
    check("target", expected.target == observed.target);
    check("variant", expected.variant == observed.variant);
    check("scheme", expected.scheme == observed.scheme);
    check("destination", expected.destination == observed.destination);
    check(
        "application-id",
        expected.application_id == observed.application_id,
    );
    check(
        "server-revision",
        expected.server_revision == observed.server_revision,
    );
    check(
        "features",
        expected.normalized_features() == observed.normalized_features(),
    );
    check(
        "environment",
        expected.environment_id == observed.environment_id,
    );
    out
}

// ---------------------------------------------------------------------------
// Journey declarations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairBinding {
    pub pair_id: String,
    /// Role inside the pair, e.g. `duplicate-delivery`, `cancellation`,
    /// `state-restoration`.
    pub role: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JourneyDeclaration {
    pub id: String,
    pub stack: Stack,
    /// Catalog category (see [`required_catalog`]), or a product-specific one.
    pub category: String,
    pub axis: OutcomeAxis,
    pub title: String,
    /// Ordered steps the evidence must examine verbatim.
    pub steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<PairBinding>,
    pub producer: EvidenceProducer,
    /// Replay only satisfies when the product explicitly allows it.
    #[serde(default)]
    pub allow_replay: bool,
}

impl JourneyDeclaration {
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.id.trim().is_empty() || self.category.trim().is_empty() {
            return Err(AuditError::Invalid(
                "journey requires non-empty id and category".into(),
            ));
        }
        if self.axis == OutcomeAxis::Source {
            return Err(AuditError::Invalid(format!(
                "journey {} cannot declare the source axis; source outcomes come from providers",
                self.id
            )));
        }
        if self.steps.is_empty() || self.steps.iter().any(|s| s.trim().is_empty()) {
            return Err(AuditError::Invalid(format!(
                "journey {} requires non-empty steps",
                self.id
            )));
        }
        if let Some(pair) = &self.pair {
            if pair.pair_id.trim().is_empty() || pair.role.trim().is_empty() {
                return Err(AuditError::Invalid(format!(
                    "journey {} has an empty pair binding",
                    self.id
                )));
            }
        }
        Ok(())
    }

    /// Scope items that examined-scope claims must contain verbatim.
    pub fn scope_items(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|step| format!("journey:{}:{}", self.id, step))
            .collect()
    }

    /// A02 `ObligationCandidate.concern`.
    pub fn concern(&self) -> String {
        format!("journey:{}:{}", self.axis.label(), self.id)
    }
}

/// Candidates for `resolve_obligations`. A gap producer still yields a
/// candidate: the obligation freezes `unmet`, never disappears.
pub fn journey_candidates(
    declarations: &[JourneyDeclaration],
    required_in: &[AuditProfile],
) -> Result<Vec<ObligationCandidate>, AuditError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for declaration in declarations {
        declaration.validate()?;
        if !seen.insert(declaration.id.clone()) {
            return Err(AuditError::Invalid(format!(
                "duplicate journey id {}",
                declaration.id
            )));
        }
        out.push(ObligationCandidate {
            concern: declaration.concern(),
            evidence_kind: declaration.axis.evidence_kind(),
            required_in: required_in.to_vec(),
            provider_ids: Vec::new(),
            required_denominator_digest: None,
            proven_inapplicable_reason: None,
        });
    }
    Ok(out)
}

/// Frozen A03 expectations for one journey. `workload_digest` is required
/// for the load axis and forbidden elsewhere by construction.
#[allow(clippy::too_many_arguments)]
pub fn journey_expected_evidence(
    declaration: &JourneyDeclaration,
    subject: &SubjectIdentity,
    repositories: Vec<RepositoryBinding>,
    toolchain: String,
    dependency_graph_digest: String,
    command: CommandBinding,
    replay_policy: ReplayPolicy,
    workload_digest: Option<String>,
) -> Result<ExpectedEvidence, AuditError> {
    declaration.validate()?;
    subject.validate()?;
    let kind = declaration
        .axis
        .import_kind()
        .ok_or_else(|| AuditError::Invalid("source axis has no import kind".into()))?;
    if declaration.axis == OutcomeAxis::Load && workload_digest.is_none() {
        return Err(AuditError::Invalid(format!(
            "load journey {} requires a workload digest",
            declaration.id
        )));
    }
    Ok(ExpectedEvidence {
        kind,
        repositories,
        target: subject.target.clone(),
        variant: subject.variant.clone(),
        toolchain,
        config_digest: subject.build_config_digest.clone(),
        test_selection_digest: None,
        dependency_graph_digest,
        workload_digest: if declaration.axis == OutcomeAxis::Load {
            workload_digest
        } else {
            None
        },
        command,
        required_scope: declaration.scope_items(),
        required_artifacts: Vec::new(),
        replay_policy,
        upstream_runtime: None,
    })
}

// ---------------------------------------------------------------------------
// Journey evaluation
// ---------------------------------------------------------------------------

/// What the qualified owner / receipt says it ran. Bound to an
/// authenticated [`ImportedEvidenceRecord`] by `evidence_id`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JourneyObserved {
    pub evidence_id: String,
    pub journey_id: String,
    pub axis: OutcomeAxis,
    pub subject: SubjectIdentity,
    pub steps_examined: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JourneyStatus {
    Satisfied,
    Findings,
    Unmet,
}

impl JourneyStatus {
    pub fn to_obligation_status(self) -> ObligationStatus {
        match self {
            Self::Satisfied => ObligationStatus::Satisfied,
            Self::Findings => ObligationStatus::Findings,
            Self::Unmet => ObligationStatus::Unmet,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Satisfied => 0,
            Self::Unmet => 1,
            Self::Findings => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JourneyOutcome {
    pub journey_id: String,
    pub axis: OutcomeAxis,
    pub status: JourneyStatus,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    pub replayed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<PairBinding>,
}

fn unmet(
    declaration: &JourneyDeclaration,
    reasons: Vec<String>,
    record: Option<&ImportedEvidenceRecord>,
) -> JourneyOutcome {
    JourneyOutcome {
        journey_id: declaration.id.clone(),
        axis: declaration.axis,
        status: JourneyStatus::Unmet,
        reasons,
        evidence_id: record.map(|r| r.evidence_id.clone()),
        replayed: record.map(|r| !r.newly_executed).unwrap_or(false),
        pair: declaration.pair.clone(),
    }
}

/// Evaluate one declared journey against authenticated evidence.
///
/// `expected` is the frozen subject; `observed` is what the evidence claims.
/// Every mismatch is named; any reason leaves the journey `Unmet` unless the
/// bound evidence authentically reports a failed outcome (`Findings`).
pub fn evaluate_journey(
    declaration: &JourneyDeclaration,
    expected: &SubjectIdentity,
    record: Option<&ImportedEvidenceRecord>,
    observed: Option<&JourneyObserved>,
    now_rfc3339_utc: &str,
) -> JourneyOutcome {
    if let Err(error) = declaration.validate() {
        return unmet(
            declaration,
            vec![format!("invalid-declaration: {error}")],
            record,
        );
    }
    let mut reasons: Vec<String> = Vec::new();
    if declaration.producer.is_gap() {
        reasons.push(match &declaration.producer {
            EvidenceProducer::Gap { reason } => format!("producer-gap: {reason}"),
            _ => "producer-unqualified".into(),
        });
    }
    let Some(record) = record else {
        reasons.push("missing-authenticated-evidence".into());
        return unmet(declaration, reasons, None);
    };
    let Some(observed) = observed else {
        reasons.push("missing-journey-observation".into());
        return unmet(declaration, reasons, Some(record));
    };

    if !record.authenticated {
        reasons.push("evidence-unauthenticated".into());
    }
    match declaration.axis.import_kind() {
        Some(kind) if record.kind == kind => {}
        _ => reasons.push("evidence-kind-mismatch".into()),
    }
    if observed.evidence_id != record.evidence_id {
        reasons.push("observation-not-bound-to-record".into());
    }
    if observed.journey_id != declaration.id || observed.axis != declaration.axis {
        reasons.push("observation-journey-mismatch".into());
    }
    reasons.extend(subject_mismatches(expected, &observed.subject));
    if record.target != expected.target {
        reasons.push("record-target-mismatch".into());
    }
    if record.variant != expected.variant {
        reasons.push("record-variant-mismatch".into());
    }
    if !is_rfc3339_utc_second(&record.fresh_until) || !is_rfc3339_utc_second(now_rfc3339_utc) {
        reasons.push("invalid-freshness-timestamp".into());
    } else if record.fresh_until.as_str() <= now_rfc3339_utc {
        reasons.push("stale-evidence".into());
    }
    if !record.newly_executed && !declaration.allow_replay {
        reasons.push("replayed-evidence-not-permitted".into());
    }
    let examined: BTreeSet<&str> = record.examined_scope.iter().map(String::as_str).collect();
    for item in declaration.scope_items() {
        if !examined.contains(item.as_str()) {
            reasons.push(format!("scope-not-examined:{item}"));
        }
    }
    let observed_steps: BTreeSet<&str> =
        observed.steps_examined.iter().map(String::as_str).collect();
    for step in &declaration.steps {
        if !observed_steps.contains(step.as_str()) {
            reasons.push(format!("step-not-observed:{step}"));
        }
    }
    for missing in &record.missing_scope {
        reasons.push(format!("scope-missing:{missing}"));
    }

    let status = if !reasons.is_empty() {
        JourneyStatus::Unmet
    } else {
        match record.outcome {
            EvidenceOutcome::Passed => JourneyStatus::Satisfied,
            EvidenceOutcome::Failed | EvidenceOutcome::Findings => {
                reasons.push("journey-failed".into());
                JourneyStatus::Findings
            }
            EvidenceOutcome::Error => {
                reasons.push("owner-reported-error".into());
                JourneyStatus::Unmet
            }
        }
    };
    JourneyOutcome {
        journey_id: declaration.id.clone(),
        axis: declaration.axis,
        status,
        reasons,
        evidence_id: Some(record.evidence_id.clone()),
        replayed: !record.newly_executed,
        pair: declaration.pair.clone(),
    }
}

// ---------------------------------------------------------------------------
// Paired scenarios
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairMember {
    pub journey_id: String,
    pub role: String,
    pub status: JourneyStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairOutcome {
    pub pair_id: String,
    pub status: JourneyStatus,
    pub members: Vec<PairMember>,
}

/// Group declared pair members. Every declared member must have its own
/// satisfied outcome; a missing member is `Unmet`, never inferred from its
/// sibling. The pair status is the weakest member.
pub fn evaluate_pairs(
    declarations: &[JourneyDeclaration],
    outcomes: &[JourneyOutcome],
) -> Vec<PairOutcome> {
    let by_id: BTreeMap<&str, &JourneyOutcome> = outcomes
        .iter()
        .map(|o| (o.journey_id.as_str(), o))
        .collect();
    let mut grouped: BTreeMap<String, Vec<PairMember>> = BTreeMap::new();
    for declaration in declarations {
        let Some(pair) = &declaration.pair else {
            continue;
        };
        let member = match by_id.get(declaration.id.as_str()) {
            Some(outcome) => PairMember {
                journey_id: declaration.id.clone(),
                role: pair.role.clone(),
                status: outcome.status,
                reasons: outcome.reasons.clone(),
            },
            None => PairMember {
                journey_id: declaration.id.clone(),
                role: pair.role.clone(),
                status: JourneyStatus::Unmet,
                reasons: vec!["pair-member-not-evaluated".into()],
            },
        };
        grouped
            .entry(pair.pair_id.clone())
            .or_default()
            .push(member);
    }
    grouped
        .into_iter()
        .map(|(pair_id, members)| {
            let mut status = JourneyStatus::Satisfied;
            for member in &members {
                if member.status.rank() > status.rank() {
                    status = member.status;
                }
            }
            PairOutcome {
                pair_id,
                status,
                members,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Required stack catalog and inventory
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub stack: Stack,
    pub category: &'static str,
    pub axis: OutcomeAxis,
    pub summary: &'static str,
}

/// Production categories every applicable stack must account for, either
/// with a declared journey (and producer) or an explicit gap row.
pub fn required_catalog() -> Vec<CatalogEntry> {
    use OutcomeAxis::*;
    use Stack::*;
    let e = |stack, category, axis, summary| CatalogEntry {
        stack,
        category,
        axis,
        summary,
    };
    vec![
        e(
            NodeCommerce,
            "checkout",
            Functional,
            "checkout with duplicate delivery",
        ),
        e(
            NodeCommerce,
            "refund",
            Functional,
            "refund state and money units",
        ),
        e(
            NodeCommerce,
            "inventory-oversell",
            Load,
            "concurrent stock decrement without oversell",
        ),
        e(
            NodeCommerce,
            "webhook-replay",
            Functional,
            "payment webhook replay is idempotent",
        ),
        e(
            NodeCommerce,
            "tenant-admin-authorization",
            Functional,
            "cross-tenant and admin authorization denial",
        ),
        e(
            NodeCommerce,
            "workload-latency",
            Load,
            "declared workload latency/error budget",
        ),
        e(
            ReactAdmin,
            "user-paths",
            Functional,
            "admin user paths in a real browser",
        ),
        e(
            ReactAdmin,
            "keyboard-a11y",
            A11y,
            "keyboard and accessibility interactions",
        ),
        e(
            ReactAdmin,
            "permission-transitions",
            Functional,
            "authorization changes enforced server-side",
        ),
        e(
            QwikStorefront,
            "user-paths",
            Functional,
            "navigation, checkout and resume",
        ),
        e(
            QwikStorefront,
            "keyboard-a11y",
            A11y,
            "keyboard and accessibility interactions",
        ),
        e(
            QwikStorefront,
            "seo-render-delivery",
            Functional,
            "rendered HTML delivered to crawlers",
        ),
        e(
            QwikStorefront,
            "resumability",
            Functional,
            "resume without re-execution or secret serialization",
        ),
        e(
            QwikStorefront,
            "visual-states",
            Visual,
            "rendered state coverage",
        ),
        e(
            Postgres,
            "migration-isolated",
            Functional,
            "migration on exact server/schema/data volume",
        ),
        e(
            Postgres,
            "recovery",
            Functional,
            "backup/restore or rollback recovery",
        ),
        e(
            Nginx,
            "routing",
            Functional,
            "isolated request routing behavior",
        ),
        e(
            Nginx,
            "private-cache",
            Functional,
            "authenticated responses never shared-cached",
        ),
        e(
            RustCore,
            "feature-target-matrix",
            Build,
            "declared feature/target/build matrix",
        ),
        e(
            TauriReact,
            "ipc-allowed-denied",
            Functional,
            "UI to IPC to Rust allowed and denied cases",
        ),
        e(TauriReact, "deep-link", Functional, "deep-link input trust"),
        e(
            TauriReact,
            "path-capability-boundary",
            Functional,
            "path and capability scope",
        ),
        e(
            TauriReact,
            "packaged-artifact-security",
            ArtifactSecurity,
            "packaged artifact and capabilities",
        ),
        e(
            NativeGui,
            "responsiveness",
            Load,
            "UI-thread responsiveness under load",
        ),
        e(
            NativeGui,
            "cancellation-shutdown",
            Functional,
            "cancellation and clean shutdown",
        ),
        e(
            SwiftMacos,
            "lifecycle-permissions",
            Functional,
            "lifecycle and permission flows",
        ),
        e(
            SwiftMacos,
            "packaged-artifact-security",
            ArtifactSecurity,
            "signed/entitled packaged artifact",
        ),
        e(
            SwiftIos,
            "lifecycle-background",
            Functional,
            "background and foreground transitions",
        ),
        e(
            SwiftIos,
            "permission-denial-regrant",
            Functional,
            "permission denial and regrant",
        ),
        e(
            SwiftIos,
            "offline-reconnect",
            Functional,
            "offline and reconnect",
        ),
        e(
            SwiftIos,
            "cancellation-state-restoration",
            Functional,
            "cancellation and state restoration",
        ),
        e(
            SwiftIos,
            "packaged-artifact-security",
            ArtifactSecurity,
            "packaged artifact identity",
        ),
        e(
            KotlinAndroid,
            "lifecycle-background",
            Functional,
            "background and foreground transitions",
        ),
        e(
            KotlinAndroid,
            "permission-denial-regrant",
            Functional,
            "permission denial and regrant",
        ),
        e(
            KotlinAndroid,
            "process-death-restore",
            Functional,
            "process death and restoration",
        ),
        e(
            KotlinAndroid,
            "offline-reconnect",
            Functional,
            "offline and reconnect",
        ),
        e(
            KotlinAndroid,
            "packaged-artifact-security",
            ArtifactSecurity,
            "packaged APK/AAB variant identity",
        ),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageRow {
    pub stack: Stack,
    pub category: String,
    pub axis: OutcomeAxis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journey_id: Option<String>,
    pub producer: EvidenceProducer,
}

/// Inventory for applicable stacks (applicability proven by root). Every
/// catalog category appears: with its declared producer, or as an explicit
/// gap. Declared journeys outside the catalog are retained as extra rows.
pub fn stack_inventory(
    applicable: &BTreeSet<Stack>,
    declarations: &[JourneyDeclaration],
) -> Vec<CoverageRow> {
    let mut rows = Vec::new();
    let mut matched: BTreeSet<&str> = BTreeSet::new();
    for entry in required_catalog() {
        if !applicable.contains(&entry.stack) {
            continue;
        }
        let found = declarations
            .iter()
            .find(|d| d.stack == entry.stack && d.category == entry.category);
        match found {
            Some(declaration) => {
                matched.insert(declaration.id.as_str());
                rows.push(CoverageRow {
                    stack: entry.stack,
                    category: entry.category.to_string(),
                    axis: declaration.axis,
                    journey_id: Some(declaration.id.clone()),
                    producer: declaration.producer.clone(),
                });
            }
            None => rows.push(CoverageRow {
                stack: entry.stack,
                category: entry.category.to_string(),
                axis: entry.axis,
                journey_id: None,
                producer: EvidenceProducer::Gap {
                    reason: "no-journey-declared-for-category".into(),
                },
            }),
        }
    }
    for declaration in declarations {
        if applicable.contains(&declaration.stack) && !matched.contains(declaration.id.as_str()) {
            rows.push(CoverageRow {
                stack: declaration.stack,
                category: declaration.category.clone(),
                axis: declaration.axis,
                journey_id: Some(declaration.id.clone()),
                producer: declaration.producer.clone(),
            });
        }
    }
    rows
}

/// Human-readable gap list; non-empty means the profile cannot be complete.
pub fn inventory_gaps(rows: &[CoverageRow]) -> Vec<String> {
    rows.iter()
        .filter(|row| row.producer.is_gap())
        .map(|row| {
            format!(
                "{}:{}:{}",
                row.stack.label(),
                row.category,
                row.axis.label()
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Separate outcome axes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AxisState {
    pub status: JourneyStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AxisReport {
    pub axes: BTreeMap<OutcomeAxis, AxisState>,
    /// Axes proven inapplicable at freeze time, with the reason.
    pub inapplicable: BTreeMap<OutcomeAxis, String>,
}

impl AxisReport {
    /// Every axis starts `Unmet: no-evidence`; unknown stays incomplete.
    pub fn new(inapplicable: BTreeMap<OutcomeAxis, String>) -> Self {
        let mut axes = BTreeMap::new();
        for axis in OutcomeAxis::ALL {
            if !inapplicable.contains_key(&axis) {
                axes.insert(
                    axis,
                    AxisState {
                        status: JourneyStatus::Unmet,
                        reasons: vec!["no-evidence".into()],
                    },
                );
            }
        }
        Self { axes, inapplicable }
    }

    /// Fold one outcome into its own axis only. A failure/unmet anywhere on
    /// the axis dominates; a satisfied outcome replaces only `no-evidence`.
    pub fn record(&mut self, axis: OutcomeAxis, status: JourneyStatus, reasons: &[String]) {
        let Some(state) = self.axes.get_mut(&axis) else {
            return;
        };
        let was_empty = state.reasons.len() == 1 && state.reasons[0] == "no-evidence";
        if was_empty {
            state.status = status;
            state.reasons = reasons.to_vec();
            return;
        }
        if status.rank() > state.status.rank() {
            state.status = status;
        }
        state.reasons.extend(reasons.iter().cloned());
    }

    pub fn record_outcomes(&mut self, outcomes: &[JourneyOutcome]) {
        for outcome in outcomes {
            self.record(outcome.axis, outcome.status, &outcome.reasons);
        }
    }

    /// Complete only when every applicable axis is satisfied.
    pub fn is_complete(&self) -> bool {
        self.axes
            .values()
            .all(|s| s.status == JourneyStatus::Satisfied)
    }
}

// ---------------------------------------------------------------------------
// Performance
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarmState {
    Cold,
    Warm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Percentile {
    P50,
    P90,
    P95,
    P99,
    Max,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    LowerIsBetter,
    HigherIsBetter,
}

fn default_direction() -> Direction {
    Direction::LowerIsBetter
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardwareIdentity {
    pub cpu_model: String,
    pub logical_cores: u32,
    pub memory_mb: u64,
    pub os: String,
    pub os_version: String,
    /// Device model / instance type for phones and cloud hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceWorkload {
    pub workload_id: String,
    pub workload_digest: String,
    pub warm_state: WarmState,
    pub dataset_digest: String,
    pub traffic_mix_digest: String,
    pub concurrency: u32,
    /// Routes/screens deliberately excluded; different sets are incomparable.
    #[serde(default)]
    pub excluded_routes: Vec<String>,
    pub environment_id: String,
    pub hardware: HardwareIdentity,
    pub measurement_method: String,
    pub sample_count: u32,
}

impl PerformanceWorkload {
    /// Names of required fields that are empty/zero. Empty = fully described.
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let blank = |s: &str| s.trim().is_empty();
        if blank(&self.workload_id) {
            out.push("workloadId");
        }
        if !self.workload_digest.starts_with("sha256:") {
            out.push("workloadDigest");
        }
        if !self.dataset_digest.starts_with("sha256:") {
            out.push("datasetDigest");
        }
        if !self.traffic_mix_digest.starts_with("sha256:") {
            out.push("trafficMixDigest");
        }
        if self.concurrency == 0 {
            out.push("concurrency");
        }
        if blank(&self.environment_id) {
            out.push("environmentId");
        }
        if blank(&self.hardware.cpu_model) {
            out.push("hardware.cpuModel");
        }
        if self.hardware.logical_cores == 0 {
            out.push("hardware.logicalCores");
        }
        if self.hardware.memory_mb == 0 {
            out.push("hardware.memoryMb");
        }
        if blank(&self.hardware.os) {
            out.push("hardware.os");
        }
        if blank(&self.hardware.os_version) {
            out.push("hardware.osVersion");
        }
        if blank(&self.measurement_method) {
            out.push("measurementMethod");
        }
        if self.sample_count == 0 {
            out.push("sampleCount");
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceMeasurement {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub metric: String,
    pub unit: String,
    pub percentile: Percentile,
    /// Integer in `unit` (no floats, so equality is exact).
    pub value: u64,
    pub workload: PerformanceWorkload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceBaseline {
    /// Evidence id / revision the baseline came from.
    pub baseline_ref: String,
    pub measurement: PerformanceMeasurement,
}

/// Product-declared budget. Nothing here has a default: no universal 10x or
/// 100-user target exists, and an absent budget is never invented.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceBudget {
    pub metric: String,
    pub unit: String,
    pub percentile: Percentile,
    #[serde(default = "default_direction")]
    pub direction: Direction,
    /// Upper bound (lower-is-better) or lower bound (higher-is-better).
    pub limit: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_samples: Option<u32>,
    /// Allowed regression vs a comparable baseline, parts per million.
    /// Absent: trend is reported but never gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_tolerance_ppm: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum BudgetState {
    NotDeclared,
    Within,
    Exceeded,
    Unevaluable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum Trend {
    NoBaseline,
    /// Baseline differs in these dimensions; no regression or improvement
    /// claim is made.
    Incomparable {
        mismatches: Vec<String>,
    },
    Improved,
    Unchanged,
    Regressed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceOutcome {
    pub status: JourneyStatus,
    pub budget: BudgetState,
    pub trend: Trend,
    pub reasons: Vec<String>,
}

/// Dimensions in which two measurements are not comparable. Empty means
/// the workload, data, traffic mix, hardware and method all match.
pub fn comparison_mismatches(
    baseline: &PerformanceMeasurement,
    current: &PerformanceMeasurement,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(name.to_string());
        }
    };
    check("target", baseline.target == current.target);
    check("variant", baseline.variant == current.variant);
    check("metric", baseline.metric == current.metric);
    check("unit", baseline.unit == current.unit);
    check("percentile", baseline.percentile == current.percentile);
    let (b, c) = (&baseline.workload, &current.workload);
    check("workload-id", b.workload_id == c.workload_id);
    check("workload-digest", b.workload_digest == c.workload_digest);
    check("warm-state", b.warm_state == c.warm_state);
    check("dataset", b.dataset_digest == c.dataset_digest);
    check("traffic-mix", b.traffic_mix_digest == c.traffic_mix_digest);
    check("concurrency", b.concurrency == c.concurrency);
    let be: BTreeSet<&String> = b.excluded_routes.iter().collect();
    let ce: BTreeSet<&String> = c.excluded_routes.iter().collect();
    check("excluded-routes", be == ce);
    check("environment", b.environment_id == c.environment_id);
    check("hardware", b.hardware == c.hardware);
    check(
        "measurement-method",
        b.measurement_method == c.measurement_method,
    );
    out
}

/// Evaluate one measurement. The load obligation is `Satisfied` only with a
/// complete workload record, a product-declared budget it meets, and enough
/// samples; a regression is a finding only against a comparable baseline.
pub fn evaluate_performance(
    current: &PerformanceMeasurement,
    baseline: Option<&PerformanceBaseline>,
    budget: Option<&PerformanceBudget>,
) -> PerformanceOutcome {
    let mut reasons: Vec<String> = Vec::new();
    let mut finding = false;
    let mut blocked = false;

    let missing = current.workload.missing_fields();
    if !missing.is_empty() {
        blocked = true;
        reasons.push(format!("incomplete-workload-record:{}", missing.join(",")));
    }

    let budget_state = match budget {
        None => {
            blocked = true;
            reasons.push("performance-budget-not-declared".into());
            BudgetState::NotDeclared
        }
        Some(b) => {
            if b.metric != current.metric
                || b.unit != current.unit
                || b.percentile != current.percentile
            {
                blocked = true;
                reasons.push("budget-measurement-mismatch".into());
                BudgetState::Unevaluable
            } else if b
                .min_samples
                .is_some_and(|min| current.workload.sample_count < min)
            {
                blocked = true;
                reasons.push("insufficient-samples".into());
                BudgetState::Unevaluable
            } else {
                let within = match b.direction {
                    Direction::LowerIsBetter => current.value <= b.limit,
                    Direction::HigherIsBetter => current.value >= b.limit,
                };
                if within {
                    BudgetState::Within
                } else {
                    finding = true;
                    reasons.push("budget-exceeded".into());
                    BudgetState::Exceeded
                }
            }
        }
    };

    let trend = match baseline {
        None => Trend::NoBaseline,
        Some(base) => {
            let mismatches = comparison_mismatches(&base.measurement, current);
            if !mismatches.is_empty() {
                reasons.push(format!("incomparable-baseline:{}", mismatches.join(",")));
                Trend::Incomparable { mismatches }
            } else if base.measurement.workload.sample_count == 0 || !missing.is_empty() {
                reasons.push("incomparable-baseline:samples".into());
                Trend::Incomparable {
                    mismatches: vec!["samples".into()],
                }
            } else {
                let direction = budget
                    .map(|b| b.direction)
                    .unwrap_or(Direction::LowerIsBetter);
                let (b, c) = (base.measurement.value as u128, current.value as u128);
                let worse = match direction {
                    Direction::LowerIsBetter => c > b,
                    Direction::HigherIsBetter => c < b,
                };
                let better = match direction {
                    Direction::LowerIsBetter => c < b,
                    Direction::HigherIsBetter => c > b,
                };
                if better {
                    Trend::Improved
                } else if worse {
                    match budget.and_then(|x| x.regression_tolerance_ppm) {
                        Some(ppm) => {
                            let scale = 1_000_000u128;
                            let beyond = match direction {
                                Direction::LowerIsBetter => c * scale > b * (scale + ppm as u128),
                                Direction::HigherIsBetter => {
                                    c * scale < b * scale.saturating_sub(ppm as u128)
                                }
                            };
                            if beyond {
                                finding = true;
                                reasons.push("regression-vs-comparable-baseline".into());
                                Trend::Regressed
                            } else {
                                Trend::Unchanged
                            }
                        }
                        None => {
                            reasons.push("regression-tolerance-not-declared".into());
                            Trend::Unchanged
                        }
                    }
                } else {
                    Trend::Unchanged
                }
            }
        }
    };

    let status = if finding {
        JourneyStatus::Findings
    } else if blocked {
        JourneyStatus::Unmet
    } else {
        JourneyStatus::Satisfied
    };
    PerformanceOutcome {
        status,
        budget: budget_state,
        trend,
        reasons,
    }
}
