//! A16: explicit Rust feature / target / build / test / unsafe obligations.
//!
//! Existing `code.rust` analyses source and (when run) one cargo selection;
//! it never claims every target, feature combination or unsafe path. This
//! module models the *declared* matrix so each (package, target triple,
//! profile, feature selection, kind) is its own obligation with its own
//! evidence identity:
//!
//! * `--all-features` is only a legal selection when the product declares it
//!   valid and no mutually-exclusive feature group exists.
//! * Evidence for one target/variant/feature set never discharges another
//!   (iOS or macOS qualification is not Linux, release is not dev).
//! * Miri evidence covers executed, Miri-supported unsafe paths only; sites
//!   not executed or unsupported (FFI, inline asm, ...) remain unmet.
//! * No declared matrix means an explicit gap, never an implied pass.
//!
//! Pure planning/evaluation: nothing here runs cargo, Miri or any tool. The
//! evidence it consumes is an authenticated A03 [`ImportedEvidenceRecord`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::artifact_evidence::{
    is_rfc3339_utc_second, CommandBinding, EvidenceOutcome, ExpectedEvidence, ImportKind,
    ImportedEvidenceRecord, ReplayPolicy, RepositoryBinding,
};
use crate::assurance::{EvidenceKind, ObligationStatus, QualificationContext};
use crate::error::AuditError;

pub const PROVIDER_ID: &str = "code.rust.targets";
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum FeatureSelection {
    /// Package default features.
    Default,
    /// `--all-features`; legal only per [`FeatureConstraints`].
    AllFeatures,
    /// `--no-default-features` plus an explicit list (possibly empty).
    NoDefaultFeatures { features: Vec<String> },
    /// Default features plus an explicit list.
    Explicit { features: Vec<String> },
}

impl FeatureSelection {
    fn sorted(features: &[String]) -> Vec<String> {
        let set: BTreeSet<&String> = features.iter().collect();
        set.into_iter().cloned().collect()
    }

    /// Stable label used in obligation variants; order independent.
    pub fn label(&self) -> String {
        match self {
            Self::Default => "default".into(),
            Self::AllFeatures => "all-features".into(),
            Self::NoDefaultFeatures { features } => {
                format!("no-default[{}]", Self::sorted(features).join("+"))
            }
            Self::Explicit { features } => {
                format!("features[{}]", Self::sorted(features).join("+"))
            }
        }
    }

    /// Explicit feature names (for qualification scope and conflict checks).
    pub fn explicit_features(&self) -> Vec<String> {
        match self {
            Self::NoDefaultFeatures { features } | Self::Explicit { features } => {
                Self::sorted(features)
            }
            Self::Default => Vec::new(),
            Self::AllFeatures => vec!["all-features".into()],
        }
    }
}

/// Per-package feature facts declared by the product/manifest inventory.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureConstraints {
    /// Every feature the manifest declares; unknown selections are invalid.
    #[serde(default)]
    pub declared_features: Vec<String>,
    /// Groups of which at most one may be enabled together.
    #[serde(default)]
    pub mutually_exclusive: Vec<Vec<String>>,
    /// Product assertion that `--all-features` builds. `None` = undeclared.
    #[serde(default)]
    pub all_features_valid: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestSelection {
    /// Digest of the exact selected test set (filters, packages, ignored).
    pub digest: String,
    #[serde(default)]
    pub filters: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RustTargetSelection {
    pub package: String,
    pub target_triple: String,
    /// `dev`, `release` or a named custom profile.
    pub profile: String,
    pub features: FeatureSelection,
    pub toolchain: String,
    pub build_config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_selection: Option<TestSelection>,
}

impl RustTargetSelection {
    /// A02 `ObligationId.variant`: package, profile and feature selection.
    pub fn variant(&self) -> String {
        format!(
            "{}:{}:{}",
            self.package,
            self.profile,
            self.features.label()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsafeSite {
    pub id: String,
    pub path: String,
    pub line: u32,
    /// `false` for FFI, inline asm, syscalls and other Miri-unsupported code.
    pub miri_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RustTargetMatrix {
    /// Who declared the matrix (product config path or owner).
    pub declared_by: String,
    pub entries: Vec<RustTargetSelection>,
    /// Package name -> feature facts.
    #[serde(default)]
    pub constraints: BTreeMap<String, FeatureConstraints>,
    /// Conservative unsafe inventory (e.g. from `code.rust` keyword
    /// candidates). Empty means none were *declared*, not none exist.
    #[serde(default)]
    pub unsafe_sites: Vec<UnsafeSite>,
}

// ---------------------------------------------------------------------------
// Obligations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RustObligationKind {
    Build,
    Lint,
    Test,
    Miri,
    UnsafeReview,
}

impl RustObligationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Lint => "lint",
            Self::Test => "test",
            Self::Miri => "miri",
            Self::UnsafeReview => "unsafe-review",
        }
    }

    pub fn concern(self) -> String {
        format!("rust-{}", self.label())
    }

    pub fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Build => EvidenceKind::Build,
            Self::Lint => EvidenceKind::ProviderExecution,
            Self::Test | Self::Miri => EvidenceKind::Test,
            Self::UnsafeReview => EvidenceKind::Review,
        }
    }

    /// A03 import kind, when such evidence may be imported at all.
    pub fn import_kind(self) -> Option<ImportKind> {
        match self {
            Self::Build => Some(ImportKind::Build),
            Self::Lint => Some(ImportKind::Sarif),
            Self::Test | Self::Miri => Some(ImportKind::Test),
            Self::UnsafeReview => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustTargetObligation {
    /// `rust:<kind>:<triple>:<package>:<profile>:<features>`; unique.
    pub id: String,
    pub kind: RustObligationKind,
    pub package: String,
    pub target_triple: String,
    pub profile: String,
    pub features: FeatureSelection,
    pub toolchain: String,
    pub build_config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_selection_digest: Option<String>,
    /// Scope items an examined-scope claim must contain verbatim.
    pub scope_items: Vec<String>,
    /// Unsafe sites this obligation must cover (miri / unsafe-review).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsafe_sites: Vec<UnsafeSite>,
    /// Structural gaps frozen at plan time; any entry blocks `Satisfied`.
    pub plan_gaps: Vec<String>,
}

impl RustTargetObligation {
    pub fn obligation_target(&self) -> String {
        self.target_triple.clone()
    }

    pub fn obligation_variant(&self) -> String {
        format!(
            "{}:{}:{}",
            self.package,
            self.profile,
            self.features.label()
        )
    }

    pub fn concern(&self) -> String {
        self.kind.concern()
    }

    /// Qualification context for this exact selection. A record qualified
    /// for another triple, variant or feature set cannot apply (N09).
    pub fn qualification_context(
        &self,
        provider_id: &str,
        provider_version: &str,
        host: &str,
        requires_production_evidence: bool,
    ) -> QualificationContext {
        QualificationContext {
            provider_id: provider_id.to_string(),
            provider_version: provider_version.to_string(),
            rule_version: None,
            host: host.to_string(),
            toolchain: self.toolchain.clone(),
            target: self.obligation_target(),
            variant: Some(self.obligation_variant()),
            features: self.features.explicit_features(),
            requires_production_evidence,
        }
    }

    /// Frozen A03 expectations for this obligation.
    pub fn expected_evidence(
        &self,
        repositories: Vec<RepositoryBinding>,
        dependency_graph_digest: String,
        command: CommandBinding,
        replay_policy: ReplayPolicy,
    ) -> Result<ExpectedEvidence, AuditError> {
        let kind = self.kind.import_kind().ok_or_else(|| {
            AuditError::Invalid(format!(
                "{} evidence cannot be imported; it requires review",
                self.kind.label()
            ))
        })?;
        Ok(ExpectedEvidence {
            kind,
            repositories,
            target: self.obligation_target(),
            variant: Some(self.obligation_variant()),
            toolchain: self.toolchain.clone(),
            config_digest: self.build_config_digest.clone(),
            test_selection_digest: self.test_selection_digest.clone(),
            dependency_graph_digest,
            workload_digest: None,
            command,
            required_scope: self.scope_items.clone(),
            required_artifacts: Vec::new(),
            replay_policy,
            upstream_runtime: None,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustTargetPlan {
    pub obligations: Vec<RustTargetObligation>,
    /// Plan-wide gaps (no matrix, duplicate entry, ...).
    pub gaps: Vec<String>,
}

/// Validate one selection against its package constraints; returns every
/// reason it is not a legal selection.
pub fn selection_problems(
    selection: &RustTargetSelection,
    constraints: Option<&FeatureConstraints>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in [
        ("package", &selection.package),
        ("target-triple", &selection.target_triple),
        ("profile", &selection.profile),
        ("toolchain", &selection.toolchain),
    ] {
        if value.trim().is_empty() {
            out.push(format!("{name}-empty"));
        }
    }
    if !selection.build_config_digest.starts_with("sha256:") {
        out.push("build-config-digest-invalid".into());
    }
    let Some(constraints) = constraints else {
        match &selection.features {
            FeatureSelection::Default => {}
            _ => out.push("feature-constraints-undeclared".into()),
        }
        return out;
    };
    let declared: BTreeSet<&str> = constraints
        .declared_features
        .iter()
        .map(String::as_str)
        .collect();
    match &selection.features {
        FeatureSelection::Default => {}
        FeatureSelection::AllFeatures => {
            if !constraints.mutually_exclusive.is_empty() {
                out.push("all-features-invalid-mutually-exclusive-features".into());
            }
            match constraints.all_features_valid {
                Some(true) => {}
                Some(false) => out.push("all-features-declared-invalid".into()),
                None => out.push("all-features-validity-undeclared".into()),
            }
        }
        FeatureSelection::NoDefaultFeatures { features }
        | FeatureSelection::Explicit { features } => {
            let chosen: BTreeSet<&str> = features.iter().map(String::as_str).collect();
            for feature in &chosen {
                if !declared.contains(feature) {
                    out.push(format!("unknown-feature:{feature}"));
                }
            }
            for group in &constraints.mutually_exclusive {
                let hits: Vec<&String> = group
                    .iter()
                    .filter(|f| chosen.contains(f.as_str()))
                    .collect();
                if hits.len() > 1 {
                    out.push(format!(
                        "mutually-exclusive-features:{}",
                        hits.iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("+")
                    ));
                }
            }
        }
    }
    out
}

/// Expand the declared matrix into obligations for the requested kinds.
/// Invalid selections still yield obligations, carrying `plan_gaps`, so they
/// stay visibly unmet instead of silently disappearing.
pub fn plan_rust_obligations(
    matrix: &RustTargetMatrix,
    kinds: &[RustObligationKind],
) -> RustTargetPlan {
    let mut plan = RustTargetPlan::default();
    if matrix.entries.is_empty() {
        plan.gaps.push(
            "no-declared-target-matrix: code.rust does not claim every target or feature set"
                .into(),
        );
        return plan;
    }
    if matrix.declared_by.trim().is_empty() {
        plan.gaps.push("matrix-declarer-missing".into());
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in &matrix.entries {
        let problems = selection_problems(entry, matrix.constraints.get(&entry.package));
        for kind in kinds {
            let id = format!(
                "rust:{}:{}:{}:{}:{}",
                kind.label(),
                entry.target_triple,
                entry.package,
                entry.profile,
                entry.features.label()
            );
            if !seen.insert(id.clone()) {
                plan.gaps.push(format!("duplicate-matrix-entry:{id}"));
                continue;
            }
            let mut gaps = problems.clone();
            let mut scope_items = vec![id.clone()];
            let mut unsafe_sites = Vec::new();
            let mut test_digest = None;
            match kind {
                RustObligationKind::Test => match &entry.test_selection {
                    Some(selection) if selection.digest.starts_with("sha256:") => {
                        test_digest = Some(selection.digest.clone());
                    }
                    _ => gaps.push("test-selection-undeclared".into()),
                },
                RustObligationKind::Miri | RustObligationKind::UnsafeReview => {
                    if matrix.unsafe_sites.is_empty() {
                        // Nothing declared: do not emit an obligation that
                        // could be read as covering unknown unsafe code.
                        continue;
                    }
                    unsafe_sites = matrix.unsafe_sites.clone();
                    for site in &unsafe_sites {
                        scope_items.push(format!("unsafe:{}", site.id));
                    }
                }
                _ => {}
            }
            plan.obligations.push(RustTargetObligation {
                id,
                kind: *kind,
                package: entry.package.clone(),
                target_triple: entry.target_triple.clone(),
                profile: entry.profile.clone(),
                features: entry.features.clone(),
                toolchain: entry.toolchain.clone(),
                build_config_digest: entry.build_config_digest.clone(),
                test_selection_digest: test_digest,
                scope_items,
                unsafe_sites,
                plan_gaps: gaps,
            });
        }
    }
    plan
}

// ---------------------------------------------------------------------------
// Miri coverage
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MiriCoverage {
    /// Always `executed-supported-paths-only`: Miri says nothing about code
    /// it did not execute or cannot interpret.
    pub claim: String,
    pub covered_sites: Vec<String>,
    pub uncovered_sites: Vec<String>,
    pub unsupported_sites: Vec<String>,
    pub complete: bool,
}

/// Compare the unsafe inventory with the sites Miri actually executed.
/// `executed_site_ids` must come from authenticated evidence scope.
pub fn evaluate_miri_coverage(
    sites: &[UnsafeSite],
    executed_site_ids: &BTreeSet<String>,
) -> MiriCoverage {
    let mut covered = Vec::new();
    let mut uncovered = Vec::new();
    let mut unsupported = Vec::new();
    for site in sites {
        if !site.miri_supported {
            unsupported.push(format!(
                "{}:{}",
                site.id,
                site.unsupported_reason
                    .as_deref()
                    .unwrap_or("miri-unsupported")
            ));
        } else if executed_site_ids.contains(&site.id) {
            covered.push(site.id.clone());
        } else {
            uncovered.push(site.id.clone());
        }
    }
    let complete = !sites.is_empty() && uncovered.is_empty() && unsupported.is_empty();
    MiriCoverage {
        claim: "executed-supported-paths-only".into(),
        covered_sites: covered,
        uncovered_sites: uncovered,
        unsupported_sites: unsupported,
        complete,
    }
}

// ---------------------------------------------------------------------------
// Evidence evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustObligationOutcome {
    pub obligation_id: String,
    pub status: ObligationStatus,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miri: Option<MiriCoverage>,
}

/// Evaluate authenticated evidence for one obligation. Any identity,
/// freshness, scope, replay or coverage problem leaves it `Unmet`.
pub fn evaluate_rust_evidence(
    obligation: &RustTargetObligation,
    record: Option<&ImportedEvidenceRecord>,
    now_rfc3339_utc: &str,
) -> RustObligationOutcome {
    let mut reasons: Vec<String> = Vec::new();
    for gap in &obligation.plan_gaps {
        reasons.push(format!("plan-gap:{gap}"));
    }
    let done = |status, reasons, miri| RustObligationOutcome {
        obligation_id: obligation.id.clone(),
        status,
        reasons,
        miri,
    };
    let Some(import_kind) = obligation.kind.import_kind() else {
        reasons.push("evidence-not-importable-requires-review".into());
        return done(ObligationStatus::Unmet, reasons, None);
    };
    let Some(record) = record else {
        reasons.push("missing-authenticated-evidence".into());
        return done(ObligationStatus::Unmet, reasons, None);
    };
    if !record.authenticated {
        reasons.push("evidence-unauthenticated".into());
    }
    if record.kind != import_kind {
        reasons.push("evidence-kind-mismatch".into());
    }
    if record.target != obligation.obligation_target() {
        reasons.push("target-mismatch".into());
    }
    if record.variant.as_deref() != Some(obligation.obligation_variant().as_str()) {
        reasons.push("variant-mismatch".into());
    }
    if record.toolchain != obligation.toolchain {
        reasons.push("toolchain-mismatch".into());
    }
    if !is_rfc3339_utc_second(&record.fresh_until) || !is_rfc3339_utc_second(now_rfc3339_utc) {
        reasons.push("invalid-freshness-timestamp".into());
    } else if record.fresh_until.as_str() <= now_rfc3339_utc {
        reasons.push("stale-evidence".into());
    }
    if !record.newly_executed {
        reasons.push("replayed-evidence".into());
    }
    let examined: BTreeSet<&str> = record.examined_scope.iter().map(String::as_str).collect();
    // The obligation id proves the selection; unsafe-site items are judged
    // through Miri coverage below rather than as a blanket scope miss.
    if !examined.contains(obligation.id.as_str()) {
        reasons.push(format!("scope-not-examined:{}", obligation.id));
    }
    if obligation.kind != RustObligationKind::Miri {
        for item in &obligation.scope_items {
            if !examined.contains(item.as_str()) {
                reasons.push(format!("scope-not-examined:{item}"));
            }
        }
    }
    for missing in &record.missing_scope {
        reasons.push(format!("scope-missing:{missing}"));
    }

    let mut miri = None;
    if obligation.kind == RustObligationKind::Miri {
        let executed: BTreeSet<String> = obligation
            .unsafe_sites
            .iter()
            .filter(|site| examined.contains(format!("unsafe:{}", site.id).as_str()))
            .map(|site| site.id.clone())
            .collect();
        let coverage = evaluate_miri_coverage(&obligation.unsafe_sites, &executed);
        for id in &coverage.uncovered_sites {
            reasons.push(format!("unsafe-site-not-executed:{id}"));
        }
        for entry in &coverage.unsupported_sites {
            reasons.push(format!("miri-unsupported:{entry}"));
        }
        if obligation.unsafe_sites.is_empty() {
            reasons.push("no-unsafe-inventory".into());
        }
        miri = Some(coverage);
    }

    if !reasons.is_empty() {
        return done(ObligationStatus::Unmet, reasons, miri);
    }
    match record.outcome {
        EvidenceOutcome::Passed => done(ObligationStatus::Satisfied, reasons, miri),
        EvidenceOutcome::Failed | EvidenceOutcome::Findings => {
            reasons.push("evidence-reports-failure".into());
            done(ObligationStatus::Findings, reasons, miri)
        }
        EvidenceOutcome::Error => {
            reasons.push("owner-reported-error".into());
            done(ObligationStatus::Unmet, reasons, miri)
        }
    }
}
