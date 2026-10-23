//! Typed production-assurance extension (`auditAssuranceV1`) for Audit.
//!
//! Obligations are the mandatory coverage inventory for one declared
//! product target, resolved before provider selection. They are kept
//! deliberately separate from the existing provider/report schemas: a
//! `ProviderResult` proves one provider ran, a qualification record proves
//! a provider was once measured, and neither proves that *this* product,
//! target, variant and snapshot were examined. An obligation is therefore
//! only `satisfied` by evidence bound to its full identity; anything
//! missing, stale, fixture-only, differently-targeted or unqualified
//! leaves it `unmet`. Waived never means executed.

use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{Coverage, ReportStatus, ReportV1, ReportV2};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AuditError;
use crate::execution::ExecutionReport;
use crate::plan::FrozenPlan;
use crate::profiles::{AuditProfile, FrozenProfile, RuntimeConstraint};

/// Report extension key (`ReportV1.extensions` / projected ReportV2); the
/// canonical constant lives with the report contract.
pub use legion_contracts::report::AUDIT_ASSURANCE_EXTENSION_KEY;

/// The frozen plan form (profile, runtime constraint, obligations). At
/// freeze every applicable obligation is `unmet`; the same type, reconciled,
/// is the projected report extension.
pub type AssurancePlan = AuditAssuranceV1;

/// Evaluation instant used only where no waiver can exist (frozen plans).
const FROZEN_NOW: &str = "9999-12-31T23:59:59Z";
/// `AuditPlan::bounds` key under which root freezes obligations + profile.
pub const ASSURANCE_BOUND: &str = "auditAssuranceV1";
/// Current (and only supported) extension schema version.
pub const AUDIT_ASSURANCE_SCHEMA_VERSION: u32 = 1;

/// Kind of evidence that can discharge an obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// A provider executed by Audit in this run over this snapshot.
    ProviderExecution,
    /// Evidence produced outside Audit (e.g. application CI) and imported
    /// only with authenticated provenance (digest + attestor).
    AuthenticatedUpstreamReceipt,
    /// Build evidence for the exact target/variant.
    Build,
    /// Test evidence for the exact target/variant.
    Test,
    /// Runtime / journey evidence for the exact target/variant.
    Runtime,
    /// Release-artifact evidence (signed/verified artifact identity).
    Artifact,
    /// Human/semantic review evidence.
    Review,
}

/// Terminal state of one obligation. `Waived` is an owner decision, never
/// an execution claim; `Deferred` is a recorded non-run for a later profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObligationStatus {
    Satisfied,
    Findings,
    Unmet,
    Deferred,
    Waived,
    Inapplicable,
}

impl ObligationStatus {
    /// Only executed-and-clean or executed-with-findings count as examined.
    pub fn was_examined(self) -> bool {
        matches!(self, Self::Satisfied | Self::Findings)
    }
    /// States that keep a run from being complete. `Inapplicable` does not:
    /// inapplicability must have been proven when the inventory froze.
    pub fn blocks_completion(self) -> bool {
        matches!(self, Self::Unmet | Self::Deferred | Self::Waived)
    }
}

/// Snapshot-set member: one repository at one frozen revision.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotRef {
    pub repository_id: String,
    /// Inventory/snapshot digest, `sha256:`-prefixed.
    pub snapshot_digest: String,
}

/// Full identity of an obligation. Two obligations differing in any field
/// are different obligations; evidence for one never discharges another.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationId {
    pub product: String,
    pub snapshots: Vec<SnapshotRef>,
    /// e.g. `aarch64-apple-darwin`, `android:phoneRelease`, `web:production`.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// e.g. `dependency-health`, `source-static`, `runtime-journey`.
    pub concern: String,
    pub evidence_kind: EvidenceKind,
    /// Rule/profile revision the obligation was frozen under.
    pub rule_profile_revision: String,
}

impl ObligationId {
    pub fn validate(&self, path: &str) -> Result<(), AuditError> {
        for (field, value) in [
            ("product", &self.product),
            ("target", &self.target),
            ("concern", &self.concern),
            ("ruleProfileRevision", &self.rule_profile_revision),
        ] {
            if value.trim().is_empty() {
                return Err(invalid(format!("{path}.{field}"), "must be non-empty"));
            }
        }
        if self.snapshots.is_empty() {
            return Err(invalid(
                format!("{path}.snapshots"),
                "obligation requires at least one frozen snapshot",
            ));
        }
        let mut seen = BTreeSet::new();
        for snapshot in &self.snapshots {
            if snapshot.repository_id.trim().is_empty()
                || !snapshot.snapshot_digest.starts_with("sha256:")
            {
                return Err(invalid(
                    format!("{path}.snapshots"),
                    "each snapshot requires a repository id and sha256: digest",
                ));
            }
            if !seen.insert(&snapshot.repository_id) {
                return Err(invalid(
                    format!("{path}.snapshots"),
                    "duplicate repository in snapshot set",
                ));
            }
        }
        Ok(())
    }
}

/// One denominator for required input. `required == 0` is only legitimate
/// when the applicable universe was proven empty at freeze time
/// (`applicable_universe_empty`); an unproven zero is never complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationDenominator {
    pub applicable_universe: u64,
    /// Required input after *proven* inapplicability only. Exclusions for
    /// convenience/scope must not shrink this (enforced by `validate`).
    pub required: u64,
    pub examined: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
    /// Proven-inapplicable units removed from the universe, each with the
    /// freeze-time reason recorded in `gaps`/evidence by the resolver.
    #[serde(default)]
    pub proven_inapplicable: u64,
}

impl ObligationDenominator {
    pub fn validate(&self, path: &str) -> Result<(), AuditError> {
        if self.required > self.applicable_universe {
            return Err(invalid(
                format!("{path}.required"),
                "required exceeds applicable universe",
            ));
        }
        if self.applicable_universe - self.required != self.proven_inapplicable {
            return Err(invalid(
                format!("{path}.provenInapplicable"),
                "only proven inapplicability may shrink the required denominator",
            ));
        }
        if self.examined > self.required {
            return Err(invalid(
                format!("{path}.examined"),
                "examined exceeds required",
            ));
        }
        Ok(())
    }

    /// Distinguishes an empty applicable universe from zero-examined
    /// required input: the former can be complete, the latter never is.
    pub fn is_complete(&self) -> bool {
        if self.applicable_universe == 0 {
            return self.required == 0 && self.gaps.is_empty();
        }
        self.required > 0 && self.examined >= self.required && self.gaps.is_empty()
    }
}

/// Explicit owner waiver. Tools and models cannot grant one: `granted_by`
/// must name a human/owner identity, never a tool/model/provider id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Waiver {
    pub granted_by: String,
    pub rationale: String,
    /// Obligation ids (canonical JSON of `ObligationId`) or a narrower
    /// named scope bound by the resolver; must be non-empty.
    pub scope: Vec<String>,
    /// RFC 3339 UTC (`...Z`) expiry. Expired waivers restore `unmet`.
    pub expires_at: String,
}

impl Waiver {
    pub fn validate(&self, path: &str, now_rfc3339_utc: &str) -> Result<(), AuditError> {
        if self.granted_by.trim().is_empty() || self.rationale.trim().is_empty() {
            return Err(invalid(path, "waiver requires grantor and rationale"));
        }
        let grantor = self.granted_by.to_ascii_lowercase();
        for forbidden in ["tool", "model", "provider", "agent", "bot", "ci"] {
            if grantor == forbidden || grantor.starts_with(&format!("{forbidden}:")) {
                return Err(invalid(
                    format!("{path}.grantedBy"),
                    "tools/models/providers cannot grant waivers",
                ));
            }
        }
        if self.scope.is_empty() || self.scope.iter().any(|s| s.trim().is_empty()) {
            return Err(invalid(
                format!("{path}.scope"),
                "waiver requires a bound non-empty scope",
            ));
        }
        if !self.expires_at.ends_with('Z') || !now_rfc3339_utc.ends_with('Z') {
            return Err(invalid(
                format!("{path}.expiresAt"),
                "waiver expiry and evaluation time must be RFC3339 UTC (...Z)",
            ));
        }
        if self.expires_at.as_str() <= now_rfc3339_utc {
            return Err(invalid(format!("{path}.expiresAt"), "waiver is expired"));
        }
        Ok(())
    }
}

/// One frozen mandatory obligation with its reconciliation outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionObligation {
    pub id: ObligationId,
    /// Profiles that require this obligation. A faster profile may omit
    /// release-only obligations; omission is recorded, never inherited.
    pub required_in: Vec<AuditProfile>,
    /// Provider ids expected to discharge it (may be empty for imported
    /// or review evidence; emptiness never implies satisfaction).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denominator: Option<ObligationDenominator>,
    /// Denominator digest a provider `Coverage` must match, when bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_denominator_digest: Option<String>,
    pub status: ObligationStatus,
    /// Evidence refs (digests/ids) backing `status`; required for
    /// satisfied/findings/inapplicable, forbidden as a substitute for
    /// execution when `waived`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver: Option<Waiver>,
}

impl ProductionObligation {
    pub fn validate(&self, path: &str, now_rfc3339_utc: &str) -> Result<(), AuditError> {
        self.id.validate(&format!("{path}.id"))?;
        if self.required_in.is_empty() {
            return Err(invalid(
                format!("{path}.requiredIn"),
                "obligation must be required in at least one profile",
            ));
        }
        if let Some(denominator) = &self.denominator {
            denominator.validate(&format!("{path}.denominator"))?;
        }
        match self.status {
            ObligationStatus::Satisfied | ObligationStatus::Findings => {
                if self.evidence_refs.is_empty() {
                    return Err(invalid(
                        format!("{path}.evidenceRefs"),
                        "examined obligation requires evidence",
                    ));
                }
                if self.waiver.is_some() {
                    return Err(invalid(
                        format!("{path}.waiver"),
                        "examined obligation cannot also be waived",
                    ));
                }
                if let Some(denominator) = &self.denominator {
                    if !denominator.is_complete() {
                        return Err(invalid(
                            format!("{path}.denominator"),
                            "examined obligation requires a complete denominator",
                        ));
                    }
                }
            }
            ObligationStatus::Waived => {
                let waiver = self
                    .waiver
                    .as_ref()
                    .ok_or_else(|| invalid(format!("{path}.waiver"), "waived requires a waiver"))?;
                waiver.validate(&format!("{path}.waiver"), now_rfc3339_utc)?;
            }
            ObligationStatus::Inapplicable => {
                if self.reason.as_deref().unwrap_or("").trim().is_empty()
                    && self.evidence_refs.is_empty()
                {
                    return Err(invalid(
                        format!("{path}.reason"),
                        "inapplicable requires a proven reason or evidence",
                    ));
                }
            }
            ObligationStatus::Unmet | ObligationStatus::Deferred => {
                if self.reason.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(invalid(
                        format!("{path}.reason"),
                        "unmet/deferred requires a reason; silence is not clean",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What a qualification record actually covers. The legacy qualified
/// Boolean / `benchmark.status == "qualified"` alone is insufficient:
/// every dimension here must match the run for accuracy to apply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationScope {
    pub provider_id: String,
    pub provider_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_version: Option<String>,
    pub host: String,
    pub toolchain: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// `fixture`, `production`, or another named basis. Fixture scope
    /// never qualifies a production clean claim.
    pub evidence_basis: String,
    pub fixture_scope: String,
    /// RFC3339 UTC freshness bound for time-sensitive evidence (e.g.
    /// advisories); evaluated as stale when `<= now`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_until: Option<String>,
    pub digest: String,
}

/// The exact context a qualification must match to apply to this run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationContext {
    pub provider_id: String,
    pub provider_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_version: Option<String>,
    pub host: String,
    pub toolchain: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    pub requires_production_evidence: bool,
}

/// Outcome of applicability evaluation, kept separate from executed
/// coverage: applicable qualification is necessary, never sufficient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationVerdict {
    pub applicable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
}

/// Evaluate whether `record` qualifies `context`. Missing record,
/// version/host/toolchain/target/variant/feature mismatch, fixture-only
/// basis for a production claim, or stale `fresh_until` all yield
/// `applicable: false` with named mismatches — never a clean default.
pub fn evaluate_qualification(
    record: Option<&QualificationScope>,
    context: &QualificationContext,
    now_rfc3339_utc: &str,
) -> QualificationVerdict {
    let Some(record) = record else {
        return QualificationVerdict {
            applicable: false,
            mismatches: vec!["missing-qualification-record".into()],
        };
    };
    let mut mismatches = Vec::new();
    let check = |name: &str, record_value: &str, context_value: &str, out: &mut Vec<String>| {
        if record_value != context_value {
            out.push(format!("{name}: record={record_value} run={context_value}"));
        }
    };
    check(
        "providerId",
        &record.provider_id,
        &context.provider_id,
        &mut mismatches,
    );
    check(
        "providerVersion",
        &record.provider_version,
        &context.provider_version,
        &mut mismatches,
    );
    match (&record.rule_version, &context.rule_version) {
        (Some(r), Some(c)) => check("ruleVersion", r, c, &mut mismatches),
        (None, Some(_)) => mismatches.push("ruleVersion: record missing".into()),
        (Some(_), None) => mismatches.push("ruleVersion: run unknown".into()),
        (None, None) => {}
    }
    check("host", &record.host, &context.host, &mut mismatches);
    check(
        "toolchain",
        &record.toolchain,
        &context.toolchain,
        &mut mismatches,
    );
    check("target", &record.target, &context.target, &mut mismatches);
    if record.variant != context.variant {
        mismatches.push("variant: record/run mismatch".into());
    }
    let record_features: BTreeSet<&str> = record.features.iter().map(String::as_str).collect();
    for feature in &context.features {
        if !record_features.contains(feature.as_str()) {
            mismatches.push(format!("feature-not-qualified:{feature}"));
        }
    }
    // Exact comparison: a record qualified with features the run did not
    // enable describes a different configuration.
    let context_features: BTreeSet<&str> = context.features.iter().map(String::as_str).collect();
    for feature in &record_features {
        if !context_features.contains(feature) {
            mismatches.push(format!("feature-not-executed:{feature}"));
        }
    }
    if context.requires_production_evidence && record.evidence_basis != "production" {
        mismatches.push(format!(
            "evidenceBasis: {} does not qualify a production claim",
            record.evidence_basis
        ));
    }
    if record.fixture_scope.trim().is_empty() {
        mismatches.push("fixtureScope: missing".into());
    }
    if !record.digest.starts_with("sha256:") {
        mismatches.push("digest: must be sha256:-prefixed".into());
    }
    if let Some(fresh_until) = &record.fresh_until {
        if !fresh_until.ends_with('Z') || !now_rfc3339_utc.ends_with('Z') {
            mismatches.push("freshUntil: must be RFC3339 UTC (...Z)".into());
        } else if fresh_until.as_str() <= now_rfc3339_utc {
            mismatches.push("stale-qualification-or-advisory".into());
        }
    }
    QualificationVerdict {
        applicable: mismatches.is_empty(),
        mismatches,
    }
}

/// Declared product target from which the mandatory inventory resolves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductTarget {
    pub product: String,
    pub snapshots: Vec<SnapshotRef>,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// One candidate obligation before profile filtering. Root builds these
/// from the declared product + registry/control inventory; A02 owns how
/// they freeze, not which providers exist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationCandidate {
    pub concern: String,
    pub evidence_kind: EvidenceKind,
    pub required_in: Vec<AuditProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_denominator_digest: Option<String>,
    /// Proven-inapplicable candidates freeze as `inapplicable` with this
    /// reason; absence of a candidate is never used to shrink inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proven_inapplicable_reason: Option<String>,
}

/// Resolve the mandatory inventory for `profile` *before* provider
/// selection. Every candidate required in `profile.profile` freezes as
/// `unmet` (or proven `inapplicable`); candidates required only in a
/// stronger profile are omitted — legitimately, for this profile only.
pub fn resolve_obligations(
    product_target: &ProductTarget,
    profile: &FrozenProfile,
    candidates: &[ObligationCandidate],
) -> Result<Vec<ProductionObligation>, AuditError> {
    if product_target.product.trim().is_empty() || product_target.target.trim().is_empty() {
        return Err(invalid(
            "productTarget",
            "product and target must be non-empty",
        ));
    }
    let mut obligations = Vec::new();
    let mut seen: BTreeSet<ObligationId> = BTreeSet::new();
    for candidate in candidates {
        if !candidate.required_in.contains(&profile.profile) {
            continue;
        }
        if candidate.concern.trim().is_empty() {
            return Err(invalid("candidates.concern", "must be non-empty"));
        }
        let id = ObligationId {
            product: product_target.product.clone(),
            snapshots: product_target.snapshots.clone(),
            target: product_target.target.clone(),
            variant: product_target.variant.clone(),
            concern: candidate.concern.clone(),
            evidence_kind: candidate.evidence_kind,
            rule_profile_revision: profile.revision.clone(),
        };
        id.validate("obligation.id")?;
        if !seen.insert(id.clone()) {
            return Err(invalid("obligations", "duplicate obligation identity"));
        }
        let (status, reason) = match &candidate.proven_inapplicable_reason {
            Some(reason) if !reason.trim().is_empty() => {
                (ObligationStatus::Inapplicable, Some(reason.clone()))
            }
            _ => (ObligationStatus::Unmet, Some("not-yet-examined".to_owned())),
        };
        obligations.push(ProductionObligation {
            id,
            required_in: candidate.required_in.clone(),
            provider_ids: candidate.provider_ids.clone(),
            denominator: None,
            required_denominator_digest: candidate.required_denominator_digest.clone(),
            status,
            evidence_refs: Vec::new(),
            reason,
            waiver: None,
        });
    }
    obligations.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(obligations)
}

/// Evidence offered to discharge one obligation. Identity fields must
/// match the obligation exactly; kind-specific requirements (complete
/// coverage, authenticated provenance, verified artifact) are enforced
/// in `apply_evidence`. Application CI may use Node/Python to *produce*
/// imported evidence; that production runtime is recorded, not executed
/// by Audit, and does not violate `NoNodePython`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationEvidence {
    pub obligation: ObligationId,
    pub kind: EvidenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    /// Authenticated provenance for imported evidence: `sha256:` digest
    /// of the artifact/receipt plus the attesting system identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_by: Option<String>,
    /// True only after upstream provenance was cryptographically or
    /// host-verified by the importer (A03/root); A02 never infers it.
    #[serde(default)]
    pub authenticated: bool,
    /// Runtime that produced imported evidence, for reporting only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_by_runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<QualificationVerdict>,
}

/// Apply evidence to a frozen obligation. Any mismatch (wrong target /
/// variant / snapshot / concern / kind / denominator, incomplete
/// coverage, unauthenticated import, unverified artifact, inapplicable
/// qualification) leaves the obligation `unmet` with a named reason.
/// Returns the updated obligation; never mutates identity.
pub fn apply_evidence(
    obligation: &ProductionObligation,
    evidence: &ObligationEvidence,
) -> ProductionObligation {
    let mut out = obligation.clone();
    let unmet = |out: &mut ProductionObligation, reason: String| {
        out.status = ObligationStatus::Unmet;
        out.reason = Some(reason);
        out.evidence_refs = Vec::new();
    };
    if evidence.obligation != obligation.id || evidence.kind != obligation.id.evidence_kind {
        unmet(&mut out, "evidence-identity-mismatch".into());
        return out;
    }
    if let Some(verdict) = &evidence.qualification {
        if !verdict.applicable {
            unmet(
                &mut out,
                format!(
                    "qualification-not-applicable:{}",
                    verdict.mismatches.join(",")
                ),
            );
            return out;
        }
    }
    match evidence.kind {
        EvidenceKind::ProviderExecution => {
            let Some(coverage) = &evidence.coverage else {
                unmet(&mut out, "missing-scanner-or-coverage".into());
                return out;
            };
            if let Some(required) = &obligation.required_denominator_digest {
                if &coverage.denominator_digest != required {
                    unmet(&mut out, "denominator-digest-mismatch".into());
                    return out;
                }
            }
            // expected == 0 with nothing examined is unproven input, not
            // an empty universe: Coverage::complete() already requires
            // expected > 0, gaps empty and examined >= expected.
            if !coverage.complete() {
                unmet(&mut out, "coverage-incomplete-or-zero-examined".into());
                return out;
            }
        }
        EvidenceKind::AuthenticatedUpstreamReceipt
        | EvidenceKind::Build
        | EvidenceKind::Test
        | EvidenceKind::Runtime
        | EvidenceKind::Artifact => {
            let digest_ok = evidence
                .artifact_digest
                .as_deref()
                .is_some_and(|d| d.starts_with("sha256:"));
            if !evidence.authenticated || !digest_ok {
                unmet(&mut out, "unverified-or-unauthenticated-artifact".into());
                return out;
            }
            if evidence.kind == EvidenceKind::AuthenticatedUpstreamReceipt
                && evidence
                    .attested_by
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                unmet(&mut out, "missing-upstream-attestor".into());
                return out;
            }
            if let Some(coverage) = &evidence.coverage {
                if !coverage.complete() {
                    unmet(&mut out, "coverage-incomplete-or-zero-examined".into());
                    return out;
                }
            }
        }
        EvidenceKind::Review => {
            if evidence.evidence_refs.is_empty() {
                unmet(&mut out, "review-evidence-missing".into());
                return out;
            }
        }
    }
    out.evidence_refs = evidence.evidence_refs.clone();
    if out.evidence_refs.is_empty() {
        if let Some(digest) = &evidence.artifact_digest {
            out.evidence_refs.push(digest.clone());
        }
    }
    if out.evidence_refs.is_empty() {
        unmet(&mut out, "evidence-refs-missing".into());
        return out;
    }
    out.reason = None;
    out.status = if evidence.finding_ids.is_empty() {
        ObligationStatus::Satisfied
    } else {
        ObligationStatus::Findings
    };
    out
}

/// Adopt an owner waiver. The result stays visibly `waived`, carries no
/// execution evidence, and never counts as examined.
pub fn apply_waiver(
    obligation: &ProductionObligation,
    waiver: Waiver,
    now_rfc3339_utc: &str,
) -> Result<ProductionObligation, AuditError> {
    waiver.validate("waiver", now_rfc3339_utc)?;
    let mut out = obligation.clone();
    out.status = ObligationStatus::Waived;
    out.evidence_refs = Vec::new();
    out.reason = Some("waived-by-owner: not executed".to_owned());
    out.waiver = Some(waiver);
    Ok(out)
}

/// Independent report axes. Completion, finding outcome and release
/// eligibility are separate fields so a partial run, a clean-but-
/// incomplete run and a release claim can never collapse into one flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Completion {
    Complete,
    Partial,
    /// Nothing applicable was examined (or no obligations were frozen).
    NotExamined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingOutcome {
    Clean,
    Findings,
    /// No findings, but required input was not examined: not clean.
    Unproven,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseEligibility {
    Eligible,
    NotEligible,
    /// This run's profile cannot make a release claim at all.
    NotAssessed,
}

/// Derived summary, always recomputable from `obligations`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssuranceSummary {
    pub completion: Completion,
    pub finding_outcome: FindingOutcome,
    pub release_eligibility: ReleaseEligibility,
    pub total: u64,
    pub satisfied: u64,
    pub findings: u64,
    pub unmet: u64,
    pub deferred: u64,
    pub waived: u64,
    pub inapplicable: u64,
}

/// The versioned audit-local extension projected into ReportV2. Root
/// stores the frozen form in `AuditPlan::bounds[ASSURANCE_BOUND]` and the
/// reconciled form in `Report.extensions[AUDIT_ASSURANCE_EXTENSION_KEY]`;
/// the existing provider/report schemas are unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditAssuranceV1 {
    pub schema_version: u32,
    pub profile: FrozenProfile,
    pub runtime_constraint: RuntimeConstraint,
    pub product_target: ProductTarget,
    pub obligations: Vec<ProductionObligation>,
    pub summary: AssuranceSummary,
}

impl AuditAssuranceV1 {
    /// Build + summarize from obligations alone.
    pub fn new(
        profile: FrozenProfile,
        product_target: ProductTarget,
        obligations: Vec<ProductionObligation>,
    ) -> Self {
        let runtime_constraint = profile.runtime_constraint;
        let summary = summarize(profile.profile, &obligations);
        Self {
            schema_version: AUDIT_ASSURANCE_SCHEMA_VERSION,
            profile,
            runtime_constraint,
            product_target,
            obligations,
            summary,
        }
    }

    /// Versioned (de)serialization gate: unknown schema versions are
    /// rejected, never best-effort-parsed into a weaker claim.
    pub fn from_value(value: &Value, now_rfc3339_utc: &str) -> Result<Self, AuditError> {
        let version = value
            .get("schemaVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("auditAssuranceV1.schemaVersion", "missing"))?;
        if version != u64::from(AUDIT_ASSURANCE_SCHEMA_VERSION) {
            return Err(invalid(
                "auditAssuranceV1.schemaVersion",
                format!("unsupported version {version}"),
            ));
        }
        let parsed: Self = serde_json::from_value(value.clone())
            .map_err(|e| invalid("auditAssuranceV1", e.to_string()))?;
        parsed.validate(now_rfc3339_utc)?;
        Ok(parsed)
    }

    pub fn to_value(&self) -> Result<Value, AuditError> {
        serde_json::to_value(self).map_err(|e| invalid("auditAssuranceV1", e.to_string()))
    }

    pub fn validate(&self, now_rfc3339_utc: &str) -> Result<(), AuditError> {
        if self.schema_version != AUDIT_ASSURANCE_SCHEMA_VERSION {
            return Err(invalid(
                "auditAssuranceV1.schemaVersion",
                "unsupported version",
            ));
        }
        self.profile.validate("auditAssuranceV1.profile")?;
        if self.runtime_constraint != self.profile.runtime_constraint {
            return Err(invalid(
                "auditAssuranceV1.runtimeConstraint",
                "disagrees with frozen profile constraint",
            ));
        }
        let mut seen: BTreeSet<&ObligationId> = BTreeSet::new();
        for (index, obligation) in self.obligations.iter().enumerate() {
            obligation.validate(
                &format!("auditAssuranceV1.obligations[{index}]"),
                now_rfc3339_utc,
            )?;
            if obligation.id.product != self.product_target.product
                || obligation.id.target != self.product_target.target
                || obligation.id.variant != self.product_target.variant
                || obligation.id.snapshots != self.product_target.snapshots
            {
                return Err(invalid(
                    format!("auditAssuranceV1.obligations[{index}].id"),
                    "obligation identity disagrees with declared product target",
                ));
            }
            if !obligation.required_in.contains(&self.profile.profile)
                && obligation.status != ObligationStatus::Inapplicable
            {
                // A stronger-profile obligation present in a weaker run
                // must have been legitimately omitted at resolve time.
                return Err(invalid(
                    format!("auditAssuranceV1.obligations[{index}].requiredIn"),
                    "obligation is not required in the frozen profile",
                ));
            }
            if !seen.insert(&obligation.id) {
                return Err(invalid(
                    "auditAssuranceV1.obligations",
                    "duplicate obligation identity",
                ));
            }
        }
        let expected = summarize(self.profile.profile, &self.obligations);
        if expected != self.summary {
            return Err(invalid(
                "auditAssuranceV1.summary",
                "summary does not recompute from obligations",
            ));
        }
        Ok(())
    }
}

/// Reason prefixes the host (never a repository/contract input) writes when
/// it proves an obligation inapplicable at freeze.
pub const HOST_PROVEN_INAPPLICABLE_PREFIXES: [&str; 2] =
    ["host-proven:", "provider-not-applicable-at-freeze:"];

/// True when an inapplicable obligation's reason carries a host-proof marker.
pub fn is_host_proven_inapplicable(reason: Option<&str>) -> bool {
    reason.is_some_and(|reason| {
        HOST_PROVEN_INAPPLICABLE_PREFIXES
            .iter()
            .any(|prefix| reason.starts_with(prefix))
    })
}

/// Recompute the three independent axes from obligations alone. Waived
/// and deferred block completion; an empty inventory is `NotExamined`,
/// never complete; only a `release`-profile run can be `Eligible`.
pub fn summarize(profile: AuditProfile, obligations: &[ProductionObligation]) -> AssuranceSummary {
    let mut summary = AssuranceSummary {
        completion: Completion::NotExamined,
        finding_outcome: FindingOutcome::Unproven,
        release_eligibility: ReleaseEligibility::NotAssessed,
        total: obligations.len() as u64,
        satisfied: 0,
        findings: 0,
        unmet: 0,
        deferred: 0,
        waived: 0,
        inapplicable: 0,
    };
    for obligation in obligations {
        match obligation.status {
            ObligationStatus::Satisfied => summary.satisfied += 1,
            ObligationStatus::Findings => summary.findings += 1,
            ObligationStatus::Unmet => summary.unmet += 1,
            ObligationStatus::Deferred => summary.deferred += 1,
            ObligationStatus::Waived => summary.waived += 1,
            ObligationStatus::Inapplicable => summary.inapplicable += 1,
        }
    }
    let applicable = summary.total - summary.inapplicable;
    let examined = summary.satisfied + summary.findings;
    let all_host_proven = obligations
        .iter()
        .filter(|o| o.status == ObligationStatus::Inapplicable)
        .all(|o| is_host_proven_inapplicable(o.reason.as_deref()));
    summary.completion = if applicable == 0 && summary.total > 0 && all_host_proven {
        // Host-proven-empty applicable universe: complete, nothing to examine.
        // Inapplicability that is not host-proven (e.g. asserted by a
        // product contract) never shrinks the denominator to Complete.
        Completion::Complete
    } else if examined == 0 {
        Completion::NotExamined
    } else if summary.unmet == 0 && summary.deferred == 0 && summary.waived == 0 {
        Completion::Complete
    } else {
        Completion::Partial
    };
    summary.finding_outcome = if summary.findings > 0 {
        FindingOutcome::Findings
    } else if summary.completion == Completion::Complete {
        FindingOutcome::Clean
    } else {
        FindingOutcome::Unproven
    };
    summary.release_eligibility = if profile != AuditProfile::Release {
        // A pre-pr/repository pass never projects a release pass.
        ReleaseEligibility::NotAssessed
    } else if summary.completion == Completion::Complete
        && summary.finding_outcome == FindingOutcome::Clean
        && summary.waived == 0
    {
        ReleaseEligibility::Eligible
    } else {
        ReleaseEligibility::NotEligible
    };
    summary
}

/// Extension entries root merges into `Report.extensions` (renderers keep
/// every partial obligation visible; nothing is dropped on failure).
pub fn assurance_extensions(
    assurance: &AuditAssuranceV1,
) -> Result<BTreeMap<String, Value>, AuditError> {
    Ok(BTreeMap::from([(
        AUDIT_ASSURANCE_EXTENSION_KEY.to_owned(),
        assurance.to_value()?,
    )]))
}

impl AuditAssuranceV1 {
    /// Resolve the mandatory inventory for `profile` and build the frozen
    /// plan form. Every applicable obligation starts `unmet`.
    pub fn freeze(
        profile: FrozenProfile,
        product_target: ProductTarget,
        candidates: &[ObligationCandidate],
    ) -> Result<Self, AuditError> {
        let obligations = resolve_obligations(&product_target, &profile, candidates)?;
        let frozen = Self::new(profile, product_target, obligations);
        frozen.validate_frozen()?;
        Ok(frozen)
    }

    /// Freeze the profile-complete denominator. `host_candidates` are the
    /// host/plan/provider-derived obligations (the only source that may be
    /// proven inapplicable); `contract_candidates` come from the
    /// unauthenticated product contract and may only ADD obligations or
    /// TIGHTEN a host obligation (widen `required_in`, add providers, pin a
    /// denominator when the host pinned none). A contract can never remove,
    /// de-require or mark inapplicable a host obligation, and its own
    /// inapplicability claims are discarded. Finally, every evidence kind the
    /// selected profile mandates becomes an unmet obligation unless an
    /// equivalent (same kind, required in this profile) obligation exists.
    pub fn freeze_for_profile(
        profile: FrozenProfile,
        product_target: ProductTarget,
        host_candidates: &[ObligationCandidate],
        contract_candidates: &[ObligationCandidate],
    ) -> Result<Self, AuditError> {
        let mut merged: Vec<ObligationCandidate> = host_candidates.to_vec();
        for contract in contract_candidates {
            let mut contract = contract.clone();
            contract.proven_inapplicable_reason = None;
            let existing = merged.iter().position(|host| {
                host.concern == contract.concern && host.evidence_kind == contract.evidence_kind
            });
            if let Some(index) = existing {
                let host = &mut merged[index];
                for required in &contract.required_in {
                    if !host.required_in.contains(required) {
                        host.required_in.push(*required);
                    }
                }
                for provider in &contract.provider_ids {
                    if !host.provider_ids.contains(provider) {
                        host.provider_ids.push(provider.clone());
                    }
                }
                if host.required_denominator_digest.is_none() {
                    host.required_denominator_digest = contract.required_denominator_digest;
                }
            } else {
                merged.push(contract);
            }
        }
        for kind in profile.profile.mandatory_evidence_kinds() {
            // A proven-inapplicable candidate never satisfies a profile
            // minimum: the minimum then freezes as its own unmet obligation.
            let covered = merged.iter().any(|candidate| {
                candidate.evidence_kind == kind
                    && candidate.required_in.contains(&profile.profile)
                    && candidate
                        .proven_inapplicable_reason
                        .as_deref()
                        .is_none_or(|reason| reason.trim().is_empty())
            });
            if covered {
                continue;
            }
            merged.push(ObligationCandidate {
                concern: format!(
                    "profile-required:{}",
                    format!("{kind:?}").to_ascii_lowercase()
                ),
                evidence_kind: kind,
                required_in: [
                    AuditProfile::PrePr,
                    AuditProfile::Repository,
                    AuditProfile::Release,
                ]
                .into_iter()
                .filter(|p| p.mandatory_evidence_kinds().contains(&kind))
                .collect(),
                provider_ids: Vec::new(),
                required_denominator_digest: None,
                proven_inapplicable_reason: None,
            });
        }
        Self::freeze(profile, product_target, &merged)
    }

    /// A frozen plan may carry only freeze-time states: `unmet` (not yet
    /// examined) or proven `inapplicable`. Pre-satisfied obligations,
    /// evidence, waivers or deferrals in a plan are claims, not a
    /// denominator, and are rejected.
    pub fn validate_frozen(&self) -> Result<(), AuditError> {
        self.validate(FROZEN_NOW)?;
        for (index, obligation) in self.obligations.iter().enumerate() {
            let path = format!("auditAssuranceV1.obligations[{index}]");
            match obligation.status {
                ObligationStatus::Unmet => {
                    if !obligation.evidence_refs.is_empty() || obligation.waiver.is_some() {
                        return Err(invalid(path, "frozen unmet obligation carries a claim"));
                    }
                }
                ObligationStatus::Inapplicable => {
                    if obligation.waiver.is_some() {
                        return Err(invalid(path, "frozen inapplicable obligation is waived"));
                    }
                }
                other => {
                    return Err(invalid(
                        path,
                        format!("frozen plan cannot pre-assert status {other:?}"),
                    ))
                }
            }
        }
        Ok(())
    }

    /// Parse the plan-bound frozen form (no clock needed; no waivers exist).
    pub fn from_frozen_value(value: &Value) -> Result<Self, AuditError> {
        let parsed = Self::from_value(value, FROZEN_NOW)?;
        parsed.validate_frozen()?;
        Ok(parsed)
    }
}

/// Obligation identity rendered for reasons/diagnostics.
fn label(id: &ObligationId) -> String {
    format!("{}/{}/{:?}", id.target, id.concern, id.evidence_kind)
}

/// Result of reconciling evidence and waivers against a frozen plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    pub assurance: AuditAssuranceV1,
    /// Evidence or waivers that matched no frozen obligation (or failed
    /// validation) and were ignored. They never add or remove denominator.
    pub rejected: Vec<String>,
}

/// Reconcile evidence against the frozen denominator. Only identities in
/// `frozen` exist in the result; absent evidence leaves an obligation
/// `unmet` (gap retained); several evidence entries for one obligation must
/// all validate; a waiver applies only to an obligation that has no
/// execution evidence and is never an execution claim.
pub fn reconcile(
    frozen: &AuditAssuranceV1,
    evidence: &[ObligationEvidence],
    waivers: &[(ObligationId, Waiver)],
    now_rfc3339_utc: &str,
) -> Result<Reconciliation, AuditError> {
    frozen.validate_frozen()?;
    let known: BTreeSet<&ObligationId> = frozen.obligations.iter().map(|o| &o.id).collect();
    let mut rejected = Vec::new();
    for item in evidence {
        if !known.contains(&item.obligation) {
            rejected.push(format!(
                "evidence-unknown-obligation:{}",
                label(&item.obligation)
            ));
        }
    }
    let mut obligations = Vec::with_capacity(frozen.obligations.len());
    for base in &frozen.obligations {
        if base.status == ObligationStatus::Inapplicable {
            obligations.push(base.clone());
            continue;
        }
        let applied: Vec<ProductionObligation> = evidence
            .iter()
            .filter(|item| item.obligation == base.id)
            .map(|item| apply_evidence(base, item))
            .collect();
        let mut current = if applied.is_empty() {
            let mut open = base.clone();
            open.status = ObligationStatus::Unmet;
            open.reason = Some("not-examined: no evidence for frozen obligation".to_owned());
            open
        } else if let Some(failed) = applied.iter().find(|o| o.status == ObligationStatus::Unmet) {
            failed.clone()
        } else if let Some(with_findings) = applied
            .iter()
            .find(|o| o.status == ObligationStatus::Findings)
        {
            with_findings.clone()
        } else {
            applied[0].clone()
        };
        if current.status == ObligationStatus::Unmet {
            if let Some((_, waiver)) = waivers.iter().find(|(id, _)| id == &base.id) {
                match apply_waiver(&current, waiver.clone(), now_rfc3339_utc) {
                    Ok(waived) => current = waived,
                    Err(error) => {
                        rejected.push(format!("waiver-rejected:{}:{error}", label(&base.id)))
                    }
                }
            }
        }
        obligations.push(current);
    }
    for (id, _) in waivers {
        if !known.contains(id) {
            rejected.push(format!("waiver-unknown-obligation:{}", label(id)));
        }
    }
    rejected.sort();
    rejected.dedup();
    let assurance = AuditAssuranceV1::new(
        frozen.profile.clone(),
        frozen.product_target.clone(),
        obligations,
    );
    assurance.validate(now_rfc3339_utc)?;
    Ok(Reconciliation {
        assurance,
        rejected,
    })
}

/// Host label a qualification record's `host` must equal: `<os>-<arch>` of
/// the process that executed the run.
pub fn run_host_label() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Plan-bound key under which the registry's qualification scope record is
/// frozen into `AuditProvider.bounds`.
pub const QUALIFICATION_SCOPE_BOUND_KEY: &str = "qualificationScope";
/// `ProviderResult.details` key under which a provider execution records the
/// toolchain it actually ran with. Qualification compares against this value,
/// never against the qualification record's own claim.
pub const EXECUTED_TOOLCHAIN_DETAIL_KEY: &str = "executedToolchain";
/// `ProviderResult.details` key recording the rule/rule-pack version (and
/// ruleset digest, `version+sha256:...`) the execution actually applied.
pub const EXECUTED_RULE_VERSION_DETAIL_KEY: &str = "executedRuleVersion";
/// `ProviderResult.details` key recording the sorted list of features the
/// execution actually enabled. Absent means UNKNOWN; `[]` means none.
pub const EXECUTED_FEATURES_DETAIL_KEY: &str = "executedFeatures";
/// Toolchain label when the execution recorded none.
pub const TOOLCHAIN_UNKNOWN: &str = "UNKNOWN";
/// Plan-bound key carrying the registry claim scope (e.g.
/// `known-answer-fixture-cases`) when no full scope record exists.
pub const CLAIM_SCOPE_BOUND_KEY: &str = "claimScope";

/// Every reason `provider`'s qualification does not apply to this run.
/// Empty means accepted. The legacy `benchmark_status == "qualified"` plus
/// digest is necessary but never sufficient for a release (production)
/// profile: a frozen scope record must match the run through
/// `evaluate_qualification`, and fixture-scoped claims never qualify.
fn provider_qualification_mismatches(
    provider: &crate::plan::AuditProvider,
    frozen: &AuditAssuranceV1,
    executed_toolchain: Option<&str>,
    executed_rule_version: Option<&str>,
    executed_features: Option<&[String]>,
) -> Vec<String> {
    let id = &provider.id;
    if provider.benchmark_status != "qualified" || provider.qualification_digest.is_none() {
        return vec![format!("provider-unqualified:{id}")];
    }
    let production = frozen.profile.profile == AuditProfile::Release;
    let claim_scope = provider
        .bounds
        .get(CLAIM_SCOPE_BOUND_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    let record: Option<QualificationScope> = provider
        .bounds
        .get(QUALIFICATION_SCOPE_BOUND_KEY)
        .and_then(|value| serde_json::from_value(value.clone()).ok());
    let mut out = Vec::new();
    if production && claim_scope.to_ascii_lowercase().contains("fixture") {
        out.push(format!(
            "provider-fixture-scope-not-production:{id}:{claim_scope}"
        ));
    }
    match record {
        Some(record) => {
            // The record's own digest must be the digest frozen for the
            // provider, exactly: a record cannot vouch for itself.
            if provider.qualification_digest.as_deref() != Some(record.digest.as_str()) {
                out.push(format!(
                    "provider-qualification:{id}:digest-mismatch: record={} frozen={}",
                    record.digest,
                    provider.qualification_digest.as_deref().unwrap_or("none")
                ));
            }
            // The toolchain comes from what the execution recorded, never from
            // the qualification record. When the execution recorded none the
            // dimension is UNKNOWN: that cannot qualify a production claim.
            let (toolchain, unknown) = match executed_toolchain.filter(|t| !t.trim().is_empty()) {
                Some(executed) => (executed.to_owned(), false),
                None => (TOOLCHAIN_UNKNOWN.to_owned(), true),
            };
            if unknown && production {
                out.push(format!(
                    "provider-qualification:{id}:toolchain-unknown: execution recorded no toolchain"
                ));
            }
            // Rule version and features come from the execution, never the
            // record. Unrecorded: UNKNOWN, which cannot qualify a production
            // claim; outside production the record's value is borrowed as a
            // disclosed gap.
            let rule_version = executed_rule_version.filter(|v| !v.trim().is_empty());
            if production && rule_version.is_none() {
                out.push(format!(
                    "provider-qualification:{id}:rule-version-unknown: execution recorded no rule version"
                ));
            }
            if production && executed_features.is_none() {
                out.push(format!(
                    "provider-qualification:{id}:features-unknown: execution recorded no feature set"
                ));
            }
            let context = QualificationContext {
                provider_id: provider.id.clone(),
                provider_version: provider.version.clone(),
                rule_version: match rule_version {
                    Some(v) => Some(v.to_owned()),
                    None if production => Some("UNKNOWN".to_owned()),
                    None => record.rule_version.clone(),
                },
                host: run_host_label(),
                // Outside production an unrecorded toolchain is a disclosed gap
                // (the record's value is borrowed for that one dimension only).
                toolchain: if unknown && !production {
                    record.toolchain.clone()
                } else {
                    toolchain
                },
                target: frozen.product_target.target.clone(),
                variant: frozen.product_target.variant.clone(),
                features: match executed_features {
                    Some(f) => f.to_vec(),
                    None if production => vec!["UNKNOWN".to_owned()],
                    None => record.features.clone(),
                },
                requires_production_evidence: production,
            };
            let verdict = evaluate_qualification(Some(&record), &context, &now_utc_for_freshness());
            out.extend(
                verdict
                    .mismatches
                    .into_iter()
                    .map(|m| format!("provider-qualification:{id}:{m}")),
            );
        }
        None if production => out.push(format!(
            "provider-qualification:{id}:missing-qualification-record"
        )),
        None => {}
    }
    out
}

fn now_utc_for_freshness() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Derive `ProviderExecution` evidence from a signed-plan execution. Only an
/// execution bound to `plan` (digest + signature present) yields evidence;
/// every listed provider must have run (not skipped) and carry coverage, and
/// a provider unqualified in the frozen plan cannot discharge an obligation.
pub fn evidence_from_execution(
    frozen: &AuditAssuranceV1,
    plan: &FrozenPlan,
    execution: &ExecutionReport,
) -> Vec<ObligationEvidence> {
    if execution.plan_signature.is_none()
        || plan.signature().is_none()
        || execution.plan_digest != plan.digest()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for obligation in &frozen.obligations {
        if obligation.status == ObligationStatus::Inapplicable
            || obligation.id.evidence_kind != EvidenceKind::ProviderExecution
            || obligation.provider_ids.is_empty()
        {
            continue;
        }
        let mut coverages: Vec<&Coverage> = Vec::new();
        let mut finding_ids = BTreeSet::new();
        let mut mismatches = Vec::new();
        let mut all_ran = true;
        for provider_id in &obligation.provider_ids {
            let ran = execution
                .results
                .iter()
                .find(|row| &row.provider == provider_id && !row.skipped);
            let Some(row) = ran else {
                all_ran = false;
                break;
            };
            if !row.result.complete || !row.result.applicable {
                all_ran = false;
                break;
            }
            match &row.result.coverage {
                Some(coverage) => coverages.push(coverage),
                None => {
                    all_ran = false;
                    break;
                }
            }
            for finding in &row.result.findings {
                finding_ids.insert(finding.id.as_str().to_owned());
            }
            let executed_toolchain = row
                .result
                .details
                .get(EXECUTED_TOOLCHAIN_DETAIL_KEY)
                .and_then(Value::as_str);
            let executed_rule_version = row
                .result
                .details
                .get(EXECUTED_RULE_VERSION_DETAIL_KEY)
                .and_then(Value::as_str);
            let executed_features: Option<Vec<String>> = row
                .result
                .details
                .get(EXECUTED_FEATURES_DETAIL_KEY)
                .and_then(Value::as_array)
                .and_then(|list| {
                    list.iter()
                        .map(|v| v.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                });
            match plan.provider(provider_id) {
                Some(p) => mismatches.extend(provider_qualification_mismatches(
                    p,
                    frozen,
                    executed_toolchain,
                    executed_rule_version,
                    executed_features.as_deref(),
                )),
                None => mismatches.push(format!("provider-unqualified:{provider_id}")),
            }
        }
        if !all_ran || coverages.is_empty() {
            continue; // gap retained: obligation stays unmet
        }
        let digests: BTreeSet<&str> = coverages
            .iter()
            .map(|c| c.denominator_digest.as_str())
            .collect();
        let combined = Coverage {
            denominator_digest: digests.iter().copied().collect::<Vec<_>>().join("+"),
            expected: coverages.iter().map(|c| c.expected).sum(),
            examined: coverages.iter().map(|c| c.examined).sum(),
            gaps: coverages.iter().flat_map(|c| c.gaps.clone()).collect(),
        };
        out.push(ObligationEvidence {
            obligation: obligation.id.clone(),
            kind: EvidenceKind::ProviderExecution,
            provider_id: Some(obligation.provider_ids.join("+")),
            coverage: Some(combined),
            finding_ids: finding_ids.into_iter().collect(),
            evidence_refs: vec![format!(
                "execution:{}:{}",
                execution.plan_digest,
                obligation.provider_ids.join("+")
            )],
            artifact_digest: None,
            attested_by: None,
            authenticated: false,
            produced_by_runtime: None,
            qualification: (!mismatches.is_empty()).then_some(QualificationVerdict {
                applicable: false,
                mismatches,
            }),
        });
    }
    out
}

/// Differences between the frozen plan and a reported assurance. A report
/// may only move obligations from `unmet` to an evidenced state; it cannot
/// drop, add, re-identify, re-scope or newly declare inapplicable any
/// frozen obligation, nor change the frozen profile/target/constraint.
pub fn frozen_mismatches(frozen: &AuditAssuranceV1, reported: &AuditAssuranceV1) -> Vec<String> {
    let mut out = Vec::new();
    if frozen.profile != reported.profile {
        out.push("profile-changed".to_owned());
    }
    if frozen.runtime_constraint != reported.runtime_constraint {
        out.push("runtime-constraint-changed".to_owned());
    }
    if frozen.product_target != reported.product_target {
        out.push("product-target-changed".to_owned());
    }
    let reported_by: BTreeMap<&ObligationId, &ProductionObligation> =
        reported.obligations.iter().map(|o| (&o.id, o)).collect();
    for base in &frozen.obligations {
        match reported_by.get(&base.id) {
            None => out.push(format!("obligation-dropped:{}", label(&base.id))),
            Some(got) => {
                if got.required_in != base.required_in
                    || got.provider_ids != base.provider_ids
                    || got.required_denominator_digest != base.required_denominator_digest
                {
                    out.push(format!("obligation-weakened:{}", label(&base.id)));
                }
                if (base.status == ObligationStatus::Inapplicable)
                    != (got.status == ObligationStatus::Inapplicable)
                {
                    out.push(format!("inapplicability-changed:{}", label(&base.id)));
                }
            }
        }
    }
    let frozen_ids: BTreeSet<&ObligationId> = frozen.obligations.iter().map(|o| &o.id).collect();
    for got in &reported.obligations {
        if !frozen_ids.contains(&got.id) {
            out.push(format!("obligation-added:{}", label(&got.id)));
        }
    }
    out
}

/// Gate verdict. Three independent outcomes: eligible, blocked by
/// findings, or incomplete (including legacy/unproven reports).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateVerdict {
    Eligible,
    BlockedFindings,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDecision {
    pub verdict: GateVerdict,
    pub reasons: Vec<String>,
}

/// Report fields the gate reads; independent of v1/v2 type.
pub struct GateSubject<'a> {
    pub status: ReportStatus,
    /// Blocking (non-advisory) findings.
    pub finding_count: usize,
    pub gaps: &'a [String],
    pub extensions: &'a BTreeMap<String, Value>,
}

/// Findings that block: advisory findings (named in the report's
/// `advisoryFindings` extension) never do, everything else does.
fn blocking_count<'i>(
    ids: impl Iterator<Item = &'i str>,
    extensions: &BTreeMap<String, Value>,
) -> usize {
    let advisory: BTreeSet<&str> = extensions
        .get("advisoryFindings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    ids.filter(|id| !advisory.contains(id)).count()
}

impl<'a> GateSubject<'a> {
    pub fn from_v1(report: &'a ReportV1) -> Self {
        Self {
            status: report.status,
            finding_count: blocking_count(
                report.findings.iter().map(|f| f.id.as_str()),
                &report.extensions,
            ),
            gaps: &report.gaps,
            extensions: &report.extensions,
        }
    }
    pub fn from_v2(report: &'a ReportV2) -> Self {
        Self {
            status: report.status,
            finding_count: blocking_count(
                report.findings.iter().map(|f| f.id.as_str()),
                &report.extensions,
            ),
            gaps: &report.gaps,
            extensions: &report.extensions,
        }
    }
}

/// Pure gate for a report/run against `required` strength. Eligible only
/// when the frozen-bound assurance is present, valid, recomputes, covers the
/// frozen plan (when supplied), was run at >= `required` strength, is
/// complete and clean, and the report's own status/gaps agree. Missing,
/// malformed or future extensions, legacy reports, partial runs and claims
/// that contradict evidence are `Incomplete`; any finding is
/// `BlockedFindings` (a finding is never overridden by completeness).
pub fn gate(
    subject: &GateSubject<'_>,
    frozen: Option<&AuditAssuranceV1>,
    required: AuditProfile,
    now_rfc3339_utc: &str,
) -> GateDecision {
    let mut blockers: Vec<String> = Vec::new();
    let mut incomplete: Vec<String> = Vec::new();
    if subject.finding_count > 0 || subject.status == ReportStatus::Findings {
        blockers.push(format!("report-findings:{}", subject.finding_count));
    }
    match subject.status {
        ReportStatus::Clean | ReportStatus::Findings => {}
        other => incomplete.push(format!("report-status:{other:?}")),
    }
    for gap in subject.gaps {
        incomplete.push(format!("report-gap:{gap}"));
    }
    let assurance = match subject.extensions.get(AUDIT_ASSURANCE_EXTENSION_KEY) {
        None => {
            incomplete.push(
                "assurance-extension-absent: legacy report cannot carry release eligibility"
                    .to_owned(),
            );
            None
        }
        Some(value) => match AuditAssuranceV1::from_value(value, now_rfc3339_utc) {
            Ok(parsed) => Some(parsed),
            Err(error) => {
                incomplete.push(format!("assurance-extension-invalid: {error}"));
                None
            }
        },
    };
    if let Some(assurance) = &assurance {
        if let Some(frozen) = frozen {
            for mismatch in frozen_mismatches(frozen, assurance) {
                incomplete.push(format!("frozen-mismatch:{mismatch}"));
            }
        } else {
            incomplete.push("frozen-plan-not-supplied: obligations unverifiable".to_owned());
        }
        if !assurance.profile.profile.can_project_to(required) {
            incomplete.push(format!(
                "profile-too-weak: ran {} required {}",
                assurance.profile.profile.as_str(),
                required.as_str()
            ));
        }
        let summary = &assurance.summary;
        if summary.findings > 0 {
            blockers.push(format!("obligation-findings:{}", summary.findings));
        }
        if summary.completion != Completion::Complete {
            incomplete.push(format!(
                "assurance-completion:{:?} unmet={} deferred={} waived={}",
                summary.completion, summary.unmet, summary.deferred, summary.waived
            ));
        }
        if summary.waived > 0 {
            incomplete.push(format!("waived-obligations:{}", summary.waived));
        }
        if required == AuditProfile::Release
            && summary.release_eligibility != ReleaseEligibility::Eligible
            && blockers.is_empty()
        {
            incomplete.push(format!(
                "release-eligibility:{:?}",
                summary.release_eligibility
            ));
        }
    }
    if !blockers.is_empty() {
        blockers.extend(incomplete);
        return GateDecision {
            verdict: GateVerdict::BlockedFindings,
            reasons: blockers,
        };
    }
    if !incomplete.is_empty() {
        return GateDecision {
            verdict: GateVerdict::Incomplete,
            reasons: incomplete,
        };
    }
    GateDecision {
        verdict: GateVerdict::Eligible,
        reasons: vec!["complete-clean-frozen-denominator".to_owned()],
    }
}

/// Gate over a v1 report (convenience).
pub fn gate_report_v1(
    report: &ReportV1,
    frozen: Option<&AuditAssuranceV1>,
    required: AuditProfile,
    now_rfc3339_utc: &str,
) -> GateDecision {
    gate(
        &GateSubject::from_v1(report),
        frozen,
        required,
        now_rfc3339_utc,
    )
}

/// Gate over a v2 report (convenience).
pub fn gate_report_v2(
    report: &ReportV2,
    frozen: Option<&AuditAssuranceV1>,
    required: AuditProfile,
    now_rfc3339_utc: &str,
) -> GateDecision {
    gate(
        &GateSubject::from_v2(report),
        frozen,
        required,
        now_rfc3339_utc,
    )
}

// ---------------------------------------------------------------------------
// Frozen selection scope
// ---------------------------------------------------------------------------

/// `AuditPlan::bounds` key holding the frozen provider/scope selection.
pub const SELECTION_SCOPE_BOUND: &str = "auditSelectionScopeV1";

/// What the operator selected at freeze time, signed into the plan. An
/// assurance gate treats any narrowing (provider filters, diff or directory
/// scope, fewer providers than the configured universe) as a partial run
/// regardless of profile: omitted work cannot be proven examined.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectionScope {
    pub schema_version: u32,
    pub only: Vec<String>,
    pub skip: Vec<String>,
    /// `whole-repo` or `diff`.
    pub scope_mode: String,
    pub scope_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    pub selected_provider_ids: Vec<String>,
    /// Every provider the application configures, before any filter.
    pub universe_provider_ids: Vec<String>,
}

impl SelectionScope {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(invalid(
                "selectionScope.schemaVersion",
                "unsupported version",
            ));
        }
        if self.scope_mode.trim().is_empty() {
            return Err(invalid("selectionScope.scopeMode", "must be non-empty"));
        }
        Ok(())
    }

    /// Every reason this selection is narrower than the whole repository with
    /// the whole provider universe. Empty means a full-scope run.
    pub fn filter_reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.only.is_empty() {
            out.push(format!("only={}", self.only.join(",")));
        }
        if !self.skip.is_empty() {
            out.push(format!("skip={}", self.skip.join(",")));
        }
        if self.scope_mode != "whole-repo" {
            out.push(format!("scope-mode={}", self.scope_mode));
        }
        if let Some(dir) = &self.dir {
            out.push(format!("dir={dir}"));
        }
        if let Some(base) = &self.base {
            out.push(format!("base={base}"));
        }
        if let Some(base) = &self.base_commit {
            out.push(format!("base-commit={base}"));
        }
        let selected: BTreeSet<&str> = self
            .selected_provider_ids
            .iter()
            .map(String::as_str)
            .collect();
        let omitted: Vec<&str> = self
            .universe_provider_ids
            .iter()
            .map(String::as_str)
            .filter(|id| !selected.contains(id))
            .collect();
        if !omitted.is_empty() {
            out.push(format!("providers-omitted={}", omitted.join(",")));
        }
        out
    }

    pub fn is_full(&self) -> bool {
        self.filter_reasons().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Verified rebuild of obligation outcomes
// ---------------------------------------------------------------------------

/// Derive `ProviderExecution` evidence from verified signed provider receipts
/// (never from `report.json`). The evidence refs are the receipts' own
/// digests. Receipts must already be signature- and journal-verified.
pub fn evidence_from_receipts(
    frozen: &AuditAssuranceV1,
    plan: &FrozenPlan,
    receipts: &[crate::resume::StoredReceipt],
) -> Vec<ObligationEvidence> {
    let by_provider: BTreeMap<&str, &crate::resume::StoredReceipt> = receipts
        .iter()
        .filter(|receipt| receipt.body.execution.provider == receipt.body.provider)
        .map(|receipt| (receipt.body.provider.as_str(), receipt))
        .collect();
    let execution = ExecutionReport {
        plan_digest: plan.digest().to_owned(),
        plan_signature: plan.signature().map(str::to_owned),
        planned_providers: plan.providers().iter().map(|p| p.id.clone()).collect(),
        results: plan
            .providers()
            .iter()
            .filter_map(|p| by_provider.get(p.id.as_str()))
            .map(|receipt| receipt.body.execution.clone())
            .collect(),
        ..ExecutionReport::default()
    };
    let mut out = evidence_from_execution(frozen, plan, &execution);
    for item in &mut out {
        let providers: Vec<String> = frozen
            .obligations
            .iter()
            .find(|obligation| obligation.id == item.obligation)
            .map(|obligation| obligation.provider_ids.clone())
            .unwrap_or_default();
        item.evidence_refs = providers
            .iter()
            .filter_map(|id| by_provider.get(id.as_str()).map(|r| r.digest.clone()))
            .collect();
    }
    out
}

/// Reconcile the frozen denominator against verified receipts alone.
pub fn rebuild_from_receipts(
    frozen: &AuditAssuranceV1,
    plan: &FrozenPlan,
    receipts: &[crate::resume::StoredReceipt],
    now_rfc3339_utc: &str,
) -> Result<Reconciliation, AuditError> {
    reconcile(
        frozen,
        &evidence_from_receipts(frozen, plan, receipts),
        &[],
        now_rfc3339_utc,
    )
}

/// Compare what a report claims against the outcome rebuilt from verified
/// receipts. Any status disagreement, and any `evidenceRefs` entry that is not
/// the digest of a verified receipt for the obligation's providers (or the
/// derived execution ref over them), is named. A claim never upgrades.
pub fn claim_disagreements(
    reported: &AuditAssuranceV1,
    rebuilt: &AuditAssuranceV1,
    plan_digest: &str,
    receipts: &[crate::resume::StoredReceipt],
) -> Vec<String> {
    let rebuilt_by: BTreeMap<&ObligationId, &ProductionObligation> =
        rebuilt.obligations.iter().map(|o| (&o.id, o)).collect();
    let digest_of: BTreeMap<&str, &str> = receipts
        .iter()
        .map(|r| (r.body.provider.as_str(), r.digest.as_str()))
        .collect();
    let mut out = Vec::new();
    for claim in &reported.obligations {
        let Some(verified) = rebuilt_by.get(&claim.id) else {
            continue; // reported only: frozen_mismatches names it
        };
        if claim.status != verified.status {
            out.push(format!(
                "claim-mismatch:{}: reported={:?} verified={:?}",
                label(&claim.id),
                claim.status,
                verified.status
            ));
        }
        if claim.status.was_examined() {
            let mut allowed: BTreeSet<String> = BTreeSet::new();
            for provider in &claim.provider_ids {
                if let Some(digest) = digest_of.get(provider.as_str()) {
                    allowed.insert((*digest).to_owned());
                }
            }
            allowed.insert(format!(
                "execution:{plan_digest}:{}",
                claim.provider_ids.join("+")
            ));
            let backed = !claim.provider_ids.is_empty()
                && claim
                    .provider_ids
                    .iter()
                    .all(|p| digest_of.contains_key(p.as_str()));
            for reference in &claim.evidence_refs {
                if !backed || !allowed.contains(reference) {
                    out.push(format!(
                        "evidence-ref-unverified:{}:{reference}",
                        label(&claim.id)
                    ));
                }
            }
        }
    }
    out
}

/// Profile minimums re-derived from the frozen profile: every evidence kind
/// `required` mandates must have a frozen obligation of that kind that is
/// required in the frozen profile and is not inapplicable. An inapplicable
/// obligation never satisfies a minimum.
pub fn profile_minimum_gaps(frozen: &AuditAssuranceV1, required: AuditProfile) -> Vec<String> {
    required
        .mandatory_evidence_kinds()
        .into_iter()
        .filter(|kind| {
            !frozen.obligations.iter().any(|obligation| {
                obligation.id.evidence_kind == *kind
                    && obligation.status != ObligationStatus::Inapplicable
                    && obligation.required_in.contains(&frozen.profile.profile)
            })
        })
        .map(|kind| format!("profile-minimum-missing:{kind:?}"))
        .collect()
}

/// Why `gate_run` could not produce a verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunGateError {
    /// Run artifacts are missing or unreadable (exit 2).
    Incomplete(String),
    /// Run artifacts are present but forged, unsigned or inconsistent (exit 5).
    Integrity(String),
}

/// A gate verdict over a persisted run, rebuilt from verified evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunGate {
    pub verdict: GateVerdict,
    pub reasons: Vec<String>,
    pub required: AuditProfile,
    /// True when the caller named the required profile; false means the
    /// release default applied.
    pub required_explicit: bool,
    pub frozen_profile: Option<AuditProfile>,
    pub plan_digest: String,
    /// `None` when the plan froze no selection scope.
    pub full_scope: Option<bool>,
    pub verified_providers: Vec<String>,
    /// Custody the plan key was resolved from (`host-state`, `environment`,
    /// `legacy-run-dir-epoch`).
    pub key_custody: String,
    /// SHA-256 over the provider universe the plan froze; `None` when the
    /// plan froze no selection scope. Makes a reduced registry visible.
    pub registry_digest: Option<String>,
}

fn custody_label(source: &crate::integrity::PlanKeySource) -> &'static str {
    match source {
        crate::integrity::PlanKeySource::Environment => "environment",
        crate::integrity::PlanKeySource::HostState => "host-state",
        crate::integrity::PlanKeySource::LegacyRunDirEpoch => "legacy-run-dir-epoch",
    }
}

fn resolve_gate_key(
    run: &std::path::Path,
    outer: &Value,
    host_only: bool,
) -> Result<(Vec<u8>, &'static str), RunGateError> {
    if host_only && outer.get("planKey").is_none_or(Value::is_null) {
        return Err(integrity(
            "plan-key-custody:missing-host-binding: assurance and schema-2 plans must carry a host planKey binding",
        ));
    }
    match crate::integrity::resolve_plan_key(run, outer) {
        crate::integrity::PlanKeyResolution::Found { key, source } => {
            let label = custody_label(&source);
            if host_only && source != crate::integrity::PlanKeySource::HostState {
                return Err(integrity(format!("plan-key-custody:{label}")));
            }
            Ok((key, label))
        }
        crate::integrity::PlanKeyResolution::Unverifiable { reason } => {
            Err(integrity(format!("unverifiable-signature: {reason}")))
        }
    }
}

fn integrity(reason: impl Into<String>) -> RunGateError {
    RunGateError::Integrity(reason.into())
}

/// Gate a persisted run directory without trusting any editable claim.
///
/// * The plan must be signed and verify under the run's plan key whenever it
///   froze an assurance denominator or is schema 2; unsigned is refused.
///   A legacy plan can only ever yield `Incomplete`.
/// * The journal must be finalized, hash-chained and match the signed anchor.
/// * Obligation outcomes are rebuilt from the signed provider receipts that the
///   journal vouches for; `report.json` assurance claims are cross-checked and
///   any disagreement is `Incomplete` with a named reason.
/// * A filtered or narrowed selection is `Incomplete` for every profile.
/// * `required == None` means release strength.
pub fn gate_run(
    run: &std::path::Path,
    required: Option<AuditProfile>,
    now_rfc3339_utc: &str,
) -> Result<RunGate, RunGateError> {
    use crate::journal::{bytes_digest, verify_dir, EventKind, Expectation, JournalAnchor};

    let read = |name: &str| -> Result<Vec<u8>, RunGateError> {
        std::fs::read(run.join(name))
            .map_err(|error| RunGateError::Incomplete(format!("{name}: {error}")))
    };
    let parse = |name: &str, bytes: &[u8]| -> Result<Value, RunGateError> {
        serde_json::from_slice(bytes)
            .map_err(|error| integrity(format!("{name} is invalid: {error}")))
    };
    let outer = parse("plan.json", &read("plan.json")?)?;
    let native = outer
        .get("nativePlan")
        .ok_or_else(|| integrity("plan.json carries no nativePlan"))?;
    let plan: crate::plan::AuditPlan = serde_json::from_value(
        native
            .get("plan")
            .cloned()
            .ok_or_else(|| integrity("nativePlan body is missing"))?,
    )
    .map_err(|error| integrity(format!("nativePlan body is invalid: {error}")))?;
    let plan_repository_id = plan.repository_id.clone();
    let digest = native
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity("nativePlan digest is missing"))?
        .to_owned();
    if outer.pointer("/seal/digest").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(integrity("plan seal differs from nativePlan"));
    }
    let signature = native.get("signature").and_then(Value::as_str);
    let binding = plan
        .assurance_binding()
        .map_err(|error| integrity(error.to_string()))?;
    let required_explicit = required.is_some();
    let required = required.unwrap_or(AuditProfile::Release);

    let signed_required = binding.is_some() || plan.schema_version >= crate::plan::PLAN_SCHEMA_V2;
    if signature.is_none() && signed_required {
        return Err(integrity(
            "unsigned-plan: assurance and schema-2 plans must carry a verifiable plan signature",
        ));
    }
    let Some(frozen) = binding else {
        // Legacy path: integrity-checked, but it can only ever be incomplete.
        let mut legacy_custody = "none";
        let key = match signature {
            Some(_) => {
                let (key, label) = resolve_gate_key(
                    run,
                    &outer,
                    plan.schema_version >= crate::plan::PLAN_SCHEMA_V2,
                )?;
                legacy_custody = label;
                Some(key)
            }
            None => None,
        };
        crate::integrity::verify(&plan, &digest, signature, key.as_deref())
            .map_err(|error| integrity(error.to_string()))?;
        return Ok(RunGate {
            verdict: GateVerdict::Incomplete,
            reasons: vec!["legacy-run: plan froze no assurance denominator".to_owned()],
            required,
            required_explicit,
            frozen_profile: None,
            plan_digest: digest,
            full_scope: None,
            verified_providers: Vec::new(),
            key_custody: legacy_custody.to_owned(),
            registry_digest: None,
        });
    };
    let signature = signature.ok_or_else(|| integrity("unsigned-plan"))?;
    let (key, key_custody) = resolve_gate_key(run, &outer, true)?;
    let frozen_plan = FrozenPlan::restore_verified(plan, &digest, signature, &key)
        .map_err(|error| integrity(error.to_string()))?;

    let mut extra: Vec<String> = Vec::new();

    // Frozen scope: any narrowing is incomplete regardless of profile.
    let selection = frozen_plan
        .plan()
        .selection_scope()
        .map_err(|error| integrity(error.to_string()))?;
    let full_scope = match &selection {
        None => {
            extra.push("selection-scope-not-frozen: plan cannot prove full scope".to_owned());
            None
        }
        Some(selection) => {
            let reasons = selection.filter_reasons();
            for reason in &reasons {
                extra.push(format!("filtered-run:{reason}"));
            }
            Some(reasons.is_empty())
        }
    };

    // Journal: finalized, chained, bound to the signed anchor.
    let anchor = match JournalAnchor::read(run) {
        Ok(anchor) => anchor,
        Err(error) => {
            extra.push(format!("journal-anchor-invalid:{error}"));
            None
        }
    };
    let mut events = Vec::new();
    match &anchor {
        None => extra.push("journal-anchor-missing: run has no signed journal anchor".to_owned()),
        Some(anchor) => {
            if !anchor.verify(&key) {
                extra.push(
                    "journal-anchor-signature: does not verify under the run plan key".to_owned(),
                );
            }
            if anchor.plan_digest != digest {
                extra.push("journal-anchor-plan-mismatch".to_owned());
            }
            if anchor.effective_plan_digest != digest {
                extra.push(
                    "amended-run: effective plan differs from the frozen plan; receipts are not rebuildable here"
                        .to_owned(),
                );
            }
            let verification = verify_dir(
                run,
                &digest,
                &Expectation {
                    require_finalized: true,
                    expected_head: None,
                    final_plan_digest: Some(anchor.effective_plan_digest.clone()),
                },
            );
            for defect in &verification.defects {
                extra.push(format!("journal-defect:{defect}"));
            }
            if verification.unsealed_tail > 0 {
                extra.push("journal-defect:committed events lie past the sealed head".to_owned());
            }
            if verification.events.len() as u64 != anchor.sequence
                || verification.events.last().map(|e| e.digest.as_str())
                    != Some(anchor.digest.as_str())
            {
                extra.push(
                    "journal-anchor-mismatch: journal does not end at the signed head".to_owned(),
                );
            }
            events = verification.events;
        }
    }

    // Report bytes must be the ones the journal finalized.
    let report_bytes = read("report.json")?;
    let report_value = parse("report.json", &report_bytes)?;
    if let Some(last) = events.last() {
        if last.kind == EventKind::ReportFinalized
            && last.payload_digest != bytes_digest(&report_bytes)
        {
            extra.push(
                "report-differs-from-finalized-digest: report.json is not the report the journal finalized"
                    .to_owned(),
            );
        }
    }
    let report = legion_contracts::Report::read_any(&report_value)
        .map_err(|error| integrity(format!("report.json is invalid: {error}")))?;

    // Receipts: signed, bound to this plan and to a journal settle event.
    let mut settled: BTreeMap<&str, &str> = BTreeMap::new();
    for event in &events {
        if matches!(
            event.kind,
            EventKind::ProviderFinished | EventKind::ProviderFailed | EventKind::ProviderSkipped
        ) {
            settled.insert(event.subject.as_str(), event.payload_digest.as_str());
        }
    }
    let mut receipts: Vec<crate::resume::StoredReceipt> = Vec::new();
    for provider in frozen_plan.providers() {
        match crate::resume::read_verified_receipt(run, &provider.id, &key) {
            Err(error) => extra.push(format!("receipt-unverified:{}:{error}", provider.id)),
            Ok(receipt) => {
                if receipt.body.plan_digest != digest {
                    extra.push(format!("receipt-plan-mismatch:{}", provider.id));
                } else if settled.get(provider.id.as_str()) != Some(&receipt.digest.as_str()) {
                    extra.push(format!("receipt-journal-mismatch:{}", provider.id));
                } else {
                    receipts.push(receipt);
                }
            }
        }
    }
    let verified_providers: Vec<String> =
        receipts.iter().map(|r| r.body.provider.clone()).collect();

    let rebuilt = rebuild_from_receipts(&frozen, &frozen_plan, &receipts, now_rfc3339_utc)
        .map_err(|error| integrity(error.to_string()))?;
    for rejected in &rebuilt.rejected {
        extra.push(format!("rebuild-rejected:{rejected}"));
    }

    // Cross-check the report's assurance claims against the rebuilt outcome.
    match report.assurance_extension() {
        None => extra.push("assurance-extension-absent".to_owned()),
        Some(value) => match AuditAssuranceV1::from_value(value, now_rfc3339_utc) {
            Err(error) => extra.push(format!("assurance-extension-invalid:{error}")),
            Ok(reported) => {
                for mismatch in frozen_mismatches(&frozen, &reported) {
                    extra.push(format!("frozen-mismatch:{mismatch}"));
                }
                extra.extend(claim_disagreements(
                    &reported,
                    &rebuilt.assurance,
                    &digest,
                    &receipts,
                ));
            }
        },
    }
    extra.extend(profile_minimum_gaps(&frozen, required));

    // The verdict is computed over the rebuilt assurance, never the claim.
    let mut extensions = report.extensions.clone();
    extensions.insert(
        AUDIT_ASSURANCE_EXTENSION_KEY.to_owned(),
        rebuilt
            .assurance
            .to_value()
            .map_err(|error| integrity(error.to_string()))?,
    );
    let subject = GateSubject {
        status: report.status,
        finding_count: blocking_count(
            report.findings.iter().map(|f| f.id.as_str()),
            &report.extensions,
        ),
        gaps: &report.gaps,
        extensions: &extensions,
    };
    // A rolled-back or deleted finding-history store for the audited source
    // repository blocks eligibility (host-custody ledger, finding_history.rs).
    let planned = std::path::Path::new(&plan_repository_id);
    let source_repo = planned
        .parent()
        .map(|object| object.join("manifest.json"))
        .filter(|manifest| manifest.is_file())
        .and_then(|manifest| crate::snapshot::FrozenSnapshot::open(&manifest).ok())
        .map(|snapshot| snapshot.manifest.scope.source_root)
        .unwrap_or_else(|| planned.to_path_buf());
    extra.extend(crate::finding_history::history_custody_gaps(&source_repo));
    let decision = gate(&subject, Some(&frozen), required, now_rfc3339_utc);
    extra.sort();
    extra.dedup();
    let (verdict, reasons) = match decision.verdict {
        GateVerdict::Eligible if extra.is_empty() => (GateVerdict::Eligible, decision.reasons),
        GateVerdict::Eligible => (GateVerdict::Incomplete, extra),
        other => {
            let mut reasons = decision.reasons;
            reasons.extend(extra);
            (other, reasons)
        }
    };
    Ok(RunGate {
        verdict,
        reasons,
        required,
        required_explicit,
        frozen_profile: Some(frozen.profile.profile),
        plan_digest: digest,
        full_scope,
        verified_providers,
        key_custody: key_custody.to_owned(),
        registry_digest: selection.as_ref().map(|selection| {
            let mut ids = selection.universe_provider_ids.clone();
            ids.sort();
            ids.dedup();
            bytes_digest(ids.join("\n").as_bytes())
        }),
    })
}

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> AuditError {
    AuditError::Invalid(format!("{}: {}", path.into(), reason.into()))
}
