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
        _ => {}
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
    summary.completion = if applicable == 0 && summary.total > 0 {
        // Proven-empty applicable universe: complete, nothing to examine.
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
            let qualified = plan.provider(provider_id).is_some_and(|p| {
                p.benchmark_status == "qualified" && p.qualification_digest.is_some()
            });
            if !qualified {
                mismatches.push(format!("provider-unqualified:{provider_id}"));
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

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> AuditError {
    AuditError::Invalid(format!("{}: {}", path.into(), reason.into()))
}
