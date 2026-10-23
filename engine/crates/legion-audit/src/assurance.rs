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

use legion_contracts::Coverage;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AuditError;
use crate::profiles::{AuditProfile, FrozenProfile, RuntimeConstraint};

/// Report extension key (`ReportV1.extensions` / projected ReportV2).
pub const AUDIT_ASSURANCE_EXTENSION_KEY: &str = "auditAssuranceV1";
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
                return Err(invalid(
                    format!("{path}.{field}"),
                    "must be non-empty",
                ));
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
            return Err(invalid(
                format!("{path}.expiresAt"),
                "waiver is expired",
            ));
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
                let waiver = self.waiver.as_ref().ok_or_else(|| {
                    invalid(format!("{path}.waiver"), "waived requires a waiver")
                })?;
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
    check("providerId", &record.provider_id, &context.provider_id, &mut mismatches);
    check("providerVersion", &record.provider_version, &context.provider_version, &mut mismatches);
    match (&record.rule_version, &context.rule_version) {
        (Some(r), Some(c)) => check("ruleVersion", r, c, &mut mismatches),
        (None, Some(_)) => mismatches.push("ruleVersion: record missing".into()),
        _ => {}
    }
    check("host", &record.host, &context.host, &mut mismatches);
    check("toolchain", &record.toolchain, &context.toolchain, &mut mismatches);
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
        return Err(invalid("productTarget", "product and target must be non-empty"));
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
            _ => (
                ObligationStatus::Unmet,
                Some("not-yet-examined".to_owned()),
            ),
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
                format!("qualification-not-applicable:{}", verdict.mismatches.join(",")),
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
                && evidence.attested_by.as_deref().unwrap_or("").trim().is_empty()
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

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> AuditError {
    AuditError::Invalid(format!("{}: {}", path.into(), reason.into()))
}
