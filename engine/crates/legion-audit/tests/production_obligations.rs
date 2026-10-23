//! A02: production obligations, frozen profiles, qualification scope and
//! the no-node-python runtime closure. Missing/wrong/stale evidence must
//! stay `unmet`; a pre-pr pass must never project a release pass; waived
//! evidence must stay visibly waived. Authored edit-only — root runs.

use legion_audit::assurance::{
    apply_evidence, apply_waiver, assurance_extensions, evaluate_qualification,
    resolve_obligations, summarize, AuditAssuranceV1, Completion, EvidenceKind, FindingOutcome,
    ObligationCandidate, ObligationDenominator, ObligationEvidence, ObligationStatus,
    ProductTarget, ProductionObligation, QualificationContext, QualificationScope,
    ReleaseEligibility, SnapshotRef, Waiver,
};
use legion_audit::profiles::{
    classify_runtime, validate_runtime_closure, AuditProfile, FrozenProfile, LaunchStep,
    LaunchStepKind, RuntimeClass, RuntimeClosure, RuntimeConstraint,
};
use legion_contracts::Coverage;
use serde_json::Value;

const NOW: &str = "2026-10-23T00:00:00Z";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/production-obligations/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn product_target() -> ProductTarget {
    ProductTarget {
        product: "fixture-app".into(),
        snapshots: vec![SnapshotRef {
            repository_id: "fixture-repo".into(),
            snapshot_digest: DIGEST.into(),
        }],
        target: "aarch64-apple-darwin".into(),
        variant: Some("release".into()),
    }
}

fn candidate(
    concern: &str,
    kind: EvidenceKind,
    required_in: Vec<AuditProfile>,
) -> ObligationCandidate {
    ObligationCandidate {
        concern: concern.into(),
        evidence_kind: kind,
        required_in,
        provider_ids: vec!["fixture.provider".into()],
        required_denominator_digest: Some(DIGEST.into()),
        proven_inapplicable_reason: None,
    }
}

fn release_profile() -> FrozenProfile {
    FrozenProfile::freeze(AuditProfile::Release, "rev-1", RuntimeConstraint::NoNodePython)
        .unwrap()
}

fn one_obligation(profile: &FrozenProfile) -> ProductionObligation {
    resolve_obligations(
        &product_target(),
        profile,
        &[candidate(
            "source-static",
            EvidenceKind::ProviderExecution,
            vec![AuditProfile::PrePr, AuditProfile::Repository, AuditProfile::Release],
        )],
    )
    .unwrap()
    .pop()
    .unwrap()
}

fn provider_evidence(obligation: &ProductionObligation, coverage: Coverage) -> ObligationEvidence {
    ObligationEvidence {
        obligation: obligation.id.clone(),
        kind: EvidenceKind::ProviderExecution,
        provider_id: Some("fixture.provider".into()),
        coverage: Some(coverage),
        finding_ids: Vec::new(),
        evidence_refs: vec![DIGEST.into()],
        artifact_digest: None,
        attested_by: None,
        authenticated: false,
        produced_by_runtime: None,
        qualification: None,
    }
}

fn complete_coverage() -> Coverage {
    Coverage {
        denominator_digest: DIGEST.into(),
        expected: 3,
        examined: 3,
        gaps: Vec::new(),
    }
}

#[test]
fn empty_universe_is_distinct_from_zero_examined_required_input() {
    let empty = ObligationDenominator {
        applicable_universe: 0,
        required: 0,
        examined: 0,
        gaps: Vec::new(),
        proven_inapplicable: 0,
    };
    assert!(empty.is_complete());
    let zero_examined = ObligationDenominator {
        applicable_universe: 4,
        required: 4,
        examined: 0,
        gaps: Vec::new(),
        proven_inapplicable: 0,
    };
    assert!(!zero_examined.is_complete());
    // Convenience exclusions cannot shrink the required denominator.
    let shrunk = ObligationDenominator {
        applicable_universe: 4,
        required: 2,
        examined: 2,
        gaps: Vec::new(),
        proven_inapplicable: 0,
    };
    assert!(shrunk.validate("denominator").is_err());
}

#[test]
fn complete_provider_evidence_satisfies_and_findings_stay_findings() {
    let obligation = one_obligation(&release_profile());
    assert_eq!(obligation.status, ObligationStatus::Unmet);
    let clean = apply_evidence(&obligation, &provider_evidence(&obligation, complete_coverage()));
    assert_eq!(clean.status, ObligationStatus::Satisfied);
    let mut with_finding = provider_evidence(&obligation, complete_coverage());
    with_finding.finding_ids = vec!["finding-1".into()];
    let found = apply_evidence(&obligation, &with_finding);
    assert_eq!(found.status, ObligationStatus::Findings);
    let summary = summarize(AuditProfile::Release, &[found]);
    assert_eq!(summary.completion, Completion::Complete);
    assert_eq!(summary.finding_outcome, FindingOutcome::Findings);
    assert_eq!(summary.release_eligibility, ReleaseEligibility::NotEligible);
}

#[test]
fn missing_scanner_and_zero_coverage_leave_obligation_unmet() {
    let obligation = one_obligation(&release_profile());
    let mut no_coverage = provider_evidence(&obligation, complete_coverage());
    no_coverage.coverage = None;
    assert_eq!(apply_evidence(&obligation, &no_coverage).status, ObligationStatus::Unmet);
    let zero = Coverage {
        denominator_digest: DIGEST.into(),
        expected: 0,
        examined: 0,
        gaps: Vec::new(),
    };
    assert_eq!(
        apply_evidence(&obligation, &provider_evidence(&obligation, zero)).status,
        ObligationStatus::Unmet
    );
}

#[test]
fn wrong_target_evidence_never_discharges_obligation() {
    let obligation = one_obligation(&release_profile());
    let mut evidence = provider_evidence(&obligation, complete_coverage());
    evidence.obligation.target = "x86_64-pc-windows-msvc".into();
    let out = apply_evidence(&obligation, &evidence);
    assert_eq!(out.status, ObligationStatus::Unmet);
    assert_eq!(out.reason.as_deref(), Some("evidence-identity-mismatch"));
}

#[test]
fn unauthenticated_or_unverified_import_stays_unmet() {
    let profile = release_profile();
    let obligations = resolve_obligations(
        &product_target(),
        &profile,
        &[candidate(
            "dependency-advisories",
            EvidenceKind::AuthenticatedUpstreamReceipt,
            vec![AuditProfile::Release],
        )],
    )
    .unwrap();
    let obligation = &obligations[0];
    let unauthenticated = ObligationEvidence {
        obligation: obligation.id.clone(),
        kind: EvidenceKind::AuthenticatedUpstreamReceipt,
        provider_id: None,
        coverage: None,
        finding_ids: Vec::new(),
        evidence_refs: vec![DIGEST.into()],
        artifact_digest: Some(DIGEST.into()),
        attested_by: Some("app-ci".into()),
        authenticated: false,
        produced_by_runtime: Some("node".into()),
        qualification: None,
    };
    assert_eq!(apply_evidence(obligation, &unauthenticated).status, ObligationStatus::Unmet);
    // Node-*produced* imported evidence is admissible once authenticated:
    // Audit did not execute Node.
    let mut authenticated = unauthenticated.clone();
    authenticated.authenticated = true;
    assert_eq!(
        apply_evidence(obligation, &authenticated).status,
        ObligationStatus::Satisfied
    );
}

#[test]
fn fixture_only_and_stale_qualification_do_not_apply() {
    let context = QualificationContext {
        provider_id: "fixture.provider".into(),
        provider_version: "1.0.0".into(),
        rule_version: None,
        host: "macos-arm64".into(),
        toolchain: "rustc-1.90".into(),
        target: "aarch64-apple-darwin".into(),
        variant: Some("release".into()),
        features: Vec::new(),
        requires_production_evidence: true,
    };
    let scope: QualificationScope =
        serde_json::from_value(fixture("qualification-fixture-only.json")).unwrap();
    let verdict = evaluate_qualification(Some(&scope), &context, NOW);
    assert!(!verdict.applicable);
    let obligation = one_obligation(&release_profile());
    let mut evidence = provider_evidence(&obligation, complete_coverage());
    evidence.qualification = Some(verdict);
    assert_eq!(apply_evidence(&obligation, &evidence).status, ObligationStatus::Unmet);
    assert!(!evaluate_qualification(None, &context, NOW).applicable);
}

#[test]
fn pre_pr_pass_never_projects_release_and_profiles_freeze_strength() {
    assert!(!AuditProfile::PrePr.can_project_to(AuditProfile::Release));
    assert!(AuditProfile::Release.can_project_to(AuditProfile::PrePr));
    assert_eq!(AuditProfile::parse("standard"), None);
    let pre_pr = FrozenProfile::freeze(
        AuditProfile::PrePr,
        "rev-1",
        RuntimeConstraint::NoNodePython,
    )
    .unwrap();
    let candidates = vec![
        candidate(
            "source-static",
            EvidenceKind::ProviderExecution,
            vec![AuditProfile::PrePr, AuditProfile::Repository, AuditProfile::Release],
        ),
        candidate("runtime-journey", EvidenceKind::Runtime, vec![AuditProfile::Release]),
    ];
    let frozen = resolve_obligations(&product_target(), &pre_pr, &candidates).unwrap();
    assert_eq!(frozen.len(), 1, "release-only work is legitimately omitted from pre-pr");
    let summary = summarize(AuditProfile::PrePr, &frozen);
    assert_eq!(summary.release_eligibility, ReleaseEligibility::NotAssessed);
    let round_trip = FrozenProfile::from_bound_value(&pre_pr.to_bound_value().unwrap()).unwrap();
    assert_eq!(round_trip, pre_pr);
}

#[test]
fn waiver_is_visible_owner_only_and_never_executed() {
    let obligation = one_obligation(&release_profile());
    let waiver = Waiver {
        granted_by: "owner:adrian".into(),
        rationale: "scanner unavailable this cycle".into(),
        scope: vec!["source-static".into()],
        expires_at: "2026-12-31T00:00:00Z".into(),
    };
    let waived = apply_waiver(&obligation, waiver, NOW).unwrap();
    assert_eq!(waived.status, ObligationStatus::Waived);
    assert!(!waived.status.was_examined());
    let summary = summarize(AuditProfile::Release, &[waived]);
    assert_eq!(summary.completion, Completion::NotExamined);
    assert_eq!(summary.release_eligibility, ReleaseEligibility::NotEligible);
    let tool_waiver = Waiver {
        granted_by: "model".into(),
        rationale: "looks fine".into(),
        scope: vec!["source-static".into()],
        expires_at: "2026-12-31T00:00:00Z".into(),
    };
    assert!(apply_waiver(&obligation, tool_waiver, NOW).is_err());
}

#[test]
fn no_node_python_closure_rejects_launchers_not_imported_evidence() {
    let closure: RuntimeClosure =
        serde_json::from_value(fixture("runtime-closure-node-launcher.json")).unwrap();
    let violations = validate_runtime_closure(RuntimeConstraint::NoNodePython, &closure);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].step, "eslint-bridge");
    let imported = RuntimeClosure {
        steps: vec![
            LaunchStep {
                name: "app-ci-eslint-report".into(),
                runtime: RuntimeClass::Node,
                kind: LaunchStepKind::ImportedEvidence,
                audit_owned: false,
            },
            LaunchStep {
                name: "detekt".into(),
                runtime: RuntimeClass::Jvm,
                kind: LaunchStepKind::Tool,
                audit_owned: true,
            },
        ],
    };
    assert!(validate_runtime_closure(RuntimeConstraint::NoNodePython, &imported).is_empty());
    assert_eq!(classify_runtime("npx"), RuntimeClass::Node);
    assert_eq!(classify_runtime("mystery-runner"), RuntimeClass::Unknown);
}

#[test]
fn assurance_extension_round_trips_and_renders_partials() {
    let profile = release_profile();
    let mut obligations = resolve_obligations(
        &product_target(),
        &profile,
        &[
            candidate(
                "source-static",
                EvidenceKind::ProviderExecution,
                vec![AuditProfile::Release],
            ),
            candidate(
                "dependency-health",
                EvidenceKind::ProviderExecution,
                vec![AuditProfile::Release],
            ),
        ],
    )
    .unwrap();
    let evidence = provider_evidence(&obligations[0], complete_coverage());
    obligations[0] = apply_evidence(&obligations[0], &evidence);
    let assurance = AuditAssuranceV1::new(profile, product_target(), obligations);
    assurance.validate(NOW).unwrap();
    assert_eq!(assurance.summary.completion, Completion::Partial);
    assert_eq!(assurance.summary.finding_outcome, FindingOutcome::Unproven);
    let value = assurance.to_value().unwrap();
    let reparsed = AuditAssuranceV1::from_value(&value, NOW).unwrap();
    assert_eq!(reparsed, assurance);
    let extensions = assurance_extensions(&assurance).unwrap();
    assert!(extensions.contains_key("auditAssuranceV1"));
    let mut future = value.clone();
    future["schemaVersion"] = Value::from(99);
    assert!(AuditAssuranceV1::from_value(&future, NOW).is_err());
}

#[test]
fn fixture_assurance_validates_as_a_partial_release_claim() {
    let value = fixture("assurance-partial-release.json");
    let assurance = AuditAssuranceV1::from_value(&value, NOW).unwrap();
    assert_eq!(assurance.summary.completion, Completion::Partial);
    assert_eq!(assurance.summary.release_eligibility, ReleaseEligibility::NotEligible);
    assert_eq!(assurance.summary.waived, 1);
}
