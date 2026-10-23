//! A02 projection: frozen assurance plan -> execution reconcile -> ReportV2
//! extension -> pure gate. Claims never override missing evidence; legacy
//! reports stay readable but never gain release eligibility; zero findings
//! with a valid examined scope is a legitimate clean result.
//!
//! Requires `lib.rs` re-exports: `canonical_report_assured`,
//! `project_assurance` (report) and `verify_assurance` (verify).

use std::collections::BTreeMap;

use legion_audit::assurance::{
    frozen_mismatches, gate, gate_report_v1, gate_report_v2, reconcile, run_host_label,
    AuditAssuranceV1, Completion, EvidenceKind, FindingOutcome, GateSubject, GateVerdict,
    ObligationCandidate, ObligationEvidence, ObligationStatus, ProductTarget, ReleaseEligibility,
    SnapshotRef, Waiver, AUDIT_ASSURANCE_EXTENSION_KEY,
};
use legion_audit::profiles::{AuditProfile, FrozenProfile, RuntimeConstraint};
use legion_audit::{
    canonical_report, canonical_report_assured, verify, verify_assurance, AuditPlan, AuditProvider,
    ExecutionReport, FrozenPlan, ProviderExecution, ProviderKind,
};
use legion_contracts::{
    Coverage, FindingRef, ProviderId, ProviderResult, ProviderStatus, ReportStatus, ReportV2,
};
use serde_json::{json, Value};

const NOW: &str = "2026-10-23T00:00:00Z";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: &[u8] = b"projection-fixture-key";
const PROVIDER: &str = "fixture.provider";

fn product_target() -> ProductTarget {
    ProductTarget {
        product: "fixture-app".into(),
        snapshots: vec![SnapshotRef {
            repository_id: "fixture-repo".into(),
            snapshot_digest: DIGEST.into(),
        }],
        target: "aarch64-apple-darwin".into(),
        variant: None,
    }
}

fn profile(p: AuditProfile) -> FrozenProfile {
    FrozenProfile::freeze(p, "rev-1", RuntimeConstraint::NoNodePython).unwrap()
}

fn candidate(concern: &str) -> ObligationCandidate {
    ObligationCandidate {
        concern: concern.into(),
        evidence_kind: EvidenceKind::ProviderExecution,
        required_in: vec![
            AuditProfile::PrePr,
            AuditProfile::Repository,
            AuditProfile::Release,
        ],
        provider_ids: vec![PROVIDER.into()],
        required_denominator_digest: Some(DIGEST.into()),
        proven_inapplicable_reason: None,
    }
}

fn frozen_assurance(p: AuditProfile) -> AuditAssuranceV1 {
    AuditAssuranceV1::freeze(profile(p), product_target(), &[candidate("source-static")]).unwrap()
}

/// Qualification scope record frozen into the provider bounds. `basis` is
/// `production` or `fixture`.
fn scope_record(basis: &str) -> Value {
    json!({
        "providerId": PROVIDER,
        "providerVersion": "1",
        "host": run_host_label(),
        "toolchain": "fixture-toolchain",
        "target": "aarch64-apple-darwin",
        "evidenceBasis": basis,
        "fixtureScope": if basis == "fixture" { "known-answer-fixture-cases" } else { "production-corpus" },
        "digest": DIGEST,
    })
}

fn provider(qualified: bool) -> AuditProvider {
    provider_with_scope(qualified, "production")
}

fn provider_with_scope(qualified: bool, basis: &str) -> AuditProvider {
    let mut configuration: BTreeMap<String, Value> = [
        "schemaVersion",
        "family",
        "consumes",
        "produces",
        "selector",
        "denominatorKind",
        "hostCapabilities",
        "execution",
        "reasoning",
        "benchmark",
        "controlIds",
        "scopes",
        "selectable",
        "runnerClass",
        "denominatorDigest",
        "denominatorCount",
    ]
    .into_iter()
    .map(|f| (f.to_owned(), Value::Null))
    .collect();
    configuration.insert("runner".into(), json!({"kind": "built-in"}));
    AuditProvider {
        id: PROVIDER.into(),
        version: "1".into(),
        role: "deterministic".into(),
        phase: "scan".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::BuiltIn,
        configuration,
        bounds: if qualified {
            BTreeMap::from([("qualificationScope".to_owned(), scope_record(basis))])
        } else {
            BTreeMap::new()
        },
        clean_claim: "fixture-claim".into(),
        benchmark_status: if qualified {
            "qualified"
        } else {
            "unqualified"
        }
        .into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: qualified.then(|| DIGEST.to_owned()),
        required: true,
    }
}

fn base_plan(qualified: bool) -> AuditPlan {
    base_plan_with(provider(qualified))
}

fn base_plan_with(provider: AuditProvider) -> AuditPlan {
    AuditPlan {
        schema_version: 1,
        repository_id: "/frozen/source".into(),
        inventory_generation: "frozen-generation".into(),
        inventory_digest: "frozen-inventory".into(),
        providers: vec![provider],
        bounds: legion_audit::execution_policy::binding()
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        excluded_conditional_providers: Vec::new(),
    }
}

fn frozen_plan(p: AuditProfile, qualified: bool) -> (FrozenPlan, AuditAssuranceV1) {
    let assurance = frozen_assurance(p);
    let plan = base_plan(qualified)
        .with_assurance(&assurance)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    (plan, assurance)
}

fn execution(plan: &FrozenPlan, coverage_digest: &str, findings: &[&str]) -> ExecutionReport {
    let result = ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(PROVIDER).unwrap(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: coverage_digest.into(),
            expected: 3,
            examined: 3,
            gaps: Vec::new(),
        }),
        findings: findings
            .iter()
            .map(|id| FindingRef {
                id: legion_contracts::FindingId::new(*id).unwrap(),
                severity: "high".into(),
            })
            .collect(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    };
    ExecutionReport {
        plan_digest: plan.digest().to_owned(),
        plan_signature: plan.signature().map(str::to_owned),
        execution_policy: plan.plan().bounds["executionPolicy"].clone(),
        execution_policy_identity: plan.plan().bounds["executionPolicyIdentity"].clone(),
        generation: "frozen-generation".into(),
        inventory_digest: "frozen-inventory".into(),
        planned_providers: vec![PROVIDER.into()],
        results: vec![ProviderExecution {
            provider: PROVIDER.into(),
            result,
            skipped: false,
        }],
        selected_lenses: Vec::new(),
        lenses_ran: Vec::new(),
        selected_reasoning_lenses: Vec::new(),
        pending_host: Vec::new(),
        deterministic_lens_tags: BTreeMap::new(),
        coverage_notes: Vec::new(),
        gaps: Vec::new(),
        provider_records: Vec::new(),
    }
}

fn empty_execution(plan: &FrozenPlan) -> ExecutionReport {
    let mut e = execution(plan, DIGEST, &[]);
    e.results.clear();
    e
}

#[test]
fn legacy_plan_without_assurance_is_unchanged() {
    let legacy = base_plan(true).freeze(Some(KEY)).unwrap();
    assert!(legacy.plan().assurance_binding().unwrap().is_none());
    assert!(!legacy.plan().bounds.contains_key("auditAssuranceV1"));
    let exec = execution(&legacy, DIGEST, &[]);
    let plain = canonical_report("/frozen/source", &exec).unwrap();
    let assured =
        canonical_report_assured("/frozen/source", &legacy, &exec, &[], &[], NOW).unwrap();
    assert_eq!(plain, assured);
    assert!(!assured
        .extensions
        .contains_key(AUDIT_ASSURANCE_EXTENSION_KEY));
    verify_assurance(&legacy, &assured, NOW).unwrap();
}

#[test]
fn assurance_is_frozen_into_signed_plan_and_tamper_breaks_it() {
    let (plan, assurance) = frozen_plan(AuditProfile::Release, true);
    assert_eq!(plan.plan().assurance_binding().unwrap().unwrap(), assurance);
    let legacy = base_plan(true).freeze(Some(KEY)).unwrap();
    assert_ne!(plan.digest(), legacy.digest());
    // Dropping the obligation after signing invalidates digest/signature.
    let mut tampered = plan.plan().clone();
    tampered.bounds.remove("auditAssuranceV1");
    assert!(verify(&tampered, plan.digest(), plan.signature(), Some(KEY)).is_err());
}

#[test]
fn frozen_form_rejects_pre_asserted_status_duplicates_and_garbage() {
    let mut claimed = frozen_assurance(AuditProfile::Release);
    claimed.obligations[0].status = ObligationStatus::Satisfied;
    claimed.obligations[0].evidence_refs = vec!["x".into()];
    claimed.summary =
        legion_audit::assurance::summarize(AuditProfile::Release, &claimed.obligations);
    assert!(base_plan(true).with_assurance(&claimed).is_err());
    let ok = frozen_assurance(AuditProfile::Release);
    let once = base_plan(true).with_assurance(&ok).unwrap();
    assert!(once.with_assurance(&ok).is_err());
    let mut garbage = base_plan(true);
    garbage
        .bounds
        .insert("auditAssuranceV1".into(), json!({"schemaVersion": 9}));
    assert!(garbage.assurance_binding().is_err());
    assert!(garbage.validate().is_err());
}

#[test]
fn qualified_complete_zero_finding_run_is_eligible() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    let exec = execution(&plan, DIGEST, &[]);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    assert_eq!(report.status, ReportStatus::Clean);
    verify_assurance(&plan, &report, NOW).unwrap();
    let assurance =
        AuditAssuranceV1::from_value(&report.extensions[AUDIT_ASSURANCE_EXTENSION_KEY], NOW)
            .unwrap();
    assert_eq!(assurance.summary.completion, Completion::Complete);
    assert_eq!(assurance.summary.finding_outcome, FindingOutcome::Clean);
    assert_eq!(
        assurance.summary.release_eligibility,
        ReleaseEligibility::Eligible
    );
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_eq!(decision.verdict, GateVerdict::Eligible, "{decision:?}");
}

#[test]
fn missing_evidence_is_retained_as_a_gap_and_cannot_be_eligible() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    let exec = empty_execution(&plan);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    assert_ne!(report.status, ReportStatus::Clean);
    assert!(report
        .gaps
        .iter()
        .any(|g| g.starts_with("assurance-unmet:")));
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_eq!(decision.verdict, GateVerdict::Incomplete);
}

#[test]
fn wrong_denominator_and_unqualified_provider_stay_unmet() {
    let (plan, _) = frozen_plan(AuditProfile::Release, true);
    let wrong = format!("sha256:{}", "b".repeat(64));
    let exec = execution(&plan, &wrong, &[]);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    assert_ne!(report.status, ReportStatus::Clean);

    let (unqualified, _) = frozen_plan(AuditProfile::Release, false);
    let exec = execution(&unqualified, DIGEST, &[]);
    let report =
        canonical_report_assured("/frozen/source", &unqualified, &exec, &[], &[], NOW).unwrap();
    assert_ne!(report.status, ReportStatus::Clean);
    assert!(report
        .gaps
        .iter()
        .any(|g| g.starts_with("assurance-unmet:")));
}

#[test]
fn obligation_findings_block_and_are_not_clean() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    let exec = execution(&plan, DIGEST, &["sha256:finding-1"]);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    assert_eq!(report.status, ReportStatus::Findings);
    let assurance =
        AuditAssuranceV1::from_value(&report.extensions[AUDIT_ASSURANCE_EXTENSION_KEY], NOW)
            .unwrap();
    assert_eq!(assurance.summary.completion, Completion::Complete);
    assert_eq!(assurance.summary.finding_outcome, FindingOutcome::Findings);
    assert_eq!(
        assurance.summary.release_eligibility,
        ReleaseEligibility::NotEligible
    );
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_eq!(decision.verdict, GateVerdict::BlockedFindings);
}

#[test]
fn claims_cannot_add_drop_or_satisfy_obligations() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    // Evidence for an identity that was never frozen is ignored and surfaced.
    let mut alien = frozen.obligations[0].id.clone();
    alien.concern = "invented".into();
    let bogus = ObligationEvidence {
        obligation: alien,
        kind: EvidenceKind::ProviderExecution,
        provider_id: None,
        coverage: Some(Coverage {
            denominator_digest: DIGEST.into(),
            expected: 1,
            examined: 1,
            gaps: Vec::new(),
        }),
        finding_ids: Vec::new(),
        evidence_refs: vec!["x".into()],
        artifact_digest: None,
        attested_by: None,
        authenticated: false,
        produced_by_runtime: None,
        qualification: None,
    };
    let rec = reconcile(&frozen, &[bogus], &[], NOW).unwrap();
    assert_eq!(rec.assurance.obligations.len(), frozen.obligations.len());
    assert_eq!(rec.assurance.obligations[0].status, ObligationStatus::Unmet);
    assert!(!rec.rejected.is_empty());

    // A report that drops the obligation (or re-profiles) mismatches the frozen plan.
    let mut dropped = frozen.clone();
    dropped.obligations.clear();
    dropped.summary = legion_audit::assurance::summarize(AuditProfile::Release, &[]);
    assert!(!frozen_mismatches(&frozen, &dropped).is_empty());
    let mut report = canonical_report("/frozen/source", &execution(&plan, DIGEST, &[])).unwrap();
    report.extensions.insert(
        AUDIT_ASSURANCE_EXTENSION_KEY.into(),
        dropped.to_value().unwrap(),
    );
    assert!(verify_assurance(&plan, &report, NOW).is_err());
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_ne!(decision.verdict, GateVerdict::Eligible);

    // A frozen plan requires the extension; a clean claim over unmet is refused.
    let plain = canonical_report("/frozen/source", &execution(&plan, DIGEST, &[])).unwrap();
    assert!(verify_assurance(&plan, &plain, NOW).is_err());
    let mut forged = plain.clone();
    forged.extensions.insert(
        AUDIT_ASSURANCE_EXTENSION_KEY.into(),
        frozen.to_value().unwrap(),
    );
    forged.status = ReportStatus::Clean;
    assert!(verify_assurance(&plan, &forged, NOW).is_err());
}

#[test]
fn waiver_is_visible_and_never_eligible() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    let waiver = Waiver {
        granted_by: "owner:adrian".into(),
        rationale: "accepted debt".into(),
        scope: vec!["source-static".into()],
        expires_at: "2027-01-01T00:00:00Z".into(),
    };
    let waivers = vec![(frozen.obligations[0].id.clone(), waiver)];
    let exec = empty_execution(&plan);
    let report =
        canonical_report_assured("/frozen/source", &plan, &exec, &[], &waivers, NOW).unwrap();
    let assurance =
        AuditAssuranceV1::from_value(&report.extensions[AUDIT_ASSURANCE_EXTENSION_KEY], NOW)
            .unwrap();
    assert_eq!(assurance.obligations[0].status, ObligationStatus::Waived);
    assert_eq!(assurance.summary.completion, Completion::NotExamined);
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_eq!(decision.verdict, GateVerdict::Incomplete);
}

#[test]
fn legacy_malformed_and_future_reports_stay_readable_never_eligible() {
    let (plan, frozen) = frozen_plan(AuditProfile::Release, true);
    let mut report = canonical_report("/frozen/source", &execution(&plan, DIGEST, &[])).unwrap();
    // Legacy: no extension.
    let d = gate_report_v1(&report, None, AuditProfile::Release, NOW);
    assert_eq!(d.verdict, GateVerdict::Incomplete);
    assert!(d
        .reasons
        .iter()
        .any(|r| r.contains("assurance-extension-absent")));
    // Legacy v1 JSON re-read as v2 view remains readable and still ineligible.
    let v2: ReportV2 = ReportV2::from_v1_view(&report).unwrap();
    assert_eq!(
        gate_report_v2(&v2, Some(&frozen), AuditProfile::Release, NOW).verdict,
        GateVerdict::Incomplete
    );
    // Malformed and future versions.
    for bad in [json!("garbage"), json!({"schemaVersion": 2}), json!({})] {
        report
            .extensions
            .insert(AUDIT_ASSURANCE_EXTENSION_KEY.into(), bad);
        let d = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
        assert_eq!(d.verdict, GateVerdict::Incomplete);
        assert!(d
            .reasons
            .iter()
            .any(|r| r.contains("assurance-extension-invalid")));
    }
}

#[test]
fn weaker_profile_never_gates_a_stronger_one() {
    let (plan, frozen) = frozen_plan(AuditProfile::PrePr, true);
    let exec = execution(&plan, DIGEST, &[]);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    let pre = gate_report_v1(&report, Some(&frozen), AuditProfile::PrePr, NOW);
    assert_eq!(pre.verdict, GateVerdict::Eligible, "{pre:?}");
    let rel = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_eq!(rel.verdict, GateVerdict::Incomplete);
    assert!(rel
        .reasons
        .iter()
        .any(|r| r.starts_with("profile-too-weak")));
    // Gate over a bare subject agrees (pure function).
    let subject = GateSubject {
        status: report.status,
        finding_count: 0,
        gaps: &report.gaps,
        extensions: &report.extensions,
    };
    assert_eq!(
        gate(&subject, Some(&frozen), AuditProfile::PrePr, NOW).verdict,
        GateVerdict::Eligible
    );
}

#[test]
fn extension_survives_v2_lift_additively() {
    let (plan, _) = frozen_plan(AuditProfile::Release, true);
    let report = canonical_report_assured(
        "/frozen/source",
        &plan,
        &execution(&plan, DIGEST, &[]),
        &[],
        &[],
        NOW,
    )
    .unwrap();
    let v2 = ReportV2::from_v1_view(&report).unwrap();
    assert!(v2.assurance_extension().is_some());
    let _ = Value::Null;
}

#[test]
fn fixture_only_qualified_provider_cannot_satisfy_release_obligation() {
    let assurance = frozen_assurance(AuditProfile::Release);
    let plan = base_plan_with(provider_with_scope(true, "fixture"))
        .with_assurance(&assurance)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let exec = execution(&plan, DIGEST, &[]);
    let report = canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
    assert_ne!(report.status, ReportStatus::Clean);
    let frozen = plan.plan().assurance_binding().unwrap().unwrap();
    let decision = gate_report_v1(&report, Some(&frozen), AuditProfile::Release, NOW);
    assert_ne!(decision.verdict, GateVerdict::Eligible, "{decision:?}");
    assert!(report
        .gaps
        .iter()
        .any(|g| g.starts_with("assurance-unmet:")));
}

#[test]
fn claim_scope_fixture_and_missing_record_do_not_qualify_release() {
    // Registry claim scope marks the provider fixture-only.
    let mut claim_only = provider(true);
    claim_only.bounds =
        BTreeMap::from([("claimScope".to_owned(), json!("known-answer-fixture-cases"))]);
    // Legacy status+digest with no scope record at all.
    let mut no_record = provider(true);
    no_record.bounds = BTreeMap::new();
    for candidate_provider in [claim_only, no_record] {
        let assurance = frozen_assurance(AuditProfile::Release);
        let plan = base_plan_with(candidate_provider)
            .with_assurance(&assurance)
            .unwrap()
            .freeze(Some(KEY))
            .unwrap();
        let exec = execution(&plan, DIGEST, &[]);
        let report =
            canonical_report_assured("/frozen/source", &plan, &exec, &[], &[], NOW).unwrap();
        assert_ne!(report.status, ReportStatus::Clean);
    }
}
