//! A16 acceptance: runtime journeys, performance comparability and Rust
//! target obligations. Authored by a packet worker, never run by it; root
//! executes. Requires root to export `runtime_obligations` from `lib.rs` and
//! `pub mod rust_targets;` from `native_providers/code/mod.rs`.
//! Fixtures here are integration fixtures only; they claim no app coverage.

use std::collections::{BTreeMap, BTreeSet};

use legion_audit::artifact_evidence::{
    EvidenceOutcome, ImportKind, ImportedEvidenceRecord, RepositoryBinding, RetainedArtifact,
};
use legion_audit::assurance::{evaluate_qualification, ObligationStatus, QualificationScope};
use legion_audit::native_providers::code::rust_targets::{
    evaluate_miri_coverage, evaluate_rust_evidence, plan_rust_obligations, FeatureConstraints,
    FeatureSelection, RustObligationKind, RustTargetMatrix, RustTargetSelection, TestSelection,
    UnsafeSite,
};
use legion_audit::profiles::AuditProfile;
use legion_audit::runtime_obligations::{
    comparison_mismatches, evaluate_journey, evaluate_pairs, evaluate_performance,
    inventory_gaps, journey_candidates, stack_inventory, AxisReport, BudgetState,
    EvidenceProducer, JourneyDeclaration, JourneyObserved, JourneyStatus, OutcomeAxis,
    PerformanceBaseline, PerformanceBudget, Stack, SubjectIdentity, Trend,
};
use serde_json::Value;

const NOW: &str = "2026-10-23T00:00:00Z";
const FRESH: &str = "2026-10-24T00:00:00Z";
const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const D3: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/runtime-obligations/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn declarations() -> Vec<JourneyDeclaration> {
    serde_json::from_value(fixture("journeys.json")).expect("journey declarations")
}

fn declaration(id: &str) -> JourneyDeclaration {
    declarations().into_iter().find(|d| d.id == id).expect("declared journey")
}

fn subject() -> SubjectIdentity {
    SubjectIdentity {
        artifact_digest: D1.into(),
        build_config_digest: D2.into(),
        target: "ios:Release".into(),
        variant: Some("App".into()),
        scheme: Some("App".into()),
        destination: Some("iPhone 17 Pro / iOS 26.0".into()),
        application_id: Some("com.example.app".into()),
        server_revision: Some("rev-42".into()),
        features: vec![],
        environment_id: "isolated-1".into(),
    }
}

fn record(decl: &JourneyDeclaration, subject: &SubjectIdentity) -> ImportedEvidenceRecord {
    ImportedEvidenceRecord {
        schema_version: 1,
        evidence_id: format!("ev-{}", decl.id),
        claims_digest: D3.into(),
        kind: decl.axis.import_kind().expect("import kind"),
        authenticated: true,
        attestor: "host-ci".into(),
        trust_root_id: "root-1".into(),
        verifier_id: "verifier-1".into(),
        outcome: EvidenceOutcome::Passed,
        repositories: vec![RepositoryBinding {
            repository_id: "app".into(),
            revision: "abc".into(),
            branch: None,
            snapshot_digest: D1.into(),
        }],
        target: subject.target.clone(),
        variant: subject.variant.clone(),
        toolchain: "tc-1".into(),
        upstream_runtime: None,
        artifacts: vec![RetainedArtifact {
            path: "receipt.json".into(),
            digest: D3.into(),
            bytes: 10,
            role: "primary".into(),
            immutable: true,
        }],
        artifact_digest: D3.into(),
        denominator_digest: D3.into(),
        examined_scope: decl.scope_items(),
        missing_scope: vec![],
        newly_executed: true,
        replay_of: None,
        issued_at: NOW.into(),
        fresh_until: FRESH.into(),
    }
}

fn observed(decl: &JourneyDeclaration, subject: &SubjectIdentity) -> JourneyObserved {
    JourneyObserved {
        evidence_id: format!("ev-{}", decl.id),
        journey_id: decl.id.clone(),
        axis: decl.axis,
        subject: subject.clone(),
        steps_examined: decl.steps.clone(),
    }
}

#[test]
fn matching_journey_satisfies_and_wrong_identity_does_not() {
    let decl = declaration("ios-state-restoration");
    let expected = subject();
    let rec = record(&decl, &expected);
    let ok = evaluate_journey(&decl, &expected, Some(&rec), Some(&observed(&decl, &expected)), NOW);
    assert_eq!(ok.status, JourneyStatus::Satisfied, "{:?}", ok.reasons);

    let mut wrong_binary = expected.clone();
    wrong_binary.artifact_digest = D2.into();
    let mut wrong_scheme = expected.clone();
    wrong_scheme.scheme = Some("AppTests".into());
    let mut wrong_variant = expected.clone();
    wrong_variant.variant = Some("Other".into());
    let mut wrong_server = expected.clone();
    wrong_server.server_revision = Some("rev-41".into());
    for (observed_subject, reason) in [
        (wrong_binary, "artifact-digest-mismatch"),
        (wrong_scheme, "scheme-mismatch"),
        (wrong_variant, "variant-mismatch"),
        (wrong_server, "server-revision-mismatch"),
    ] {
        let outcome = evaluate_journey(
            &decl,
            &expected,
            Some(&rec),
            Some(&observed(&decl, &observed_subject)),
            NOW,
        );
        assert_eq!(outcome.status, JourneyStatus::Unmet, "{reason}");
        assert!(outcome.reasons.iter().any(|r| r == reason), "{reason}: {:?}", outcome.reasons);
    }
}

#[test]
fn missing_stale_replayed_and_gap_evidence_never_satisfy() {
    let decl = declaration("ios-state-restoration");
    let expected = subject();
    let none = evaluate_journey(&decl, &expected, None, None, NOW);
    assert_eq!(none.status, JourneyStatus::Unmet);

    let mut stale = record(&decl, &expected);
    stale.fresh_until = "2026-10-22T00:00:00Z".into();
    let out = evaluate_journey(&decl, &expected, Some(&stale), Some(&observed(&decl, &expected)), NOW);
    assert!(out.reasons.iter().any(|r| r == "stale-evidence"));

    let mut replayed = record(&decl, &expected);
    replayed.newly_executed = false;
    let out = evaluate_journey(&decl, &expected, Some(&replayed), Some(&observed(&decl, &expected)), NOW);
    assert_eq!(out.status, JourneyStatus::Unmet);
    assert!(out.replayed);

    let mut partial = record(&decl, &expected);
    partial.examined_scope.pop();
    let out = evaluate_journey(&decl, &expected, Some(&partial), Some(&observed(&decl, &expected)), NOW);
    assert_eq!(out.status, JourneyStatus::Unmet);

    // A declared producer gap stays unmet even with otherwise valid evidence.
    let gap = declaration("android-process-death");
    let rec = record(&gap, &expected);
    let out = evaluate_journey(&gap, &expected, Some(&rec), Some(&observed(&gap, &expected)), NOW);
    assert_eq!(out.status, JourneyStatus::Unmet);
    assert!(out.reasons.iter().any(|r| r.starts_with("producer-gap")));
}

#[test]
fn paired_scenarios_report_evidence_specific_outcomes() {
    let decls = declarations();
    let expected = subject();
    let dup = declaration("node-checkout-duplicate-delivery");
    let cancel = declaration("node-checkout-cancellation");

    let dup_rec = record(&dup, &expected);
    let dup_out = evaluate_journey(&dup, &expected, Some(&dup_rec), Some(&observed(&dup, &expected)), NOW);
    assert_eq!(dup_out.status, JourneyStatus::Satisfied, "{:?}", dup_out.reasons);

    // Cancellation has no evidence: duplicate-delivery pass does not cover it.
    let pairs = evaluate_pairs(&decls, &[dup_out.clone()]);
    let pair = pairs.iter().find(|p| p.pair_id == "checkout-pair").expect("pair");
    assert_eq!(pair.status, JourneyStatus::Unmet);
    let member = |role: &str| pair.members.iter().find(|m| m.role == role).expect("member");
    assert_eq!(member("duplicate-delivery").status, JourneyStatus::Satisfied);
    assert_eq!(member("cancellation").status, JourneyStatus::Unmet);

    // A failed cancellation is a finding for that member only.
    let mut failed = record(&cancel, &expected);
    failed.outcome = EvidenceOutcome::Failed;
    let cancel_out = evaluate_journey(&cancel, &expected, Some(&failed), Some(&observed(&cancel, &expected)), NOW);
    assert_eq!(cancel_out.status, JourneyStatus::Findings);
    let pairs = evaluate_pairs(&decls, &[dup_out, cancel_out]);
    let pair = pairs.iter().find(|p| p.pair_id == "checkout-pair").expect("pair");
    assert_eq!(pair.status, JourneyStatus::Findings);
    assert_eq!(
        pair.members.iter().find(|m| m.role == "duplicate-delivery").unwrap().status,
        JourneyStatus::Satisfied
    );
}

#[test]
fn inventory_lists_every_applicable_category_with_producer_or_gap() {
    let applicable: BTreeSet<Stack> = [
        Stack::NodeCommerce,
        Stack::ReactAdmin,
        Stack::QwikStorefront,
        Stack::Postgres,
        Stack::Nginx,
        Stack::RustCore,
        Stack::TauriReact,
        Stack::NativeGui,
        Stack::SwiftMacos,
        Stack::SwiftIos,
        Stack::KotlinAndroid,
    ]
    .into_iter()
    .collect();
    let rows = stack_inventory(&applicable, &declarations());
    for stack in &applicable {
        assert!(rows.iter().any(|r| r.stack == *stack), "{stack:?} absent from inventory");
    }
    let gaps = inventory_gaps(&rows);
    // Declared-but-gap and undeclared categories are explicit.
    assert!(gaps.iter().any(|g| g.starts_with("kotlin-android:process-death-restore")));
    assert!(gaps.iter().any(|g| g.starts_with("postgres:recovery")));
    // A producer-backed category is not listed as a gap.
    assert!(!gaps.iter().any(|g| g.starts_with("swift-ios:cancellation-state-restoration")));
    let ios = rows
        .iter()
        .find(|r| r.stack == Stack::SwiftIos && r.category == "cancellation-state-restoration")
        .expect("ios row");
    assert!(matches!(ios.producer, EvidenceProducer::Owner { .. }));
    // Inapplicable stacks are omitted only when root excluded them.
    let only_nginx: BTreeSet<Stack> = [Stack::Nginx].into_iter().collect();
    assert!(stack_inventory(&only_nginx, &[]).iter().all(|r| r.stack == Stack::Nginx));
}

#[test]
fn candidates_keep_gap_producers_and_reject_duplicates() {
    let decls = declarations();
    let candidates = journey_candidates(&decls, &[AuditProfile::Release]).expect("candidates");
    assert_eq!(candidates.len(), decls.len());
    assert!(candidates.iter().any(|c| c.concern == "journey:functional:android-process-death"));
    let mut dup = decls.clone();
    dup.push(decls[0].clone());
    assert!(journey_candidates(&dup, &[AuditProfile::Release]).is_err());
}

#[test]
fn outcome_axes_stay_separate_and_unknown_stays_incomplete() {
    let mut report = AxisReport::new(BTreeMap::new());
    report.record(OutcomeAxis::Functional, JourneyStatus::Satisfied, &[]);
    assert_eq!(report.axes[&OutcomeAxis::Functional].status, JourneyStatus::Satisfied);
    for axis in [
        OutcomeAxis::Source,
        OutcomeAxis::Build,
        OutcomeAxis::Visual,
        OutcomeAxis::A11y,
        OutcomeAxis::Load,
        OutcomeAxis::ArtifactSecurity,
    ] {
        assert_eq!(report.axes[&axis].status, JourneyStatus::Unmet, "{axis:?}");
    }
    assert!(!report.is_complete());
    report.record(OutcomeAxis::Functional, JourneyStatus::Findings, &["journey-failed".into()]);
    assert_eq!(report.axes[&OutcomeAxis::Functional].status, JourneyStatus::Findings);
}

fn perf_baseline() -> PerformanceBaseline {
    serde_json::from_value(fixture("performance.json")["baseline"].clone()).expect("baseline")
}

fn perf_budget() -> PerformanceBudget {
    serde_json::from_value(fixture("performance.json")["budget"].clone()).expect("budget")
}

#[test]
fn missing_budget_is_not_invented() {
    let base = perf_baseline();
    let current = base.measurement.clone();
    let outcome = evaluate_performance(&current, Some(&base), None);
    assert_eq!(outcome.status, JourneyStatus::Unmet);
    assert_eq!(outcome.budget, BudgetState::NotDeclared);
    assert!(outcome.reasons.iter().any(|r| r == "performance-budget-not-declared"));
}

#[test]
fn comparable_regression_is_a_finding_and_incomparable_is_not() {
    let base = perf_baseline();
    let budget = perf_budget();

    let mut regressed = base.measurement.clone();
    regressed.value = 900; // +12.5% against a 5% tolerance, still under the 1000 limit.
    let outcome = evaluate_performance(&regressed, Some(&base), Some(&budget));
    assert_eq!(outcome.trend, Trend::Regressed);
    assert_eq!(outcome.status, JourneyStatus::Findings);
    assert_eq!(outcome.budget, BudgetState::Within);

    // Different hardware: slower number is incomparable, never a regression
    // and a faster one is never an improvement (N18).
    for (value, label) in [(900u64, "slower"), (500u64, "faster")] {
        let mut other = base.measurement.clone();
        other.value = value;
        other.workload.hardware.cpu_model = "other-class".into();
        let outcome = evaluate_performance(&other, Some(&base), Some(&budget));
        match &outcome.trend {
            Trend::Incomparable { mismatches } => {
                assert!(mismatches.iter().any(|m| m == "hardware"), "{label}");
            }
            other => panic!("{label}: expected incomparable, got {other:?}"),
        }
        assert_eq!(outcome.status, JourneyStatus::Satisfied, "{label}");
    }

    // Excluded slow routes and a different traffic mix are incomparable too.
    let mut excluded = base.measurement.clone();
    excluded.workload.excluded_routes = vec!["/slow-report".into()];
    excluded.workload.traffic_mix_digest = D2.into();
    let mismatches = comparison_mismatches(&base.measurement, &excluded);
    assert!(mismatches.iter().any(|m| m == "excluded-routes"));
    assert!(mismatches.iter().any(|m| m == "traffic-mix"));

    // Comparable and faster is an improvement.
    let mut faster = base.measurement.clone();
    faster.value = 700;
    let outcome = evaluate_performance(&faster, Some(&base), Some(&budget));
    assert_eq!(outcome.trend, Trend::Improved);
    assert_eq!(outcome.status, JourneyStatus::Satisfied);
}

#[test]
fn undeclared_tolerance_never_gates_and_budget_exceed_is_a_finding() {
    let base = perf_baseline();
    let mut budget = perf_budget();
    budget.regression_tolerance_ppm = None;
    let mut slower = base.measurement.clone();
    slower.value = 900;
    let outcome = evaluate_performance(&slower, Some(&base), Some(&budget));
    assert_eq!(outcome.status, JourneyStatus::Satisfied);
    assert!(outcome.reasons.iter().any(|r| r == "regression-tolerance-not-declared"));

    let mut over = base.measurement.clone();
    over.value = 1200;
    let outcome = evaluate_performance(&over, None, Some(&perf_budget()));
    assert_eq!(outcome.budget, BudgetState::Exceeded);
    assert_eq!(outcome.status, JourneyStatus::Findings);
    assert_eq!(outcome.trend, Trend::NoBaseline);
}

#[test]
fn incomplete_workload_or_samples_stay_unmet() {
    let base = perf_baseline();
    let budget = perf_budget();
    let mut thin = base.measurement.clone();
    thin.workload.sample_count = 10; // below budget.minSamples
    let outcome = evaluate_performance(&thin, None, Some(&budget));
    assert_eq!(outcome.status, JourneyStatus::Unmet);
    let mut blank = base.measurement.clone();
    blank.workload.measurement_method = String::new();
    blank.workload.dataset_digest = "unknown".into();
    let outcome = evaluate_performance(&blank, None, Some(&budget));
    assert_eq!(outcome.status, JourneyStatus::Unmet);
    assert!(outcome.reasons.iter().any(|r| r.starts_with("incomplete-workload-record")));
}

// ---------------------------------------------------------------------------
// Rust targets
// ---------------------------------------------------------------------------

fn selection(triple: &str, features: FeatureSelection) -> RustTargetSelection {
    RustTargetSelection {
        package: "core".into(),
        target_triple: triple.into(),
        profile: "release".into(),
        features,
        toolchain: "rustc-1.90".into(),
        build_config_digest: D2.into(),
        test_selection: Some(TestSelection { digest: D3.into(), filters: vec![] }),
    }
}

fn matrix(entries: Vec<RustTargetSelection>, unsafe_sites: Vec<UnsafeSite>) -> RustTargetMatrix {
    let mut constraints = BTreeMap::new();
    constraints.insert(
        "core".to_string(),
        FeatureConstraints {
            declared_features: vec!["tls-rustls".into(), "tls-native".into(), "gui".into()],
            mutually_exclusive: vec![vec!["tls-rustls".into(), "tls-native".into()]],
            all_features_valid: Some(true),
        },
    );
    RustTargetMatrix {
        declared_by: "product.toml".into(),
        entries,
        constraints,
        unsafe_sites,
    }
}

fn rust_record(
    obligation_id: &str,
    target: &str,
    variant: &str,
    kind: ImportKind,
    scope: Vec<String>,
) -> ImportedEvidenceRecord {
    let mut rec = record(&declaration("ios-state-restoration"), &subject());
    rec.kind = kind;
    rec.target = target.into();
    rec.variant = Some(variant.into());
    rec.toolchain = "rustc-1.90".into();
    rec.examined_scope = scope;
    rec.examined_scope.push(obligation_id.into());
    rec
}

#[test]
fn empty_matrix_is_an_explicit_gap_not_a_pass() {
    let plan = plan_rust_obligations(&RustTargetMatrix::default(), &[RustObligationKind::Build]);
    assert!(plan.obligations.is_empty());
    assert!(plan.gaps.iter().any(|g| g.starts_with("no-declared-target-matrix")));
}

#[test]
fn all_features_is_invalid_with_mutually_exclusive_features() {
    let m = matrix(vec![selection("x86_64-unknown-linux-gnu", FeatureSelection::AllFeatures)], vec![]);
    let plan = plan_rust_obligations(&m, &[RustObligationKind::Build]);
    let obligation = &plan.obligations[0];
    assert!(obligation
        .plan_gaps
        .iter()
        .any(|g| g == "all-features-invalid-mutually-exclusive-features"));
    let outcome = evaluate_rust_evidence(obligation, None, NOW);
    assert_eq!(outcome.status, ObligationStatus::Unmet);

    let conflicting = matrix(
        vec![selection(
            "x86_64-unknown-linux-gnu",
            FeatureSelection::Explicit { features: vec!["tls-rustls".into(), "tls-native".into()] },
        )],
        vec![],
    );
    let plan = plan_rust_obligations(&conflicting, &[RustObligationKind::Build]);
    assert!(plan.obligations[0].plan_gaps.iter().any(|g| g.starts_with("mutually-exclusive-features")));
}

#[test]
fn evidence_for_another_target_or_feature_set_cannot_discharge() {
    let linux = selection(
        "x86_64-unknown-linux-gnu",
        FeatureSelection::Explicit { features: vec!["gui".into()] },
    );
    let mac = selection("aarch64-apple-darwin", linux.features.clone());
    let m = matrix(vec![linux, mac], vec![]);
    let plan = plan_rust_obligations(&m, &[RustObligationKind::Build]);
    assert_eq!(plan.obligations.len(), 2);
    let linux_ob = plan.obligations.iter().find(|o| o.target_triple.contains("linux")).unwrap();
    let mac_ob = plan.obligations.iter().find(|o| o.target_triple.contains("darwin")).unwrap();

    let good = rust_record(
        &linux_ob.id,
        &linux_ob.obligation_target(),
        &linux_ob.obligation_variant(),
        ImportKind::Build,
        vec![],
    );
    assert_eq!(evaluate_rust_evidence(linux_ob, Some(&good), NOW).status, ObligationStatus::Satisfied);

    // The Linux record presented for the macOS obligation is rejected.
    let borrowed = evaluate_rust_evidence(mac_ob, Some(&good), NOW);
    assert_eq!(borrowed.status, ObligationStatus::Unmet);
    assert!(borrowed.reasons.iter().any(|r| r == "target-mismatch"));

    // Same target, different feature selection is a different obligation.
    let other_features = plan_rust_obligations(
        &matrix(
            vec![selection("x86_64-unknown-linux-gnu", FeatureSelection::Default)],
            vec![],
        ),
        &[RustObligationKind::Build],
    );
    let default_ob = &other_features.obligations[0];
    let out = evaluate_rust_evidence(default_ob, Some(&good), NOW);
    assert!(out.reasons.iter().any(|r| r == "variant-mismatch"));

    // Qualification recorded for macOS never applies to the Linux context.
    let context = linux_ob.qualification_context("code.rust", "1", "linux-host", true);
    let record = QualificationScope {
        provider_id: "code.rust".into(),
        provider_version: "1".into(),
        rule_version: None,
        host: "linux-host".into(),
        toolchain: "rustc-1.90".into(),
        target: "aarch64-apple-darwin".into(),
        variant: Some(mac_ob.obligation_variant()),
        features: vec!["gui".into()],
        evidence_basis: "production".into(),
        fixture_scope: "none".into(),
        fresh_until: None,
        digest: D1.into(),
    };
    let verdict = evaluate_qualification(Some(&record), &context, NOW);
    assert!(!verdict.applicable);
}

#[test]
fn miri_covers_only_executed_supported_unsafe_paths() {
    let sites = vec![
        UnsafeSite { id: "u1".into(), path: "src/a.rs".into(), line: 10, miri_supported: true, unsupported_reason: None },
        UnsafeSite { id: "u2".into(), path: "src/b.rs".into(), line: 20, miri_supported: true, unsupported_reason: None },
        UnsafeSite {
            id: "u3".into(),
            path: "src/ffi.rs".into(),
            line: 5,
            miri_supported: false,
            unsupported_reason: Some("ffi".into()),
        },
    ];
    let executed: BTreeSet<String> = ["u1".to_string()].into_iter().collect();
    let coverage = evaluate_miri_coverage(&sites, &executed);
    assert!(!coverage.complete);
    assert_eq!(coverage.covered_sites, vec!["u1".to_string()]);
    assert_eq!(coverage.uncovered_sites, vec!["u2".to_string()]);
    assert_eq!(coverage.unsupported_sites, vec!["u3:ffi".to_string()]);
    assert_eq!(coverage.claim, "executed-supported-paths-only");

    // A passing Miri receipt that executed one site leaves the obligation unmet.
    let m = matrix(vec![selection("x86_64-unknown-linux-gnu", FeatureSelection::Default)], sites);
    let plan = plan_rust_obligations(&m, &[RustObligationKind::Miri]);
    let ob = &plan.obligations[0];
    let rec = rust_record(
        &ob.id,
        &ob.obligation_target(),
        &ob.obligation_variant(),
        ImportKind::Test,
        vec!["unsafe:u1".into()],
    );
    let outcome = evaluate_rust_evidence(ob, Some(&rec), NOW);
    assert_eq!(outcome.status, ObligationStatus::Unmet);
    assert!(outcome.reasons.iter().any(|r| r == "unsafe-site-not-executed:u2"));
    assert!(outcome.reasons.iter().any(|r| r.starts_with("miri-unsupported:u3")));
}

#[test]
fn test_obligation_requires_declared_selection() {
    let mut entry = selection("x86_64-unknown-linux-gnu", FeatureSelection::Default);
    entry.test_selection = None;
    let plan = plan_rust_obligations(&matrix(vec![entry], vec![]), &[RustObligationKind::Test]);
    assert!(plan.obligations[0].plan_gaps.iter().any(|g| g == "test-selection-undeclared"));
}
