//! Imported quality semantics: authored here; root integration owns command-based verification.
use legion_audit::quality_observation::*;
use serde_json::{json, Value};

fn input() -> QualityObservationInput {
    serde_json::from_str(include_str!("fixtures/quality-observation/example.json")).unwrap()
}

fn measured_mutation(outcomes: Vec<MutationOutcome>, denominator: u64) -> MutationObservation {
    MutationObservation::Measured {
        baseline_status: QualityExecutionStatus::Succeeded,
        outcomes,
        declared_denominator: denominator,
    }
}

fn outcome(id: &str, category: MutationCategory) -> MutationOutcome {
    MutationOutcome {
        id: id.into(), path: "src/lib.rs".into(), category,
        upstream_label: "killed".into(), evidence_ref: "reports/mutation.json".into(),
    }
}

#[test]
fn real_zero_differs_from_missing_and_neither_is_clean() {
    let mut observation = input();
    let measured = summarize_quality(&observation).unwrap();
    assert_eq!(measured.coverage.percent, Some(0.0));
    assert_eq!(measured.coverage.total, Some(12));
    assert_eq!(measured.state, QualityObservationState::Measured);
    assert!(!measured.authoritative);
    assert_eq!(measured.origin, QualityEvidenceOrigin::Imported);
    assert!(!serde_json::to_string(&measured).unwrap().contains("\"clean\""));
    observation.coverage = CoverageObservation::Unavailable { reason: "tool absent".into() };
    let missing = summarize_quality(&observation).unwrap();
    assert_eq!(missing.coverage.percent, None);
    assert_eq!(missing.coverage.total, None);
    assert_eq!(missing.state, QualityObservationState::Unavailable);
}

#[test]
fn zero_denominator_never_yields_percentage() {
    let mut observation = input();
    observation.coverage = CoverageObservation::Measured { covered: 0, total: 0, evidence_ref: "reports/coverage.json".into() };
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.coverage.percent, None);
    assert_ne!(result.coverage.state, QualityObservationState::Measured);
}

#[test]
fn failed_command_cannot_make_numeric_zero_a_measurement() {
    let mut observation = input();
    observation.report.execution_status = QualityExecutionStatus::Failed;
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.coverage.percent, None);
    assert_eq!(result.coverage.state, QualityObservationState::Unavailable);
    assert_eq!(result.state, QualityObservationState::Unavailable);
}

#[test]
fn stale_report_and_invalid_coverage_denominator_are_rejected() {
    let mut observation = input();
    observation.report.source_digest = "b".repeat(64);
    assert!(summarize_quality(&observation).is_err());
    observation.report.source_digest = observation.subject.source_digest.clone();
    observation.coverage = CoverageObservation::Measured { covered: 13, total: 12, evidence_ref: "reports/coverage.json".into() };
    assert!(summarize_quality(&observation).is_err());
}

#[test]
fn unknown_upstream_kill_cannot_count_as_assertion_detection() {
    let mut observation = input();
    observation.mutation = measured_mutation(vec![
        outcome("unknown", MutationCategory::UpstreamKilledCauseUnclassified),
        outcome("survivor", MutationCategory::Survived),
    ], 1);
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.mutation.assertion_detected, 0);
    assert_eq!(result.mutation.denominator, 1);
    assert_eq!(result.mutation.detection_percent, Some(0.0));
    assert_eq!(result.mutation.state, QualityObservationState::Partial);
    assert_eq!(result.mutation.outcomes[0].upstream_label, "killed");
    assert_eq!(result.mutation.outcomes[0].evidence_ref, "reports/mutation.json");
    assert_eq!(result.state, QualityObservationState::Partial);
}

#[test]
fn excluded_outcomes_do_not_inflate_numerator_or_denominator() {
    let mut observation = input();
    observation.mutation = measured_mutation(vec![
        outcome("assertion", MutationCategory::AssertionDetected),
        outcome("uncovered", MutationCategory::Uncovered),
        outcome("invalid", MutationCategory::InvalidCompilation),
        outcome("timeout", MutationCategory::Timeout),
        outcome("infra", MutationCategory::InfrastructureFailure),
        outcome("not-run", MutationCategory::NotRun),
    ], 2);
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.mutation.assertion_detected, 1);
    assert_eq!(result.mutation.denominator, 2);
    assert_eq!(result.mutation.detection_percent, Some(50.0));
    assert_eq!(result.mutation.state, QualityObservationState::Partial);
    observation.mutation = measured_mutation(vec![outcome("invalid", MutationCategory::InvalidCompilation)], 1);
    assert!(summarize_quality(&observation).is_err());
}

#[test]
fn passing_baseline_is_required_for_effectiveness_percentage() {
    let mut observation = input();
    observation.mutation = MutationObservation::Measured {
        baseline_status: QualityExecutionStatus::Failed,
        outcomes: vec![outcome("assertion", MutationCategory::AssertionDetected)],
        declared_denominator: 1,
    };
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.mutation.detection_percent, None);
    assert_eq!(result.mutation.state, QualityObservationState::Unavailable);
    assert_eq!(result.state, QualityObservationState::Partial);
}

#[test]
fn partial_report_stays_partial_even_when_available_counts_are_perfect() {
    let mut observation = input();
    observation.report.completeness = ObservationCompleteness::Partial;
    observation.coverage = CoverageObservation::Measured { covered: 12, total: 12, evidence_ref: "reports/coverage.json".into() };
    let result = summarize_quality(&observation).unwrap();
    assert_eq!(result.coverage.percent, Some(100.0));
    assert_eq!(result.state, QualityObservationState::Partial);
}

#[test]
fn duplicate_mutation_and_cross_measurement_ids_are_rejected() {
    let mut observation = input();
    observation.mutation = measured_mutation(vec![outcome("same", MutationCategory::Survived), outcome("same", MutationCategory::Uncovered)], 2);
    assert!(summarize_quality(&observation).is_err());
    observation.mutation = measured_mutation(vec![outcome("same", MutationCategory::Survived)], 1);
    observation.duplication_candidates.push(DuplicationCandidate {
        id: "same".into(), first_path: "src/lib.rs".into(), second_path: "src/lib.rs".into(), evidence_ref: "reports/duplicates.json".into(),
    });
    assert!(summarize_quality(&observation).is_err());
}

#[test]
fn schema_and_input_trust_spoofs_are_rejected() {
    let mut observation = input();
    observation.schema_version = 2;
    assert!(summarize_quality(&observation).is_err());
    for (pointer, key, value) in [
        ("", "authoritative", json!(true)),
        ("/report", "origin", json!("native")),
        ("/coverage", "trusted", json!(true)),
    ] {
        let mut encoded = serde_json::to_value(input()).unwrap();
        encoded.pointer_mut(pointer).unwrap().as_object_mut().unwrap().insert(key.into(), value);
        assert!(serde_json::from_value::<QualityObservationInput>(encoded).is_err());
    }
    let mut encoded = serde_json::to_value(input()).unwrap();
    encoded["coverage"]["kind"] = Value::String("clean".into());
    assert!(serde_json::from_value::<QualityObservationInput>(encoded).is_err());
}

#[test]
fn threshold_is_scoped_policy_attention_and_missing_evidence_does_not_pass() {
    let mut observation = input();
    observation.thresholds = Some(ScopedQualityThresholds {
        paths: observation.subject.paths.clone(), min_coverage_percent: Some(80.0),
        min_mutation_detection_percent: None, max_duplication_candidates: None,
    });
    assert_eq!(summarize_quality(&observation).unwrap().state, QualityObservationState::PolicyAttention);
    observation.coverage = CoverageObservation::Unavailable { reason: "missing report".into() };
    assert_eq!(summarize_quality(&observation).unwrap().state, QualityObservationState::PolicyAttention);
    observation.thresholds.as_mut().unwrap().paths = vec!["other.rs".into()];
    assert!(summarize_quality(&observation).is_err());
}

#[test]
fn unsafe_paths_noncanonical_digests_and_excessive_counts_are_rejected() {
    let mut observation = input();
    observation.subject.paths = vec!["../escape.rs".into()];
    assert!(summarize_quality(&observation).is_err());
    observation = input();
    observation.report.evidence_ref = "C:\\report.json".into();
    assert!(summarize_quality(&observation).is_err());
    observation = input();
    observation.report.report_digest = "A".repeat(64);
    assert!(summarize_quality(&observation).is_err());
    observation = input();
    observation.coverage = CoverageObservation::Measured { covered: 0, total: 1_000_000_001, evidence_ref: "reports/coverage.json".into() };
    assert!(summarize_quality(&observation).is_err());
}

#[test]
fn imported_input_is_bounded_in_text_collections_and_aggregate_bytes() {
    let mut observation = input();
    observation.report.provider = "x".repeat(4097);
    assert!(summarize_quality(&observation).is_err());
    observation = input();
    observation.mutation = measured_mutation(vec![outcome("id", MutationCategory::NotRun); 10_001], 0);
    assert!(summarize_quality(&observation).is_err());
    observation = input();
    observation.report.provider = "x".repeat(MAX_QUALITY_OBSERVATION_BYTES + 1);
    assert!(summarize_quality(&observation).is_err());
}

fn fingerprint() -> QualityReuseFingerprint {
    QualityReuseFingerprint {
        source_digest: "a".repeat(64), tests_digest: "b".repeat(64), fixtures_digest: "c".repeat(64),
        toolchain_digest: "d".repeat(64), dependencies_digest: "e".repeat(64),
        command_digest: "f".repeat(64), config_digest: "0".repeat(64), environment_digest: "1".repeat(64),
    }
}

#[test]
fn changed_tests_and_every_other_fingerprint_input_invalidate_reuse() {
    let cached = fingerprint();
    let unchanged = quality_reuse_compatibility(&cached, &cached).unwrap();
    assert!(unchanged.reuse_permitted);
    assert!(!unchanged.verified);
    for field in ["sourceDigest", "testsDigest", "fixturesDigest", "toolchainDigest", "dependenciesDigest", "commandDigest", "configDigest", "environmentDigest"] {
        let mut encoded = serde_json::to_value(&cached).unwrap();
        encoded[field] = json!("2".repeat(64));
        let current = serde_json::from_value(encoded).unwrap();
        let result = quality_reuse_compatibility(&cached, &current).unwrap();
        assert!(!result.reuse_permitted, "{field}");
        assert!(!result.verified);
        assert_eq!(result.changed_inputs.len(), 1);
    }
}

#[test]
fn fixture_digest_binds_actual_raw_report_bytes() {
    use sha2::{Digest, Sha256};
    let raw = include_bytes!("fixtures/quality-observation/quality-raw-report.json");
    assert_eq!(input().report.report_digest, hex::encode(Sha256::digest(raw)));
}
