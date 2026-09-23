//! Integration tests for wf071's ported modules
//! (`legion_policy::wf_port::wf071::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! (if not already present from another wf packet) and `pub mod wf071;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (see the wf071 report).
//! Until then, the equivalent coverage lives as `#[cfg(test)]` unit tests
//! inside each `wf_port::wf071::*` submodule.

use legion_policy::wf_port::wf071::{
    calibration_convergence_scenario_facts, classify_calibration_drift, completion_integrated_state,
    converge_clarifications, dispose_frozen_review_finding, evaluate_calibration_convergence_case,
    path_matches, repository_relative, validate_calibration_convergence_observation,
    CalibrationConvergenceOutcome, CalibrationDriftInput, ClarificationQuestion,
    ConvergeClarificationsInput, DisposeFrozenReviewFindingInput, FrozenDecision, ReviewFinding,
    RuntimeMeasurement, TargetPublication,
};
use std::fs;
use std::process::Command;

// ---------------------------------------------------------------------
// calibration-convergence-policy.mjs
// ---------------------------------------------------------------------

#[test]
fn ae_control_plane_budgets_002_drift_failure() {
    let facts = calibration_convergence_scenario_facts("AE-CONTROL-PLANE-BUDGETS-002");
    assert!(facts.is_some());
    let outcome = evaluate_calibration_convergence_case("AE-CONTROL-PLANE-BUDGETS-002").unwrap();
    assert!(validate_calibration_convergence_observation("AE-CONTROL-PLANE-BUDGETS-002", &outcome));
    assert!(matches!(outcome, CalibrationConvergenceOutcome::DriftFailure { .. }));
}

#[test]
fn ae_convergence_001_resolve_one() {
    let outcome = evaluate_calibration_convergence_case("AE-CONVERGENCE-001").unwrap();
    assert!(validate_calibration_convergence_observation("AE-CONVERGENCE-001", &outcome));
    match outcome {
        CalibrationConvergenceOutcome::ResolveOne { active_question_id, deferred_question_ids, .. } => {
            assert_eq!(active_question_id, "q-blocker");
            assert_eq!(deferred_question_ids.len(), 4);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn ae_convergence_003_frozen_retained() {
    let outcome = evaluate_calibration_convergence_case("AE-CONVERGENCE-003").unwrap();
    assert!(validate_calibration_convergence_observation("AE-CONVERGENCE-003", &outcome));
    assert!(matches!(outcome, CalibrationConvergenceOutcome::FrozenRetained { .. }));
}

#[test]
fn classify_calibration_drift_incomplete_facts() {
    let outcome = classify_calibration_drift(&CalibrationDriftInput::default());
    assert!(matches!(outcome, CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }));
}

#[test]
fn converge_clarifications_incomplete_facts() {
    let outcome = converge_clarifications(&ConvergeClarificationsInput::default());
    assert!(matches!(outcome, CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }));
}

#[test]
fn converge_clarifications_multiple_blockers_reported() {
    let input = ConvergeClarificationsInput {
        slice_id: Some("slice".into()),
        questions: Some(vec![
            ClarificationQuestion { id: "q1".into(), blocks_current_slice: true },
            ClarificationQuestion { id: "q2".into(), blocks_current_slice: true },
            ClarificationQuestion { id: "q3".into(), blocks_current_slice: false },
        ]),
    };
    match converge_clarifications(&input) {
        CalibrationConvergenceOutcome::MultipleBlockingQuestions { blocking_question_ids, deferred_question_ids, .. } => {
            assert_eq!(blocking_question_ids, vec!["q1".to_string(), "q2".to_string()]);
            assert_eq!(deferred_question_ids, vec!["q3".to_string()]);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn dispose_frozen_review_finding_incomplete_facts() {
    let outcome = dispose_frozen_review_finding(&DisposeFrozenReviewFindingInput::default());
    assert!(matches!(outcome, CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }));
}

#[test]
fn dispose_frozen_review_finding_not_frozen() {
    let input = DisposeFrozenReviewFindingInput {
        decision: Some(FrozenDecision { id: "D-9".into(), status: Some("DRAFT".into()) }),
        finding: Some(ReviewFinding { id: "f".into(), kind: "IMPROVEMENT".into(), invalidates_decision: false }),
    };
    match dispose_frozen_review_finding(&input) {
        CalibrationConvergenceOutcome::DecisionNotFrozen { decision_id, status } => {
            assert_eq!(decision_id, "D-9");
            assert_eq!(status.as_deref(), Some("DRAFT"));
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn calibration_drift_publication_target_gate() {
    let base = RuntimeMeasurement {
        metric: Some("retry_threshold".into()),
        value: Some(3.0),
        domain: Some("retry".into()),
        observation_id: None,
    };
    let recorded = classify_calibration_drift(&CalibrationDriftInput {
        measurement: Some(base.clone()),
        publication: Some(TargetPublication { target: Some("CALIBRATION_TABLE".into()) }),
    });
    assert!(matches!(recorded, CalibrationConvergenceOutcome::CalibrationRecorded { .. }));

    let rejected = classify_calibration_drift(&CalibrationDriftInput {
        measurement: Some(base),
        publication: Some(TargetPublication { target: Some("PERMANENT_CANON".into()) }),
    });
    assert!(matches!(rejected, CalibrationConvergenceOutcome::DriftFailure { .. }));
}

// ---------------------------------------------------------------------
// completion-state.mjs
// ---------------------------------------------------------------------

#[test]
fn path_matches_double_star_prefix_and_suffix() {
    assert!(path_matches("docs/**", "docs/a/b/c.md"));
    assert!(!path_matches("docs/**", "other/a.md"));
    assert!(path_matches("**/*.rs", "engine/crates/foo/src/lib.rs"));
}

#[test]
fn repository_relative_rejects_dotdot_segment_relative_input() {
    let dir = std::env::temp_dir().join(format!("legion-wf071-int-esc-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(repository_relative("../outside", &dir), None);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn completion_integrated_state_none_outside_git_repo() {
    let dir = std::env::temp_dir().join(format!("legion-wf071-int-nogit-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // Not a git repository: `git rev-parse --show-toplevel` fails, so the
    // JS `completionIntegratedState` catches and returns null.
    assert_eq!(completion_integrated_state(&dir, &[]), None);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn completion_integrated_state_end_to_end_fixture_repo() {
    let dir = std::env::temp_dir().join(format!("legion-wf071-int-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        assert!(Command::new("git").args(args).current_dir(&dir).status().unwrap().success());
    };
    run(&["init", "-q"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Test"]);
    fs::write(dir.join("tracked.txt"), "v1\n").unwrap();
    run(&["add", "tracked.txt"]);
    run(&["commit", "-q", "-m", "init"]);

    let clean = completion_integrated_state(&dir, &[]);
    assert!(clean.as_deref().is_some_and(|s| s.starts_with("git:")));

    fs::write(dir.join("tracked.txt"), "v2\n").unwrap();
    let dirty = completion_integrated_state(&dir, &[]);
    assert_ne!(clean, dirty);

    fs::remove_dir_all(&dir).ok();
}
