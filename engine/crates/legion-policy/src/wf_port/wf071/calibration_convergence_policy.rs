//! Rust port of `src/lib/verification/arcane/calibration-convergence-policy.mjs`.
//!
//! Executable policy for runtime calibration & convergent clarification.
//! Inputs are structured facts; corpus prose & `expect` values never enter
//! here. Faithful, 1:1 port of the JS: same status/code strings, same field
//! names (kept in JS `snake_case` spelling to match the original output
//! shape byte-for-byte), same validation order, same S11 fixed facts table.

use std::collections::BTreeMap;

/// `{ status: 'PENDING', code, detail }` outcome shape used for both the
/// invalid-input rejection and (for `convergeClarifications`) the
/// no-single-blocker case.
#[derive(Debug, Clone, PartialEq)]
pub enum CalibrationConvergenceOutcome {
    /// `classifyCalibrationDrift` / `convergeClarifications` /
    /// `disposeFrozenReviewFinding` input validation failure.
    PolicyFactsIncomplete { required: Vec<&'static str> },
    /// `classifyCalibrationDrift`: publication.target === 'PERMANENT_CANON'.
    DriftFailure { calibration: Calibration },
    /// `classifyCalibrationDrift`: publication.target === 'CALIBRATION_TABLE'.
    CalibrationRecorded { calibration: Calibration },
    /// `convergeClarifications`: not exactly one blocking question.
    NoBlockingQuestion {
        slice_id: String,
        blocking_question_ids: Vec<String>,
        deferred_question_ids: Vec<String>,
    },
    MultipleBlockingQuestions {
        slice_id: String,
        blocking_question_ids: Vec<String>,
        deferred_question_ids: Vec<String>,
    },
    /// `convergeClarifications`: exactly one blocking question.
    ResolveOne {
        slice_id: String,
        active_question_id: String,
        deferred_question_ids: Vec<String>,
    },
    /// `disposeFrozenReviewFinding`: decision.status !== 'FROZEN'.
    DecisionNotFrozen {
        decision_id: String,
        status: Option<String>,
    },
    /// `disposeFrozenReviewFinding`: finding invalidates the decision.
    ReopenRequired {
        decision_id: String,
        finding_id: String,
    },
    /// `disposeFrozenReviewFinding`: non-falsifying improvement retained.
    FrozenRetained {
        decision_id: String,
        finding_id: String,
        finding_kind: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Calibration {
    pub metric: String,
    pub value: f64,
    pub domain: String,
    pub observation_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeMeasurement {
    pub metric: Option<String>,
    pub value: Option<f64>,
    pub domain: Option<String>,
    pub observation_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TargetPublication {
    pub target: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CalibrationDriftInput {
    pub measurement: Option<RuntimeMeasurement>,
    pub publication: Option<TargetPublication>,
}

/// Runtime measurements can inform a calibration table, but cannot turn into
/// permanent doctrine merely by being observed during a retry or scheduling
/// run.
pub fn classify_calibration_drift(input: &CalibrationDriftInput) -> CalibrationConvergenceOutcome {
    let measurement = match &input.measurement {
        Some(m)
            if m.metric.as_deref().is_some_and(|s| !s.is_empty())
                && m.value.is_some_and(|v| v.is_finite() && v >= 0.0)
                && matches!(m.domain.as_deref(), Some("retry") | Some("concurrency")) =>
        {
            m
        }
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec!["measurement.metric", "measurement.value", "measurement.domain"],
            }
        }
    };
    let publication = match &input.publication {
        Some(p) if matches!(p.target.as_deref(), Some("CALIBRATION_TABLE") | Some("PERMANENT_CANON")) => p,
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec!["publication.target"],
            }
        }
    };

    let calibration = Calibration {
        metric: measurement.metric.clone().unwrap(),
        value: measurement.value.unwrap(),
        domain: measurement.domain.clone().unwrap(),
        observation_id: measurement.observation_id.clone(),
    };

    if publication.target.as_deref() == Some("PERMANENT_CANON") {
        CalibrationConvergenceOutcome::DriftFailure { calibration }
    } else {
        CalibrationConvergenceOutcome::CalibrationRecorded { calibration }
    }
}

#[derive(Debug, Clone)]
pub struct ClarificationQuestion {
    pub id: String,
    pub blocks_current_slice: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ConvergeClarificationsInput {
    pub slice_id: Option<String>,
    pub questions: Option<Vec<ClarificationQuestion>>,
}

/// Resolve only questions that block current slice; preserve all others for
/// later.
pub fn converge_clarifications(input: &ConvergeClarificationsInput) -> CalibrationConvergenceOutcome {
    let slice_id = match &input.slice_id {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec!["slice_id", "questions[].id", "questions[].blocks_current_slice"],
            }
        }
    };
    let questions = match &input.questions {
        Some(q) if !q.is_empty() && q.iter().all(|question| !question.id.is_empty()) => q,
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec!["slice_id", "questions[].id", "questions[].blocks_current_slice"],
            }
        }
    };

    let blockers: Vec<&ClarificationQuestion> =
        questions.iter().filter(|q| q.blocks_current_slice).collect();
    let deferred: Vec<String> = questions
        .iter()
        .filter(|q| !q.blocks_current_slice)
        .map(|q| q.id.clone())
        .collect();

    if blockers.len() != 1 {
        let blocking_question_ids: Vec<String> = blockers.iter().map(|q| q.id.clone()).collect();
        return if blockers.is_empty() {
            CalibrationConvergenceOutcome::NoBlockingQuestion {
                slice_id,
                blocking_question_ids,
                deferred_question_ids: deferred,
            }
        } else {
            CalibrationConvergenceOutcome::MultipleBlockingQuestions {
                slice_id,
                blocking_question_ids,
                deferred_question_ids: deferred,
            }
        };
    }

    CalibrationConvergenceOutcome::ResolveOne {
        slice_id,
        active_question_id: blockers[0].id.clone(),
        deferred_question_ids: deferred,
    }
}

#[derive(Debug, Clone)]
pub struct FrozenDecision {
    pub id: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReviewFinding {
    pub id: String,
    pub kind: String,
    pub invalidates_decision: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DisposeFrozenReviewFindingInput {
    pub decision: Option<FrozenDecision>,
    pub finding: Option<ReviewFinding>,
}

/// A non-falsifying improvement after freeze is retained as future work
/// only.
pub fn dispose_frozen_review_finding(
    input: &DisposeFrozenReviewFindingInput,
) -> CalibrationConvergenceOutcome {
    let decision = match &input.decision {
        Some(d) if !d.id.is_empty() => d,
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec![
                    "decision.id",
                    "decision.status",
                    "finding.id",
                    "finding.kind",
                    "finding.invalidates_decision",
                ],
            }
        }
    };
    let finding = match &input.finding {
        Some(f) if !f.id.is_empty() && matches!(f.kind.as_str(), "IMPROVEMENT" | "FAILURE") => f,
        _ => {
            return CalibrationConvergenceOutcome::PolicyFactsIncomplete {
                required: vec![
                    "decision.id",
                    "decision.status",
                    "finding.id",
                    "finding.kind",
                    "finding.invalidates_decision",
                ],
            }
        }
    };

    if decision.status.as_deref() != Some("FROZEN") {
        return CalibrationConvergenceOutcome::DecisionNotFrozen {
            decision_id: decision.id.clone(),
            status: decision.status.clone(),
        };
    }

    if finding.invalidates_decision || finding.kind == "FAILURE" {
        return CalibrationConvergenceOutcome::ReopenRequired {
            decision_id: decision.id.clone(),
            finding_id: finding.id.clone(),
        };
    }

    CalibrationConvergenceOutcome::FrozenRetained {
        decision_id: decision.id.clone(),
        finding_id: finding.id.clone(),
        finding_kind: finding.kind.clone(),
    }
}

/// The fixed S11 scenario facts table (`S11_FACTS` in the JS). Kept as a
/// function returning fresh owned values each call (the JS `Object.freeze`s
/// module-level constants; Rust has no shared runtime frozen singleton
/// requirement here, so we rebuild on each lookup).
pub fn calibration_convergence_scenario_facts(id: &str) -> Option<ScenarioFacts> {
    let mut table: BTreeMap<&'static str, ScenarioFacts> = BTreeMap::new();
    table.insert(
        "AE-CONTROL-PLANE-BUDGETS-002",
        ScenarioFacts::Drift(CalibrationDriftInput {
            measurement: Some(RuntimeMeasurement {
                metric: Some("retry_threshold".to_string()),
                value: Some(3.0),
                domain: Some("retry".to_string()),
                observation_id: Some("runtime-retry-17".to_string()),
            }),
            publication: Some(TargetPublication {
                target: Some("PERMANENT_CANON".to_string()),
            }),
        }),
    );
    table.insert(
        "AE-CONVERGENCE-001",
        ScenarioFacts::Converge(ConvergeClarificationsInput {
            slice_id: Some("s11-current-slice".to_string()),
            questions: Some(vec![
                ClarificationQuestion { id: "q-blocker".to_string(), blocks_current_slice: true },
                ClarificationQuestion { id: "q-later-1".to_string(), blocks_current_slice: false },
                ClarificationQuestion { id: "q-later-2".to_string(), blocks_current_slice: false },
                ClarificationQuestion { id: "q-later-3".to_string(), blocks_current_slice: false },
                ClarificationQuestion { id: "q-later-4".to_string(), blocks_current_slice: false },
            ]),
        }),
    );
    table.insert(
        "AE-CONVERGENCE-003",
        ScenarioFacts::Dispose(DisposeFrozenReviewFindingInput {
            decision: Some(FrozenDecision { id: "D-3".to_string(), status: Some("FROZEN".to_string()) }),
            finding: Some(ReviewFinding {
                id: "review-opportunity-1".to_string(),
                kind: "IMPROVEMENT".to_string(),
                invalidates_decision: false,
            }),
        }),
    );
    table.get(id).cloned()
}

#[derive(Debug, Clone)]
pub enum ScenarioFacts {
    Drift(CalibrationDriftInput),
    Converge(ConvergeClarificationsInput),
    Dispose(DisposeFrozenReviewFindingInput),
}

/// Executor adapter: case identity selects facts; disposition comes only
/// from policy.
pub fn evaluate_calibration_convergence_case(id: &str) -> Option<CalibrationConvergenceOutcome> {
    let facts = calibration_convergence_scenario_facts(id)?;
    Some(match facts {
        ScenarioFacts::Drift(input) => classify_calibration_drift(&input),
        ScenarioFacts::Converge(input) => converge_clarifications(&input),
        ScenarioFacts::Dispose(input) => dispose_frozen_review_finding(&input),
    })
}

/// Faithful port of `validateCalibrationConvergenceObservation`.
pub fn validate_calibration_convergence_observation(
    id: &str,
    value: &CalibrationConvergenceOutcome,
) -> bool {
    match id {
        "AE-CONTROL-PLANE-BUDGETS-002" => {
            matches!(value, CalibrationConvergenceOutcome::DriftFailure { .. })
        }
        "AE-CONVERGENCE-001" => matches!(
            value,
            CalibrationConvergenceOutcome::ResolveOne { deferred_question_ids, .. }
                if deferred_question_ids.len() == 4
        ),
        "AE-CONVERGENCE-003" => matches!(
            value,
            CalibrationConvergenceOutcome::FrozenRetained { .. }
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_calibration_drift_rejects_missing_measurement() {
        let outcome = classify_calibration_drift(&CalibrationDriftInput::default());
        assert!(matches!(
            outcome,
            CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }
        ));
    }

    #[test]
    fn classify_calibration_drift_rejects_bad_domain() {
        let input = CalibrationDriftInput {
            measurement: Some(RuntimeMeasurement {
                metric: Some("x".into()),
                value: Some(1.0),
                domain: Some("other".into()),
                observation_id: None,
            }),
            publication: Some(TargetPublication { target: Some("CALIBRATION_TABLE".into()) }),
        };
        assert!(matches!(
            classify_calibration_drift(&input),
            CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }
        ));
    }

    #[test]
    fn classify_calibration_drift_rejects_negative_value() {
        let input = CalibrationDriftInput {
            measurement: Some(RuntimeMeasurement {
                metric: Some("x".into()),
                value: Some(-1.0),
                domain: Some("retry".into()),
                observation_id: None,
            }),
            publication: Some(TargetPublication { target: Some("CALIBRATION_TABLE".into()) }),
        };
        assert!(matches!(
            classify_calibration_drift(&input),
            CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }
        ));
    }

    #[test]
    fn classify_calibration_drift_permanent_canon_rejected() {
        let input = CalibrationDriftInput {
            measurement: Some(RuntimeMeasurement {
                metric: Some("retry_threshold".into()),
                value: Some(3.0),
                domain: Some("retry".into()),
                observation_id: Some("runtime-retry-17".into()),
            }),
            publication: Some(TargetPublication { target: Some("PERMANENT_CANON".into()) }),
        };
        match classify_calibration_drift(&input) {
            CalibrationConvergenceOutcome::DriftFailure { calibration } => {
                assert_eq!(calibration.metric, "retry_threshold");
                assert_eq!(calibration.value, 3.0);
                assert_eq!(calibration.domain, "retry");
                assert_eq!(calibration.observation_id.as_deref(), Some("runtime-retry-17"));
            }
            other => panic!("expected DriftFailure, got {other:?}"),
        }
    }

    #[test]
    fn classify_calibration_drift_calibration_table_accepted() {
        let input = CalibrationDriftInput {
            measurement: Some(RuntimeMeasurement {
                metric: Some("concurrency_cap".into()),
                value: Some(5.0),
                domain: Some("concurrency".into()),
                observation_id: None,
            }),
            publication: Some(TargetPublication { target: Some("CALIBRATION_TABLE".into()) }),
        };
        assert!(matches!(
            classify_calibration_drift(&input),
            CalibrationConvergenceOutcome::CalibrationRecorded { .. }
        ));
    }

    #[test]
    fn converge_clarifications_rejects_empty_questions() {
        let input = ConvergeClarificationsInput {
            slice_id: Some("slice".into()),
            questions: Some(vec![]),
        };
        assert!(matches!(
            converge_clarifications(&input),
            CalibrationConvergenceOutcome::PolicyFactsIncomplete { .. }
        ));
    }

    #[test]
    fn converge_clarifications_no_blocker() {
        let input = ConvergeClarificationsInput {
            slice_id: Some("slice".into()),
            questions: Some(vec![ClarificationQuestion {
                id: "q1".into(),
                blocks_current_slice: false,
            }]),
        };
        match converge_clarifications(&input) {
            CalibrationConvergenceOutcome::NoBlockingQuestion { deferred_question_ids, .. } => {
                assert_eq!(deferred_question_ids, vec!["q1".to_string()]);
            }
            other => panic!("expected NoBlockingQuestion, got {other:?}"),
        }
    }

    #[test]
    fn converge_clarifications_multiple_blockers() {
        let input = ConvergeClarificationsInput {
            slice_id: Some("slice".into()),
            questions: Some(vec![
                ClarificationQuestion { id: "q1".into(), blocks_current_slice: true },
                ClarificationQuestion { id: "q2".into(), blocks_current_slice: true },
            ]),
        };
        assert!(matches!(
            converge_clarifications(&input),
            CalibrationConvergenceOutcome::MultipleBlockingQuestions { .. }
        ));
    }

    #[test]
    fn converge_clarifications_resolve_one() {
        let input = ConvergeClarificationsInput {
            slice_id: Some("slice".into()),
            questions: Some(vec![
                ClarificationQuestion { id: "q1".into(), blocks_current_slice: true },
                ClarificationQuestion { id: "q2".into(), blocks_current_slice: false },
            ]),
        };
        match converge_clarifications(&input) {
            CalibrationConvergenceOutcome::ResolveOne { active_question_id, deferred_question_ids, .. } => {
                assert_eq!(active_question_id, "q1");
                assert_eq!(deferred_question_ids, vec!["q2".to_string()]);
            }
            other => panic!("expected ResolveOne, got {other:?}"),
        }
    }

    #[test]
    fn dispose_frozen_review_finding_rejects_non_frozen_decision() {
        let input = DisposeFrozenReviewFindingInput {
            decision: Some(FrozenDecision { id: "D-1".into(), status: Some("DRAFT".into()) }),
            finding: Some(ReviewFinding {
                id: "f1".into(),
                kind: "IMPROVEMENT".into(),
                invalidates_decision: false,
            }),
        };
        assert!(matches!(
            dispose_frozen_review_finding(&input),
            CalibrationConvergenceOutcome::DecisionNotFrozen { .. }
        ));
    }

    #[test]
    fn dispose_frozen_review_finding_reopen_on_failure() {
        let input = DisposeFrozenReviewFindingInput {
            decision: Some(FrozenDecision { id: "D-1".into(), status: Some("FROZEN".into()) }),
            finding: Some(ReviewFinding {
                id: "f1".into(),
                kind: "FAILURE".into(),
                invalidates_decision: false,
            }),
        };
        assert!(matches!(
            dispose_frozen_review_finding(&input),
            CalibrationConvergenceOutcome::ReopenRequired { .. }
        ));
    }

    #[test]
    fn dispose_frozen_review_finding_reopen_when_invalidates() {
        let input = DisposeFrozenReviewFindingInput {
            decision: Some(FrozenDecision { id: "D-1".into(), status: Some("FROZEN".into()) }),
            finding: Some(ReviewFinding {
                id: "f1".into(),
                kind: "IMPROVEMENT".into(),
                invalidates_decision: true,
            }),
        };
        assert!(matches!(
            dispose_frozen_review_finding(&input),
            CalibrationConvergenceOutcome::ReopenRequired { .. }
        ));
    }

    #[test]
    fn dispose_frozen_review_finding_retained() {
        let input = DisposeFrozenReviewFindingInput {
            decision: Some(FrozenDecision { id: "D-1".into(), status: Some("FROZEN".into()) }),
            finding: Some(ReviewFinding {
                id: "f1".into(),
                kind: "IMPROVEMENT".into(),
                invalidates_decision: false,
            }),
        };
        assert!(matches!(
            dispose_frozen_review_finding(&input),
            CalibrationConvergenceOutcome::FrozenRetained { .. }
        ));
    }

    #[test]
    fn s11_scenarios_match_js_fixed_table() {
        let a = evaluate_calibration_convergence_case("AE-CONTROL-PLANE-BUDGETS-002").unwrap();
        assert!(validate_calibration_convergence_observation("AE-CONTROL-PLANE-BUDGETS-002", &a));

        let b = evaluate_calibration_convergence_case("AE-CONVERGENCE-001").unwrap();
        assert!(validate_calibration_convergence_observation("AE-CONVERGENCE-001", &b));

        let c = evaluate_calibration_convergence_case("AE-CONVERGENCE-003").unwrap();
        assert!(validate_calibration_convergence_observation("AE-CONVERGENCE-003", &c));
    }

    #[test]
    fn unknown_scenario_id_returns_none() {
        assert!(evaluate_calibration_convergence_case("unknown").is_none());
    }
}
