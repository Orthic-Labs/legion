//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-concurrency-convergence.mjs`.
//!
//! Two of five cases (`AE-CONCURRENCY-ATTENTION-002`,
//! `AE-CONCURRENCY-ATTENTION-006`) call `scheduleProviders` from
//! `src/lib/core/scheduler.mjs`. Packet R64 ported that module in full at
//! [`crate::wf_port::r64::scheduler`] (it has no Rust port anywhere else
//! and is not an owned wf074 file, but porting a small pure-logic sibling
//! to close a partial port's gap is exactly what R64's mandate calls for —
//! see that module's doc comment). Both cases now run the real scheduler
//! against the exact fixtures the JS source builds inline
//! (`rejectWholeStageBarrier`/`admitIndependentReadyWork`) via
//! [`ConcurrencyConvergenceResult::Observed`], instead of reporting
//! `BlockedOnDependency`. The remaining three cases are unconditionally
//! PENDING in the JS source (no dependency call at all) and were already
//! ported in full, including their `family` derivation.

use crate::wf_port::r64::scheduler::{schedule_providers, Provider, ScheduleOptions};
use std::collections::BTreeMap;

pub const IDS: &[&str] = &[
    "AE-CONCURRENCY-ATTENTION-002",
    "AE-CONCURRENCY-ATTENTION-006",
    "AE-CONTROL-PLANE-BUDGETS-002",
    "AE-CONVERGENCE-001",
    "AE-CONVERGENCE-003",
];

pub fn concurrency_convergence_binding_ids() -> &'static [&'static str] {
    IDS
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConcurrencyConvergenceResult {
    BlockedOnDependency {
        id: &'static str,
        dependency: &'static str,
    },
    /// Mirrors JS `rejectWholeStageBarrier`/`admitIndependentReadyWork`'s
    /// `observation(id, producer, consumer, value)` return shape, `value`
    /// flattened into `outcome`/`waves`/`consumed_artifacts`/`admitted`/
    /// `ready`/`blocked`.
    Observed {
        id: &'static str,
        outcome: &'static str,
        waves: Vec<Vec<String>>,
        consumed_artifacts: Vec<String>,
        admitted: Vec<String>,
        ready: Vec<String>,
        blocked: Vec<String>,
    },
    Pending {
        id: &'static str,
        family: &'static str,
        reason: &'static str,
    },
    UnknownCase,
}

/// Mirrors JS `rejectWholeStageBarrier()`. Dependencies are the only
/// scheduler barrier: disjoint tasks have no consumed artifacts, so a
/// common stage label must not serialize them.
fn reject_whole_stage_barrier() -> ConcurrencyConvergenceResult {
    let providers = vec![
        Provider::new("author-a"),
        Provider::new("fixture-b"),
    ];
    let result = schedule_providers(&providers, &ScheduleOptions { concurrency: 2, ..Default::default() })
        .expect("fixture providers have no unknown dependencies or cycles");
    let outcome = if result.waves.len() == 1 && result.waves[0].len() == 2 { "PARALLEL_ADMITTED" } else { "BARRIER_REJECTED" };
    ConcurrencyConvergenceResult::Observed {
        id: "AE-CONCURRENCY-ATTENTION-002",
        outcome,
        waves: result.waves,
        consumed_artifacts: vec![],
        admitted: vec![],
        ready: vec![],
        blocked: vec![],
    }
}

/// Mirrors JS `admitIndependentReadyWork()`.
fn admit_independent_ready_work() -> ConcurrencyConvergenceResult {
    let providers = vec![
        Provider::new("task-a").with_resources([("cpu", 1.0)]),
        Provider::new("task-b").with_resources([("cpu", 1.0)]),
        Provider::new("task-c").with_resources([("cpu", 1.0)]),
    ];
    let mut resources = BTreeMap::new();
    resources.insert("cpu".to_string(), 2.0);
    let result = schedule_providers(
        &providers,
        &ScheduleOptions { concurrency: 2, resources: Some(resources), ..Default::default() },
    )
    .expect("fixture providers have no unknown dependencies or cycles");
    let outcome = if result.admitted.len() == 2 { "INDEPENDENT_READY_WORK_ADMITTED" } else { "CAPACITY_NOT_ADMITTED" };
    ConcurrencyConvergenceResult::Observed {
        id: "AE-CONCURRENCY-ATTENTION-006",
        outcome,
        waves: result.waves,
        consumed_artifacts: vec![],
        admitted: result.admitted,
        ready: result.ready,
        blocked: result.blocked.into_iter().map(|b| b.id).collect(),
    }
}

/// Mirrors the JS `family` derivation inline in `executeConcurrencyConvergenceCase`.
fn family_for(id: &str) -> &'static str {
    if id.starts_with("AE-CONCURRENCY") {
        "concurrency-attention"
    } else if id.starts_with("AE-CONTROL") {
        "control-plane-budgets"
    } else {
        "convergence"
    }
}

pub fn execute_concurrency_convergence_case(id: &str) -> ConcurrencyConvergenceResult {
    match id {
        "AE-CONCURRENCY-ATTENTION-002" => reject_whole_stage_barrier(),
        "AE-CONCURRENCY-ATTENTION-006" => admit_independent_ready_work(),
        "AE-CONTROL-PLANE-BUDGETS-002" => ConcurrencyConvergenceResult::Pending {
            id: "AE-CONTROL-PLANE-BUDGETS-002",
            family: family_for(id),
            reason: "requires authenticated calibration authority to distinguish doctrine drift",
        },
        "AE-CONVERGENCE-001" => ConcurrencyConvergenceResult::Pending {
            id: "AE-CONVERGENCE-001",
            family: family_for(id),
            reason: "clarification priority requires Sage judgment",
        },
        "AE-CONVERGENCE-003" => ConcurrencyConvergenceResult::Pending {
            id: "AE-CONVERGENCE-003",
            family: family_for(id),
            reason: "post-freeze opportunity disposition requires authenticated review judgment",
        },
        _ => ConcurrencyConvergenceResult::UnknownCase,
    }
}

/// Mirrors JS `validateConcurrencyConvergenceObservation(id, observed)`.
/// `Pending`/`UnknownCase`/`BlockedOnDependency` are never PASS/FAIL
/// observations, so they fall through to `false`, matching the JS
/// validator for any non-matching `id`/shape.
pub fn validate_concurrency_convergence_observation(result: &ConcurrencyConvergenceResult) -> bool {
    match result {
        ConcurrencyConvergenceResult::Observed { id: "AE-CONCURRENCY-ATTENTION-002", outcome, waves, consumed_artifacts, .. } => {
            *outcome == "PARALLEL_ADMITTED" && waves.len() == 1 && waves[0].len() == 2 && consumed_artifacts.is_empty()
        }
        ConcurrencyConvergenceResult::Observed { id: "AE-CONCURRENCY-ATTENTION-006", outcome, admitted, ready, blocked, .. } => {
            *outcome == "INDEPENDENT_READY_WORK_ADMITTED" && admitted.len() == 2 && ready.len() == 1 && blocked.is_empty()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_002_and_006_now_run_the_real_scheduler() {
        let r002 = execute_concurrency_convergence_case("AE-CONCURRENCY-ATTENTION-002");
        assert!(validate_concurrency_convergence_observation(&r002));
        let r006 = execute_concurrency_convergence_case("AE-CONCURRENCY-ATTENTION-006");
        assert!(validate_concurrency_convergence_observation(&r006));
    }

    #[test]
    fn control_plane_budgets_002_is_pending_with_family() {
        let r = execute_concurrency_convergence_case("AE-CONTROL-PLANE-BUDGETS-002");
        match r {
            ConcurrencyConvergenceResult::Pending { family, reason, .. } => {
                assert_eq!(family, "control-plane-budgets");
                assert!(reason.contains("calibration authority"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn convergence_001_and_003_use_convergence_family() {
        for id in ["AE-CONVERGENCE-001", "AE-CONVERGENCE-003"] {
            match execute_concurrency_convergence_case(id) {
                ConcurrencyConvergenceResult::Pending { family, .. } => assert_eq!(family, "convergence"),
                other => panic!("{id}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_id_is_unknown_case() {
        assert!(matches!(
            execute_concurrency_convergence_case("AE-NOPE"),
            ConcurrencyConvergenceResult::UnknownCase
        ));
    }

    #[test]
    fn validator_accepts_the_two_scheduler_backed_cases_and_rejects_pending() {
        for id in IDS {
            let r = execute_concurrency_convergence_case(id);
            let expect_valid = matches!(id, &"AE-CONCURRENCY-ATTENTION-002" | &"AE-CONCURRENCY-ATTENTION-006");
            assert_eq!(validate_concurrency_convergence_observation(&r), expect_valid, "{id}");
        }
    }

    #[test]
    fn id_list_has_five_entries() {
        assert_eq!(concurrency_convergence_binding_ids().len(), 5);
    }
}
