//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-concurrency-convergence.mjs`.
//!
//! Two of five cases (`AE-CONCURRENCY-ATTENTION-002`,
//! `AE-CONCURRENCY-ATTENTION-006`) call `scheduleProviders` from
//! `src/lib/core/scheduler.mjs`, which has no Rust port in `engine/`
//! (`git grep -l schedule_providers -- 'engine/**/*.rs'`: no hits) and is
//! not an owned wf074 file. Faking scheduler output here would silently
//! diverge from the real scheduler the first time either side changes, so
//! those two are ported as `BlockedOnDependency`, not simulated. The
//! remaining three cases are unconditionally PENDING in the JS source (no
//! dependency call at all) and are ported in full, including their
//! `family` derivation and observation validator.

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
    Pending {
        id: &'static str,
        family: &'static str,
        reason: &'static str,
    },
    UnknownCase,
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
        "AE-CONCURRENCY-ATTENTION-002" | "AE-CONCURRENCY-ATTENTION-006" => {
            ConcurrencyConvergenceResult::BlockedOnDependency {
                id: IDS.iter().find(|&&i| i == id).copied().unwrap(),
                dependency: "scheduleProviders (src/lib/core/scheduler.mjs) has no Rust port",
            }
        }
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

/// Ported directly: neither reachable variant here is a PASS/FAIL
/// observation, so this always returns `false`, matching what
/// `validateConcurrencyConvergenceObservation` would return for any
/// PENDING-shaped `observed` value.
pub fn validate_concurrency_convergence_observation(_result: &ConcurrencyConvergenceResult) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_002_and_006_are_blocked_not_faked() {
        assert!(matches!(
            execute_concurrency_convergence_case("AE-CONCURRENCY-ATTENTION-002"),
            ConcurrencyConvergenceResult::BlockedOnDependency { .. }
        ));
        assert!(matches!(
            execute_concurrency_convergence_case("AE-CONCURRENCY-ATTENTION-006"),
            ConcurrencyConvergenceResult::BlockedOnDependency { .. }
        ));
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
    fn validator_rejects_every_currently_producible_result() {
        for id in IDS {
            let r = execute_concurrency_convergence_case(id);
            assert!(!validate_concurrency_convergence_observation(&r));
        }
    }

    #[test]
    fn id_list_has_five_entries() {
        assert_eq!(concurrency_convergence_binding_ids().len(), 5);
    }
}
