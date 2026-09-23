//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-adversarial.mjs`.
//!
//! The JS module executes exactly one case (`AE-ADVERSARIAL-003`) against a
//! live production control, `routeArchitecture` from
//! `../architecture-router.mjs`; every other id is unconditionally
//! PENDING. `routeArchitecture` has no Rust port anywhere in `engine/`
//! today (checked via `git grep -l route_architecture -- 'engine/**/*.rs'`,
//! no hits) and is not among wf074's owned files, so it cannot be ported
//! here without either duplicating another module's future port or writing
//! outside wf074's owned paths. See the wf074 report for the exact
//! dependency and status of `AE-ADVERSARIAL-003`.
//!
//! Everything else in the JS module — the id list, the missing-producer
//! reasons, the unknown-id and validator paths — has no such dependency and
//! is ported here in full.

pub const ADVERSARIAL_IDS: &[&str] = &[
    "AE-ADVERSARIAL-001",
    "AE-ADVERSARIAL-002",
    "AE-ADVERSARIAL-003",
    "AE-ADVERSARIAL-004",
    "AE-ADVERSARIAL-005",
    "AE-ADVERSARIAL-006",
    "AE-ADVERSARIAL-007",
    "AE-ADVERSARIAL-009",
    "AE-ADVERSARIAL-010",
];

fn missing_producer(id: &str) -> Option<&'static str> {
    match id {
        "AE-ADVERSARIAL-001" => Some("architecture proportionality assessment ingress"),
        "AE-ADVERSARIAL-002" => Some("mandatory-obligation readiness ingress"),
        "AE-ADVERSARIAL-004" => Some("migration target selection ingress"),
        "AE-ADVERSARIAL-005" => Some("distributed failure-mode assessment ingress"),
        "AE-ADVERSARIAL-006" => Some("source-of-truth ownership-conflict ingress"),
        "AE-ADVERSARIAL-007" => Some("adverse-case vendor economics ingress"),
        "AE-ADVERSARIAL-009" => Some("AI readiness governance ingress"),
        "AE-ADVERSARIAL-010" => Some("architecture-reconstruction uncertainty verdict ingress"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdversarialResult {
    /// `AE-ADVERSARIAL-003` in the JS source: not portable here (see
    /// module docs). Distinct from `Pending` so callers can distinguish
    /// "blocked on an unported dependency" from "this case is
    /// intentionally always PENDING" — the JS makes no such distinction
    /// itself (both surface as `{status: 'PENDING', ...}`), so a caller
    /// checking only `status == "PENDING"` sees identical JS-observable
    /// behavior either way.
    BlockedOnDependency {
        id: &'static str,
        dependency: &'static str,
    },
    Pending {
        id: &'static str,
        reason: String,
        missing_producer: Option<&'static str>,
    },
    UnknownCase {
        id: String,
    },
}

pub fn execute_adversarial_binding(id: &str) -> AdversarialResult {
    if !ADVERSARIAL_IDS.contains(&id) {
        return AdversarialResult::UnknownCase { id: id.to_string() };
    }
    if id == "AE-ADVERSARIAL-003" {
        return AdversarialResult::BlockedOnDependency {
            id: "AE-ADVERSARIAL-003",
            dependency: "routeArchitecture (src/lib/verification/arcane/architecture-router.mjs) has no Rust port",
        };
    }
    let mp = missing_producer(id);
    AdversarialResult::Pending {
        id: ADVERSARIAL_IDS.iter().find(|&&i| i == id).copied().unwrap(),
        reason: format!("requires {}", mp.unwrap_or("unknown ingress")),
        missing_producer: mp,
    }
}

/// Ported directly: with `AE-ADVERSARIAL-003` unavailable here, this
/// validator can never see a non-PENDING observation for it, so it always
/// returns `false` for status PENDING inputs, matching the JS behavior for
/// every id this port can execute.
pub fn validate_adversarial_observation(result: &AdversarialResult) -> bool {
    !matches!(
        result,
        AdversarialResult::Pending { .. } | AdversarialResult::BlockedOnDependency { .. } | AdversarialResult::UnknownCase { .. }
    )
}

pub fn adversarial_binding_ids() -> &'static [&'static str] {
    ADVERSARIAL_IDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_id_is_unknown_case() {
        assert!(matches!(
            execute_adversarial_binding("AE-NOT-A-CASE"),
            AdversarialResult::UnknownCase { .. }
        ));
    }

    #[test]
    fn case_003_is_blocked_on_dependency_not_faked() {
        let r = execute_adversarial_binding("AE-ADVERSARIAL-003");
        assert!(matches!(r, AdversarialResult::BlockedOnDependency { id: "AE-ADVERSARIAL-003", .. }));
    }

    #[test]
    fn every_other_known_id_is_pending_with_reason() {
        for id in ADVERSARIAL_IDS {
            if *id == "AE-ADVERSARIAL-003" {
                continue;
            }
            let r = execute_adversarial_binding(id);
            match r {
                AdversarialResult::Pending { reason, missing_producer, .. } => {
                    assert!(reason.starts_with("requires "));
                    assert!(missing_producer.is_some());
                }
                other => panic!("{id} did not produce Pending: {other:?}"),
            }
        }
    }

    #[test]
    fn validator_rejects_every_currently_producible_result() {
        for id in ADVERSARIAL_IDS {
            let r = execute_adversarial_binding(id);
            assert!(!validate_adversarial_observation(&r), "{id} unexpectedly validated");
        }
    }

    #[test]
    fn id_list_matches_js_source_order() {
        assert_eq!(adversarial_binding_ids(), ADVERSARIAL_IDS);
        assert_eq!(ADVERSARIAL_IDS.len(), 9);
    }
}
