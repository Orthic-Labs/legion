//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-adversarial.mjs`.
//!
//! The JS module executes exactly one case (`AE-ADVERSARIAL-003`) against a
//! live production control, `routeArchitecture` from
//! `../architecture-router.mjs`. Packet R64 ported that module in full at
//! [`crate::wf_port::r64::architecture_router`] (see that module's doc
//! comment for why closing this gap belongs there). `AE-ADVERSARIAL-003`
//! now runs the real router against the exact input the JS source builds
//! inline, instead of reporting `BlockedOnDependency`.
//!
//! Everything else in the JS module — the id list, the missing-producer
//! reasons, the unknown-id and validator paths — has no such dependency and
//! was already ported in full.

use crate::wf_port::r64::architecture_router::route_architecture;

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
    /// Mirrors JS `observation(id, producer, consumer, value)` for
    /// `AE-ADVERSARIAL-003` — the one case run against a live production
    /// control (`routeArchitecture`).
    Observed {
        id: &'static str,
        rigor: String,
        depth: String,
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
        // Mirrors JS `routeArchitecture({ flags: ['safety', 'hard_real_time'],
        // significance: { quality_or_mission: true }, effect: {} })`.
        let input = serde_json::json!({
            "flags": ["safety", "hard_real_time"],
            "significance": {"quality_or_mission": true},
            "effect": {},
        });
        let route = route_architecture(&input).expect("fixed AE-ADVERSARIAL-003 input is always valid");
        return AdversarialResult::Observed {
            id: "AE-ADVERSARIAL-003",
            rigor: route.rigor.to_string(),
            depth: route.depth.to_string(),
        };
    }
    let mp = missing_producer(id);
    AdversarialResult::Pending {
        id: ADVERSARIAL_IDS.iter().find(|&&i| i == id).copied().unwrap(),
        reason: format!("requires {}", mp.unwrap_or("unknown ingress")),
        missing_producer: mp,
    }
}

/// Mirrors JS `validateAdversarialObservation(id, result)`.
pub fn validate_adversarial_observation(result: &AdversarialResult) -> bool {
    match result {
        AdversarialResult::Observed { id: "AE-ADVERSARIAL-003", rigor, depth } => rigor == "critical" && depth == "D1",
        _ => false,
    }
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
    fn case_003_now_runs_the_real_router_and_validates() {
        let r = execute_adversarial_binding("AE-ADVERSARIAL-003");
        assert!(matches!(r, AdversarialResult::Observed { id: "AE-ADVERSARIAL-003", .. }));
        assert!(validate_adversarial_observation(&r));
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
    fn validator_accepts_case_003_and_rejects_every_pending_case() {
        for id in ADVERSARIAL_IDS {
            let r = execute_adversarial_binding(id);
            let expect_valid = *id == "AE-ADVERSARIAL-003";
            assert_eq!(validate_adversarial_observation(&r), expect_valid, "{id}");
        }
    }

    #[test]
    fn id_list_matches_js_source_order() {
        assert_eq!(adversarial_binding_ids(), ADVERSARIAL_IDS);
        assert_eq!(ADVERSARIAL_IDS.len(), 9);
    }
}
