//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-review-security.mjs`.
//!
//! Two of four cases (`AE-REVIEW-ADMISSION-001`,
//! `AE-REVIEW-VERDICT-SECURITY-006`) call `validateGate`/
//! `executeValidatedGate` from `../gate-validity.mjs`, which has no Rust
//! port in `engine/` (`git grep -l validate_gate -- 'engine/**/*.rs'`: no
//! hits) and is not an owned wf074 file, so they are ported as
//! `BlockedOnDependency`. The other two cases (`AE-REVIEW-VERDICT-SECURITY-002`,
//! `-005`) call no dependency at all in the JS source — they are the fixed
//! `pending(id, reason)` helper — and are ported here in full, including
//! the blocker-reason table.

pub const IDS: &[&str] = &[
    "AE-REVIEW-ADMISSION-001",
    "AE-REVIEW-VERDICT-SECURITY-002",
    "AE-REVIEW-VERDICT-SECURITY-005",
    "AE-REVIEW-VERDICT-SECURITY-006",
];

pub fn review_security_runtime_ids() -> &'static [&'static str] {
    IDS
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReviewSecurityResult {
    BlockedOnDependency {
        id: &'static str,
        dependency: &'static str,
    },
    Pending {
        producer: &'static str,
        consumer: &'static str,
        case_id: &'static str,
        reason: &'static str,
    },
    UnknownCase,
}

fn blocker_reason(id: &str) -> Option<&'static str> {
    match id {
        "AE-REVIEW-VERDICT-SECURITY-002" => {
            Some("requires pre-existing Sage/Oracle judgment for exploit-chain evidence and coverage claims")
        }
        "AE-REVIEW-VERDICT-SECURITY-005" => {
            Some("requires pre-existing Sage/Oracle judgment for reopening disposition")
        }
        _ => None,
    }
}

pub fn execute_review_security_binding(id: &str) -> ReviewSecurityResult {
    match id {
        "AE-REVIEW-ADMISSION-001" => ReviewSecurityResult::BlockedOnDependency {
            id: "AE-REVIEW-ADMISSION-001",
            dependency: "validateGate + executeValidatedGate (src/lib/verification/arcane/gate-validity.mjs) has no Rust port",
        },
        "AE-REVIEW-VERDICT-SECURITY-006" => ReviewSecurityResult::BlockedOnDependency {
            id: "AE-REVIEW-VERDICT-SECURITY-006",
            dependency: "validateGate + executeValidatedGate (src/lib/verification/arcane/gate-validity.mjs) has no Rust port",
        },
        "AE-REVIEW-VERDICT-SECURITY-002" | "AE-REVIEW-VERDICT-SECURITY-005" => {
            ReviewSecurityResult::Pending {
                producer: "advisory-judgment",
                consumer: "review verdict security admission",
                case_id: IDS.iter().find(|&&i| i == id).copied().unwrap(),
                reason: blocker_reason(id).unwrap(),
            }
        }
        _ => ReviewSecurityResult::UnknownCase,
    }
}

/// Ported directly for the two reachable pending cases: matches
/// `validateReviewSecurityObservation`'s pending branch
/// (`value?.status === 'PENDING' && value.exactProducer === 'advisory-judgment'`).
pub fn validate_review_security_observation(result: &ReviewSecurityResult) -> bool {
    matches!(
        result,
        ReviewSecurityResult::Pending { producer: "advisory-judgment", .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_001_and_006_are_blocked_not_faked() {
        assert!(matches!(
            execute_review_security_binding("AE-REVIEW-ADMISSION-001"),
            ReviewSecurityResult::BlockedOnDependency { .. }
        ));
        assert!(matches!(
            execute_review_security_binding("AE-REVIEW-VERDICT-SECURITY-006"),
            ReviewSecurityResult::BlockedOnDependency { .. }
        ));
    }

    #[test]
    fn security_002_and_005_are_pending_advisory_judgment() {
        for id in ["AE-REVIEW-VERDICT-SECURITY-002", "AE-REVIEW-VERDICT-SECURITY-005"] {
            let r = execute_review_security_binding(id);
            match &r {
                ReviewSecurityResult::Pending { producer, consumer, .. } => {
                    assert_eq!(*producer, "advisory-judgment");
                    assert_eq!(*consumer, "review verdict security admission");
                }
                other => panic!("{id}: unexpected {other:?}"),
            }
            assert!(validate_review_security_observation(&r));
        }
    }

    #[test]
    fn security_002_reason_mentions_exploit_chain() {
        match execute_review_security_binding("AE-REVIEW-VERDICT-SECURITY-002") {
            ReviewSecurityResult::Pending { reason, .. } => assert!(reason.contains("exploit-chain")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn security_005_reason_mentions_reopening() {
        match execute_review_security_binding("AE-REVIEW-VERDICT-SECURITY-005") {
            ReviewSecurityResult::Pending { reason, .. } => assert!(reason.contains("reopening")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_id_is_unknown_case() {
        assert!(matches!(
            execute_review_security_binding("AE-NOPE"),
            ReviewSecurityResult::UnknownCase
        ));
    }

    #[test]
    fn validator_rejects_blocked_and_unknown() {
        assert!(!validate_review_security_observation(&execute_review_security_binding(
            "AE-REVIEW-ADMISSION-001"
        )));
        assert!(!validate_review_security_observation(&execute_review_security_binding("AE-NOPE")));
    }

    #[test]
    fn id_list_has_four_entries() {
        assert_eq!(review_security_runtime_ids().len(), 4);
    }
}
