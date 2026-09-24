//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-review-security.mjs`.
//!
//! Two of four cases (`AE-REVIEW-ADMISSION-001`,
//! `AE-REVIEW-VERDICT-SECURITY-006`) call `validateGate`/
//! `executeValidatedGate` from `../gate-validity.mjs`. Packet R64 ported
//! that module in full at [`crate::wf_port::r64::gate_validity`] (see that
//! module's doc comment for why closing this gap belongs there). Both
//! cases now run the real gate-validity machinery against the exact
//! contract/fixtures the JS source builds inline (`admission`/
//! `configuredScope`) via [`ReviewSecurityResult::Observed`], instead of
//! reporting `BlockedOnDependency`. The other two cases
//! (`AE-REVIEW-VERDICT-SECURITY-002`, `-005`) call no dependency at all in
//! the JS source — they are the fixed `pending(id, reason)` helper — and
//! were already ported in full, including the blocker-reason table.

use std::collections::BTreeMap;

use crate::wf_port::r64::gate_validity::{execute_validated_gate, validate_gate, CaseResult, Fixture, GateContract, GateMatch};

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
    /// Mirrors JS `{ producer, consumer, value: { result, ... } }` for
    /// `AE-REVIEW-ADMISSION-001` (`admission()`) and
    /// `AE-REVIEW-VERDICT-SECURITY-006` (`configuredScope()`).
    Observed {
        id: &'static str,
        producer: &'static str,
        consumer: &'static str,
        allowed: bool,
        code: Option<&'static str>,
        inspection_count: usize,
        configured_scope: Option<Vec<String>>,
    },
    Pending {
        producer: &'static str,
        consumer: &'static str,
        case_id: &'static str,
        reason: &'static str,
    },
    UnknownCase,
}

/// Mirrors JS `gateContract` (the fixed contract every evaluator in this
/// file shares).
fn gate_contract() -> GateContract {
    GateContract {
        id: "review-admission-s11".into(),
        inspected_scope: vec!["packages/arcane/**".into()],
        discovery_breadth: "configured".into(),
        blocking_filter: "security".into(),
        threshold: 3,
        gates: true,
        authority: "oracle".into(),
        failure_semantics: "fail-closed".into(),
    }
}

/// Mirrors JS `gateFixtures()`.
fn gate_fixtures() -> BTreeMap<&'static str, Fixture> {
    let mut m = BTreeMap::new();
    m.insert("knownGood", Fixture { id: "known-good".into(), status: "PASS".into() });
    m.insert("knownBad", Fixture { id: "known-bad".into(), status: "FAIL".into() });
    m.insert("empty", Fixture { id: "empty".into(), status: "FAIL".into() });
    m.insert("malformed", Fixture { id: "malformed".into(), status: "FAIL".into() });
    m
}

/// Mirrors JS `admission()`: `validateGate` + `executeValidatedGate` with
/// zero inspected items, so `inspectionCount` is always `0`.
fn admission() -> ReviewSecurityResult {
    let contract = gate_contract();
    let validity = validate_gate(&contract, &gate_fixtures(), |f| CaseResult { status: f.status.clone() });
    let result = execute_validated_gate(&contract, Some(&validity), &[], &[]);
    ReviewSecurityResult::Observed {
        id: "AE-REVIEW-ADMISSION-001",
        producer: "validateGate + executeValidatedGate",
        consumer: "review admission gate",
        allowed: result.allowed,
        code: result.code,
        inspection_count: result.detail.get("inspectionCount").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        configured_scope: None,
    }
}

/// Mirrors JS `configuredScope()`: an independently supplied observation
/// (a claim about an area outside configured scope) must not produce
/// CLEAN.
fn configured_scope() -> ReviewSecurityResult {
    let contract = gate_contract();
    let validity = validate_gate(&contract, &gate_fixtures(), |f| CaseResult { status: f.status.clone() });
    let inspected = vec![serde_json::json!({"subjectId": "src/lib/verification/arcane/gate-validity.mjs"})];
    let matches = vec![GateMatch { rule_id: Some("UNINSPECTED_SCOPE".into()), reason: Some("outside configured scope".into()) }];
    let result = execute_validated_gate(&contract, Some(&validity), &inspected, &matches);
    ReviewSecurityResult::Observed {
        id: "AE-REVIEW-VERDICT-SECURITY-006",
        producer: "validateGate + executeValidatedGate",
        consumer: "configured-scope verdict admission",
        allowed: result.allowed,
        code: result.code,
        inspection_count: result.detail.get("inspectionCount").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        configured_scope: Some(contract.inspected_scope.clone()),
    }
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
        "AE-REVIEW-ADMISSION-001" => admission(),
        "AE-REVIEW-VERDICT-SECURITY-006" => configured_scope(),
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

/// Mirrors JS `validateReviewSecurityObservation(id, observation)`.
pub fn validate_review_security_observation(result: &ReviewSecurityResult) -> bool {
    match result {
        ReviewSecurityResult::Observed { id: "AE-REVIEW-ADMISSION-001", producer, allowed, code, inspection_count, .. } => {
            *producer == "validateGate + executeValidatedGate"
                && !*allowed
                && *code == Some("ARC_EVIDENCE_INSUFFICIENT")
                && *inspection_count == 0
        }
        ReviewSecurityResult::Observed { id: "AE-REVIEW-VERDICT-SECURITY-006", producer, allowed, code, configured_scope, .. } => {
            *producer == "validateGate + executeValidatedGate"
                && !*allowed
                && *code == Some("ARC_CLAIM_PREREQUISITE_UNMET")
                && configured_scope.is_some()
        }
        ReviewSecurityResult::Pending { producer: "advisory-judgment", .. } => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_001_and_006_now_run_the_real_gate_machinery() {
        let r001 = execute_review_security_binding("AE-REVIEW-ADMISSION-001");
        assert!(validate_review_security_observation(&r001));
        match &r001 {
            ReviewSecurityResult::Observed { allowed, code, inspection_count, .. } => {
                assert!(!allowed);
                assert_eq!(*code, Some("ARC_EVIDENCE_INSUFFICIENT"));
                assert_eq!(*inspection_count, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
        let r006 = execute_review_security_binding("AE-REVIEW-VERDICT-SECURITY-006");
        assert!(validate_review_security_observation(&r006));
        match &r006 {
            ReviewSecurityResult::Observed { allowed, code, configured_scope, .. } => {
                assert!(!allowed);
                assert_eq!(*code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
                assert!(configured_scope.is_some());
            }
            other => panic!("unexpected {other:?}"),
        }
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
    fn validator_rejects_unknown_case() {
        assert!(!validate_review_security_observation(&execute_review_security_binding("AE-NOPE")));
    }

    #[test]
    fn id_list_has_four_entries() {
        assert_eq!(review_security_runtime_ids().len(), 4);
    }
}
