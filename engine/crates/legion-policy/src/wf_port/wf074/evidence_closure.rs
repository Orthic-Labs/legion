//! Partial Rust port of
//! `src/lib/verification/arcane/s11-bindings/evidence-closure.mjs`.
//!
//! The JS module's `SUPPORTED` table (6 ids) each drives a real production
//! verifier: `architecture-state.mjs`, `evidence-registry.mjs`,
//! `provider-capability.mjs`, `seal-reachability.mjs`, `gate-validity.mjs`,
//! and `canonical.mjs`'s `digestValue`. None of those production modules
//! has a Rust port anywhere in `engine/` (checked with `git grep` for
//! `architecture_state`, `AcceptanceEvidenceRegistry`,
//! `verify_external_provider_capability`, `compile_seal_reachability`,
//! `validate_gate`: no hits), and none is an owned wf074 file, so those 6
//! cases are ported as `BlockedOnDependency` rather than reimplemented
//! against fixtures that would silently drift from the real verifiers.
//!
//! The `UNSUPPORTED` table (12 ids) calls no dependency at all in the JS
//! source — it is a fixed id → missing-capability-string map returned
//! verbatim as PENDING — and is ported here in full.

pub const SUPPORTED_IDS: &[&str] = &[
    "AE-EVIDENCE-ARTIFACTS-001",
    "AE-EVIDENCE-ARTIFACTS-002",
    "AE-EVIDENCE-FRESHNESS-001",
    "AE-GATE-VALIDITY-001",
    "AE-GATE-VALIDITY-002",
    "AE-SEAL-REACHABILITY-001",
];

fn unsupported_capability(id: &str) -> Option<&'static str> {
    match id {
        "AE-EVIDENCE-001" => Some("authority-backed candidate constraint/admission evaluator"),
        "AE-EVIDENCE-002" => Some("authority-backed preference-versus-constraint classifier"),
        "AE-EVIDENCE-003" => {
            Some("candidate comparison engine with pre-score hard-gate elimination")
        }
        "AE-EVIDENCE-ARTIFACTS-003" => {
            Some("catalog capability registry with adapter-backed gateability state")
        }
        "AE-EVIDENCE-FRESHNESS-002" => {
            Some("waiver lifecycle store that exposes REFRESH_REQUIRED while retaining visible waiver state")
        }
        "AE-FINDING-LIFECYCLE-001" => {
            Some("finding store keyed by stable fingerprint with review-round identity")
        }
        "AE-FINDING-LIFECYCLE-002" => {
            Some("independent finding-closure verifier that rejects fix-author certification")
        }
        "AE-FINDING-LIFECYCLE-003" => {
            Some("scoped recheck consumer that closes blockers & defers unrelated findings")
        }
        "AE-DEFICIT-PROPAGATION-001" => {
            Some("acceptance deficit classifier & completion claim-ceiling consumer")
        }
        "AE-DEFICIT-PROPAGATION-002" => Some("required correctness/safety debt-conversion guard"),
        "AE-DEFICIT-PROPAGATION-003" => {
            Some("dispatch admission consumer for canonical downstream deficit acknowledgement")
        }
        "AE-OUTCOME-CLOSURE-001" => {
            Some("outcome state machine with acceptance-surface observation status")
        }
        _ => None,
    }
}

/// Sorted union of `SUPPORTED` + `UNSUPPORTED` ids, mirroring
/// `evidenceClosureRuntimePolicyIds`.
pub fn evidence_closure_runtime_policy_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = SUPPORTED_IDS.to_vec();
    ids.extend([
        "AE-EVIDENCE-001",
        "AE-EVIDENCE-002",
        "AE-EVIDENCE-003",
        "AE-EVIDENCE-ARTIFACTS-003",
        "AE-EVIDENCE-FRESHNESS-002",
        "AE-FINDING-LIFECYCLE-001",
        "AE-FINDING-LIFECYCLE-002",
        "AE-FINDING-LIFECYCLE-003",
        "AE-DEFICIT-PROPAGATION-001",
        "AE-DEFICIT-PROPAGATION-002",
        "AE-DEFICIT-PROPAGATION-003",
        "AE-OUTCOME-CLOSURE-001",
    ]);
    ids.sort_unstable();
    ids
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceClosureResult {
    BlockedOnDependency {
        id: &'static str,
        dependency: &'static str,
    },
    Pending {
        id: &'static str,
        reason: String,
        missing_capability: &'static str,
    },
    /// Mirrors the JS fallback: an id with no `SUPPORTED`/`UNSUPPORTED`
    /// entry still gets a PENDING result (`'no evidence-closure binding is
    /// registered'`), not an execution error.
    NoBindingRegistered { id: String },
}

pub fn execute_evidence_closure_runtime_case(id: &str) -> EvidenceClosureResult {
    if let Some(&sid) = SUPPORTED_IDS.iter().find(|&&i| i == id) {
        return EvidenceClosureResult::BlockedOnDependency {
            id: sid,
            dependency: supported_dependency(sid),
        };
    }
    if let Some(capability) = unsupported_capability(id) {
        let sid = evidence_closure_runtime_policy_ids()
            .into_iter()
            .find(|&i| i == id)
            .unwrap();
        return EvidenceClosureResult::Pending {
            id: sid,
            reason: format!("missing production capability: {}", capability),
            missing_capability: capability,
        };
    }
    EvidenceClosureResult::NoBindingRegistered { id: id.to_string() }
}

fn supported_dependency(id: &str) -> &'static str {
    match id {
        "AE-EVIDENCE-ARTIFACTS-001" | "AE-EVIDENCE-ARTIFACTS-002" => {
            "verifyExternalProviderCapability (provider-capability.mjs) + architecture-state.mjs have no Rust port"
        }
        "AE-EVIDENCE-FRESHNESS-001" => {
            "AcceptanceEvidenceRegistry (evidence-registry.mjs) + architecture-state.mjs have no Rust port"
        }
        "AE-GATE-VALIDITY-001" | "AE-GATE-VALIDITY-002" => {
            "validateGate + executeValidatedGate (gate-validity.mjs) + architecture-state.mjs have no Rust port"
        }
        "AE-SEAL-REACHABILITY-001" => {
            "compileSealReachability (seal-reachability.mjs) + architecture-state.mjs have no Rust port"
        }
        _ => "unported production dependency",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_id_is_blocked_not_faked() {
        for id in SUPPORTED_IDS {
            assert!(matches!(
                execute_evidence_closure_runtime_case(id),
                EvidenceClosureResult::BlockedOnDependency { .. }
            ));
        }
    }

    #[test]
    fn every_unsupported_id_is_pending_with_its_capability_string() {
        let unsupported = [
            "AE-EVIDENCE-001",
            "AE-EVIDENCE-002",
            "AE-EVIDENCE-003",
            "AE-EVIDENCE-ARTIFACTS-003",
            "AE-EVIDENCE-FRESHNESS-002",
            "AE-FINDING-LIFECYCLE-001",
            "AE-FINDING-LIFECYCLE-002",
            "AE-FINDING-LIFECYCLE-003",
            "AE-DEFICIT-PROPAGATION-001",
            "AE-DEFICIT-PROPAGATION-002",
            "AE-DEFICIT-PROPAGATION-003",
            "AE-OUTCOME-CLOSURE-001",
        ];
        assert_eq!(unsupported.len(), 12);
        for id in unsupported {
            match execute_evidence_closure_runtime_case(id) {
                EvidenceClosureResult::Pending { reason, missing_capability, .. } => {
                    assert!(reason.starts_with("missing production capability: "));
                    assert!(reason.ends_with(missing_capability));
                }
                other => panic!("{id}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn deficit_propagation_002_names_debt_conversion_guard() {
        match execute_evidence_closure_runtime_case("AE-DEFICIT-PROPAGATION-002") {
            EvidenceClosureResult::Pending { missing_capability, .. } => {
                assert_eq!(
                    missing_capability,
                    "required correctness/safety debt-conversion guard"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unrecognized_id_has_no_binding_registered() {
        assert!(matches!(
            execute_evidence_closure_runtime_case("AE-NOT-A-REAL-CASE"),
            EvidenceClosureResult::NoBindingRegistered { .. }
        ));
    }

    #[test]
    fn runtime_policy_ids_has_eighteen_sorted_entries() {
        let ids = evidence_closure_runtime_policy_ids();
        assert_eq!(ids.len(), 18);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn gate_validity_dependency_names_gate_validity_module() {
        match execute_evidence_closure_runtime_case("AE-GATE-VALIDITY-001") {
            EvidenceClosureResult::BlockedOnDependency { dependency, .. } => {
                assert!(dependency.contains("gate-validity.mjs"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
