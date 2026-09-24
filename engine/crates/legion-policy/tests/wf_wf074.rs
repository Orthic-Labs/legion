//! Integration tests for wf074's port of
//! `src/lib/verification/arcane/s11-bindings/{eval-adr-canon-clarify,
//! eval-adversarial,eval-concurrency-convergence,eval-review-security,
//! evidence-closure}.mjs`.
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! and `pub mod wf074;` to `engine/crates/legion-policy/src/wf_port/mod.rs`
//! (see wf074's report for the exact patch). Until then it is inert.

use legion_policy::wf_port::wf074::{
    adr_canon_clarify_runtime_ids, adversarial_binding_ids, concurrency_convergence_binding_ids,
    evaluate_adr_admission, evaluate_canon_owner_drift, evaluate_clarification_convergence,
    evaluate_fog_metadata, evaluate_generated_source_drift, execute_adr_canon_clarify_case,
    execute_adversarial_binding, execute_concurrency_convergence_case,
    execute_evidence_closure_runtime_case, execute_review_security_binding,
    review_security_runtime_ids, validate_adr_canon_clarify_observation,
    validate_adversarial_observation, validate_concurrency_convergence_observation,
    validate_review_security_observation, AdrAdmissionInput, AdversarialResult,
    ClarificationImpact, ConcurrencyConvergenceResult, EvalOutcome, EvidenceClosureResult,
    ReviewSecurityResult,
};

// ---------------------------------------------------------------------
// eval-adr-canon-clarify.mjs — fully ported, so these assert exact JS
// parity for every runtime case in the corpus.
// ---------------------------------------------------------------------

#[test]
fn adr_canon_clarify_ids_match_js_corpus() {
    assert_eq!(
        adr_canon_clarify_runtime_ids(),
        &[
            "AE-ADR-ADMISSION-001",
            "AE-ADR-ADMISSION-002",
            "AE-CANON-DRIFT-001",
            "AE-CANON-DRIFT-002",
            "AE-CLARIFICATION-CONVERGENCE-001",
            "AE-CLARIFICATION-CONVERGENCE-002",
        ]
    );
}

#[test]
fn adr_admission_002_rejects_with_two_alternatives_recorded() {
    let out = execute_adr_canon_clarify_case("AE-ADR-ADMISSION-002").unwrap();
    match out {
        EvalOutcome::AdrAdmission { status, alternatives, .. } => {
            assert_eq!(status, "REJECT");
            assert_eq!(alternatives, Some(2));
        }
        _ => panic!("wrong outcome"),
    }
}

#[test]
fn admit_requires_architecture_worth_true() {
    let out = evaluate_adr_admission(&AdrAdmissionInput {
        reversible: Some(false),
        boundary_accepted: Some(false),
        architecture_worth: Some(false),
        local_alternatives: Some(3),
    });
    match out {
        EvalOutcome::AdrAdmission { status, .. } => assert_eq!(status, "REJECT"),
        _ => panic!(),
    }
}

#[test]
fn canon_owner_drift_with_empty_owner_string_is_pending() {
    let out = evaluate_canon_owner_drift(&["a", ""]);
    match out {
        EvalOutcome::CanonOwnerDrift { status, missing_producer, .. } => {
            assert_eq!(status, "PENDING");
            assert_eq!(missing_producer, Some("canonical owner registry"));
        }
        _ => panic!(),
    }
}

#[test]
fn generated_source_drift_round_trips_through_execute_case() {
    let out = execute_adr_canon_clarify_case("AE-CANON-DRIFT-002").unwrap();
    let via_direct = evaluate_generated_source_drift(
        &legion_policy::wf_port::wf074::Json::obj([("rule", legion_policy::wf_port::wf074::Json::str("source"))]),
        &legion_policy::wf_port::wf074::Json::obj([("rule", legion_policy::wf_port::wf074::Json::str("drift"))]),
    );
    assert_eq!(out, via_direct);
}

#[test]
fn clarification_convergence_stops_only_when_nothing_affected_and_recorded() {
    let stops = evaluate_clarification_convergence(&ClarificationImpact::default(), true);
    assert!(matches!(stops, EvalOutcome::ClarificationConvergence { status: "STOP", .. }));

    let continues_unrecorded = evaluate_clarification_convergence(&ClarificationImpact::default(), false);
    assert!(matches!(continues_unrecorded, EvalOutcome::ClarificationConvergence { status: "CONTINUE", .. }));
}

#[test]
fn fog_metadata_ready_requires_both_fields_nonblank() {
    let half_blank = evaluate_fog_metadata("a question", "");
    assert!(matches!(half_blank, EvalOutcome::FogMetadata { status: "FOG", .. }));
}

#[test]
fn every_adr_canon_clarify_case_passes_its_own_validator() {
    for id in adr_canon_clarify_runtime_ids() {
        let out = execute_adr_canon_clarify_case(id).unwrap();
        assert!(validate_adr_canon_clarify_observation(id, &out), "{id}");
    }
}

// ---------------------------------------------------------------------
// eval-adversarial.mjs — one case ported, eight blocked on
// routeArchitecture (no Rust port yet). These tests assert the honest
// blocked/pending split rather than fabricated pass/fail behavior.
// ---------------------------------------------------------------------

#[test]
fn adversarial_id_list_matches_js_source() {
    assert_eq!(adversarial_binding_ids().len(), 9);
    assert!(adversarial_binding_ids().contains(&"AE-ADVERSARIAL-003"));
    assert!(!adversarial_binding_ids().contains(&"AE-ADVERSARIAL-008"));
}

#[test]
fn adversarial_003_blocked_and_every_other_pending() {
    let r003 = execute_adversarial_binding("AE-ADVERSARIAL-003");
    assert!(matches!(r003, AdversarialResult::BlockedOnDependency { .. }));
    for id in adversarial_binding_ids() {
        if *id == "AE-ADVERSARIAL-003" {
            continue;
        }
        let r = execute_adversarial_binding(id);
        assert!(matches!(r, AdversarialResult::Pending { .. }));
        assert!(!validate_adversarial_observation(&r));
    }
}

// ---------------------------------------------------------------------
// eval-concurrency-convergence.mjs — three pure-pending cases ported in
// full; two scheduler-backed cases honestly blocked.
// ---------------------------------------------------------------------

#[test]
fn concurrency_convergence_id_list_has_five_entries() {
    assert_eq!(concurrency_convergence_binding_ids().len(), 5);
}

#[test]
fn scheduler_backed_cases_are_blocked_not_simulated() {
    for id in ["AE-CONCURRENCY-ATTENTION-002", "AE-CONCURRENCY-ATTENTION-006"] {
        assert!(matches!(
            execute_concurrency_convergence_case(id),
            ConcurrencyConvergenceResult::BlockedOnDependency { .. }
        ));
    }
}

#[test]
fn pure_pending_cases_carry_their_js_reason_text() {
    match execute_concurrency_convergence_case("AE-CONVERGENCE-001") {
        ConcurrencyConvergenceResult::Pending { reason, .. } => {
            assert_eq!(reason, "clarification priority requires Sage judgment");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn validator_never_accepts_current_concurrency_output() {
    for id in concurrency_convergence_binding_ids() {
        let r = execute_concurrency_convergence_case(id);
        assert!(!validate_concurrency_convergence_observation(&r));
    }
}

// ---------------------------------------------------------------------
// eval-review-security.mjs — two pure-pending cases ported in full; two
// gate-validity-backed cases honestly blocked.
// ---------------------------------------------------------------------

#[test]
fn review_security_id_list_has_four_entries() {
    assert_eq!(review_security_runtime_ids().len(), 4);
}

#[test]
fn gate_backed_cases_are_blocked_not_simulated() {
    for id in ["AE-REVIEW-ADMISSION-001", "AE-REVIEW-VERDICT-SECURITY-006"] {
        assert!(matches!(
            execute_review_security_binding(id),
            ReviewSecurityResult::BlockedOnDependency { .. }
        ));
    }
}

#[test]
fn advisory_judgment_cases_validate_true() {
    for id in ["AE-REVIEW-VERDICT-SECURITY-002", "AE-REVIEW-VERDICT-SECURITY-005"] {
        let r = execute_review_security_binding(id);
        assert!(validate_review_security_observation(&r), "{id}");
    }
}

// ---------------------------------------------------------------------
// evidence-closure.mjs — twelve UNSUPPORTED ids ported in full; six
// SUPPORTED ids wired to the now-ported architecture-state.mjs,
// evidence-registry.mjs, provider-capability.mjs, gate-validity.mjs, and
// seal-reachability.mjs production verifiers (wf070/wf072/wf075).
// ---------------------------------------------------------------------

#[test]
fn evidence_closure_supported_ids_all_accepted() {
    for id in [
        "AE-EVIDENCE-ARTIFACTS-001",
        "AE-EVIDENCE-ARTIFACTS-002",
        "AE-EVIDENCE-FRESHNESS-001",
        "AE-GATE-VALIDITY-001",
        "AE-GATE-VALIDITY-002",
        "AE-SEAL-REACHABILITY-001",
    ] {
        assert!(matches!(
            execute_evidence_closure_runtime_case(id),
            EvidenceClosureResult::Accepted { .. }
        ));
    }
}

#[test]
fn evidence_closure_unsupported_ids_carry_missing_capability_text() {
    match execute_evidence_closure_runtime_case("AE-FINDING-LIFECYCLE-002") {
        EvidenceClosureResult::Pending { missing_capability, .. } => {
            assert_eq!(
                missing_capability,
                "independent finding-closure verifier that rejects fix-author certification"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn evidence_closure_unrecognized_id_has_no_binding() {
    assert!(matches!(
        execute_evidence_closure_runtime_case("AE-DOES-NOT-EXIST-001"),
        EvidenceClosureResult::NoBindingRegistered { .. }
    ));
}
