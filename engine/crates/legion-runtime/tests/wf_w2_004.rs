//! wf_port chunk w2_004 (`skills/covenant/lib/flows.mjs`).
//!
//! `flows.mjs` is ALREADY-NATIVE-VERIFIED via `legion_runtime::p9_skills::covenant`, which ports
//! the deterministic pieces of `flows.mjs` (`CONTRACT_BOUNDARIES`, `aggregateDecisionVerdict`)
//! and documents why the provider-IO orchestration (`runSeats`, `executeDecisionChallenge`,
//! `executeBlockerConsult`, `executePacketOnly`) is not natively portable. See
//! `src/wf_port/w2_004/mod.rs` and `src/p9_skills/covenant.rs` for the full rationale.
//!
//! These tests assert on the PRODUCTION entry point (`p9_skills::covenant`), not on a duplicate
//! helper, per the "assert on the production entry point" rule in `docs/agent-rules.md`.

use legion_runtime::p9_skills::covenant::{aggregate_decision_verdict, CONTRACT_BOUNDARIES};

/// Mirrors flows.mjs's frozen `CONTRACT_BOUNDARIES` array exactly, in order.
#[test]
fn contract_boundaries_matches_flows_mjs() {
    assert_eq!(
        CONTRACT_BOUNDARIES,
        &[
            "changesSealedDecision",
            "changesLockedInvariant",
            "changesAcceptance",
            "expandsScope",
            "addsMaterialDependency",
            "changesPublicBehavior",
            "altersSecurity",
            "exceedsEffectClass",
        ]
    );
}

/// Mirrors `aggregateDecisionVerdict`'s priority order from flows.mjs: any
/// PROVIDER_FAILURE/UNRESOLVED position wins outright, then any REVISE/MUTATION_DETECTED,
/// else SUPPORTED. Case-insensitive on the position strings, like the JS `.toUpperCase()` scan.
#[test]
fn aggregate_decision_verdict_unresolved_beats_revise_beats_supported() {
    assert_eq!(
        aggregate_decision_verdict(["supported", "provider_failure: seat down"]),
        "UNRESOLVED"
    );
    assert_eq!(
        aggregate_decision_verdict(["supported", "unresolved"]),
        "UNRESOLVED"
    );
    assert_eq!(
        aggregate_decision_verdict(["supported", "please revise"]),
        "REVISE"
    );
    assert_eq!(
        aggregate_decision_verdict(["supported", "MUTATION_DETECTED"]),
        "REVISE"
    );
    // UNRESOLVED still wins even when a REVISE signal is also present.
    assert_eq!(
        aggregate_decision_verdict(["revise", "provider_failure: x"]),
        "UNRESOLVED"
    );
    assert_eq!(
        aggregate_decision_verdict(["SUPPORTED", "supported"]),
        "SUPPORTED"
    );
}

#[test]
fn aggregate_decision_verdict_empty_seats_is_supported() {
    // flows.mjs: `positions.some(...)` on an empty array is false for both checks, so an
    // (unreachable in practice, since runSeats requires >=1 seat) empty list defaults SUPPORTED.
    let empty: [&str; 0] = [];
    assert_eq!(aggregate_decision_verdict(empty), "SUPPORTED");
}
