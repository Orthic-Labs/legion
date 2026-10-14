//! wf_port chunk w2_004 (`skills/council/lib/flows.mjs`).
//!
//! `flows.mjs` is ALREADY-NATIVE-VERIFIED via `legion_runtime::p9_skills::council`, which ports
//! the deterministic pieces of `flows.mjs` (`CONTRACT_BOUNDARIES`) and the v2 verdict rule (`decide_verdict`)
//! and documents why the provider-IO orchestration (`runSeats`, `executeDecisionChallenge`,
//! `executeBlockerConsult`, `executePacketOnly`) is not natively portable. See
//! `src/wf_port/w2_004/mod.rs` and `src/p9_skills/council.rs` for the full rationale.
//!
//! These tests assert on the PRODUCTION entry point (`p9_skills::council`), not on a duplicate
//! helper, per the "assert on the production entry point" rule in `docs/agent-rules.md`.

use legion_runtime::p9_skills::council::{decide_verdict, CONTRACT_BOUNDARIES};

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

/// The v2 verdict rule: a failed CHALLENGING seat or a missing adjudication is UNRESOLVED; a
/// merged P0 finding or a MISSING requirement forces REVISE over SUPPORTED; otherwise the
/// adjudicator's verdict stands. Blocker consults use their own outcome names.
#[test]
fn decide_verdict_unresolved_beats_forced_revise_beats_adjudicator() {
    let d = "DECISION_CHALLENGE";
    assert_eq!(
        decide_verdict(d, true, Some("SUPPORTED"), false),
        Some("UNRESOLVED")
    );
    assert_eq!(decide_verdict(d, false, None, false), Some("UNRESOLVED"));
    assert_eq!(
        decide_verdict(d, false, Some("SUPPORTED"), true),
        Some("REVISE")
    );
    assert_eq!(
        decide_verdict(d, false, Some("REVISE"), false),
        Some("REVISE")
    );
    assert_eq!(
        decide_verdict(d, false, Some("SUPPORTED"), false),
        Some("SUPPORTED")
    );
    let b = "BLOCKER_CONSULT";
    assert_eq!(
        decide_verdict(b, true, Some("CONTRACT_SAFE"), false),
        Some("INSUFFICIENT_EVIDENCE")
    );
    assert_eq!(
        decide_verdict(b, false, Some("CONTRACT_SAFE"), true),
        Some("AMENDMENT_REQUIRED")
    );
}

#[test]
fn decide_verdict_has_no_outcome_for_packet_only() {
    assert_eq!(
        decide_verdict("PACKET_ONLY", false, Some("SUPPORTED"), false),
        None
    );
}
