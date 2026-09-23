//! Chunk w2_048 (`area src/lib/host`, target crate `legion-runtime`).
//!
//! This chunk's four source files:
//!
//! - `src/lib/host/arcane/session-binding.mjs` -> ALREADY-NATIVE-VERIFIED at
//!   `legion_arcane::session_binding::SessionBindingStore` (a different
//!   crate; `legion-runtime`'s `Cargo.toml` does not currently depend on
//!   `legion-arcane`, so its own coverage is not re-exercised from this test
//!   target — see the chunk report for the gaps found while verifying it).
//! - `src/lib/host/arcane/source-revision.mjs` (fs HEAD resolver) ->
//!   ALREADY-NATIVE-VERIFIED at `resolve_source_revision` in
//!   `engine/bins/legion-hook/src/main.rs` (binary-local; not linkable from
//!   this crate).
//! - `src/lib/skill-projection.mjs` -> ALREADY-NATIVE-VERIFIED at
//!   `legion_harness::skills` (a different crate; not a current
//!   `legion-runtime` dependency either).
//! - `src/lib/host/arcane/stop-disposition.mjs` -> ported fresh below as
//!   `legion_runtime::wf_port::w2_048::stop_disposition`, the only file in
//!   this chunk that actually lives in this crate. Its unit tests are
//!   inline in that module (mirroring the JS integration test's
//!   stop-disposition matrix); this file re-asserts the same behaviour as a
//!   crate-level smoke.

use legion_runtime::wf_port::w2_048::stop_disposition::{
    classify_stop_disposition, stop_outcome, StopDispositionInput, STOP_DISPOSITIONS,
};

#[test]
fn stop_disposition_matrix_terminates_every_non_completion_intent() {
    for intent in ["UNKNOWN", "QUESTION", "PLAN", "PAUSE"] {
        let outcome = stop_outcome(&StopDispositionInput {
            authenticated_claim: false,
            intent,
        });
        assert!(outcome.termination_allowed);
        assert_eq!(outcome.certification, "not_claimed");
    }
}

#[test]
fn stop_disposition_authenticated_completion_is_genuine() {
    let outcome = stop_outcome(&StopDispositionInput {
        authenticated_claim: true,
        intent: "UNKNOWN",
    });
    assert_eq!(outcome.disposition, "completion");
    assert_eq!(outcome.certification, "genuine");
}

#[test]
fn stop_disposition_in_progress_intent_wins_over_authenticated_claim() {
    // JS checks the in-progress intent list before the authenticatedClaim
    // flag, so an authenticated claim cannot turn a QUESTION/PLAN/PAUSE/
    // REVOKE/SCOPE_NARROW intent into a completion.
    for intent in ["QUESTION", "PLAN", "PAUSE", "REVOKE", "SCOPE_NARROW"] {
        let disposition = classify_stop_disposition(&StopDispositionInput {
            authenticated_claim: true,
            intent,
        });
        assert_eq!(disposition, "question");
    }
}

#[test]
fn stop_disposition_set_matches_js() {
    assert_eq!(
        STOP_DISPOSITIONS,
        ["completion", "question", "pause", "archive", "other"]
    );
}
