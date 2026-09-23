//! Integration tests for w2_036's ported module
//! (`legion_policy::wf_port::w2_036::stop_shape`), plus a check that wf007's
//! already-ported `user-intent.mjs` subset (which this chunk's target file,
//! `stop-shape.mjs`, imports) is reachable from the same crate path.
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` (if not already present) and `pub mod w2_036;` are
//! wired into `engine/crates/legion-policy/src/wf_port/mod.rs`, alongside
//! the existing `pub mod wf007;`. Until then, the equivalent coverage lives
//! as `#[cfg(test)]` unit tests inside `wf_port::w2_036::stop_shape` itself.

use legion_policy::wf_port::w2_036::stop_shape::{
    continue_intent, deferred_defect_codes, escalated_this_session, evaluate_stop_shape, is_push_gate_laundering,
    reserved_categories, scope_cut_match, tool_denial_match, work_left_stuck, StopShapeOptions,
};
use legion_policy::wf_port::wf007::user_intent::{classify_latest_user_intent, Intent};

fn opts() -> StopShapeOptions {
    StopShapeOptions::default()
}

// --- ported from tests/stop-shape.test.mjs -----------------------------

#[test]
fn permission_question_blocks_and_completed_work_passes() {
    assert!(evaluate_stop_shape("Shall I proceed with the fix?", &opts()).block);
    assert!(!evaluate_stop_shape("Fixed the parser, 12/12 tests, committed abc123.", &opts()).block);
}

#[test]
fn a_reserved_blocker_is_legal_in_any_format() {
    for ending in [
        "Deploy staged. HARD BLOCKER: the Cloudflare token only the operator can supply.",
        "BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication/production mutation)",
        "blocked-on-approval: new spend — the Hetzner upgrade needs your card",
    ] {
        let verdict = evaluate_stop_shape(ending, &StopShapeOptions { escalated: true, ..opts() });
        assert!(!verdict.block, "{ending}");
    }
}

#[test]
fn deferral_offer_is_caught_exact_mac_escape() {
    let escaped = "Next action: add export RIGHT_RELEASE_CACHE_ROOT=/Volumes/D/rightsuite-cache/release to your ~/.zshenv, or tell me to and I'll do it.";
    let verdict = evaluate_stop_shape(escaped, &opts());
    assert!(verdict.block);
    assert_eq!(verdict.shape.as_deref(), Some("deferral-offer"));
}

#[test]
fn push_gate_laundering_exempts_only_ordinary_pushes() {
    let laundered = "BLOCKED-ON-APPROVAL:\nGate: git push origin main in membrane (3 commits)\nReserved-reason: outward-facing and irreversible-in-effect\nDone: verified locally\nRemaining: push\nNo-ungated-work: true";
    assert!(is_push_gate_laundering(laundered));
    let real_publish = "BLOCKED-ON-APPROVAL:\nGate: npm publish @rightkit/git 0.2.0, then push the tag to origin";
    assert!(!is_push_gate_laundering(real_publish));
    let force_push = "BLOCKED-ON-APPROVAL:\nGate: git push --force to rewrite shared main history";
    assert!(!is_push_gate_laundering(force_push));
}

#[test]
fn deferred_defect_markers_and_carve_outs() {
    let codes = deferred_defect_codes("Worth flagging for later: this needs cleanup.");
    assert_eq!(codes, vec!["worth-flagging"]);

    let carved = deferred_defect_codes("Worth flagging: sampleapp's AGENTS.md is stale — filed as a background task via spawn_task.");
    assert!(carved.is_empty());

    let overridden = deferred_defect_codes("Worth flagging for later: this is a separate cleanup. [deferred-ok: the operator owns this call]");
    assert!(overridden.is_empty());
}

#[test]
fn reserved_categories_names_the_canonical_five() {
    assert_eq!(reserved_categories("this needs new spend of $40"), vec!["new-spend"]);
    assert!(reserved_categories("per HANDOFF this is reserved to the operator").is_empty());
}

#[test]
fn escalation_evidence_requires_a_real_dispatch() {
    assert!(!escalated_this_session("I considered dispatching Sage about this."));
    assert!(escalated_this_session(r#"{"subagent_type":"sage","prompt":"..."}"#));
}

#[test]
fn work_left_stuck_and_tool_denial_and_scope_cut_are_pure() {
    assert!(work_left_stuck("The render is still queued and not running."));
    assert!(!work_left_stuck("All done, nothing pending."));
    assert!(tool_denial_match("I don't have web search.").is_some());
    assert!(scope_cut_match("I will drop the models.").is_some());
    assert!(scope_cut_match("Nothing scope-related here.").is_none());
}

#[test]
fn continue_intent_distinguishes_correction_from_plain_question() {
    assert!(continue_intent("Can't we make this a hook and include it in brief?").is_some());
    assert!(continue_intent("What is gstack?").is_none());
}

#[test]
fn end_to_end_reserved_decision_requires_escalation_unless_authorized() {
    let packet = "BLOCKED-ON-APPROVAL: flipping VCS_PUSH from deny to allow — reserved decision, it changes what the enforcement plane permits globally.";
    assert_eq!(evaluate_stop_shape(packet, &opts()).shape.as_deref(), Some("unescalated-blocker"));
    assert!(!evaluate_stop_shape(packet, &StopShapeOptions { escalated: true, ..opts() }).block);
    let authorized = evaluate_stop_shape(
        packet,
        &StopShapeOptions { escalated: true, authorized: true, authorized_evidence: Some("Go on, fix it.".to_string()), ..opts() },
    );
    assert!(authorized.block);
    assert_eq!(authorized.shape.as_deref(), Some("already-authorized"));
}

// --- confirms user-intent.mjs's `classifyLatestUserIntent` (already ported
// as wf007::user_intent) is what this chunk's `evaluateTranscriptStop`
// equivalent relies on for `intent`/`authorized`/`authorizedEvidence`. ---

#[test]
fn user_intent_execute_feeds_stop_shape_authorization() {
    let transcript = r#"{"type":"user","message":{"content":[{"type":"text","text":"please fix the login bug"}]}}"#;
    let classification = classify_latest_user_intent(transcript);
    assert_eq!(classification.intent, Intent::Execute);
    let verdict = evaluate_stop_shape(
        "BLOCKED-ON-APPROVAL: destruction — drop the legacy table.",
        &StopShapeOptions {
            intent: "EXECUTE".to_string(),
            authorized: true,
            authorized_evidence: classification.evidence,
            ..opts()
        },
    );
    assert!(verdict.block);
    assert_eq!(verdict.shape.as_deref(), Some("already-authorized"));
}
