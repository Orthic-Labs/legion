//! Integration tests for chunk r22 (`live-insert.mjs` / `live-poll.mjs`),
//! exercising the port through the crate's public `wf_port::r22` module.
//! Unit tests covering the detailed behavior live alongside the source in
//! `src/wf_port/r22/live_insert.rs` and `src/wf_port/r22/live_poll.rs`; this
//! file just checks the public API surface is reachable and wired together
//! correctly.

use legion_runtime::wf_port::r22::live_insert::{
    arg_val, build_insert_wrapper_lines, compute_insert_line, is_insert_position,
    CommentSyntax, InsertWrapperArgs,
};
use legion_runtime::wf_port::r22::live_poll::{
    build_accept_script_args, build_poll_reply_payload, is_event_pending, manual_apply_poll_banner,
    parse_reply_args, requires_agent_reply, AcceptEvent, DEFAULT_EVENT_LEASE_MS,
    PER_REQUEST_TIMEOUT_MS,
};
use serde_json::json;

#[test]
fn live_insert_public_api_roundtrip() {
    assert!(is_insert_position("before"));
    assert_eq!(compute_insert_line(5, 9, "after"), 10);

    let args = vec!["--position".to_string(), "after".to_string()];
    assert_eq!(arg_val(&args, "--position"), Some("after"));

    let cs = CommentSyntax {
        open: "<!--".to_string(),
        close: "-->".to_string(),
    };
    let lines = build_insert_wrapper_lines(InsertWrapperArgs {
        id: "s1",
        count: 2,
        indent: "",
        comment_syntax: &cs,
        is_jsx: false,
    });
    assert_eq!(lines.len(), 5);
}

#[test]
fn live_poll_public_api_roundtrip() {
    assert!(requires_agent_reply(Some("generate")));
    assert_eq!(PER_REQUEST_TIMEOUT_MS, 270_000);
    assert_eq!(DEFAULT_EVENT_LEASE_MS, 600_000);

    let payload = build_poll_reply_payload("tok", "ev1", "done", None, None, None);
    assert_eq!(payload["id"], "ev1");

    let status = json!({ "pendingEvents": [{"id": "ev1"}] });
    assert!(is_event_pending(&status, "ev1"));

    let parsed = parse_reply_args(&[
        "--reply".to_string(),
        "ev1".to_string(),
        "done".to_string(),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(parsed.id, "ev1");

    let event = AcceptEvent {
        event_type: "discard".to_string(),
        id: "ev1".to_string(),
        ..Default::default()
    };
    assert_eq!(
        build_accept_script_args(&event),
        vec!["--id", "ev1", "--discard"]
    );

    assert!(manual_apply_poll_banner(Some("ev1")).contains("ev1"));
}
