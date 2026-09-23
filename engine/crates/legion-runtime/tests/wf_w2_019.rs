//! Integration tests for the ported `wf_port::w2_019` module, mirroring
//! `skills/designer/engine/scripts/live-{poll,resume,server,status,
//! target}.mjs`'s pure logic. See the module's own unit tests for
//! finer-grained coverage; these exercise a few cross-function scenarios
//! end to end.

use legion_runtime::wf_port::w2_019::live_poll::{
    build_accept_script_args, build_poll_reply_payload, is_event_pending, manual_apply_poll_banner,
    parse_reply_args, requires_agent_reply, AcceptEvent,
};
use legion_runtime::wf_port::w2_019::live_resume::{
    manual_apply_resume_hint, parse_args as parse_resume_args, ChunkRef, ManualApplyEvent,
};
use legion_runtime::wf_port::w2_019::live_server::{EventQueue, CHAT_POLL_FRESHNESS_MS};
use legion_runtime::wf_port::w2_019::live_status::find_pending_manual_apply;
use legion_runtime::wf_port::w2_019::live_target::resolve_live_target;
use serde_json::json;
use std::path::Path;

// -- live-poll.mjs -----------------------------------------------------------

#[test]
fn poll_reply_round_trip_for_a_generate_event_done_reply() {
    let args: Vec<String> = "--reply ev1 done --file src/App.svelte"
        .split_whitespace()
        .map(String::from)
        .collect();
    let reply = parse_reply_args(&args).unwrap().unwrap();
    assert!(requires_agent_reply("generate"));
    let payload = build_poll_reply_payload("secret-token", &reply);
    assert_eq!(
        payload,
        json!({
            "token": "secret-token",
            "id": "ev1",
            "type": "done",
            "file": "src/App.svelte",
        })
    );
}

#[test]
fn poll_error_reply_carries_a_free_text_message() {
    let args: Vec<String> = vec![
        "--reply".into(),
        "ev2".into(),
        "error".into(),
        "boom".into(),
    ];
    let reply = parse_reply_args(&args).unwrap().unwrap();
    assert_eq!(reply.message.as_deref(), Some("boom"));
    let payload = build_poll_reply_payload("tok", &reply);
    assert_eq!(payload["message"], "boom");
}

#[test]
fn manual_edit_apply_needs_reply_and_gets_a_banner() {
    assert!(requires_agent_reply("manual_edit_apply"));
    let banner = manual_apply_poll_banner(Some("ev9"));
    assert!(banner.contains("--reply ev9 done --data"));
    assert!(banner.contains("Do not poll again before replying."));
}

#[test]
fn is_event_pending_reflects_status_snapshot() {
    let pending = vec!["ev1".to_string(), "ev2".to_string()];
    assert!(is_event_pending(&pending, "ev1"));
    assert!(!is_event_pending(&pending, "ev3"));
}

#[test]
fn accept_and_discard_events_build_matching_cli_args() {
    let accept = AcceptEvent {
        event_type: "accept".into(),
        id: "ev1".into(),
        variant_id: Some("v2".into()),
        page_url: Some("https://app.local/".into()),
        param_values: Some(json!({"theme": "dark"})),
    };
    let args = build_accept_script_args(&accept);
    assert_eq!(args[0..6], [
        "--id", "ev1", "--variant", "v2", "--page-url", "https://app.local/"
    ]);
    assert_eq!(args[6], "--param-values");

    let discard = AcceptEvent {
        event_type: "discard".into(),
        id: "ev1".into(),
        ..Default::default()
    };
    assert_eq!(
        build_accept_script_args(&discard),
        vec!["--id", "ev1", "--discard"]
    );
}

// -- live-resume.mjs ---------------------------------------------------------

#[test]
fn manual_apply_resume_hint_matches_js_wording_shape() {
    let event = ManualApplyEvent {
        id: Some("ev5".into()),
        page_url: Some("http://localhost:5173/pricing".into()),
        chunk: Some(ChunkRef { index: 1, total: 2 }),
        batch: Some(json!({
            "entries": [{"ops": [{"sourceHint": {"file": "src/Pricing.svelte"}}]}]
        })),
    };
    let hint = manual_apply_resume_hint(&event);
    assert!(hint.contains("page http://localhost:5173/pricing"));
    assert!(hint.contains("chunk 1/2"));
    assert!(hint.contains("1 op(s)"));
    assert!(hint.contains("1 entry"));
    assert!(hint.contains("likely files: src/Pricing.svelte"));
    assert!(hint.contains("live-poll.mjs --reply ev5 done --data '<json>'"));
}

#[test]
fn resume_cli_args_parse_id_flag_forms() {
    let a = parse_resume_args(&["--id=sess-42".to_string()]);
    assert_eq!(a.id.as_deref(), Some("sess-42"));
    let b = parse_resume_args(&["--help".to_string()]);
    assert!(b.help);
}

// -- live-status.mjs ----------------------------------------------------------

#[test]
fn status_recovery_hint_selects_the_manual_apply_event_when_present() {
    let server_events = vec![
        json!({"type": "generate", "id": "g1"}),
        json!({"type": "manual_edit_apply", "id": "m1", "pageUrl": "http://localhost:5173/"}),
    ];
    let found = find_pending_manual_apply(Some(&server_events), &[]).unwrap();
    let event = ManualApplyEvent {
        id: found.get("id").and_then(|v| v.as_str()).map(String::from),
        page_url: found
            .get("pageUrl")
            .and_then(|v| v.as_str())
            .map(String::from),
        chunk: None,
        batch: None,
    };
    let hint = manual_apply_resume_hint(&event);
    assert!(hint.contains("page http://localhost:5173/"));
    assert!(hint.contains("--reply m1 done"));
}

#[test]
fn status_recovery_falls_back_to_generic_hint_when_nothing_pending() {
    assert_eq!(find_pending_manual_apply(Some(&[]), &[]), None);
}

// -- live-target.mjs -----------------------------------------------------------

#[test]
fn live_target_resolution_joins_relative_path_and_carries_project_root() {
    let cwd = Path::new("/work/app");
    let res = resolve_live_target(cwd, Some("packages/ui"), Path::new("/work/app"));
    assert_eq!(
        res.absolute_target_path.as_deref(),
        Some(Path::new("/work/app/packages/ui"))
    );
    assert_eq!(res.target_options, json!({"targetPath": "/work/app/packages/ui"}));
    assert_eq!(res.project_root, Path::new("/work/app"));
}

#[test]
fn live_target_resolution_with_no_target_uses_original_cwd_as_root() {
    let cwd = Path::new("/work/app");
    let res = resolve_live_target(cwd, None, cwd);
    assert_eq!(res.absolute_target_path, None);
    assert_eq!(res.target_options, json!({}));
}

// -- live-server.mjs -----------------------------------------------------------

#[test]
fn event_queue_lease_ack_and_replace_cycle() {
    let mut queue = EventQueue::new();
    assert!(queue.enqueue_event(Some("gen-1".into()), "generate"));
    // Duplicate id+type re-enqueue is a no-op, mirroring the JS dedupe guard.
    assert!(!queue.enqueue_event(Some("gen-1".into()), "generate"));

    let now = 10_000;
    let entry = queue.find_available_pending_event(now).cloned().unwrap();
    let leased = queue.lease_by_seq(entry.seq, 5_000, now).unwrap();
    assert_eq!(leased.event_id.as_deref(), Some("gen-1"));

    // Leased, so no longer "available" until the lease elapses.
    assert!(queue.find_available_pending_event(now + 1_000).is_none());
    assert!(queue
        .find_available_pending_event(now + 5_000)
        .is_some());

    assert!(queue.acknowledge_pending_event("gen-1"));
    assert!(queue.find_pending_event_by_id("gen-1").is_none());
}

#[test]
fn event_queue_anonymous_exit_events_are_cancellable_but_never_deduped() {
    let mut queue = EventQueue::new();
    queue.enqueue_event(None, "exit");
    queue.enqueue_event(None, "exit");
    queue.enqueue_event(Some("real-exit".into()), "exit");
    assert_eq!(queue.pending_events().len(), 3);
    assert_eq!(queue.cancel_queued_anonymous_exit_events(), 2);
    assert_eq!(queue.pending_events().len(), 1);
}

#[test]
fn event_queue_agent_polling_and_chat_freshness_track_together() {
    let mut queue = EventQueue::new();
    let now = 0;
    assert!(!queue.agent_polling_connected(now));
    assert!(!queue.chat_agent_likely_active(now));

    queue.record_poll_at(now);
    assert!(queue.chat_agent_likely_active(now + CHAT_POLL_FRESHNESS_MS - 1));
    assert!(!queue.chat_agent_likely_active(now + CHAT_POLL_FRESHNESS_MS));
}
