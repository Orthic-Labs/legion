//! Integration tests for wf_port chunk w2_017
//! (`skills/designer/engine/scripts/live-browser-dom.js`,
//! `live-browser-session.js`, `live-browser.js`,
//! `live-commit-manual-edits.mjs`, `live-complete.mjs`).
//!
//! Unit tests for each ported function already live beside the code in
//! `src/wf_port/w2_017/*.rs`; these integration tests exercise the modules
//! through the crate's public path the way another chunk (or the CLI glue
//! that will eventually wrap them) would.
//!
//! `live-browser.js` itself is not ported (see `src/wf_port/w2_017/mod.rs`
//! for why: it is in-page overlay JS driven over CDP, with no Rust
//! equivalent), so it has no tests here.

use legion_runtime::wf_port::w2_017::browser_dom::{
    css_id_fallback, desc, rect_is_usable_anchor, ElementShape, Rect,
};
use legion_runtime::wf_port::w2_017::commit_edits::{
    all_entry_ids, arg_val, build_repair_batch, candidates_for_entry, count_ops, escape_regexp,
    line_has_object_key, line_matches_manual_edit_locator, line_shows_applied_op,
    merge_failed_entries, merge_unique_strings, normalize_failed_entries,
    normalize_verification_text, op_has_locator, repair_attempt_limit,
    summarize_applied_entries, summarize_repair_failures, unique_strings,
    verification_target_passes_lines, window_shows_applied_op, ArgVal, Op, VerificationTarget,
};
use legion_runtime::wf_port::w2_017::complete::{
    build_event, parse_args, server_poll_type, usage_exit_code, CompletionEvent, Status,
};
use legion_runtime::wf_port::w2_017::session::{LiveBrowserSessionState, MemoryKvStore};
use serde_json::json;

// ---- live-browser-dom.js (pure subset) ----

#[test]
fn browser_dom_desc_matches_js_precedence() {
    let with_id = ElementShape {
        tag_name: "DIV".into(),
        id: "hero".into(),
        class_list: vec!["a".into(), "b".into()],
    };
    assert_eq!(desc(Some(&with_id)), "div#hero");

    let with_classes = ElementShape {
        tag_name: "SPAN".into(),
        id: String::new(),
        class_list: vec!["x".into(), "y".into(), "z".into()],
    };
    assert_eq!(desc(Some(&with_classes)), "span.x.y");

    assert_eq!(desc(None), "");
}

#[test]
fn browser_dom_rect_and_css_id() {
    assert!(!rect_is_usable_anchor(None));
    assert!(rect_is_usable_anchor(Some(&Rect { width: 20.0, height: 20.0 })));
    assert_eq!(css_id_fallback("id with space"), "id\\ with\\ space");
}

// ---- live-browser-session.js ----

#[test]
fn browser_session_lifecycle() {
    let mut s = LiveBrowserSessionState::new("impeccable", MemoryKvStore::new(), "owner-1".into())
        .expect("valid prefix");
    assert_eq!(s.session_key(), "impeccable-session");
    assert!(s.load_session().is_none());

    s.save_session(&json!({"id": "sess-1", "phase": "editing"}));
    let loaded = s.load_session().expect("saved session");
    assert_eq!(loaded["id"], "sess-1");
    assert_eq!(loaded["checkpointRevision"], 0);

    assert_eq!(s.next_checkpoint_revision(), 1);
    let loaded_again = s.load_session().expect("still present");
    assert_eq!(loaded_again["checkpointRevision"], 1);

    s.mark_handled("evt-1");
    assert!(s.is_handled("evt-1"));
    assert!(!s.is_handled("evt-2"));

    s.write_scroll_y(42.25);
    assert_eq!(s.read_scroll_y(), Some(42.25));
    s.clear_scroll_y();
    assert_eq!(s.read_scroll_y(), None);

    s.clear_session();
    assert!(s.load_session().is_none());
}

#[test]
fn browser_session_empty_prefix_is_rejected() {
    assert!(LiveBrowserSessionState::new("", MemoryKvStore::new(), "o".into()).is_err());
}

// ---- live-commit-manual-edits.mjs (pure subset) ----

#[test]
fn commit_edits_arg_and_count_helpers() {
    let args: Vec<String> = vec!["--page-url=/home".into(), "--flag".into()];
    assert_eq!(arg_val(&args, "--flag"), ArgVal::Bool(true));
    assert_eq!(arg_val(&args, "--page-url"), ArgVal::Str("/home".into()));
    assert_eq!(arg_val(&args, "--nope"), ArgVal::None);

    let entries = vec![json!({"id": "a", "ops": [1, 2]}), json!({"id": "b", "ops": [1]})];
    assert_eq!(count_ops(&entries), 3);
    assert_eq!(all_entry_ids(&json!({"entries": entries})), vec!["a", "b"]);
}

#[test]
fn commit_edits_entry_summarization_and_failures() {
    let entries = vec![json!({
        "id": "e1",
        "ops": [{"ref": "r1", "originalText": "old", "newText": "new"}]
    })];
    let summary = summarize_applied_entries(&entries, &["e1".to_string()]);
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["newText"], "new");

    let batch = json!({
        "entries": entries,
        "candidates": [{"entryId": "e1", "sourceHint": "hint"}]
    });
    let candidates = candidates_for_entry(&batch, "e1");
    assert_eq!(candidates, vec![json!("hint")]);

    let result = json!({"failed": [{"id": "e1", "reason": "mismatch"}]});
    let failed = normalize_failed_entries(&batch, &result, "fallback");
    assert_eq!(failed[0]["reason"], "mismatch");
    assert_eq!(failed[0]["candidates"], json!(["hint"]));

    let merged = merge_failed_entries(&[
        &[json!({"id": "e1", "reason": "first", "candidates": ["c1"]})],
        &[json!({"id": "e1", "reason": "second"})],
    ]);
    assert_eq!(merged[0]["reason"], "second");
    assert_eq!(merged[0]["candidates"], json!(["c1"]));

    assert_eq!(
        merge_unique_strings(&[&[json!("a"), json!("")], &[json!("a"), json!("b")]]),
        vec!["a", "b"]
    );
    assert_eq!(unique_strings(&[json!("a"), json!(1), json!(" ")]), vec!["a"]);

    let repaired = build_repair_batch(&batch, json!({"attempt": 1}));
    assert_eq!(repaired["repair"]["attempt"], 1);
    assert_eq!(repaired["entries"], batch["entries"]);

    let repair_failures = vec![json!({"entryId": "e1", "detail": "still stale", "file": "src/a.tsx"})];
    let summarized = summarize_repair_failures(&repair_failures);
    assert_eq!(summarized[0]["reason"], "still stale");
    assert_eq!(summarized[0]["file"], "src/a.tsx");
}

#[test]
fn commit_edits_repair_attempt_limit_and_escaping() {
    assert_eq!(repair_attempt_limit(None), 3);
    assert_eq!(repair_attempt_limit(Some("15")), 10);
    assert_eq!(repair_attempt_limit(Some("-4")), 1);
    assert_eq!(escape_regexp("a+b?"), "a\\+b\\?");
    assert_eq!(normalize_verification_text(" a   b\n c "), "a b c");
}

#[test]
fn commit_edits_op_matching_helpers() {
    let insertion = Op {
        original_text: Some("Save".into()),
        new_text: Some("Save changes".into()),
        deleted: false,
        ..Default::default()
    };
    assert!(line_shows_applied_op("<button>Save changes</button>", &insertion));
    assert!(!line_shows_applied_op("<button>Save</button>", &insertion));

    let deletion = Op {
        original_text: Some("Legacy label".into()),
        deleted: true,
        ..Default::default()
    };
    assert!(line_shows_applied_op("<span>New label</span>", &deletion));
    assert!(!line_shows_applied_op("<span>Legacy label</span>", &deletion));

    let locator = Op {
        tag: Some("button".into()),
        classes: vec!["primary".into()],
        ..Default::default()
    };
    assert!(op_has_locator(&locator));
    assert!(line_matches_manual_edit_locator(
        r#"<button class="primary">Go</button>"#,
        &locator
    ));
    assert!(!line_matches_manual_edit_locator(
        r#"<a class="primary">Go</a>"#,
        &locator
    ));

    assert!(line_has_object_key(r#"  label: "Save",  "#, "label"));
    assert!(line_has_object_key(r#"  "count-1": 4,  "#, "count-1"));
    assert!(!line_has_object_key(r#"  otherLabel: "Save",  "#, "label"));

    assert!(window_shows_applied_op(
        &["const copy = {", "  label: 'Save changes'", "}"],
        &insertion
    ));
}

#[test]
fn commit_edits_verification_target_window_search() {
    let op = Op {
        original_text: Some("Draft".into()),
        new_text: Some("Published".into()),
        ..Default::default()
    };
    let lines = vec![
        "line 0",
        "line 1",
        "status is Published now",
        "line 3",
        "line 4",
    ];
    let direct = VerificationTarget { line: 3, kind: "text_match".into(), reported: false };
    assert!(verification_target_passes_lines(&lines, &direct, &op));

    let far_lines = vec!["a", "still Draft here", "b", "c", "d", "e", "Published elsewhere", "f"];
    let reported = VerificationTarget { line: 2, kind: "reported_locator_match".into(), reported: true };
    // direct line still shows original text -> fails without a window search fallback bailing early
    assert!(!verification_target_passes_lines(&far_lines, &reported, &op));
}

// ---- live-complete.mjs ----

#[test]
fn complete_parses_and_builds_events_like_js() {
    let id_args = vec!["--id".to_string(), "sess-9".to_string()];
    let parsed = parse_args(&id_args);
    assert_eq!(usage_exit_code(&parsed), None);
    assert_eq!(build_event("sess-9", &parsed.status), CompletionEvent::Complete { id: "sess-9".into() });
    assert_eq!(server_poll_type(&parsed.status), "complete");

    let discard_args = vec!["--id=sess-9".to_string(), "--discard".to_string()];
    let parsed_discard = parse_args(&discard_args);
    assert_eq!(parsed_discard.status, Status::Discarded);
    assert_eq!(server_poll_type(&parsed_discard.status), "discarded");

    let error_args = vec!["--id".to_string(), "sess-9".to_string(), "--error".to_string()];
    let parsed_error = parse_args(&error_args);
    assert_eq!(
        build_event("sess-9", &parsed_error.status),
        CompletionEvent::AgentError { id: "sess-9".into(), message: "unknown error".into() }
    );

    let help_only = parse_args(&["--help".to_string()]);
    assert_eq!(usage_exit_code(&help_only), Some(0));

    let missing_id = parse_args(&[]);
    assert_eq!(usage_exit_code(&missing_id), Some(1));
}
