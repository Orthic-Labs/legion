//! Port of `skills/alchemist/scripts/viewer.py` behaviour (chunk w2_002),
//! including the `classify`/`iter_events` pieces of
//! `skills/alchemist/scripts/parse_events.py` it depends on.

use std::fs;
use std::io::BufReader;
use std::path::PathBuf;

use legion_runtime::wf_port::w2_002::{
    classify, events_from, first_text, iter_events, list_runs, resolve_target, strip_bom, PAGE,
};
use serde_json::json;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_002")
}

// --- first_text ------------------------------------------------------------

#[test]
fn first_text_prefers_earliest_key_in_priority_order() {
    let v = json!({"content": "c", "message": "m", "delta": "d"});
    assert_eq!(first_text(&v), "c");
}

#[test]
fn first_text_falls_through_empty_strings_to_next_key() {
    let v = json!({"text": "", "content": "real"});
    assert_eq!(first_text(&v), "real");
}

#[test]
fn first_text_joins_list_items() {
    let v = json!([{"text": "a"}, {"text": "b"}]);
    assert_eq!(first_text(&v), "ab");
}

#[test]
fn first_text_of_plain_string_is_itself() {
    assert_eq!(first_text(&json!("hello")), "hello");
}

#[test]
fn first_text_of_number_is_empty() {
    assert_eq!(first_text(&json!(42)), "");
}

// --- classify ---------------------------------------------------------------

#[test]
fn classify_reasoning_event() {
    let e = json!({"type": "reasoning_delta", "text": "thinking..."});
    assert_eq!(classify(&e), ("reasoning".to_string(), "thinking...".to_string()));
}

#[test]
fn classify_command_from_item_wrapper() {
    let e = json!({"item": {"type": "exec_command", "command": ["ls", "-la"]}});
    assert_eq!(classify(&e), ("command".to_string(), "ls -la".to_string()));
}

#[test]
fn classify_command_falls_back_to_first_text_when_no_command_field() {
    let e = json!({"type": "shell_call", "text": "whoami"});
    assert_eq!(classify(&e), ("command".to_string(), "whoami".to_string()));
}

#[test]
fn classify_patch_event() {
    let e = json!({"type": "apply_patch", "text": "--- a\n+++ b"});
    assert_eq!(classify(&e), ("patch".to_string(), "--- a\n+++ b".to_string()));
}

#[test]
fn classify_error_from_top_level_error_field_even_without_error_in_type() {
    let e = json!({"type": "turn_completed", "error": {"text": "boom"}});
    assert_eq!(classify(&e), ("error".to_string(), "boom".to_string()));
}

#[test]
fn classify_assistant_message() {
    let e = json!({"msg": {"type": "agent_message", "text": "hello there"}});
    assert_eq!(classify(&e), ("assistant".to_string(), "hello there".to_string()));
}

#[test]
fn classify_usage_event_dumps_json_capped_at_200_chars() {
    let e = json!({"type": "token_usage", "total_tokens": 123, "cached": 45});
    let (kind, detail) = classify(&e);
    assert_eq!(kind, "usage");
    // Must be the JSON of the payload (which equals the whole event here,
    // since there is no "item"/"msg" wrapper), not of some other shape.
    let parsed: serde_json::Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(parsed["total_tokens"], 123);
}

#[test]
fn classify_unknown_kind_passes_through_as_its_own_bucket() {
    let e = json!({"type": "weird_custom_event", "text": "detail text"});
    assert_eq!(
        classify(&e),
        ("weird_custom_event".to_string(), "detail text".to_string())
    );
}

#[test]
fn classify_missing_type_is_unknown() {
    let e = json!({"text": "no type here"});
    assert_eq!(classify(&e), ("unknown".to_string(), "no type here".to_string()));
}

#[test]
fn classify_truncates_detail_to_400_chars() {
    let long = "x".repeat(1000);
    let e = json!({"type": "reasoning", "text": long});
    let (_, detail) = classify(&e);
    assert_eq!(detail.chars().count(), 400);
}

#[test]
fn classify_command_string_form_not_list() {
    let e = json!({"type": "command", "command": "echo hi"});
    assert_eq!(classify(&e), ("command".to_string(), "echo hi".to_string()));
}

// --- strip_bom ---------------------------------------------------------------

#[test]
fn strip_bom_removes_utf8_bom() {
    assert_eq!(strip_bom("\u{feff}{\"a\":1}"), "{\"a\":1}");
}

#[test]
fn strip_bom_removes_mojibake_bom() {
    assert_eq!(strip_bom("ï»¿{\"a\":1}"), "{\"a\":1}");
}

#[test]
fn strip_bom_no_bom_is_unchanged() {
    assert_eq!(strip_bom("{\"a\":1}"), "{\"a\":1}");
}

// --- iter_events --------------------------------------------------------------

#[test]
fn iter_events_skips_blank_and_malformed_lines() {
    let text = "{\"type\":\"a\"}\n\nnot json\n{\"type\":\"b\"}\n";
    let events = iter_events(BufReader::new(text.as_bytes()));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["type"], "a");
    assert_eq!(events[1]["type"], "b");
}

#[test]
fn iter_events_strips_bom_on_first_line() {
    let text = "\u{feff}{\"type\":\"a\"}\n{\"type\":\"b\"}\n";
    let events = iter_events(BufReader::new(text.as_bytes()));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["type"], "a");
}

// --- list_runs / resolve_target / events_from (filesystem-backed) ------------

fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[&str]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    path
}

#[test]
fn list_runs_counts_nonblank_lines_and_only_jsonl_files() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_list_runs_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    write_jsonl(&tmp, "run-a.jsonl", &["{\"type\":\"a\"}", "", "{\"type\":\"b\"}"]);
    write_jsonl(&tmp, "run-b.jsonl", &["{\"type\":\"a\"}"]);
    fs::write(tmp.join("not-a-run.txt"), "ignore me").unwrap();

    let runs = list_runs(&tmp);
    assert_eq!(runs.len(), 2);
    let names: Vec<&str> = runs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"run-a.jsonl"));
    assert!(names.contains(&"run-b.jsonl"));
    let run_a = runs.iter().find(|r| r.name == "run-a.jsonl").unwrap();
    assert_eq!(run_a.events, 2);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn list_runs_on_missing_directory_is_empty() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_missing_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    assert!(list_runs(&tmp).is_empty());
}

#[test]
fn resolve_target_accepts_file_inside_runs_dir() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_resolve_ok_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    write_jsonl(&tmp, "run.jsonl", &["{\"type\":\"a\"}"]);

    let target = resolve_target(&tmp, "run.jsonl");
    assert!(target.is_some());

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn resolve_target_rejects_path_traversal() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_resolve_traverse_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let runs_dir = tmp.join("runs");
    fs::create_dir_all(&runs_dir).unwrap();
    // A secret file that lives outside runs_dir, sibling to it.
    fs::write(tmp.join("secret.jsonl"), "{\"type\":\"leak\"}\n").unwrap();

    let target = resolve_target(&runs_dir, "../secret.jsonl");
    assert!(target.is_none(), "must never resolve outside runs_dir");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn resolve_target_rejects_empty_name_and_missing_file() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_resolve_empty_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    assert!(resolve_target(&tmp, "").is_none());
    assert!(resolve_target(&tmp, "nonexistent.jsonl").is_none());

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn events_from_respects_from_offset_and_classifies() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_events_from_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    write_jsonl(
        &tmp,
        "run.jsonl",
        &[
            "{\"type\":\"reasoning\",\"text\":\"one\"}",
            "{\"type\":\"agent_message\",\"text\":\"two\"}",
            "{\"type\":\"agent_message\",\"text\":\"three\"}",
        ],
    );

    let all = events_from(&tmp, "run.jsonl", 0);
    assert_eq!(all.len(), 3);
    assert_eq!(all[0], ("reasoning".to_string(), "one".to_string()));

    let tail = events_from(&tmp, "run.jsonl", 1);
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0], ("assistant".to_string(), "two".to_string()));

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn events_from_unknown_run_is_empty() {
    let tmp = std::env::temp_dir().join(format!("wf_w2_002_events_unknown_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    assert!(events_from(&tmp, "does-not-exist.jsonl", 0).is_empty());
    fs::remove_dir_all(&tmp).ok();
}

// --- fixture-backed regression (a captured worker run log) --------------------

#[test]
fn events_from_fixture_run_matches_expected_classification() {
    let dir = fixtures_dir();
    let events = events_from(&dir, "sample_run.jsonl", 0);
    assert_eq!(
        events,
        vec![
            ("reasoning".to_string(), "Looking at the failing test".to_string()),
            ("command".to_string(), "cargo test --lib".to_string()),
            ("assistant".to_string(), "Fixed the off-by-one error.".to_string()),
            ("usage".to_string(), "{\"total_tokens\":512,\"type\":\"token_count\"}".to_string()),
        ]
    );
}

// --- page constant -------------------------------------------------------------

#[test]
fn page_html_is_nonempty_and_carries_the_viewer_title() {
    assert!(PAGE.contains("Citadel"));
    assert!(PAGE.contains("/api/runs"));
    assert!(PAGE.contains("/api/events"));
}
