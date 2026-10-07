use legion_handoff::l1_port::continuity::{normalize, verify_context_receipt, ContinuityInput};
use legion_handoff::l1_port::pointer::Platform;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;

fn write_rows(path: &std::path::Path, rows: &[&str], tail: &[u8]) -> (u64, String) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(path).unwrap();
    for row in rows {
        writeln!(file, "{row}").unwrap();
    }
    file.write_all(tail).unwrap();
    let prefix = rows
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    let digest = hex::encode(Sha256::digest(prefix.as_bytes()));
    (prefix.len() as u64, digest)
}

fn input(path: &std::path::Path, platform: Platform, cutoff: u64, digest: &str) -> ContinuityInput {
    ContinuityInput::new(path, platform, "session-1", "/repo", cutoff, digest)
}

#[test]
fn rejects_prefix_hash_mismatch_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, _) = write_rows(
        &path,
        &[r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"hello"}}"#],
        &[],
    );
    let error = normalize(&input(&path, Platform::Claude, cutoff, &"0".repeat(64))).unwrap_err();
    assert!(error.contains("sha256 mismatch"));
}

#[test]
fn appended_tail_is_outside_bound_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"keep this request"}}"#,
        ],
        br#"{"type":"user","sessionId":"wrong","cwd":"/other","message":{"content":"tail"}}
"#,
    );
    let context = normalize(&input(&path, Platform::Claude, cutoff, &digest)).unwrap();
    assert_eq!(context.user_requests.len(), 1);
    assert_eq!(context.user_requests[0].text, "keep this request");
    verify_context_receipt(&context).unwrap();
}

#[test]
fn claude_adapter_keeps_user_request_and_typed_tool_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"Please fix parser"}}"#,
            r#"{"type":"assistant","sessionId":"session-1","cwd":"/repo","message":{"content":[{"type":"tool_use","id":"call-1","name":"Read","input":{"path":"src/lib.rs"}}]}}"#,
            r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":[{"type":"tool_result","tool_use_id":"call-1","content":"ok"}]}}"#,
        ],
        &[],
    );
    let context = normalize(&input(&path, Platform::Claude, cutoff, &digest)).unwrap();
    assert_eq!(context.user_requests[0].text, "Please fix parser");
    assert!(context.events.iter().any(|event| event.kind == "tool_call"));
    assert!(context
        .events
        .iter()
        .any(|event| event.kind == "tool_result"));
    assert!(context.events.iter().all(|event| !event.trusted));
}

#[test]
fn codex_adapter_omits_runtime_and_private_reasoning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"session_meta","payload":{"id":"session-1","cwd":"/repo"}}"#,
            r#"{"type":"response_item","id":"event-7","timestamp":"t1","payload":{"type":"message","id":"message-8","role":"user","content":[{"type":"input_text","text":"Build it"}]}}"#,
            r#"{"type":"response_item","payload":{"type":"reasoning"}}"#,
            r#"{"type":"response_item","payload":{"type":"event_msg","type":"event_msg"}}"#,
        ],
        &[],
    );
    let context = normalize(&input(&path, Platform::Codex, cutoff, &digest)).unwrap();
    assert_eq!(context.user_requests[0].text, "Build it");
    assert!(context
        .omissions
        .iter()
        .any(|item| item.reason == "private_reasoning_omitted"));
    assert!(context
        .omissions
        .iter()
        .any(|item| item.reason == "runtime_event_omitted"));
}

#[test]
fn malformed_rows_are_explicit_and_secrets_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"token: sk-abcdefghijklmnop1234"}}"#,
            "not json",
        ],
        &[],
    );
    let context = normalize(&input(&path, Platform::Claude, cutoff, &digest)).unwrap();
    assert!(context.user_requests[0].text.contains("[REDACTED]"));
    assert!(!context.user_requests[0]
        .text
        .contains("sk-abcdefghijklmnop1234"));
    assert!(context
        .omissions
        .iter()
        .any(|item| item.reason == "malformed_or_non_object_row"));
    verify_context_receipt(&context).unwrap();
}

#[test]
fn unlabelled_long_base64_blob_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let blob = "A".repeat(768);
    let row = format!(
        r#"{{"type":"user","sessionId":"session-1","cwd":"/repo","message":{{"content":"prefix {blob} suffix"}}}}"#
    );
    let (cutoff, digest) = write_rows(&path, &[&row], &[]);
    let context = normalize(&input(&path, Platform::Claude, cutoff, &digest)).unwrap();
    let text = &context.user_requests[0].text;
    assert!(text.contains("[BINARY_BLOB_REMOVED]"));
    assert!(!text.contains(&blob));
}

#[test]
fn user_request_preserves_whitespace_while_redacting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"  keep\n  token: sk-abcdefghijklmnop1234  "}}"#,
        ],
        &[],
    );
    let context = normalize(&input(&path, Platform::Claude, cutoff, &digest)).unwrap();
    assert_eq!(
        context.user_requests[0].text,
        "  keep\n  [REDACTED]  "
    );
}

#[test]
fn codex_string_user_request_preserves_whitespace_and_omits_notifications() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_rows(
        &path,
        &[
            r#"{"type":"session_meta","payload":{"id":"session-1","cwd":"/repo"}}"#,
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"  Keep exact whitespace.  "}}"#,
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<subagent_notification>synthetic completion</subagent_notification>"}]}}"#,
        ],
        &[],
    );
    let context = normalize(&input(&path, Platform::Codex, cutoff, &digest)).unwrap();
    assert_eq!(context.user_requests.len(), 1);
    assert_eq!(context.user_requests[0].text, "  Keep exact whitespace.  ");
}
