//! Tests for the L1 literal port of `transcript_handoff.py`'s pointer logic.

use legion_handoff::l1_port::pointer::{
    build_pointer, candidates, normalized_path, paste_prompt, read_header, resolve_source,
    Platform,
};
use std::fs;
use std::io::Write;

fn write_jsonl(path: &std::path::Path, lines: &[&str]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(path).unwrap();
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
}

#[test]
fn normalized_path_matches_python_semantics() {
    assert_eq!(normalized_path("C:\\Foo\\Bar\\"), "c:/foo/bar");
    assert_eq!(normalized_path("/a/b/"), "/a/b");
    assert_eq!(normalized_path("/a/b"), "/a/b");
}

#[test]
fn candidates_finds_claude_transcripts_two_levels_deep() {
    let home = tempfile::tempdir().unwrap();
    let a = home.path().join(".claude/projects/proj1/session-a.jsonl");
    let b = home.path().join(".claude/projects/proj2/session-b.jsonl");
    write_jsonl(&a, &[r#"{"id":"a","cwd":"/work/proj1"}"#]);
    write_jsonl(&b, &[r#"{"id":"b","cwd":"/work/proj2"}"#]);

    let found = candidates(Platform::Claude, home.path()).unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.contains(&a));
    assert!(found.contains(&b));
}

#[test]
fn candidates_finds_codex_transcripts_three_levels_deep() {
    let home = tempfile::tempdir().unwrap();
    let a = home
        .path()
        .join(".codex/sessions/2026/09/23/thread-a.jsonl");
    write_jsonl(&a, &[r#"{"payload":{"id":"thread-a","cwd":"/work"}}"#]);

    let found = candidates(Platform::Codex, home.path()).unwrap();
    assert_eq!(found, vec![a]);
}

#[test]
fn candidates_on_missing_home_is_empty_not_error() {
    let home = tempfile::tempdir().unwrap();
    let found = candidates(Platform::Claude, home.path()).unwrap();
    assert!(found.is_empty());
}

#[test]
fn read_header_reads_claude_top_level_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-x.jsonl");
    write_jsonl(
        &path,
        &[
            r#"{"other":"row"}"#,
            r#"{"id":"session-x","cwd":"/work/repo"}"#,
        ],
    );
    let (id, workspace) = read_header(&path, Platform::Claude).unwrap();
    assert_eq!(id, "session-x");
    assert_eq!(workspace, "/work/repo");
}

#[test]
fn read_header_reads_codex_nested_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("thread-y.jsonl");
    write_jsonl(
        &path,
        &[r#"{"payload":{"session_id":"thread-y","cwd":"/work/other"}}"#],
    );
    let (id, workspace) = read_header(&path, Platform::Codex).unwrap();
    assert_eq!(id, "thread-y");
    assert_eq!(workspace, "/work/other");
}

#[test]
fn read_header_defaults_id_to_file_stem_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stem-name.jsonl");
    write_jsonl(&path, &["not json", "{}"]);
    let (id, workspace) = read_header(&path, Platform::Claude).unwrap();
    assert_eq!(id, "stem-name");
    assert_eq!(workspace, "");
}

#[test]
fn resolve_source_picks_newest_when_no_session_requested() {
    let home = tempfile::tempdir().unwrap();
    let older = home.path().join(".claude/projects/p1/older.jsonl");
    let newer = home.path().join(".claude/projects/p1/newer.jsonl");
    write_jsonl(&older, &[r#"{"id":"older","cwd":"/work"}"#]);
    std::thread::sleep(std::time::Duration::from_millis(10));
    write_jsonl(&newer, &[r#"{"id":"newer","cwd":"/work"}"#]);

    let (path, id, workspace, method) =
        resolve_source(Platform::Claude, None, None, home.path(), None).unwrap();
    assert_eq!(id, "newer");
    assert_eq!(workspace, "/work");
    assert_eq!(method, "newest_workspace_match");
    assert!(path.ends_with("newer.jsonl"));
}

#[test]
fn resolve_source_filters_by_requested_session_id() {
    let home = tempfile::tempdir().unwrap();
    let a = home.path().join(".claude/projects/p1/a.jsonl");
    let b = home.path().join(".claude/projects/p1/b.jsonl");
    write_jsonl(&a, &[r#"{"id":"session-a","cwd":"/work"}"#]);
    write_jsonl(&b, &[r#"{"id":"session-b","cwd":"/work"}"#]);

    let (path, id, _workspace, method) = resolve_source(
        Platform::Claude,
        Some("session-b"),
        None,
        home.path(),
        None,
    )
    .unwrap();
    assert_eq!(id, "session-b");
    assert_eq!(method, "exact_session_id");
    assert!(path.ends_with("b.jsonl"));
}

#[test]
fn resolve_source_errors_when_no_match() {
    let home = tempfile::tempdir().unwrap();
    let err = resolve_source(Platform::Claude, Some("missing"), None, home.path(), None)
        .unwrap_err();
    assert!(err.contains("no transcript matches"));
}

#[test]
fn build_pointer_computes_cutoff_and_sha256_over_complete_rows_only() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join(".claude/projects/p1/sess.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Two complete rows plus a trailing partial (no newline) row that must
    // be excluded from the cutoff and the hash.
    let mut file = fs::File::create(&path).unwrap();
    write!(
        file,
        "{}\n{}\n{}",
        r#"{"id":"sess","cwd":"/work","type":"user","timestamp":"t1"}"#,
        r#"{"type":"assistant","timestamp":"t2"}"#,
        r#"{"type":"partial"#
    )
    .unwrap();
    drop(file);

    let pointer = build_pointer(Platform::Claude, None, None, home.path(), None).unwrap();
    assert_eq!(pointer.schema, "handoff.source-pointer.v1");
    assert_eq!(pointer.session_id, "sess");
    assert_eq!(pointer.last_complete_row, 2);
    assert_eq!(pointer.last_event_type, "assistant");
    assert_eq!(pointer.last_event_timestamp, "t2");

    let complete_bytes = format!(
        "{}\n{}\n",
        r#"{"id":"sess","cwd":"/work","type":"user","timestamp":"t1"}"#,
        r#"{"type":"assistant","timestamp":"t2"}"#,
    );
    assert_eq!(pointer.cutoff_bytes, complete_bytes.len() as u64);
    use sha2::{Digest, Sha256};
    let expected = hex::encode(Sha256::digest(complete_bytes.as_bytes()));
    assert_eq!(pointer.sha256, expected);
}

#[test]
fn build_pointer_errors_on_transcript_with_no_complete_row() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join(".claude/projects/p1/empty.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(&path).unwrap();
    write!(file, "{{\"no newline\":true").unwrap();
    drop(file);

    let err = build_pointer(Platform::Claude, None, None, home.path(), None).unwrap_err();
    assert!(err.contains("no complete JSONL row"));
}

#[test]
fn paste_prompt_renders_posix_layout() {
    let home = tempfile::tempdir().unwrap();
    let pointer = legion_handoff::l1_port::pointer::SourcePointer {
        schema: "handoff.source-pointer.v1".into(),
        platform: "claude".into(),
        session_id: "sess-1".into(),
        workspace: "/work/repo".into(),
        source_path: "/home/u/.claude/projects/p1/sess-1.jsonl".into(),
        cutoff_bytes: 42,
        sha256: "abc123".into(),
        last_complete_row: 3,
        last_complete_offset: 42,
        last_event_type: "assistant".into(),
        last_event_timestamp: "t".into(),
        selection_method: "exact_session_id".into(),
        created_at: "2026-09-23T00:00:00.000000+00:00".into(),
    };
    let prompt = paste_prompt(&pointer, home.path(), "2026-09-23");
    assert!(prompt.contains("session_id: sess-1"));
    assert!(prompt.contains("sha256: abc123"));
    assert!(prompt.contains("python3 \"/work/repo/tools/skills/legion/skills/handoff/scripts/transcript-handoff.py\""));
    assert!(prompt.contains("continuity --pointer \"/home/u/.claude/projects/p1/sess-1.jsonl\""));
    assert!(prompt.contains("READBACK"));
}

#[test]
fn paste_prompt_renders_windows_drive_layout() {
    let home = tempfile::tempdir().unwrap();
    let pointer = legion_handoff::l1_port::pointer::SourcePointer {
        schema: "handoff.source-pointer.v1".into(),
        platform: "codex".into(),
        session_id: "sess-2".into(),
        workspace: "D:\\work\\repo".into(),
        source_path: "D:\\home\\.codex\\sessions\\a\\b\\c\\sess-2.jsonl".into(),
        cutoff_bytes: 10,
        sha256: "def456".into(),
        last_complete_row: 1,
        last_complete_offset: 10,
        last_event_type: "user".into(),
        last_event_timestamp: "t".into(),
        selection_method: "newest_workspace_match".into(),
        created_at: "2026-09-23T00:00:00.000000+00:00".into(),
    };
    let prompt = paste_prompt(&pointer, home.path(), "2026-09-23");
    assert!(prompt.contains("py -3.11"));
    assert!(prompt.contains("D:\\work\\repo\\tools\\skills\\legion\\skills\\handoff\\scripts\\transcript-handoff.py"));
}
