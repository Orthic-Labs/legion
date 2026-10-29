//! Source assertion block, in-flight reconciliation, post-cutoff notes, and
//! target stop-guard wording.

use legion_handoff::l1_port::continuity::{normalize, verify_context_receipt, ContinuityInput};
use legion_handoff::l1_port::live_state::{
    append_note, check_reconciliation, verify_notes, NoteKind, Reconciliation, SourceBlock,
};
use legion_handoff::l1_port::pointer::Platform;
use legion_handoff::l1_port::{run, RunEnv};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn block_json() -> String {
    format!(
        r#"{{"schema":"legion.handoff.source-block.v1","trust":"source_assertion",
"heads":[{{"repo":".","sha":"{SHA}"}}],
"uncommitted":[
 {{"path":"src/a.rs","owner":"alchemist-1","state":"partial","reviewed":false}},
 {{"path":"src/b.rs","owner":"legion","state":"complete","reviewed":true}}],
"ownership_transfer":{{"repository":".","from":"source","to":"target"}},
"memory":{{"dir":"/home/u/.claude/projects/p/memory"}},
"in_flight":[
 {{"kind":"subagent","id":"agent-7","state":"stopped","output_path":"/tmp/agent-7.out","owner":"source"}},
 {{"kind":"broker_build","id":"req-9","state":"running","owner":"source"}}]}}"#
    )
}

fn reject(edit: impl Fn(String) -> String) -> String {
    SourceBlock::parse(&edit(block_json())).unwrap_err()
}

#[test]
fn block_accepts_valid_and_hash_is_whitespace_independent() {
    let a = SourceBlock::parse(&block_json()).unwrap();
    let compact: serde_json::Value = serde_json::from_str(&block_json()).unwrap();
    let b = SourceBlock::parse(&compact.to_string()).unwrap();
    assert_eq!(a.digest().unwrap(), b.digest().unwrap());
}

#[test]
fn block_rejects_malformed_claims() {
    assert!(reject(|s| s.replace(SHA, "abc123")).contains("40-character"));
    assert!(reject(|s| s.replace(SHA, &SHA.to_uppercase())).contains("40-character"));
    assert!(reject(|s| s.replace("src/a.rs", "/etc/passwd")).contains("repository-relative"));
    assert!(reject(|s| s.replace("src/a.rs", "../a.rs")).contains("'..'"));
    assert!(reject(|s| s.replace("src/a.rs", "C:/x")).contains("repository-relative"));
    assert!(reject(|s| s.replace("\"source_assertion\"", "\"transcript\"")).contains("trust"));
    assert!(reject(|s| s.replace(
        "\"complete\",\"reviewed\":true",
        "\"partial\",\"reviewed\":true"
    ))
    .contains("cannot be marked reviewed"));
    assert!(reject(|s| s
        .replace("req-9", "agent-7")
        .replace("broker_build", "subagent"))
    .contains("duplicate"));
    assert!(reject(|s| s.replace("\"heads\"", "\"extra\":1,\"heads\"")).contains("unknown field"));
}

fn write_transcript(path: &Path) -> (u64, String) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let row =
        r#"{"type":"user","sessionId":"session-1","cwd":"/repo","message":{"content":"do it"}}"#;
    let mut f = fs::File::create(path).unwrap();
    writeln!(f, "{row}").unwrap();
    let prefix = format!("{row}\n");
    (
        prefix.len() as u64,
        hex::encode(Sha256::digest(prefix.as_bytes())),
    )
}

fn input(path: &Path, cutoff: u64, digest: &str) -> ContinuityInput {
    ContinuityInput::new(path, Platform::Claude, "session-1", "/repo", cutoff, digest)
}

#[test]
fn receipt_binds_block_and_keeps_it_out_of_transcript_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session-1.jsonl");
    let (cutoff, digest) = write_transcript(&path);
    let block = SourceBlock::parse(&block_json()).unwrap();
    let context =
        normalize(&input(&path, cutoff, &digest).with_source_block(block.clone())).unwrap();
    verify_context_receipt(&context).unwrap();
    assert_eq!(
        context.receipt.source_block_sha256,
        Some(block.digest().unwrap())
    );
    assert_eq!(context.source_assertion.as_ref(), Some(&block));
    assert!(context.events.iter().all(|e| !e.text.contains("agent-7")));

    let mut tampered = context.clone();
    tampered.source_assertion.as_mut().unwrap().uncommitted[0].reviewed = true;
    // `partial` + reviewed is invalid, and digest no longer matches either way.
    assert!(verify_context_receipt(&tampered).is_err());
    let mut dropped = context.clone();
    dropped.source_assertion = None;
    assert!(verify_context_receipt(&dropped).is_err());

    let plain = normalize(&input(&path, cutoff, &digest)).unwrap();
    assert!(plain.source_assertion.is_none() && plain.receipt.source_block_sha256.is_none());
    let json = serde_json::to_string(&plain).unwrap();
    assert!(!json.contains("sourceAssertion") && !json.contains("sourceBlockSha256"));
}

#[test]
fn reconciliation_requires_every_declared_item_with_evidence() {
    let block = SourceBlock::parse(&block_json()).unwrap();
    let rec = |items: &str| -> Reconciliation {
        serde_json::from_str(&format!(
            r#"{{"schema":"legion.handoff.reconciliation.v1","items":[{items}]}}"#
        ))
        .unwrap()
    };
    let a = r#"{"kind":"subagent","id":"agent-7","resolution":"stopped","evidence":"output tail shows abort"}"#;
    let b = r#"{"kind":"broker_build","id":"req-9","resolution":"completed","evidence":"receipt read"}"#;
    assert!(check_reconciliation(&block, &rec(&format!("{a},{b}"))).is_ok());
    assert!(check_reconciliation(&block, &rec(a))
        .unwrap_err()
        .contains("not reconciled"));
    assert!(check_reconciliation(&block, &rec(&format!("{a},{a},{b}"))).is_err());
    let blank = b.replace("receipt read", " ");
    assert!(check_reconciliation(&block, &rec(&format!("{a},{blank}"))).is_err());
    let stray = r#"{"kind":"subagent","id":"nope","resolution":"abandoned","evidence":"x"}"#;
    assert!(check_reconciliation(&block, &rec(&format!("{a},{b},{stray}"))).is_err());
}

#[test]
fn notes_chain_detects_tamper_reorder_truncation_and_wrong_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.notes.jsonl");
    let prefix = "ab".repeat(32);
    assert_eq!(verify_notes(&path, &prefix).unwrap().notes.len(), 0);
    append_note(
        &path,
        &prefix,
        NoteKind::AgentStopped,
        "src",
        "agent-7 stopped",
        "t1".into(),
    )
    .unwrap();
    append_note(
        &path,
        &prefix,
        NoteKind::BuildFinished,
        "src",
        "token sk-abcdefghijklmnopqrstuv done",
        "t2".into(),
    )
    .unwrap();
    let ok = verify_notes(&path, &prefix).unwrap();
    assert_eq!(ok.notes.len(), 2);
    assert!(!ok.notes[1].text.contains("sk-abcdefghijklmnopqrstuv"));
    assert!(verify_notes(&path, &"cd".repeat(32)).is_err());

    let original = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = original.lines().collect();
    fs::write(&path, original.replace("agent-7 stopped", "agent-7 fine")).unwrap();
    assert!(verify_notes(&path, &prefix)
        .unwrap_err()
        .contains("hash mismatch"));
    fs::write(&path, format!("{}\n{}\n", lines[1], lines[0])).unwrap();
    assert!(verify_notes(&path, &prefix).is_err());
    fs::write(&path, format!("{}\n", lines[1])).unwrap();
    assert!(verify_notes(&path, &prefix).is_err());
    fs::write(&path, &original[..original.len() - 5]).unwrap();
    assert!(verify_notes(&path, &prefix).is_err());
    // Appending onto a broken chain is refused.
    assert!(append_note(&path, &prefix, NoteKind::Other, "src", "x", "t".into()).is_err());
}

fn cli(args: &[&str], env: &RunEnv) -> (i32, String) {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let code = run(&argv, env, &mut out);
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn cli_end_to_end_bootstrap_continuity_reconcile_and_notes() {
    let home = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let ws_str = ws.path().to_str().unwrap().to_string();
    let transcript = home.path().join(".claude/projects/p/session-1.jsonl");
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let row = format!(
        r#"{{"type":"user","sessionId":"session-1","cwd":{},"message":{{"content":"do it"}}}}"#,
        serde_json::to_string(&ws_str).unwrap()
    );
    fs::write(&transcript, format!("{row}\n")).unwrap();
    let env = RunEnv {
        home: home.path().to_path_buf(),
        cwd: ws.path().to_path_buf(),
        today: "2026-10-23".into(),
    };
    let live_in = ws.path().join("live.json");
    fs::write(&live_in, block_json()).unwrap();
    let live_out = ws.path().join("out/session-1.source-block.json");

    // Invalid block is refused before any prompt is produced.
    fs::write(ws.path().join("bad.json"), block_json().replace(SHA, "zz")).unwrap();
    let (code, text) = cli(
        &[
            "bootstrap",
            "--platform",
            "claude",
            "--session-id",
            "session-1",
            "--live-state",
            ws.path().join("bad.json").to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(code, 2, "{text}");

    let (code, text) = cli(
        &[
            "bootstrap",
            "--platform",
            "claude",
            "--session-id",
            "session-1",
            "--live-state",
            live_in.to_str().unwrap(),
            "--live-state-out",
            live_out.to_str().unwrap(),
            "--json",
        ],
        &env,
    );
    assert_eq!(code, 0, "{text}");
    let pointer: serde_json::Value = serde_json::from_str(&text).unwrap();
    let assertion = &pointer["source_assertion"];
    assert_eq!(assertion["trust"], "source_assertion");
    assert_eq!(assertion["in_flight"].as_array().unwrap().len(), 2);
    let block_sha = assertion["sha256"].as_str().unwrap().to_string();

    let (code, prompt) = cli(
        &[
            "bootstrap",
            "--platform",
            "claude",
            "--session-id",
            "session-1",
            "--live-state",
            live_in.to_str().unwrap(),
            "--live-state-out",
            live_out.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(code, 0, "{prompt}");
    assert!(prompt.contains("--source-block "), "{prompt}");
    assert!(prompt.contains("reconcile every item"));
    assert!(prompt.contains("Do not end your turn"));
    assert!(prompt.contains(".notes.jsonl"));

    let context = ws.path().join("tasks/session-1.context.json");
    let source_path = pointer["source_path"].as_str().unwrap();
    let cutoff = pointer["cutoff_bytes"].as_u64().unwrap().to_string();
    let prefix_sha = pointer["sha256"].as_str().unwrap();
    let continuity = |extra: &[&str]| {
        let mut args = vec![
            "continuity",
            "--pointer",
            source_path,
            "--platform",
            "claude",
            "--session-id",
            "session-1",
            "--workspace",
            ws_str.as_str(),
            "--cutoff-bytes",
            cutoff.as_str(),
            "--sha256",
            prefix_sha,
            "--output",
            context.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        cli(&args, &env)
    };
    // Wrong digest and half-supplied flags are rejected.
    assert_eq!(
        continuity(&[
            "--source-block",
            live_out.to_str().unwrap(),
            "--source-block-sha256",
            "sha256:00"
        ])
        .0,
        2
    );
    assert_eq!(
        continuity(&["--source-block", live_out.to_str().unwrap()]).0,
        2
    );
    let (code, text) = continuity(&[
        "--source-block",
        live_out.to_str().unwrap(),
        "--source-block-sha256",
        &block_sha,
    ]);
    assert_eq!(code, 0, "{text}");

    let receipt = ws.path().join("tasks/session-1.context.receipt.json");
    let verify = |extra: &[&str]| {
        let mut args = vec![
            "continuity",
            "--output",
            context.to_str().unwrap(),
            "--verify-receipt",
            receipt.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        cli(&args, &env)
    };
    let (code, text) = verify(&[]);
    assert_eq!(code, 1, "unreconciled in-flight work must fail: {text}");
    assert!(text.contains("SOURCE_ASSERTION") && text.contains("NOT transcript evidence"));
    assert!(text.contains("IN_FLIGHT_UNRECONCILED: 2"));

    let rec = ws.path().join("rec.json");
    fs::write(
        &rec,
        r#"{"schema":"legion.handoff.reconciliation.v1","items":[
        {"kind":"subagent","id":"agent-7","resolution":"stopped","evidence":"tail shows abort"}]}"#,
    )
    .unwrap();
    assert_eq!(verify(&["--reconciliation", rec.to_str().unwrap()]).0, 1);
    fs::write(
        &rec,
        r#"{"schema":"legion.handoff.reconciliation.v1","items":[
        {"kind":"subagent","id":"agent-7","resolution":"stopped","evidence":"tail shows abort"},
        {"kind":"broker_build","id":"req-9","resolution":"completed","evidence":"receipt read"}]}"#,
    )
    .unwrap();
    let (code, text) = verify(&["--reconciliation", rec.to_str().unwrap()]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("RECONCILE_PASS"));

    // Notes appended by the source are discovered next to the context and folded.
    let notes = ws.path().join("tasks/session-1.notes.jsonl");
    let (code, text) = cli(
        &[
            "notes",
            "append",
            "--notes",
            notes.to_str().unwrap(),
            "--prefix-sha256",
            prefix_sha,
            "--kind",
            "agent_stopped",
            "--author",
            "source",
            "--text",
            "agent-7 exited",
        ],
        &env,
    );
    assert_eq!(code, 0, "{text}");
    let (code, text) = verify(&["--reconciliation", rec.to_str().unwrap()]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("NOTES_PASS: 1 note(s)") && text.contains("agent-7 exited"));
    let original = fs::read_to_string(&notes).unwrap();
    fs::write(&notes, original.replace("exited", "alive")).unwrap();
    assert_eq!(verify(&["--reconciliation", rec.to_str().unwrap()]).0, 1);
}

#[test]
fn default_prompt_without_block_declares_unknown_state_and_stop_guard() {
    use legion_handoff::l1_port::pointer::{paste_prompt, SourcePointer};
    let pointer = SourcePointer {
        schema: "handoff.source-pointer.v1".into(),
        platform: "claude".into(),
        session_id: "s".into(),
        workspace: "/w".into(),
        source_path: "/w/s.jsonl".into(),
        cutoff_bytes: 1,
        sha256: "aa".into(),
        last_complete_row: 1,
        last_complete_offset: 1,
        last_event_type: "user".into(),
        last_event_timestamp: "t".into(),
        selection_method: "exact_session_id".into(),
        created_at: "t".into(),
    };
    let prompt = paste_prompt(&pointer, Path::new("/w"), "2026-10-23");
    assert!(prompt.contains("SOURCE ASSERTIONS: none supplied"));
    assert!(prompt.contains("permanent packet, its receipt, and READBACK all exist"));
    assert!(!prompt.contains("--source-block"));
}

#[test]
fn legacy_block_digest_is_unchanged_by_new_optional_fields() {
    let legacy = SourceBlock::parse(&block_json().replace(
        "\"memory\":{\"dir\":\"/home/u/.claude/projects/p/memory\"},",
        "",
    ))
    .unwrap();
    let value = serde_json::to_string(&legacy).unwrap();
    assert!(
        !value.contains("changed_since")
            && !value.contains("memory")
            && !value.contains("artifact_roots")
    );
    assert!(legacy.require_handoff_complete().is_err());
    let with_memory = SourceBlock::parse(&block_json()).unwrap();
    assert!(with_memory.require_handoff_complete().is_ok());
    assert_ne!(legacy.digest().unwrap(), with_memory.digest().unwrap());
}

#[test]
fn bootstrap_refuses_a_block_without_memory_record() {
    let home = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let ws_str = ws.path().to_str().unwrap().to_string();
    let transcript = home.path().join(".claude/projects/p/session-1.jsonl");
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let row = format!(
        r#"{{"type":"user","sessionId":"session-1","cwd":{},"message":{{"content":"do it"}}}}"#,
        serde_json::to_string(&ws_str).unwrap()
    );
    fs::write(&transcript, format!("{row}\n")).unwrap();
    let env = RunEnv {
        home: home.path().to_path_buf(),
        cwd: ws.path().to_path_buf(),
        today: "2026-10-30".into(),
    };
    let no_memory = ws.path().join("no-memory.json");
    fs::write(
        &no_memory,
        block_json().replace(
            "\"memory\":{\"dir\":\"/home/u/.claude/projects/p/memory\"},",
            "",
        ),
    )
    .unwrap();
    let (code, text) = cli(
        &[
            "bootstrap",
            "--platform",
            "claude",
            "--session-id",
            "session-1",
            "--live-state",
            no_memory.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("must record memory"), "{text}");
}
