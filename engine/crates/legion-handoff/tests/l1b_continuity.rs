//! Continuity-bound packet checks: changed-since accounting, memory record,
//! artifact roots, and bounded identifier accounting. Mechanical only.

use legion_handoff::l1_port::continuity::{normalize, ContinuityContext, ContinuityInput};
use legion_handoff::l1_port::live_state::{bare_hex, SourceBlock};
use legion_handoff::l1_port::pointer::Platform;
use legion_handoff::l1_port::{run as bootstrap_run, RunEnv};
use legion_handoff::l1b_port::{artifact_root_errors, continuity_errors, run as validate_run};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const OLD_PIN: &str = "license 0.3.0 held back";
const NEW_PIN: &str = "license 0.3.0 adopted";

fn transcript(dir: &Path) -> (PathBuf, u64, String) {
    let path = dir.join("session-1.jsonl");
    let turns = [
        ("user", "kickoff, tracking issue #111"),
        ("assistant", "acknowledged"),
        ("user", "PR 12 needs review"),
        ("assistant", "reviewing"),
        ("user", "exception M21 is still open"),
        ("assistant", "noted"),
    ];
    let mut body = String::new();
    for (role, text) in turns {
        body.push_str(&format!(
            r#"{{"type":"{role}","sessionId":"session-1","cwd":"/repo","message":{{"content":"{text}"}}}}"#
        ));
        body.push('\n');
    }
    fs::write(&path, &body).unwrap();
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    (path, body.len() as u64, digest)
}

fn block_value(changed: bool, memory: serde_json::Value) -> serde_json::Value {
    let mut block = serde_json::json!({
        "schema": "legion.handoff.source-block.v1",
        "trust": "source_assertion",
        "heads": [{"repo": ".", "sha": "0123456789abcdef0123456789abcdef01234567"}],
        "uncommitted": [],
        "in_flight": [],
    });
    if !memory.is_null() {
        block["memory"] = memory;
    }
    if changed {
        block["changed_since"] = serde_json::json!([{
            "id": "C1",
            "decision": "license pin",
            "old": OLD_PIN,
            "new": NEW_PIN,
            "when": "2026-10-22T10:00:00Z",
            "since": {"cutoff_bytes": 10},
            "evidence": "commit 0123456789abcdef0123456789abcdef01234567 package.json:12"
        }]);
    }
    block
}

fn context(dir: &Path, block: serde_json::Value) -> (ContinuityContext, PathBuf) {
    let (path, cutoff, digest) = transcript(dir);
    let block = SourceBlock::parse(&block.to_string()).unwrap();
    let input = ContinuityInput::new(
        &path,
        Platform::Claude,
        "session-1",
        "/repo",
        cutoff,
        digest,
    )
    .with_source_block(block);
    (
        normalize(&input).unwrap(),
        dir.join("session-1.context.json"),
    )
}

struct Packet {
    memory: String,
    window: String,
    accounted: String,
    omitted: String,
    decision: String,
    artifact_rows: String,
    validator_flag: &'static str,
}

impl Packet {
    fn good() -> Self {
        Packet {
            memory: "- **Source memory:** /home/u/.claude/projects/p/memory\n".into(),
            window: "- **Identifier accounting window:** last 2 turns\n".into(),
            accounted: format!("- **Changed-since accounted:** C1 — pin now reads {NEW_PIN}\n"),
            omitted: String::new(),
            decision: "| D1 | License pin is adopted: license 0.3.0 adopted | transcript | LOCKED | never |\n".into(),
            artifact_rows: "| register | /home/u/work/register.md | tracker | draft | n/a | checked |\n".into(),
            validator_flag: "--context /ctx/session-1.context.json",
        }
    }

    fn render(&self, ctx: &ContinuityContext, ctx_path: &Path) -> String {
        let digest = ctx.receipt.source_block_sha256.clone().unwrap_or_default();
        format!(
            "- **Source evidence mode:** TRANSCRIPT_INGEST\n\
             - **Transcript evidence path:** `{}`\n\
             - **Source prefix receipt:** PLATFORM: claude SESSION_ID: session-1 CUTOFF_BYTES: {} SHA256:{} PARSER_VERSION: x\n\
             - **Source assertion (hash-bound claim, not transcript evidence):** {digest}\n\
             {}{}{}{}\
             ## 4. Decisions, Invariants & User Corrections\n\
             | ID | Decision | Source | Status | Reopen |\n|---|---|---|---|---|\n{}\
             ## 5. Artifacts & Evidence\n\
             | A | Path | R | S | V | C |\n|---|---|---|---|---|---|\n{}\
             ## 6. Failures, Dead Ends & Attempts\n\
             Work on #12 continues.\n\
             - **Validator command:**\n\n```text\nlegion script handoff/validate-handoff p.md --write-receipt r.json {}\n```\n\
             - **Receiver receipt check:**\n\n```text\nlegion script handoff/validate-handoff p.md --verify-receipt r.json {}\n```\n",
            ctx_path.display(),
            ctx.source.cutoff_bytes,
            bare_hex(&ctx.source.sha256),
            self.memory,
            self.window,
            self.accounted,
            self.omitted,
            self.decision,
            self.artifact_rows,
            self.validator_flag,
            self.validator_flag,
        )
    }
}

fn check(packet: &Packet, ctx: &ContinuityContext, ctx_path: &Path) -> Vec<String> {
    continuity_errors(&packet.render(ctx, ctx_path), ctx, ctx_path, false)
}

fn has(errors: &[String], needle: &str) -> bool {
    errors.iter().any(|e| e.contains(needle))
}

fn memory() -> serde_json::Value {
    serde_json::json!({"dir": "/home/u/.claude/projects/p/memory"})
}

#[test]
fn accounted_changes_and_covered_identifiers_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(true, memory()));
    let mut packet = Packet::good();
    // exception M21 is in the window; the packet carries #12 in its body and
    // omits M21 with a reason.
    packet.omitted = "- **Omitted identifier:** exception M21 — unrelated to this task\n".into();
    let errors = check(&packet, &ctx, &path);
    assert!(
        errors
            .iter()
            .all(|e| !e.contains("accounted") && !e.contains("LOCKED") && !e.contains("reference")),
        "{errors:?}"
    );
}

#[test]
fn locked_decision_with_superseded_value_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(true, memory()));
    let mut packet = Packet::good();
    packet.decision = format!("| D1 | Pin policy: {OLD_PIN} | transcript | LOCKED | never |\n");
    let errors = check(&packet, &ctx, &path);
    assert!(
        has(&errors, "as LOCKED with the superseded value"),
        "{errors:?}"
    );
    // The same text as an assumption is not a locked claim.
    packet.decision =
        format!("| D1 | Pin policy: {OLD_PIN} | transcript | ACTIVE_ASSUMPTION | never |\n");
    assert!(!has(&check(&packet, &ctx, &path), "superseded"));
    // A locked row that states both old and new documents the change.
    packet.decision = format!("| D1 | {OLD_PIN} then {NEW_PIN} | transcript | LOCKED | never |\n");
    assert!(!has(&check(&packet, &ctx, &path), "superseded"));
}

#[test]
fn unaccounted_unknown_and_vague_changes_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(true, memory()));
    let mut packet = Packet::good();
    packet.accounted = String::new();
    assert!(has(&check(&packet, &ctx, &path), "unaccounted change C1"));

    packet.accounted = "- **Changed-since accounted:** C9 — pin now reads whatever\n".into();
    let errors = check(&packet, &ctx, &path);
    assert!(has(&errors, "unknown change id C9") && has(&errors, "unaccounted change C1"));

    packet.accounted = "- **Changed-since accounted:** C1 — handled\n".into();
    assert!(has(
        &check(&packet, &ctx, &path),
        "must restate the new value"
    ));

    packet.accounted = format!(
        "- **Changed-since accounted:** C1 — pin now reads {NEW_PIN}\n\
         - **Changed-since accounted:** C1 — pin now reads {NEW_PIN}\n"
    );
    assert!(has(&check(&packet, &ctx, &path), "more than once"));
}

#[test]
fn changed_since_is_bound_to_prior_receipt_and_cutoff() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cutoff, digest) = transcript(dir.path());
    let parse = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut block = block_value(true, memory());
        edit(&mut block);
        SourceBlock::parse(&block.to_string())
    };
    let input = |block: SourceBlock| {
        ContinuityInput::new(
            &path,
            Platform::Claude,
            "session-1",
            "/repo",
            cutoff,
            &digest,
        )
        .with_source_block(block)
    };

    // Baseline cutoff at or after the frozen cutoff is not a prior state.
    let late =
        parse(&|b| b["changed_since"][0]["since"] = serde_json::json!({"cutoff_bytes": cutoff}))
            .unwrap();
    assert!(normalize(&input(late)).unwrap_err().contains("not earlier"));

    // A baseline receipt equal to the current prefix is the current state.
    let same =
        parse(&|b| b["changed_since"][0]["since"] = serde_json::json!({"receipt_sha256": digest}))
            .unwrap();
    assert!(normalize(&input(same))
        .unwrap_err()
        .contains("current prefix"));

    // A genuine prior receipt digest is accepted.
    let prior = "ab".repeat(32);
    let ok =
        parse(&|b| b["changed_since"][0]["since"] = serde_json::json!({"receipt_sha256": prior}))
            .unwrap();
    assert!(normalize(&input(ok)).is_ok());

    // Shape failures.
    let err = |edit: &dyn Fn(&mut serde_json::Value)| parse(edit).unwrap_err();
    assert!(
        err(&|b| b["changed_since"][0]["since"] = serde_json::json!({}))
            .contains("prior receipt_sha256 or cutoff_bytes")
    );
    assert!(
        err(&|b| b["changed_since"][0]["new"] = serde_json::json!(OLD_PIN))
            .contains("lists no change")
    );
    assert!(
        err(&|b| b["changed_since"][0]["when"] = serde_json::json!("yesterday"))
            .contains("YYYY-MM-DD")
    );
    assert!(
        err(&|b| b["changed_since"][0]["evidence"] = serde_json::json!(" ")).contains("non-empty")
    );
    assert!(
        err(&|b| b["changed_since"][0]["since"] = serde_json::json!({"receipt_sha256": "abc"}))
            .contains("64-hex")
    );
    assert!(err(
        &|b| b["changed_since"][0]["new"] = serde_json::json!("api_key: abcdefghijklmnop1234")
    )
    .contains("secret"));
    assert!(err(&|b| {
        let first = b["changed_since"][0].clone();
        b["changed_since"].as_array_mut().unwrap().push(first);
    })
    .contains("duplicate changed_since id"));
}

#[test]
fn memory_directory_or_explicit_absence_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(false, serde_json::Value::Null));
    let mut packet = Packet::good();
    packet.accounted.clear();
    assert!(has(
        &check(&packet, &ctx, &path),
        "does not record a memory directory"
    ));

    let (ctx, path) = context(dir.path(), block_value(false, memory()));
    packet.memory = "- **Source memory:** /somewhere/else\n".into();
    assert!(has(
        &check(&packet, &ctx, &path),
        "must record the source memory directory"
    ));
    packet.memory = "- **Source memory:** /home/u/.claude/projects/p/memory\n".into();
    assert!(!has(&check(&packet, &ctx, &path), "Source memory"));

    let absent = serde_json::json!({"absent_reason": "source profile has no auto-memory"});
    let (ctx, path) = context(dir.path(), block_value(false, absent));
    packet.memory = "- **Source memory:** ABSENT: source profile has no auto-memory\n".into();
    assert!(!has(&check(&packet, &ctx, &path), "Source memory"));
    packet.memory = "- **Source memory:** none\n".into();
    assert!(has(&check(&packet, &ctx, &path), "ABSENT: <reason>"));

    // Exactly one of dir / absent_reason.
    let both = serde_json::json!({"dir": "/m", "absent_reason": "x"});
    assert!(SourceBlock::parse(&block_value(false, both).to_string())
        .unwrap_err()
        .contains("exactly one"));
    let relative = serde_json::json!({"dir": "memory"});
    assert!(
        SourceBlock::parse(&block_value(false, relative).to_string())
            .unwrap_err()
            .contains("absolute")
    );
}

#[test]
fn identifier_accounting_flags_omissions_in_the_declared_window() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(true, memory()));
    let mut packet = Packet::good();

    // exception M21 is in the last 2 turns and absent from the packet.
    let errors = check(&packet, &ctx, &path);
    assert!(has(&errors, "reference exception:M21"), "{errors:?}");
    // #111 is outside the last 2 turns, so it is not demanded.
    assert!(!has(&errors, "#111"));

    // Widening the window to 3 turns demands #111 too.
    packet.window = "- **Identifier accounting window:** last 3 turns\n".into();
    assert!(has(&check(&packet, &ctx, &path), "reference #111"));

    // An omission needs a reason and must name a reference in the window.
    packet.omitted = "- **Omitted identifier:** exception M21 — x\n\
                      - **Omitted identifier:** #111 — tracked in a separate finished lane\n"
        .into();
    let errors = check(&packet, &ctx, &path);
    assert!(has(&errors, "needs a concrete reason"), "{errors:?}");
    packet.omitted = "- **Omitted identifier:** exception M21 — unrelated to this task\n\
                      - **Omitted identifier:** #111 — tracked in a separate finished lane\n"
        .into();
    assert!(!has(&check(&packet, &ctx, &path), "reference"));
    packet
        .omitted
        .push_str("- **Omitted identifier:** #999 — never mentioned anywhere\n");
    assert!(has(
        &check(&packet, &ctx, &path),
        "does not appear in the last 3 turns"
    ));

    // The omission line itself never satisfies the packet-body check.
    let mut only_omitted = Packet::good();
    only_omitted.omitted = String::new();
    only_omitted.window = "- **Identifier accounting window:** last 2 turns\n".into();
    assert!(has(&check(&only_omitted, &ctx, &path), "exception:M21"));

    // The window must be declared and bounded.
    packet.window = "- **Identifier accounting window:** recent turns\n".into();
    assert!(has(&check(&packet, &ctx, &path), "must declare the window"));
    packet.window = "- **Identifier accounting window:** last 0 turns\n".into();
    assert!(has(&check(&packet, &ctx, &path), "must declare the window"));
}

#[test]
fn packet_must_bind_prefix_digest_and_context_flag() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, path) = context(dir.path(), block_value(true, memory()));
    let mut packet = Packet::good();
    packet.validator_flag = "";
    let errors = check(&packet, &ctx, &path);
    assert!(has(&errors, "Validator command must include --context"));
    assert!(has(
        &errors,
        "Receiver receipt check must include --context"
    ));

    let text = Packet::good()
        .render(&ctx, &path)
        .replace(&bare_hex(&ctx.source.sha256), &"0".repeat(64));
    assert!(has(
        &continuity_errors(&text, &ctx, &path, false),
        "source prefix SHA256 does not match"
    ));
    let text = Packet::good().render(&ctx, &path).replace(
        &bare_hex(ctx.receipt.source_block_sha256.as_deref().unwrap()),
        &"1".repeat(64),
    );
    assert!(has(
        &continuity_errors(&text, &ctx, &path, false),
        "must carry the context's source block SHA-256"
    ));
    let text = Packet::good()
        .render(&ctx, &path)
        .replace("TRANSCRIPT_INGEST", "LIVE_CONTEXT");
    assert!(has(
        &continuity_errors(&text, &ctx, &path, false),
        "requires Source evidence mode"
    ));
    let text = Packet::good()
        .render(&ctx, &path)
        .replace(&path.display().to_string(), "/elsewhere/other.context.json");
    assert!(has(
        &continuity_errors(&text, &ctx, &path, false),
        "Transcript evidence path"
    ));
}

#[test]
fn artifact_roots_are_listed_and_durable_ones_resolve_outside_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch").join("register");
    fs::create_dir_all(&scratch).unwrap();
    let scratch_str = scratch.to_str().unwrap().to_string();
    let root_block = |path: &str, durable: bool| {
        let mut block = block_value(false, memory());
        block["artifact_roots"] = serde_json::json!([{
            "path": path, "owner": "legion", "rerender": "render-register --html", "durable": durable
        }]);
        block
    };

    // Durable root inside scratch storage is rejected and must be listed.
    let (ctx, path) = context(dir.path(), root_block(&scratch_str, true));
    let mut packet = Packet::good();
    packet.accounted.clear();
    packet.artifact_rows = "| other | /home/u/other | x | draft | n/a | checked |\n".into();
    let errors = check(&packet, &ctx, &path);
    assert!(
        has(&errors, "not in the Artifacts & Evidence table"),
        "{errors:?}"
    );
    assert!(
        has(&errors, "resolves into temp/cache/scratch storage"),
        "{errors:?}"
    );

    // A non-durable root only needs to be listed.
    let (ctx, path) = context(dir.path(), root_block(&scratch_str, false));
    packet.artifact_rows =
        format!("| register | {scratch_str} | tracker | draft | n/a | checked |\n");
    let errors = check(&packet, &ctx, &path);
    assert!(
        !has(&errors, "artifact root") && !has(&errors, "scratch"),
        "{errors:?}"
    );

    // A durable root that does not exist is not resolvable.
    let missing = dir.path().join("nope");
    let (ctx, path) = context(dir.path(), root_block(missing.to_str().unwrap(), true));
    packet.artifact_rows = format!(
        "| register | {} | tracker | draft | n/a | checked |\n",
        missing.display()
    );
    assert!(has(&check(&packet, &ctx, &path), "not resolvable"));

    // Relative root paths are not accepted in the block.
    assert!(
        SourceBlock::parse(&root_block("rel/path", true).to_string())
            .unwrap_err()
            .contains("absolute")
    );
    assert!(SourceBlock::parse(&root_block("/a/../b", true).to_string())
        .unwrap_err()
        .contains("'..'"));
}

#[test]
fn packet_storage_must_sit_inside_declared_artifact_root() {
    let dir = tempfile::tempdir().unwrap();
    let packet = dir.path().join("handoff.md");
    fs::write(&packet, "x").unwrap();
    let receipt = dir.path().join("handoff.receipt.json");

    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).unwrap();
    let errors = artifact_root_errors(&packet, &receipt, &[scratch], false);
    assert!(
        has(
            &errors,
            "cannot use temporary/cache/review-run/scratch storage"
        ),
        "{errors:?}"
    );

    let relative = artifact_root_errors(&packet, &receipt, &[PathBuf::from("rel")], false);
    assert!(has(&relative, "must be an absolute path"));

    let elsewhere = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let errors = artifact_root_errors(&packet, &receipt, &[elsewhere], false);
    assert!(
        has(&errors, "outside every declared --artifact-root"),
        "{errors:?}"
    );
}

#[test]
fn validator_cli_requires_context_for_transcript_ingest_and_rejects_bad_combos() {
    let dir = tempfile::tempdir().unwrap();
    let packet = dir.path().join("h.md");
    fs::write(&packet, "- **Source evidence mode:** TRANSCRIPT_INGEST\n").unwrap();
    let receipt = dir.path().join("h.receipt.json");
    let run = |args: Vec<String>| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = validate_run(&args, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    };
    let base = vec![
        packet.to_str().unwrap().to_string(),
        "--write-receipt".to_string(),
        receipt.to_str().unwrap().to_string(),
    ];
    let (code, out, _) = run(base.clone());
    assert_eq!(code, 1);
    assert!(
        out.contains("TRANSCRIPT_INGEST packets must be validated with --context"),
        "{out}"
    );
    assert!(!receipt.exists());

    let mut with_context = base.clone();
    with_context.extend([
        "--context".into(),
        dir.path().join("none.json").to_str().unwrap().to_string(),
    ]);
    let (code, out, _) = run(with_context);
    assert_eq!(code, 1);
    assert!(
        out.contains("continuity context cannot be verified"),
        "{out}"
    );
    assert!(!receipt.exists());

    let (code, _, err) = run(vec![
        packet.to_str().unwrap().to_string(),
        "--template-self-check".into(),
        "--context".into(),
        "c.json".into(),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("invalid combination"), "{err}");
    let (code, _, err) = run(vec![
        packet.to_str().unwrap().to_string(),
        "--context-receipt".into(),
        "r.json".into(),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("requires --context"), "{err}");
}

#[test]
fn bootstrap_artifact_root_is_validated_and_reported() {
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
    let cli = |extra: &[&str]| {
        let mut argv: Vec<String> = [
            "bootstrap",
            "--platform",
            "claude",
            "--session-id",
            "session-1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        argv.extend(extra.iter().map(|s| s.to_string()));
        let mut out = Vec::new();
        let code = bootstrap_run(&argv, &env, &mut out);
        (code, String::from_utf8(out).unwrap())
    };
    let scratch = ws.path().join("scratch");
    fs::create_dir_all(&scratch).unwrap();
    let (code, text) = cli(&["--artifact-root", scratch.to_str().unwrap()]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("scratch storage"), "{text}");
    let (code, text) = cli(&["--artifact-root", "relative/root"]);
    assert_eq!(code, 2, "{text}");

    let root = env!("CARGO_MANIFEST_DIR");
    let (code, text) = cli(&["--artifact-root", root]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(
            &std::path::Path::new("handoffs")
                .join("2026-10-30")
                .join("session-1.context.json")
                .display()
                .to_string()
        ),
        "{text}"
    );
    assert!(text.contains("--artifact-root"), "{text}");
    assert!(
        text.contains("cannot certify semantic completeness"),
        "{text}"
    );
}
