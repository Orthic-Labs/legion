//! Integration tests closing the R18R26 packet's gaps:
//! `skills/designer/engine/scripts/live-commit-manual-edits.mjs`'s
//! directory-walk rollback/snapshot + CLI entry point
//! (`legion_runtime::wf_port::r18::{rollback, commit_cli}`), and
//! `skills/designer/engine/scripts/live-wrap.mjs`'s `wrapCli()` argv/exit
//! orchestration + Svelte-injection branch
//! (`legion_runtime::wf_port::w2_020::wrap_cli`).
//!
//! Per-function unit tests already live beside the code; these exercise the
//! public API end to end through the crate boundary.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_runtime::wf_port::r18::{
    commit_manual_edits, rollback_changed_files, run_cli, snapshot_rollback_files,
    CommitOptions,
};
use legion_runtime::wf_port::w2_018::copy_edit_agent::{ProcessRunResult, ProcessRunner, ProcessSpec};
use legion_runtime::wf_port::w2_020::wrap_cli;
use serde_json::json;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "legion-r18r26-{tag}-{}-{}",
        std::process::id(),
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct FailRunner;
impl ProcessRunner for FailRunner {
    fn run(&self, _spec: &ProcessSpec) -> ProcessRunResult {
        ProcessRunResult {
            success: false,
            spawn_failed: true,
            timed_out: false,
            stdout: String::new(),
            stderr: "unused in this test".to_string(),
        }
    }
}

#[test]
fn rollback_round_trip_via_public_api() {
    let dir = temp_dir("rollback");
    std::fs::write(dir.join("a.ts"), "before").unwrap();
    let snapshot = snapshot_rollback_files(&dir, None);
    std::fs::write(dir.join("a.ts"), "after").unwrap();
    let scope = vec!["a.ts".to_string()];
    let result = rollback_changed_files(&dir, &snapshot, &[], &scope);
    assert_eq!(result.rolled_back_files, vec!["a.ts".to_string()]);
    assert_eq!(std::fs::read_to_string(dir.join("a.ts")).unwrap(), "before");
}

#[test]
fn commit_manual_edits_reports_no_pending_edits_for_empty_batch() {
    let dir = temp_dir("commit");
    let env = HashMap::new();
    let opts = CommitOptions {
        cwd: dir,
        page_url: None,
        provider: Some("mock".to_string()),
        env: &env,
        timeout_ms: None,
        repair_only: false,
        transaction_id: None,
        batch: Some(json!({ "entries": [], "candidates": [] })),
    };
    let runner = FailRunner;
    let result = commit_manual_edits(opts, &runner);
    assert_eq!(result["reason"], "no_pending_edits");
}

#[test]
fn run_cli_help_matches_usage_banner() {
    let env = HashMap::new();
    let (code, out) = run_cli(&["--help".to_string()], PathBuf::from("."), &env);
    assert_eq!(code, 0);
    assert!(out.starts_with("Usage: legion-commit-manual-edits"));
}

#[test]
fn wrap_cli_wraps_element_end_to_end() {
    let dir = temp_dir("wrap");
    std::fs::write(
        dir.join("index.html"),
        "<div>\n  <section class=\"hero\">\n    <p>hi</p>\n  </section>\n</div>",
    )
    .unwrap();
    let env = HashMap::new();
    let args = vec![
        "--id".to_string(),
        "s1".to_string(),
        "--count".to_string(),
        "2".to_string(),
        "--file".to_string(),
        "index.html".to_string(),
        "--classes".to_string(),
        "hero".to_string(),
    ];
    let (code, out) = wrap_cli(&args, &dir, &env);
    assert_eq!(code, 0, "unexpected error: {out}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["file"], "index.html");
    let content = std::fs::read_to_string(dir.join("index.html")).unwrap();
    assert!(content.contains("impeccable-variants-start s1"));
}

#[test]
fn wrap_cli_help_flag() {
    let env = HashMap::new();
    let (code, out) = wrap_cli(&["--help".to_string()], &PathBuf::from("."), &env);
    assert_eq!(code, 0);
    assert!(out.contains("Usage: impeccable wrap"));
}
