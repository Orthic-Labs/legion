//! Integration tests for packet r19: `completeCli()`
//! (`skills/designer/engine/scripts/live-complete.mjs`) and `liveCli()`
//! (`skills/designer/engine/scripts/live.mjs`) orchestration, ported onto
//! `legion_runtime::wf_port::w2_017::complete` and
//! `legion_runtime::wf_port::w2_020::live_cli`.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_runtime::wf_port::w2_017::complete::{completion_cli, HttpPoster};
use legion_runtime::wf_port::w2_020::live_cli::{inject_check, inject_port, live_cli, ProcessRunner};
use serde_json::{json, Value};

fn tmp_dir(name: &str) -> std::path::PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "legion-r19-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ─── complete.rs: completion_cli() ──────────────────────────────────────

struct NoServer;
impl HttpPoster for NoServer {
    fn post_poll(&self, _port: u64, _body: &Value) -> Option<Value> {
        None
    }
}

struct OkServer;
impl HttpPoster for OkServer {
    fn post_poll(&self, _port: u64, _body: &Value) -> Option<Value> {
        Some(json!({ "ok": true }))
    }
}

#[test]
fn completion_cli_missing_id_prints_usage_and_exits_1() {
    let cwd = tmp_dir("complete-usage");
    let (code, out) = completion_cli(&NoServer, &cwd, &[]);
    assert_eq!(code, 1);
    assert!(out.contains("Usage: node live-complete.mjs"));
}

#[test]
fn completion_cli_help_exits_0() {
    let cwd = tmp_dir("complete-help");
    let (code, out) = completion_cli(&NoServer, &cwd, &["--help".to_string()]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage:"));
}

#[test]
fn completion_cli_falls_back_to_session_store_when_no_server() {
    let cwd = tmp_dir("complete-fallback");
    let argv = vec!["--id".to_string(), "sess-1".to_string()];
    let (code, out) = completion_cli(&NoServer, &cwd, &argv);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["id"], json!("sess-1"));
    // `appendEvent` maps the 'complete' event type to phase 'completed'
    // (session-store.mjs's `applyEvent`, case 'complete' -> 'completed').
    assert_eq!(v["phase"], json!("completed"));

    // The durable journal file was actually written.
    let journal = cwd.join(".impeccable/live/sessions/sess-1.jsonl");
    assert!(journal.exists());
}

#[test]
fn completion_cli_discarded_and_error_statuses() {
    let cwd = tmp_dir("complete-discard");
    let argv = vec!["--id".to_string(), "sess-2".to_string(), "--discarded".to_string()];
    let (code, out) = completion_cli(&NoServer, &cwd, &argv);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["phase"], json!("discarded"));

    let cwd2 = tmp_dir("complete-error");
    let argv2 = vec!["--id".to_string(), "sess-3".to_string(), "--error".to_string(), "boom".to_string()];
    let (code2, out2) = completion_cli(&NoServer, &cwd2, &argv2);
    assert_eq!(code2, 0);
    let v2: Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(v2["phase"], json!("agent_error"));
}

#[test]
fn completion_cli_uses_server_when_server_json_present_and_poll_succeeds() {
    let cwd = tmp_dir("complete-server");
    std::fs::create_dir_all(cwd.join(".impeccable/live")).unwrap();
    std::fs::write(
        cwd.join(".impeccable/live/server.json"),
        json!({ "pid": std::process::id(), "port": 4567, "token": "tok" }).to_string(),
    )
    .unwrap();
    let argv = vec!["--id".to_string(), "sess-4".to_string()];
    let (code, out) = completion_cli(&OkServer, &cwd, &argv);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["id"], json!("sess-4"));
    // No prior journal entries, so `getSnapshot` rebuilds the default
    // snapshot (phase 'new') and returns it directly — `getSnapshot` only
    // returns null for a *completed* session, never for a missing one, so
    // the `snapshot?.phase || args.status` fallback is not reached here.
    assert_eq!(v["phase"], json!("new"));
}

// ─── live_cli.rs: live_cli() ─────────────────────────────────────────────

struct NeverRunner;
impl ProcessRunner for NeverRunner {
    fn start_live_server(&self, _cwd: &Path) -> String {
        String::new()
    }
}

#[test]
fn live_cli_help_exits_0() {
    let cwd = tmp_dir("live-help");
    let (code, out) = live_cli(&NeverRunner, &cwd, &["--help".to_string()]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage: node live.mjs"));
}

#[test]
fn live_cli_reports_context_missing_when_no_product_md() {
    let cwd = tmp_dir("live-context-missing");
    let (code, out) = live_cli(&NeverRunner, &cwd, &[]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], json!(false));
    assert_eq!(v["error"], json!("context_missing"));
    let missing = v["missing"].as_array().unwrap();
    assert!(missing.iter().any(|m| m == "PRODUCT.md"));
    assert_eq!(v["nextCommand"], json!("init"));
}

#[test]
fn live_cli_reports_config_missing_when_product_present_but_no_live_config() {
    let cwd = tmp_dir("live-config-missing");
    // Both PRODUCT.md and DESIGN.md must be present, or `missingLiveContext`
    // reports `context_missing` first (live.mjs checks context before
    // config.json).
    std::fs::write(cwd.join("PRODUCT.md"), "# Product\n").unwrap();
    std::fs::write(cwd.join("DESIGN.md"), "# Design\n").unwrap();
    let (code, out) = live_cli(&NeverRunner, &cwd, &[]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], json!(false));
    assert_eq!(v["error"], json!("config_missing"));
}

#[test]
fn live_cli_target_flag_without_value_errors_in_strict_mode() {
    let cwd = tmp_dir("live-target-missing-value");
    let (code, out) = live_cli(&NeverRunner, &cwd, &["--target".to_string()]);
    assert_eq!(code, 1);
    assert!(out.contains("--target requires a path value"));
}

#[test]
fn inject_check_reports_config_missing() {
    let cwd = tmp_dir("inject-check-missing");
    let v = inject_check(&cwd);
    assert_eq!(v["ok"], json!(false));
    assert_eq!(v["error"], json!("config_missing"));
}

#[test]
fn inject_check_reports_ok_for_valid_config() {
    let cwd = tmp_dir("inject-check-ok");
    std::fs::create_dir_all(cwd.join(".impeccable/live")).unwrap();
    let cfg = json!({
        "files": ["index.html"],
        "insertBefore": "</head>",
        "commentSyntax": "html",
    });
    std::fs::write(cwd.join(".impeccable/live/config.json"), cfg.to_string()).unwrap();
    let v = inject_check(&cwd);
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["config"]["files"][0], json!("index.html"));
}

#[test]
fn inject_check_reports_invalid_for_bad_config() {
    let cwd = tmp_dir("inject-check-invalid");
    std::fs::create_dir_all(cwd.join(".impeccable/live")).unwrap();
    // No insertBefore/insertAfter -> validate_config fails.
    let cfg = json!({ "files": ["index.html"], "commentSyntax": "html" });
    std::fs::write(cwd.join(".impeccable/live/config.json"), cfg.to_string()).unwrap();
    let v = inject_check(&cwd);
    assert_eq!(v["ok"], json!(false));
    assert_eq!(v["error"], json!("config_invalid"));
}

#[test]
fn inject_port_inserts_tag_into_resolved_file() {
    let cwd = tmp_dir("inject-port-insert");
    std::fs::create_dir_all(cwd.join(".impeccable/live")).unwrap();
    let cfg = json!({
        "files": ["index.html"],
        "insertBefore": "</head>",
        "commentSyntax": "html",
    });
    std::fs::write(cwd.join(".impeccable/live/config.json"), cfg.to_string()).unwrap();
    std::fs::write(cwd.join("index.html"), "<html><head></head><body></body></html>").unwrap();

    let result = inject_port(&cwd, 4321).expect("inject_port should succeed");
    assert_eq!(result["ok"], json!(true));
    let updated = std::fs::read_to_string(cwd.join("index.html")).unwrap();
    assert!(updated.contains("4321"));
}

#[test]
fn inject_port_returns_none_when_config_missing() {
    let cwd = tmp_dir("inject-port-missing");
    assert!(inject_port(&cwd, 1234).is_none());
}
