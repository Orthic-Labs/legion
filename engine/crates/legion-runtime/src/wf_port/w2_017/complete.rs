//! Port of `live-complete.mjs`'s pure logic: CLI argument parsing and the
//! durable completion event it appends.
//!
//! [`completion_cli`] (packet r19) is the full `completeCli()` orchestration:
//! it reads the live server's connection info
//! (`crate::wf_port::w2_016::impeccable_paths::read_live_server_info`), POSTs
//! the completion payload to `http://localhost:{port}/poll` through the
//! injectable [`HttpPoster`] trait (a [`ReqwestPoster`] backs it for real
//! use), and on any miss falls back to
//! `crate::wf_port::w2_021::session_store::LiveSessionStore` — the same
//! `live/session-store.mjs` port `live-complete.mjs` calls — exactly as the
//! JS does.

/// Port of the CLI status `parseArgs` derives from `--discarded`/`--discard`,
/// `--error[=MESSAGE]`, or the default.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Complete,
    Discarded,
    AgentError { message: String },
}

/// Port of the object `parseArgs(argv)` returns (`{ status, id, help,
/// message }`, with `status` defaulting to `'complete'`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArgs {
    pub status: Status,
    pub id: Option<String>,
    pub help: bool,
}

/// Port of:
/// ```js
/// function parseArgs(argv) {
///   const out = { status: 'complete' };
///   for (let i = 0; i < argv.length; i++) {
///     const arg = argv[i];
///     if (arg === '--id') out.id = argv[++i];
///     else if (arg.startsWith('--id=')) out.id = arg.slice('--id='.length);
///     else if (arg === '--discarded' || arg === '--discard') out.status = 'discarded';
///     else if (arg === '--error') { out.status = 'agent_error'; out.message = argv[++i] || 'unknown error'; }
///     else if (arg.startsWith('--error=')) { out.status = 'agent_error'; out.message = arg.slice('--error='.length); }
///     else if (arg === '--help' || arg === '-h') out.help = true;
///   }
///   return out;
/// }
/// ```
/// `argv` here is already `process.argv.slice(2)` — the script's own
/// arguments, not `["node", "live-complete.mjs", ...]`.
pub fn parse_args(argv: &[String]) -> ParsedArgs {
    let mut status = Status::Complete;
    let mut id: Option<String> = None;
    let mut help = false;
    let mut i = 0usize;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--id" {
            i += 1;
            id = argv.get(i).cloned();
        } else if let Some(rest) = arg.strip_prefix("--id=") {
            id = Some(rest.to_string());
        } else if arg == "--discarded" || arg == "--discard" {
            status = Status::Discarded;
        } else if arg == "--error" {
            i += 1;
            let message = argv
                .get(i)
                .cloned()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown error".to_string());
            status = Status::AgentError { message };
        } else if let Some(rest) = arg.strip_prefix("--error=") {
            status = Status::AgentError {
                message: rest.to_string(),
            };
        } else if arg == "--help" || arg == "-h" {
            help = true;
        }
        i += 1;
    }
    ParsedArgs { status, id, help }
}

/// Port of the usage-gate check:
/// ```js
/// if (args.help || !args.id) {
///   console.log(usage);
///   process.exit(args.help ? 0 : 1);
/// }
/// ```
/// Returns the process exit code the script would use, or `None` if the CLI
/// should proceed.
pub fn usage_exit_code(args: &ParsedArgs) -> Option<i32> {
    if args.help || args.id.is_none() {
        Some(if args.help { 0 } else { 1 })
    } else {
        None
    }
}

/// Port of the event object built from a resolved `ParsedArgs`:
/// ```js
/// const event = args.status === 'discarded'
///   ? { type: 'discarded', id: args.id }
///   : args.status === 'agent_error'
///     ? { type: 'agent_error', id: args.id, message: args.message || 'unknown error' }
///     : { type: 'complete', id: args.id };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum CompletionEvent {
    Complete { id: String },
    Discarded { id: String },
    AgentError { id: String, message: String },
}

/// Builds the durable event for a resolved `id` + `Status`, matching the JS
/// ternary above exactly (only reachable once `usage_exit_code` returns
/// `None`, i.e. `id` is present).
pub fn build_event(id: &str, status: &Status) -> CompletionEvent {
    match status {
        Status::Discarded => CompletionEvent::Discarded { id: id.to_string() },
        Status::AgentError { message } => CompletionEvent::AgentError {
            id: id.to_string(),
            message: if message.is_empty() {
                "unknown error".to_string()
            } else {
                message.clone()
            },
        },
        Status::Complete => CompletionEvent::Complete { id: id.to_string() },
    }
}

/// Port of the `/poll` request body's `type` field derivation in
/// `completeThroughServer`:
/// ```js
/// const type = args.status === 'discarded' ? 'discarded' : args.status === 'agent_error' ? 'error' : 'complete';
/// ```
/// Note this differs from [`CompletionEvent`]'s local-store `type` field
/// (`'agent_error'` vs. the server's `'error'`) — both are ported faithfully
/// as separate strings, matching the JS source exactly.
pub fn server_poll_type(status: &Status) -> &'static str {
    match status {
        Status::Discarded => "discarded",
        Status::AgentError { .. } => "error",
        Status::Complete => "complete",
    }
}

// ─── r19: completeCli() orchestration ───────────────────────────────────

use crate::wf_port::w2_016::impeccable_paths::read_live_server_info;
use crate::wf_port::w2_021::session_store::LiveSessionStore;
use serde_json::{json, Value};
use std::path::Path;

/// Port of the `fetch(http://localhost:${port}/poll, ...)` call in
/// `completeThroughServer`. Implementations return `None` on any network
/// failure or non-OK response, mirroring the JS `try { ... } catch { return
/// null; }` and `if (!res.ok) return null;` branches; `Some(body)` mirrors
/// `await res.json()`.
pub trait HttpPoster {
    fn post_poll(&self, port: u64, body: &Value) -> Option<Value>;
}

/// Real [`HttpPoster`] backed by a blocking `reqwest::blocking::Client`.
pub struct ReqwestPoster {
    client: reqwest::blocking::Client,
}

impl ReqwestPoster {
    pub fn new() -> Self {
        Self { client: reqwest::blocking::Client::new() }
    }
}

impl Default for ReqwestPoster {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpPoster for ReqwestPoster {
    fn post_poll(&self, port: u64, body: &Value) -> Option<Value> {
        let res = self
            .client
            .post(format!("http://localhost:{port}/poll"))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .ok()?;
        if !res.status().is_success() {
            return None;
        }
        res.json::<Value>().ok()
    }
}

/// Port of `completeThroughServer(info, args)`'s request body plus the
/// `/poll` POST, using an injected [`HttpPoster`] in place of `fetch`.
/// `server_info` mirrors `info` (the parsed contents of
/// `.impeccable/live/server.json`, expected to carry `port` and `token`).
fn complete_through_server(
    poster: &dyn HttpPoster,
    server_info: &Value,
    args: &ParsedArgs,
) -> Option<Value> {
    let port = server_info.get("port")?.as_u64()?;
    let token = server_info.get("token").cloned().unwrap_or(Value::Null);
    let message = match &args.status {
        Status::AgentError { message } => Some(message.clone()),
        _ => None,
    };
    let body = json!({
        "token": token,
        "id": args.id,
        "type": server_poll_type(&args.status),
        "message": message,
    });
    poster.post_poll(port, &body)
}

/// Port of `completeCli()`'s post-usage-gate body: the server round trip
/// then the durable session-store fallback. Returns the exact JSON value
/// the JS `console.log(JSON.stringify(...))` would print; the caller decides
/// how to emit it (stdout, etc.) and always exits 0 on this path, matching
/// the JS (no `process.exit` after either branch).
///
/// `cwd` mirrors `process.cwd()`. `id` mirrors `args.id` (already known
/// `Some` — callers must have handled [`usage_exit_code`] first).
pub fn complete_through_server_or_store(
    poster: &dyn HttpPoster,
    cwd: &Path,
    id: &str,
    args: &ParsedArgs,
) -> Value {
    let server_info = read_live_server_info(cwd).map(|i| i.raw);
    if let Some(info) = &server_info {
        if let Some(server_result) = complete_through_server(poster, info, args) {
            let ok = server_result.get("ok").and_then(Value::as_bool).unwrap_or(false);
            if ok {
                if let Ok(mut store) = LiveSessionStore::new(cwd, Some(id.to_string())) {
                    let snapshot = store.get_snapshot(Some(id), true).ok().flatten();
                    let phase = snapshot
                        .as_ref()
                        .and_then(|s| s.get("phase"))
                        .cloned()
                        .unwrap_or_else(|| json!(status_label(&args.status)));
                    return json!({
                        "ok": true,
                        "id": id,
                        "phase": phase,
                        "snapshot": snapshot,
                    });
                }
            }
        }
    }

    // Fallback: append the durable event via the local session store,
    // mirroring the `event` ternary and `store.appendEvent(event)` call.
    let event = build_event(id, &args.status);
    let event_value = match &event {
        CompletionEvent::Complete { id } => json!({ "type": "complete", "id": id }),
        CompletionEvent::Discarded { id } => json!({ "type": "discarded", "id": id }),
        CompletionEvent::AgentError { id, message } => {
            json!({ "type": "agent_error", "id": id, "message": message })
        }
    };
    match LiveSessionStore::new(cwd, Some(id.to_string())) {
        Ok(mut store) => match store.append_event(event_value, Some(id)) {
            Ok(snapshot) => {
                let phase = snapshot.get("phase").cloned().unwrap_or(Value::Null);
                json!({ "ok": true, "id": id, "phase": phase, "snapshot": snapshot })
            }
            Err(message) => json!({ "ok": false, "id": id, "error": message }),
        },
        Err(err) => json!({ "ok": false, "id": id, "error": err.to_string() }),
    }
}

/// Port of `args.status` stringified back to the local-store `'complete'` /
/// `'discarded'` / `'agent_error'` label the JS uses as `snapshot?.phase ||
/// args.status` fallback when the server path succeeds but returns no
/// snapshot.
fn status_label(status: &Status) -> &'static str {
    match status {
        Status::Complete => "complete",
        Status::Discarded => "discarded",
        Status::AgentError { .. } => "agent_error",
    }
}

/// Faithful port of `completeCli()`: parses `argv` (already
/// `process.argv.slice(2)`), applies the usage gate, and either returns the
/// usage text (for the `--help`/missing-`--id` exit) or the JSON value to
/// print. Mirrors the JS's `console.log` + `process.exit(code)` pair as
/// `(exit_code, output)`; `output` is `None` only when nothing should be
/// printed (never happens here — every branch prints something, matching
/// the JS).
pub fn completion_cli(poster: &dyn HttpPoster, cwd: &Path, argv: &[String]) -> (i32, String) {
    let args = parse_args(argv);
    if let Some(code) = usage_exit_code(&args) {
        let usage = "Usage: node live-complete.mjs --id SESSION_ID [--discarded|--error MESSAGE]\n\nAppend the final durable session acknowledgement. Use after accept/discard cleanup is verified.";
        return (code, usage.to_string());
    }
    let id = args.id.clone().expect("usage_exit_code guarantees id is present");
    let result = complete_through_server_or_store(poster, cwd, &id, &args);
    (0, serde_json::to_string_pretty(&result).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_to_complete() {
        let parsed = parse_args(&args(&["--id", "abc"]));
        assert_eq!(parsed.status, Status::Complete);
        assert_eq!(parsed.id.as_deref(), Some("abc"));
        assert!(!parsed.help);
    }

    #[test]
    fn parse_args_id_equals_form() {
        let parsed = parse_args(&args(&["--id=xyz"]));
        assert_eq!(parsed.id.as_deref(), Some("xyz"));
    }

    #[test]
    fn parse_args_discarded_variants() {
        assert_eq!(parse_args(&args(&["--discarded"])).status, Status::Discarded);
        assert_eq!(parse_args(&args(&["--discard"])).status, Status::Discarded);
    }

    #[test]
    fn parse_args_error_with_message() {
        let parsed = parse_args(&args(&["--error", "boom"]));
        assert_eq!(
            parsed.status,
            Status::AgentError { message: "boom".to_string() }
        );
    }

    #[test]
    fn parse_args_error_missing_message_defaults() {
        let parsed = parse_args(&args(&["--error"]));
        assert_eq!(
            parsed.status,
            Status::AgentError { message: "unknown error".to_string() }
        );
    }

    #[test]
    fn parse_args_error_equals_form_empty_message_kept_empty() {
        let parsed = parse_args(&args(&["--error="]));
        assert_eq!(parsed.status, Status::AgentError { message: String::new() });
    }

    #[test]
    fn parse_args_help_flags() {
        assert!(parse_args(&args(&["--help"])).help);
        assert!(parse_args(&args(&["-h"])).help);
    }

    #[test]
    fn usage_exit_code_help_takes_priority() {
        let parsed = ParsedArgs { status: Status::Complete, id: None, help: true };
        assert_eq!(usage_exit_code(&parsed), Some(0));
    }

    #[test]
    fn usage_exit_code_missing_id_is_error() {
        let parsed = ParsedArgs { status: Status::Complete, id: None, help: false };
        assert_eq!(usage_exit_code(&parsed), Some(1));
    }

    #[test]
    fn usage_exit_code_ok_when_id_present() {
        let parsed = ParsedArgs { status: Status::Complete, id: Some("x".into()), help: false };
        assert_eq!(usage_exit_code(&parsed), None);
    }

    #[test]
    fn build_event_variants() {
        assert_eq!(build_event("id1", &Status::Complete), CompletionEvent::Complete { id: "id1".into() });
        assert_eq!(build_event("id1", &Status::Discarded), CompletionEvent::Discarded { id: "id1".into() });
        assert_eq!(
            build_event("id1", &Status::AgentError { message: "oops".into() }),
            CompletionEvent::AgentError { id: "id1".into(), message: "oops".into() }
        );
        // empty message falls back to 'unknown error', matching `args.message || 'unknown error'`
        assert_eq!(
            build_event("id1", &Status::AgentError { message: String::new() }),
            CompletionEvent::AgentError { id: "id1".into(), message: "unknown error".into() }
        );
    }

    #[test]
    fn server_poll_type_matches_js() {
        assert_eq!(server_poll_type(&Status::Complete), "complete");
        assert_eq!(server_poll_type(&Status::Discarded), "discarded");
        assert_eq!(
            server_poll_type(&Status::AgentError { message: "x".into() }),
            "error"
        );
    }
}
