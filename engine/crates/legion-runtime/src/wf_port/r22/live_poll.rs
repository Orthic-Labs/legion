//! Port of `skills/designer/engine/scripts/live-poll.mjs`, now including
//! the network/CLI half (packet r22r24 follow-up): the two timeout
//! constants, `buildPollReplyPayload`, `parseReplyArgs` (+ its
//! `validateReplyArgs` helper), `requiresAgentReply`, `isEventPending`,
//! `buildAcceptScriptArgs`, `manualApplyPollBanner`, `readServerInfo`,
//! `postReply`, `fetchServerStatus`, `waitForEventAck`, `fetchNextEvent`,
//! `augmentEventWithAcceptHandling`, `writeCarbonizeBanner`,
//! `printPollEvent`, `runPollOnce`, `runPollStream`, `handlePollError`, and
//! `pollCli` (-> [`run`]).
//!
//! HTTP calls against the local `live-server.mjs`/`r24` server use
//! `reqwest::blocking` (already a `legion-runtime` dependency, `features =
//! ["blocking"]`). `augmentEventWithAcceptHandling`'s
//! `execFileSync('node', ['live-accept.mjs', ...])` becomes an in-process
//! call to [`crate::wf_port::w2_016::live_accept::run`]: that script is
//! itself now a Rust module in this same crate (not a separate file to
//! shell out to), so calling it directly is the faithful equivalent of "run
//! live-accept.mjs and capture its stdout" once both live in one binary —
//! same argv, same stdout-JSON contract, no process spawn needed.
//! `readServerInfo` reuses `r24::server_info::read_live_server_info`
//! (mirrors `lib/impeccable-paths.mjs::readLiveServerInfo`) rather than
//! re-deriving it.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::wf_port::r24;
use crate::wf_port::w2_016::live_accept;
use crate::wf_port::w2_020::completion::{completion_ack_for_accept_result, completion_type_for_accept_result};

/// Mirrors `PER_REQUEST_TIMEOUT_MS`.
pub const PER_REQUEST_TIMEOUT_MS: u64 = 270_000;
/// Mirrors `DEFAULT_EVENT_LEASE_MS`.
pub const DEFAULT_EVENT_LEASE_MS: u64 = 600_000;

/// Mirrors `EVENT_TYPES_NEEDING_AGENT_REPLY`.
const EVENT_TYPES_NEEDING_AGENT_REPLY: [&str; 3] = ["generate", "steer", "manual_edit_apply"];

/// Mirrors `requiresAgentReply(event)`. `event_type` is `event?.type`
/// (absent/non-string types never require a reply, same as the source's
/// `Set.has(undefined)` being `false`).
pub fn requires_agent_reply(event_type: Option<&str>) -> bool {
    match event_type {
        Some(t) => EVENT_TYPES_NEEDING_AGENT_REPLY.contains(&t),
        None => false,
    }
}

/// Mirrors `buildPollReplyPayload(token, { id, type, message, file, data })`.
/// Fields absent in the source's optional destructure serialize as JSON
/// `null`, matching `JSON.stringify` on an object with `undefined` fields
/// dropped... note: the JS object literal keeps `undefined` keys out of
/// `JSON.stringify` output entirely (they are omitted, not `null`). This is
/// reproduced by omitting `None` fields from the emitted object.
pub fn build_poll_reply_payload(
    token: &str,
    id: &str,
    reply_type: &str,
    message: Option<&str>,
    file: Option<&str>,
    data: Option<Value>,
) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("token".to_string(), json!(token));
    obj.insert("id".to_string(), json!(id));
    obj.insert("type".to_string(), json!(reply_type));
    if let Some(m) = message {
        obj.insert("message".to_string(), json!(m));
    }
    if let Some(f) = file {
        obj.insert("file".to_string(), json!(f));
    }
    if let Some(d) = data {
        obj.insert("data".to_string(), d);
    }
    Value::Object(obj)
}

/// Mirrors `isEventPending(status, eventId)`:
/// `(status.pendingEvents || []).some((entry) => entry.id === eventId)`.
pub fn is_event_pending(status: &Value, event_id: &str) -> bool {
    status
        .get("pendingEvents")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .any(|entry| entry.get("id").and_then(Value::as_str) == Some(event_id))
        })
        .unwrap_or(false)
}

/// Error shape mirroring the JS `Error` objects thrown by
/// `validateReplyArgs`/`parseReplyArgs`, which callers inspect via `.code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyArgsError {
    pub code: &'static str,
    pub message: String,
}

const REPLY_USAGE: &str =
    "Usage: node live-poll.mjs --reply <id> <status> [--file path] [--data '<json>'] [message]";

/// Mirrors `validateReplyArgs({ id, status })`.
fn validate_reply_args(id: Option<&str>, status: Option<&str>) -> Result<(), ReplyArgsError> {
    let id_missing_or_flag = id.map(|v| v.starts_with("--")).unwrap_or(true);
    if id_missing_or_flag {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!("{REPLY_USAGE}\nMissing event id after --reply."),
        });
    }
    let id = id.unwrap();
    if matches!(id, "done" | "error" | "complete" | "discard" | "discarded") {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!(
                "{REPLY_USAGE}\nThe value after --reply must be the event id, not the status {:?}. Use --reply EVENT_ID {id}.",
                id
            ),
        });
    }
    let status_missing_or_flag = status.map(|v| v.starts_with("--")).unwrap_or(true);
    if status_missing_or_flag {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!(
                "{REPLY_USAGE}\nMissing reply status after event id {:?}.",
                id
            ),
        });
    }
    Ok(())
}

/// A parsed `--reply` invocation, mirroring the object returned by
/// `parseReplyArgs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReply {
    pub id: String,
    pub reply_type: String,
    pub message: Option<String>,
    pub file: Option<String>,
    pub data: Option<Value>,
}

/// Mirrors `parseReplyArgs(args)`. Returns `Ok(None)` when `--reply` is
/// absent (source returns `null`), `Ok(Some(parsed))` on success, and
/// `Err` for `INVALID_REPLY_ARGS` / `INVALID_DATA_JSON`, exactly matching
/// the source's thrown-`Error.code` values.
pub fn parse_reply_args(args: &[String]) -> Result<Option<ParsedReply>, ReplyArgsError> {
    let Some(reply_idx) = args.iter().position(|a| a == "--reply") else {
        return Ok(None);
    };

    let id = args.get(reply_idx + 1).map(|s| s.as_str());
    let status = args.get(reply_idx + 2).map(|s| s.as_str());
    validate_reply_args(id, status)?;
    let id = id.unwrap().to_string();
    let status = status.unwrap().to_string();

    let file_idx = args.iter().position(|a| a == "--file");
    let file = file_idx
        .filter(|&i| i + 1 < args.len())
        .map(|i| args[i + 1].clone());

    let data_idx = args.iter().position(|a| a == "--data");
    let data = match data_idx.filter(|&i| i + 1 < args.len()) {
        Some(i) => {
            let raw = &args[i + 1];
            match serde_json::from_str::<Value>(raw) {
                Ok(v) => Some(v),
                Err(err) => {
                    return Err(ReplyArgsError {
                        code: "INVALID_DATA_JSON",
                        message: format!("--data must be valid JSON: {err}"),
                    })
                }
            }
        }
        None => None,
    };

    // message = args.find((a, i) => i > replyIdx + 2 && !a.startsWith('--')
    //   && i !== fileIdx + 1 && i !== dataIdx + 1)
    // Note: when fileIdx/dataIdx are -1 (absent), `fileIdx + 1 === 0` /
    // `dataIdx + 1 === 0` in JS, which can only ever collide with index 0 —
    // impossible here since the predicate already requires `i > replyIdx + 2
    // >= 2`. Reproduced with Option-based index comparison, which has the
    // same effective behavior.
    let file_next = file_idx.map(|i| i + 1);
    let data_next = data_idx.map(|i| i + 1);
    let message = args.iter().enumerate().find_map(|(i, a)| {
        if i > reply_idx + 2
            && !a.starts_with("--")
            && Some(i) != file_next
            && Some(i) != data_next
        {
            Some(a.clone())
        } else {
            None
        }
    });

    Ok(Some(ParsedReply {
        id,
        reply_type: status,
        message,
        file,
        data,
    }))
}

/// The subset of a poll event's fields `buildAcceptScriptArgs` reads.
#[derive(Debug, Clone, Default)]
pub struct AcceptEvent {
    pub event_type: String,
    pub id: String,
    pub variant_id: Option<String>,
    pub page_url: Option<String>,
    pub param_values: Option<serde_json::Map<String, Value>>,
}

/// Mirrors `buildAcceptScriptArgs(event)`.
pub fn build_accept_script_args(event: &AcceptEvent) -> Vec<String> {
    let mut args = if event.event_type == "discard" {
        vec!["--id".to_string(), event.id.clone(), "--discard".to_string()]
    } else {
        vec![
            "--id".to_string(),
            event.id.clone(),
            "--variant".to_string(),
            event.variant_id.clone().unwrap_or_default(),
        ]
    };
    if let Some(page_url) = &event.page_url {
        args.push("--page-url".to_string());
        args.push(page_url.clone());
    }
    if event.event_type == "accept" {
        if let Some(pv) = &event.param_values {
            if !pv.is_empty() {
                args.push("--param-values".to_string());
                args.push(Value::Object(pv.clone()).to_string());
            }
        }
    }
    args
}

/// Mirrors `manualApplyPollBanner(event = {})`; `event_id` is `event.id ||
/// 'EVENT_ID'`.
pub fn manual_apply_poll_banner(event_id: Option<&str>) -> String {
    let id = event_id.filter(|s| !s.is_empty()).unwrap_or("EVENT_ID");
    let lines = [
        format!(
            "Manual Apply action required: edit source, then reply with `live-poll.mjs --reply {id} done --data '<json>'`."
        ),
        "The JSON data must include status, appliedEntryIds, failed, files, and notes; summary counters are only a recovery fallback.".to_string(),
        "Do not run live-commit-manual-edits.mjs for this leased event.".to_string(),
        "Do not poll again before replying.".to_string(),
    ];
    format!("{}\n", lines.join("\n"))
}

/// Failure shape shared by the network functions below, mirroring the JS
/// `Error` objects with a `.code` property that `handlePollError`/callers
/// branch on (`AUTH_FAILED`, `ACK_TIMEOUT`, or `None` for a plain message).
#[derive(Debug, Clone)]
pub struct PollError {
    pub code: Option<&'static str>,
    pub message: String,
}

impl PollError {
    fn plain(message: impl Into<String>) -> Self {
        Self { code: None, message: message.into() }
    }
    fn auth_failed() -> Self {
        Self { code: Some("AUTH_FAILED"), message: "Authentication failed. The server token may have changed.".to_string() }
    }
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Mirrors `readServerInfo()`: resolves the running live server's
/// connection record via `r24`'s port of `readLiveServerInfo`.
pub fn read_server_info(cwd: &Path) -> Result<r24::ServerInfo, String> {
    r24::read_live_server_info(cwd)
        .map(|(info, _path)| info)
        .ok_or_else(|| {
            "No running live server found. Start one with: node live-server.mjs".to_string()
        })
}

fn http_client() -> reqwest::blocking::Client {
    // No fixed per-request timeout here: callers pass an explicit slice via
    // `PER_REQUEST_TIMEOUT_MS`/`totalDeadline` math, same as the JS relying
    // on `fetch`'s per-request headers timeout being bounded by that
    // constant rather than a client-wide setting.
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(PER_REQUEST_TIMEOUT_MS + 5_000))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Mirrors `postReply(base, token, reply)`.
pub fn post_reply(base: &str, token: &str, reply: &ParsedReply) -> Result<(), PollError> {
    let client = http_client();
    let body = build_poll_reply_payload(
        token,
        &reply.id,
        &reply.reply_type,
        reply.message.as_deref(),
        reply.file.as_deref(),
        reply.data.clone(),
    );
    let res = client
        .post(format!("{base}/poll"))
        .json(&body)
        .send()
        .map_err(|e| PollError::plain(e.to_string()))?;
    if !res.status().is_success() {
        let body: Value = res.json().unwrap_or(Value::Null);
        let parts: Vec<String> = [
            body.get("error").and_then(Value::as_str).map(str::to_string),
            body.get("reason").and_then(Value::as_str).map(str::to_string),
            body.get("hint").and_then(Value::as_str).map(str::to_string),
        ]
        .into_iter()
        .flatten()
        .collect();
        return Err(PollError::plain(parts.join(": ")));
    }
    Ok(())
}

/// Mirrors `fetchServerStatus(base, token)`.
pub fn fetch_server_status(base: &str, token: &str) -> Result<Value, PollError> {
    let client = http_client();
    let res = client
        .get(format!("{base}/status"))
        .query(&[("token", token)])
        .send()
        .map_err(|e| PollError::plain(e.to_string()))?;
    if res.status().as_u16() == 401 {
        return Err(PollError::auth_failed());
    }
    if !res.status().is_success() {
        return Err(PollError::plain(format!(
            "Status failed: {} {}",
            res.status().as_u16(),
            res.status().canonical_reason().unwrap_or("")
        )));
    }
    res.json::<Value>().map_err(|e| PollError::plain(e.to_string()))
}

/// Mirrors `waitForEventAck(base, token, eventId, { pollIntervalMs, maxWaitMs })`.
pub fn wait_for_event_ack(base: &str, token: &str, event_id: &str, poll_interval_ms: u64, max_wait_ms: u64) -> Result<bool, PollError> {
    let deadline = std::time::Instant::now() + Duration::from_millis(max_wait_ms);
    while std::time::Instant::now() < deadline {
        let status = fetch_server_status(base, token)?;
        if !is_event_pending(&status, event_id) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(poll_interval_ms));
    }
    Ok(false)
}

/// Mirrors `fetchNextEvent(base, token, { totalDeadline })`.
pub fn fetch_next_event(base: &str, token: &str, total_deadline: Option<std::time::Instant>) -> Result<Value, PollError> {
    let client = http_client();
    loop {
        if let Some(deadline) = total_deadline {
            if std::time::Instant::now() >= deadline {
                return Ok(json!({ "type": "timeout" }));
            }
        }
        let remaining_ms = total_deadline
            .map(|d| d.saturating_duration_since(std::time::Instant::now()).as_millis() as u64)
            .unwrap_or(PER_REQUEST_TIMEOUT_MS);
        let slice_ms = remaining_ms.clamp(1_000, PER_REQUEST_TIMEOUT_MS);

        let res = client
            .get(format!("{base}/poll"))
            .query(&[
                ("token", token.to_string()),
                ("timeout", slice_ms.to_string()),
                ("leaseMs", DEFAULT_EVENT_LEASE_MS.to_string()),
            ])
            .send()
            .map_err(|e| PollError::plain(e.to_string()))?;

        if res.status().as_u16() == 401 {
            return Err(PollError::auth_failed());
        }
        if !res.status().is_success() {
            return Err(PollError::plain(format!(
                "Poll failed: {} {}",
                res.status().as_u16(),
                res.status().canonical_reason().unwrap_or("")
            )));
        }

        let next: Value = res.json().map_err(|e| PollError::plain(e.to_string()))?;
        if next.get("type").and_then(Value::as_str) == Some("timeout") {
            if let Some(deadline) = total_deadline {
                if std::time::Instant::now() < deadline {
                    continue;
                }
            } else {
                continue;
            }
            return Ok(next);
        }
        return Ok(next);
    }
}

/// Mirrors `augmentEventWithAcceptHandling(event, base, token)`: for
/// `accept`/`discard` events, runs `live-accept`'s logic in-process (see
/// module doc comment) and stashes `_acceptResult`/`_completionAck` on the
/// event object, exactly like the JS mutating `event._acceptResult` /
/// `event._completionAck`.
pub fn augment_event_with_accept_handling(mut event: Value, base: &str, token: &str, cwd: &Path) -> Value {
    let event_type = event.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    if event_type != "accept" && event_type != "discard" {
        return event;
    }

    let accept_event = AcceptEvent {
        event_type: event_type.clone(),
        id: event.get("id").map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).unwrap_or_default(),
        variant_id: event.get("variantId").and_then(Value::as_str).map(str::to_string),
        page_url: event.get("pageUrl").and_then(Value::as_str).map(str::to_string),
        param_values: event.get("paramValues").and_then(Value::as_object).cloned(),
    };
    let script_args = build_accept_script_args(&accept_event);

    let (exit_code, output) = live_accept::run(&script_args, cwd);
    let accept_result: Value = if exit_code == 0 {
        serde_json::from_str(output.trim()).unwrap_or(Value::Null)
    } else {
        json!({ "handled": false, "mode": "error", "error": output })
    };

    let completion_type = completion_type_for_accept_result(&event_type, Some(&accept_result)).to_string();
    let reply = ParsedReply {
        id: accept_event.id.clone(),
        reply_type: completion_type.clone(),
        message: accept_result.get("error").and_then(Value::as_str).map(str::to_string),
        file: accept_result.get("file").and_then(Value::as_str).map(str::to_string),
        data: if accept_result.get("carbonize").and_then(Value::as_bool) == Some(true) {
            Some(json!({ "carbonize": true }))
        } else {
            None
        },
    };

    let completion_ack = match post_reply(base, token, &reply) {
        Ok(()) => completion_ack_for_accept_result(&accept_event.id, &completion_type, Some(&accept_result)),
        Err(err) => json!({ "ok": false, "error": err.message }),
    };

    if let Value::Object(map) = &mut event {
        map.insert("_acceptResult".to_string(), accept_result);
        map.insert("_completionAck".to_string(), completion_ack);
    }
    event
}

/// Mirrors `writeCarbonizeBanner(event)`.
pub fn write_carbonize_banner(event: &Value) {
    if event.get("type").and_then(Value::as_str) == Some("manual_edit_apply") {
        eprintln!("\n{}\n", manual_apply_poll_banner(event.get("id").and_then(Value::as_str)));
    }
    if event.get("_acceptResult").and_then(|r| r.get("carbonize")).and_then(Value::as_bool) == Some(true) {
        let id = event.get("id").and_then(Value::as_str).unwrap_or("");
        eprintln!(
            "\n\u{26A0} Carbonize cleanup REQUIRED before next poll. After cleanup, run live-complete.mjs --id {id}. See reference/live.md \"Required after accept\".\n"
        );
    }
}

/// Mirrors `printPollEvent(event)`.
pub fn print_poll_event(event: &Value) {
    println!("{event}");
}

/// Mirrors `runPollOnce(base, token, { totalTimeout })`.
pub fn run_poll_once(base: &str, token: &str, total_timeout_ms: u64, cwd: &Path) -> Result<Value, PollError> {
    let deadline = std::time::Instant::now() + Duration::from_millis(total_timeout_ms);
    let event = fetch_next_event(base, token, Some(deadline))?;
    let event = augment_event_with_accept_handling(event, base, token, cwd);
    write_carbonize_banner(&event);
    print_poll_event(&event);
    Ok(event)
}

/// Mirrors `runPollStream(base, token, { ackTimeoutMs, ackPollIntervalMs })`.
/// `shouldContinue` in JS is always `() => true` at every real call site;
/// modeled here as a plain loop that returns on `type: "exit"` or an ack
/// timeout, exactly like the JS's only reachable exit paths.
pub fn run_poll_stream(base: &str, token: &str, ack_timeout_ms: u64, cwd: &Path) -> Result<Option<Value>, PollError> {
    eprintln!("[impeccable-poll] stream mode: one JSON object per line on stdout; use --reply while this process stays running");
    let ack_poll_interval_ms = 400;
    loop {
        let event = fetch_next_event(base, token, None)?;
        let event = augment_event_with_accept_handling(event, base, token, cwd);
        write_carbonize_banner(&event);
        print_poll_event(&event);

        if event.get("type").and_then(Value::as_str) == Some("exit") {
            return Ok(Some(event));
        }

        let event_type = event.get("type").and_then(Value::as_str);
        if requires_agent_reply(event_type) {
            let event_id = event.get("id").and_then(Value::as_str).unwrap_or("");
            let acked = wait_for_event_ack(base, token, event_id, ack_poll_interval_ms, ack_timeout_ms)?;
            if !acked {
                return Err(PollError { code: Some("ACK_TIMEOUT"), message: format!("Timed out waiting for --reply on event {event_id}") });
            }
        }
    }
}

fn handle_poll_error(err: &PollError) -> i32 {
    match err.code {
        Some("AUTH_FAILED") => {
            eprintln!("{}", err.message);
            eprintln!("Try restarting: node live-server.mjs stop && node live.mjs");
            1
        }
        Some("ACK_TIMEOUT") => {
            eprintln!("{}", err.message);
            1
        }
        _ => {
            eprintln!("Poll failed: {}", err.message);
            1
        }
    }
}

/// Mirrors `pollCli()`. Prints directly to stdout/stderr (rather than
/// returning `(exit_code, text)` like sibling single-shot CLI ports)
/// because `--stream` mode prints one JSON line per event as they arrive,
/// which doesn't fit a single buffered return value without breaking the
/// "line arrives as the event arrives" contract callers of `--stream` rely
/// on.
pub fn run(args: &[String], cwd: &Path) -> i32 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: impeccable poll [options]\n\nWait for a browser event from the live variant server, or reply to one.\n\nModes:\n  poll                             Block until a browser event arrives, print JSON, exit\n  poll --stream                    Keep polling; print one JSON line per event (see live.md)\n  poll --reply <id> done           Reply \"done\" to event <id> (replace or insert generate)\n  poll --reply <id> steer_done     Reply after handling a steer event (unlocks Steer bar)\n  poll --reply <id> error \"msg\"    Reply with an error message\n  poll --reply <id> done --data '<json>'\n                                   Reply with a structured JSON result (manual_edit_apply)\n\nOptions:\n  --timeout=MS        One-shot poll timeout in ms (default: 600000). Ignored in --stream mode\n  --ack-timeout=MS    Stream mode: max wait for --reply after generate/steer (default: 600000)\n  --file PATH         Attach a source file path to the reply (generate/steer flow)\n  --data JSON         Attach a JSON result object to the reply (manual_edit_apply flow). Must be valid JSON\n  --help              Show this help message\n\nHarness note:\n  Default one-shot mode is the portable contract for Claude Code, Codex, and Cursor.\n  --stream is experimental for harnesses with fast incremental stdout; do not use on Cursor."
        );
        return 0;
    }

    let info = match read_server_info(cwd) {
        Ok(info) => info,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };
    let base = format!("http://localhost:{}", info.port);

    if args.iter().any(|a| a == "--reply") {
        let reply = match parse_reply_args(args) {
            Ok(Some(r)) => r,
            Ok(None) => unreachable!("checked args.contains(\"--reply\") above"),
            Err(err) => {
                eprintln!("{}", err.message);
                return 1;
            }
        };
        return match post_reply(&base, &info.token, &reply) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("Reply failed: {}", err.message);
                1
            }
        };
    }

    let stream_mode = args.iter().any(|a| a == "--stream");
    let ack_timeout_ms = args
        .iter()
        .find_map(|a| a.strip_prefix("--ack-timeout="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(600_000);

    if stream_mode {
        return match run_poll_stream(&base, &info.token, ack_timeout_ms, cwd) {
            Ok(_) => 0,
            Err(err) => handle_poll_error(&err),
        };
    }

    let total_timeout_ms = args
        .iter()
        .find_map(|a| a.strip_prefix("--timeout="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(600_000);
    match run_poll_once(&base, &info.token, total_timeout_ms, cwd) {
        Ok(_) => 0,
        Err(err) => handle_poll_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_agent_reply_matches_set() {
        assert!(requires_agent_reply(Some("generate")));
        assert!(requires_agent_reply(Some("steer")));
        assert!(requires_agent_reply(Some("manual_edit_apply")));
        assert!(!requires_agent_reply(Some("accept")));
        assert!(!requires_agent_reply(None));
    }

    #[test]
    fn build_poll_reply_payload_omits_absent_optionals() {
        let payload = build_poll_reply_payload("tok", "ev1", "done", None, None, None);
        assert_eq!(
            payload,
            json!({ "token": "tok", "id": "ev1", "type": "done" })
        );
    }

    #[test]
    fn build_poll_reply_payload_includes_present_optionals() {
        let payload = build_poll_reply_payload(
            "tok",
            "ev1",
            "error",
            Some("oops"),
            Some("a.txt"),
            Some(json!({"carbonize": true})),
        );
        assert_eq!(
            payload,
            json!({
                "token": "tok",
                "id": "ev1",
                "type": "error",
                "message": "oops",
                "file": "a.txt",
                "data": {"carbonize": true}
            })
        );
    }

    #[test]
    fn is_event_pending_true_when_id_present() {
        let status = json!({ "pendingEvents": [{"id": "a"}, {"id": "b"}] });
        assert!(is_event_pending(&status, "b"));
        assert!(!is_event_pending(&status, "c"));
    }

    #[test]
    fn is_event_pending_defaults_to_false_when_missing() {
        let status = json!({});
        assert!(!is_event_pending(&status, "b"));
    }

    #[test]
    fn parse_reply_args_absent_flag_returns_none() {
        let args = vec!["--stream".to_string()];
        assert_eq!(parse_reply_args(&args), Ok(None));
    }

    #[test]
    fn parse_reply_args_missing_id_errors() {
        let args = vec!["--reply".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
    }

    #[test]
    fn parse_reply_args_status_looking_id_errors() {
        let args = vec!["--reply".to_string(), "done".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
        assert!(err.message.contains("not the status"));
    }

    #[test]
    fn parse_reply_args_missing_status_errors() {
        let args = vec!["--reply".to_string(), "ev1".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
    }

    #[test]
    fn parse_reply_args_basic_done() {
        let args = vec!["--reply".to_string(), "ev1".to_string(), "done".to_string()];
        let parsed = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(parsed.id, "ev1");
        assert_eq!(parsed.reply_type, "done");
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.file, None);
        assert_eq!(parsed.data, None);
    }

    #[test]
    fn parse_reply_args_with_message_file_and_data() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "error".to_string(),
            "--file".to_string(),
            "a.txt".to_string(),
            "--data".to_string(),
            "{\"k\":1}".to_string(),
            "boom".to_string(),
        ];
        let parsed = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(parsed.file.as_deref(), Some("a.txt"));
        assert_eq!(parsed.data, Some(json!({"k": 1})));
        assert_eq!(parsed.message.as_deref(), Some("boom"));
    }

    #[test]
    fn parse_reply_args_invalid_data_json_errors() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "done".to_string(),
            "--data".to_string(),
            "{not json".to_string(),
        ];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_DATA_JSON");
    }

    #[test]
    fn build_accept_script_args_discard() {
        let event = AcceptEvent {
            event_type: "discard".to_string(),
            id: "ev1".to_string(),
            ..Default::default()
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec!["--id", "ev1", "--discard"]
        );
    }

    #[test]
    fn build_accept_script_args_accept_with_variant_and_params() {
        let mut pv = serde_json::Map::new();
        pv.insert("color".to_string(), json!("blue"));
        let event = AcceptEvent {
            event_type: "accept".to_string(),
            id: "ev1".to_string(),
            variant_id: Some("2".to_string()),
            page_url: Some("http://x/y".to_string()),
            param_values: Some(pv),
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec![
                "--id",
                "ev1",
                "--variant",
                "2",
                "--page-url",
                "http://x/y",
                "--param-values",
                "{\"color\":\"blue\"}",
            ]
        );
    }

    #[test]
    fn build_accept_script_args_accept_empty_params_omitted() {
        let event = AcceptEvent {
            event_type: "accept".to_string(),
            id: "ev1".to_string(),
            variant_id: Some("1".to_string()),
            param_values: Some(serde_json::Map::new()),
            ..Default::default()
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec!["--id", "ev1", "--variant", "1"]
        );
    }

    #[test]
    fn manual_apply_poll_banner_default_id() {
        let banner = manual_apply_poll_banner(None);
        assert!(banner.contains("--reply EVENT_ID done"));
        assert!(banner.ends_with('\n'));
    }

    #[test]
    fn manual_apply_poll_banner_with_id() {
        let banner = manual_apply_poll_banner(Some("ev42"));
        assert!(banner.contains("--reply ev42 done"));
    }

    #[test]
    fn timeout_constants_match_source() {
        assert_eq!(PER_REQUEST_TIMEOUT_MS, 270_000);
        assert_eq!(DEFAULT_EVENT_LEASE_MS, 600_000);
    }
}
