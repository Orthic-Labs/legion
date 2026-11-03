//! Synchronous `std::net::TcpListener` HTTP/1.1 server loop, per the port
//! brief's guidance to use `TcpListener` (no `tiny_http` pinned in
//! `engine/Cargo.lock`, checked). Ports `createRequestHandler`'s routing
//! table and `httpServer.listen(...)` from `live-server.mjs`, plus the
//! `shutdown()` cleanup path. Every route in the help text in `mod.rs` has a
//! match arm here; the unported-sibling gaps are listed in `mod.rs`'s doc
//! comment.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{json, Value};

use super::design_parser::parse_design_md;
use super::manual_edit_deps::{LiveServerManualEditDeps, QueueCallbacks};
use super::queue::QueueState;
use super::remove_all_svelte_component_sessions;
use super::server_info::remove_live_server_info;
use crate::wf_port::w2_010::context::{load_context, TargetOptions};
use crate::wf_port::w2_016::impeccable_paths::resolve_design_sidecar_path;
use crate::wf_port::w2_020::browser_script_parts::{
    assemble_live_browser_script, read_live_browser_script_parts,
    resolve_live_browser_script_parts, LIVE_BROWSER_SCRIPT_PARTS,
};
use crate::wf_port::w2_021::manual_apply::{
    validate_manual_apply_result_message, ManualApplyController,
};
use crate::wf_port::w2_021::manual_edit_routes::{handle_manual_edit_route, ManualEditRequest};
use crate::wf_port::w2_022::vocabulary::live_commands;

/// Candidate locations for the skill's `scripts/` directory relative to a
/// project root, mirroring `loadBrowserScripts()`'s own search order
/// (`__dirname` there is always exactly this directory since the JS file
/// lives in it; ported here as a search list since a Rust binary has no
/// equivalent "my own directory is the scripts dir" notion).
fn candidate_scripts_dirs(project_root: &Path) -> Vec<std::path::PathBuf> {
    let exe_dir = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    candidate_scripts_dirs_with(project_root, exe_dir.as_deref())
}

/// Project-local candidates first, then the installed package layout derived
/// from the running executable's directory: `<exe_dir>/../plugin/skills/...`
/// and `<exe_dir>/../skills/...`.
fn candidate_scripts_dirs_with(
    project_root: &Path,
    exe_dir: Option<&Path>,
) -> Vec<std::path::PathBuf> {
    let mut dirs = vec![
        project_root.join("skills/designer/engine/scripts"),
        project_root.join("node_modules/impeccable/skills/designer/engine/scripts"),
    ];
    if let Some(base) = exe_dir.and_then(Path::parent) {
        dirs.push(base.join("plugin/skills/designer/engine/scripts"));
        dirs.push(base.join("skills/designer/engine/scripts"));
    }
    dirs
}

/// Locates the scripts directory holding `live-browser*.js` and
/// `detector/detect-antipatterns-browser.js`, the two static browser assets
/// `/live.js` and `/detect.js` serve. Returns `None` if neither candidate
/// exists (matches JS's "keep trying candidates, fall back to empty" for
/// the detect script; for `/live.js`'s required parts, `None` here maps to
/// the same 500 `assertLiveBrowserScriptParts` would have raised at
/// startup).
fn find_scripts_dir(project_root: &Path) -> Option<std::path::PathBuf> {
    candidate_scripts_dirs(project_root)
        .into_iter()
        .find(|d| d.is_dir())
}

struct Request {
    method: String,
    path: String,
    query: std::collections::HashMap<String, String>,
    body: Vec<u8>,
    content_type: String,
}

fn parse_query(raw: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        map.insert(urldecode(k), urldecode(v));
    }
    map
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) =
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_request(stream: &mut impl Read) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut content_length: usize = 0;
    let mut content_type = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.trim().eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_string();
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }

    let (path, query_raw) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    Some(Request {
        method,
        path,
        query: parse_query(&query_raw),
        body,
        content_type,
    })
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) {
    let headers = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body);
}

fn write_json(stream: &mut impl Write, status: u16, status_text: &str, value: &Value) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    write_response(stream, status, status_text, "application/json", &body);
}

fn write_unauthorized(stream: &mut impl Write) {
    write_response(stream, 401, "Unauthorized", "text/plain", b"Unauthorized");
}

/// Token check for routes whose browser caller may send the token either in
/// the query string or (like `sendEvent` in `live-browser.js`, which does
/// `msg.token = TOKEN` and POSTs to a bare `/events`) as a `token` field of
/// the JSON body.
fn request_token_matches(req: &Request, token: &str) -> bool {
    if req.query.get("token").map(String::as_str) == Some(token) {
        return true;
    }
    serde_json::from_slice::<Value>(&req.body)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(|t| t == token))
        .unwrap_or(false)
}

/// `GET /events` with the matching query token: the request that opens an SSE
/// stream and so holds a client slot for the exit grace accounting.
fn is_authorized_sse_request(req: &Request, token: &str) -> bool {
    req.method == "GET"
        && req.path == "/events"
        && req.query.get("token").map(String::as_str) == Some(token)
}

/// Result of resolving the `GET /source` `path` parameter.
enum SourceRead {
    /// Missing or empty `path`, or one containing `..` (JS 400 `Bad path`).
    BadPath,
    /// Resolves outside the project root (JS 403 `Forbidden`).
    Forbidden,
    /// Absent, unreadable, or a directory (JS 404 `File not found`).
    NotFound,
    Found(String),
}

/// Port of the `/source` handler in `live-server.mjs`, the browser's no-HMR
/// fallback. The JS restriction is kept: the request may not contain `..`,
/// and the file must lie under the project root (JS `startsWith(cwd)`, here
/// component-wise so `/proj-evil` does not pass for `/proj`). This port also
/// resolves symlinks before the containment check, so a link inside the root
/// cannot point the read outside it.
fn read_source_file(project_root: &Path, requested: Option<&str>) -> SourceRead {
    let requested = match requested {
        Some(p) if !p.is_empty() => p,
        _ => return SourceRead::BadPath,
    };
    if requested.contains("..") {
        return SourceRead::BadPath;
    }
    let root = match project_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return SourceRead::NotFound,
    };
    // `path.resolve(cwd, filePath)`: an absolute request replaces the base.
    let lexical = root.join(requested);
    if !lexical.starts_with(&root) {
        return SourceRead::Forbidden;
    }
    let resolved = match lexical.canonicalize() {
        Ok(p) => p,
        Err(_) => return SourceRead::NotFound,
    };
    if !resolved.starts_with(&root) {
        return SourceRead::Forbidden;
    }
    match std::fs::read(&resolved) {
        Ok(bytes) => SourceRead::Found(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => SourceRead::NotFound,
    }
}

/// How long an SSE connection may live before the server ends it (the
/// browser's `EventSource` reconnects on its own).
const SSE_MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// JS `SSE_HEARTBEAT_INTERVAL`.
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const SSE_STEP: Duration = Duration::from_millis(100);
/// Per-connection read timeout so a silent client cannot pin a thread.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn write_sse_data<W: Write>(stream: &mut W, msg: &Value) -> std::io::Result<()> {
    let line = format!(
        "data: {}\n\n",
        serde_json::to_string(msg).unwrap_or_else(|_| "{}".to_string())
    );
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

/// `GET /events` (server to browser): writes the SSE response head, the
/// initial `connected` message the browser's `onmessage` switch expects
/// (`hasProjectContext`, `agentPolling`, `activeSessions`), then relays every
/// message published through `QueueState::publish_sse`, with an SSE comment
/// keep-alive line whenever `keepalive` elapses without a write. Returns when
/// the client goes away (write error), the server shuts down, or
/// `max_duration` passes.
fn stream_sse<W: Write>(
    stream: &mut W,
    queue: &QueueState,
    project_root: &Path,
    max_duration: Duration,
    keepalive: Duration,
    step: Duration,
) {
    let head = "HTTP/1.1 200 OK\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: keep-alive\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }
    let mut cursor = queue.sse_cursor();
    let has_project_context = load_context(project_root, &TargetOptions::none()).has_product;
    let connected = json!({
        "type": "connected",
        "hasProjectContext": has_project_context,
        "agentPolling": queue.agent_polling_connected(),
        // Durable session summaries live in the unported session store.
        "activeSessions": [],
    });
    if write_sse_data(stream, &connected).is_err() {
        return;
    }
    let started = Instant::now();
    let mut last_write = Instant::now();
    loop {
        if queue.is_shutdown() || started.elapsed() >= max_duration {
            return;
        }
        for (seq, msg) in queue.sse_messages_after(cursor) {
            cursor = seq;
            if write_sse_data(stream, &msg).is_err() {
                return;
            }
            last_write = Instant::now();
        }
        if last_write.elapsed() >= keepalive {
            if stream.write_all(b": keepalive\n\n").is_err() || stream.flush().is_err() {
                return;
            }
            last_write = Instant::now();
        }
        thread::sleep(step);
    }
}

/// The SSE message the JS `POST /poll` handler forwards to the browser after
/// an agent reply is acknowledged: `{ type, id, message, file, data }`
/// (absent fields omitted; `type` defaults to `done`).
fn poll_reply_broadcast(body: &Value, id: &str) -> Value {
    let mut out = serde_json::Map::new();
    let ty = body.get("type").and_then(Value::as_str).unwrap_or("done");
    out.insert("type".to_string(), Value::String(ty.to_string()));
    out.insert("id".to_string(), Value::String(id.to_string()));
    for key in ["message", "file", "data"] {
        if let Some(v) = body.get(key) {
            if !v.is_null() {
                out.insert(key.to_string(), v.clone());
            }
        }
    }
    Value::Object(out)
}

enum PollReplyOutcome {
    Acknowledged(bool),
    Rejected(u16, Value),
}

fn reject_timed_out_manual_apply<C: crate::wf_port::w2_021::manual_apply::ManualApplyCallbacks>(
    controller: &ManualApplyController<C>,
    id: &str,
) -> PollReplyOutcome {
    let Some(_mutation) = controller.try_begin_timeout_rollback() else {
        return PollReplyOutcome::Rejected(409, json!({ "error": "manual_edit_busy" }));
    };
    let rollback = controller.rollback_timed_out_reply(id);
    PollReplyOutcome::Rejected(
        410,
        json!({
            "error": "manual_apply_timed_out",
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
        }),
    )
}

/// Settles controller-owned manual-apply work before acknowledging its queue
/// event. Other poll replies retain the ordinary queue acknowledgement path.
fn settle_poll_reply<'a>(
    queue: &QueueState,
    controller: &ManualApplyController<QueueCallbacks<'a>>,
    message: &Value,
    id: &str,
) -> PollReplyOutcome {
    if let Some(event) = queue.find_pending_event_by_id(id) {
        if event.get("type").and_then(Value::as_str) == Some("manual_edit_apply") {
            let Some(batch) = controller.get_deferred_batch(id) else {
                if controller.has_timed_out_id(id) {
                    return reject_timed_out_manual_apply(controller, id);
                }
                return PollReplyOutcome::Rejected(
                    409,
                    json!({ "error": "stale_manual_apply_reply" }),
                );
            };
            if message.get("id").and_then(Value::as_str) != Some(id) {
                return PollReplyOutcome::Rejected(
                    400,
                    json!({ "error": "manual_apply_reply_id_mismatch" }),
                );
            }
            let result = match validate_manual_apply_result_message(message, Some(id), Some(&batch))
            {
                Ok(result) => result,
                Err(error) => {
                    let body = error.get("body").cloned().unwrap_or(error);
                    return PollReplyOutcome::Rejected(400, body);
                }
            };
            let mut activity = result.as_object().cloned().unwrap_or_default();
            activity.insert("id".to_string(), Value::String(id.to_string()));
            for key in ["pageUrl", "chunk", "repair"] {
                activity.insert(
                    key.to_string(),
                    event.get(key).cloned().unwrap_or(Value::Null),
                );
            }
            activity.insert(
                "appliedCount".to_string(),
                json!(result
                    .get("appliedEntryIds")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0)),
            );
            activity.insert(
                "fileCount".to_string(),
                json!(result
                    .get("files")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0)),
            );
            activity.insert(
                "noteCount".to_string(),
                json!(result
                    .get("notes")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0)),
            );
            if !controller.resolve_deferred_with_activity(id, result, Value::Object(activity)) {
                if controller.has_timed_out_id(id) {
                    return reject_timed_out_manual_apply(controller, id);
                }
                return PollReplyOutcome::Rejected(
                    409,
                    json!({ "error": "stale_manual_apply_reply" }),
                );
            }
            // The synchronous commit waiter now owns final source verification,
            // rollback, and buffer clearing. Ack only after delivery succeeds.
            return PollReplyOutcome::Acknowledged(queue.acknowledge_pending_event(id).is_some());
        }
    } else if controller.has_timed_out_id(id) {
        return reject_timed_out_manual_apply(controller, id);
    }

    if queue.acknowledge_pending_event(id).is_some() {
        PollReplyOutcome::Acknowledged(true)
    } else {
        PollReplyOutcome::Acknowledged(false)
    }
}

fn mtime_ms(path: &Path) -> Option<u128> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

/// Locates `DESIGN.md` and the design sidecar JSON for the project, using
/// the same resolvers the rest of the designer scripts use.
fn locate_design_files(project_root: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    let ctx = load_context(project_root, &TargetOptions::none());
    let md = ctx
        .design_path
        .as_deref()
        .map(|rel| ctx.project_root.join(rel))
        .filter(|p| p.is_file());
    let context_dir = ctx
        .design_context_dir
        .clone()
        .unwrap_or_else(|| ctx.context_dir.clone());
    let sidecar =
        resolve_design_sidecar_path(&ctx.project_root, &context_dir).filter(|p| p.is_file());
    (md, sidecar)
}

/// `/design-system.json`. `parsed` is the `parseDesignMd` model of DESIGN.md
/// (see `design_parser`) and stays `null` only when DESIGN.md is absent. The
/// sidecar half and the presence/staleness flags are produced faithfully.
/// When nothing exists the answer is 404 with `present: false`, which the
/// panel renders as its empty state.
fn design_system_json(project_root: &Path) -> (u16, &'static str, Value) {
    let (md, sidecar) = locate_design_files(project_root);
    if md.is_none() && sidecar.is_none() {
        return (
            404,
            "Not Found",
            json!({
                "present": false,
                "error": "unavailable",
                "reason": "design-system-not-available",
            }),
        );
    }
    let md_time = md.as_deref().and_then(mtime_ms);
    let json_time = sidecar.as_deref().and_then(mtime_ms);
    let md_newer = match (md_time, json_time) {
        (Some(m), Some(j)) => m > j + 1000,
        _ => false,
    };
    let mut response = json!({
        "present": true,
        "hasMd": md.is_some(),
        "hasSidecar": sidecar.is_some(),
        "mdNewerThanJson": md_newer,
        "parsed": Value::Null,
    });
    if let Some(path) = md.as_deref() {
        match std::fs::read(path) {
            // Node reads DESIGN.md as UTF-8 with replacement, so decode lossily to match.
            Ok(bytes) => {
                response["parsed"] = parse_design_md(&String::from_utf8_lossy(&bytes));
            }
            Err(err) => {
                response["parseError"] = Value::String(err.to_string());
            }
        }
    }
    if let Some(path) = sidecar {
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
        {
            Ok(v) => response["sidecar"] = v,
            Err(e) => {
                response["sidecarError"] =
                    Value::String(format!("Failed to parse .impeccable/design.json: {e}"));
            }
        }
    }
    (200, "OK", response)
}

/// Poll timeout, matching `DEFAULT_POLL_TIMEOUT = 600_000` (10 min) in the
/// JS source. Kept short in the request handler below via a polling loop
/// with a 200ms sleep, since this is a synchronous server with no
/// event-driven wakeup (`flushPendingPolls()`'s callback resolution has no
/// synchronous equivalent here); functionally identical from the client's
/// point of view — it still blocks up to the same ceiling and returns as
/// soon as an event is available.
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_millis(600_000);
const POLL_SLEEP_STEP: Duration = Duration::from_millis(200);
/// `leaseMs` used by `/poll` GET before an ack is required (mirrors the
/// lease window the JS source grants a dispatched event while waiting for
/// the agent's ack).
const POLL_LEASE_MS: u64 = 30_000;

const MAX_ANNOTATION_BYTES: usize = 10 * 1024 * 1024;

/// `/^[A-Za-z0-9_-]{1,64}$/` — the `eventId` validation the JS route applies
/// before using it as a filename component.
fn is_valid_event_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[allow(clippy::too_many_arguments)]
fn handle_request<'a>(
    req: Request,
    mut stream: impl Write,
    token: &str,
    queue: &QueueState,
    project_root: &Path,
    port: u16,
    manual_apply_controller: &ManualApplyController<QueueCallbacks<'a>>,
    session_dir: &Path,
) -> bool {
    if req.method == "OPTIONS" {
        write_response(&mut stream, 204, "No Content", "text/plain", b"");
        return true;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            if let Some(provided) = req.query.get("token") {
                if provided != token {
                    write_unauthorized(&mut stream);
                    return true;
                }
                write_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "ok": true, "pid": std::process::id(), "port": port }),
                );
            } else {
                write_json(&mut stream, 200, "OK", &json!({ "ok": true }));
            }
            true
        }
        ("GET", "/stop") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "text/plain",
                    b"Unauthorized",
                );
                return true;
            }
            write_json(
                &mut stream,
                200,
                "OK",
                &json!({ "ok": true, "accepted": true, "pid": std::process::id(), "port": port }),
            );
            false // signal caller to shut down after this response
        }
        ("GET", "/events") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_unauthorized(&mut stream);
                return true;
            }
            // A browser (re)connecting supersedes any queued anonymous exit.
            queue.cancel_queued_anonymous_exit_events();
            stream_sse(
                &mut stream,
                queue,
                project_root,
                SSE_MAX_DURATION,
                SSE_KEEPALIVE_INTERVAL,
                SSE_STEP,
            );
            true
        }
        ("GET", "/modern-screenshot.js") => {
            let asset = find_scripts_dir(project_root)
                .map(|scripts| scripts.join("modern-screenshot.umd.js"));
            match asset.and_then(|path| std::fs::read(path).ok()) {
                Some(content) => {
                    write_response(&mut stream, 200, "OK", "application/javascript", &content)
                }
                None => write_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    b"Not available",
                ),
            }
            true
        }
        ("GET", "/design-system.json") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_unauthorized(&mut stream);
                return true;
            }
            let (status, reason, body) = design_system_json(project_root);
            write_json(&mut stream, status, reason, &body);
            true
        }
        ("GET", "/design-system/raw") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_unauthorized(&mut stream);
                return true;
            }
            let (md, _sidecar) = locate_design_files(project_root);
            match md.and_then(|p| std::fs::read_to_string(p).ok()) {
                Some(text) => write_response(
                    &mut stream,
                    200,
                    "OK",
                    "text/markdown; charset=utf-8",
                    text.as_bytes(),
                ),
                None => write_response(&mut stream, 404, "Not Found", "text/plain", b"Not found"),
            }
            true
        }
        ("GET", "/source") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_unauthorized(&mut stream);
                return true;
            }
            match read_source_file(project_root, req.query.get("path").map(String::as_str)) {
                SourceRead::BadPath => {
                    write_response(&mut stream, 400, "Bad Request", "text/plain", b"Bad path")
                }
                SourceRead::Forbidden => {
                    write_response(&mut stream, 403, "Forbidden", "text/plain", b"Forbidden")
                }
                SourceRead::NotFound => write_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    b"File not found",
                ),
                SourceRead::Found(text) => write_response(
                    &mut stream,
                    200,
                    "OK",
                    "text/html; charset=utf-8",
                    text.as_bytes(),
                ),
            }
            true
        }
        ("POST", "/events") => {
            // The browser's `sendEvent` POSTs to a bare `/events` with the
            // token inside the JSON body; the agent CLI uses the query.
            if !request_token_matches(&req, token) {
                write_unauthorized(&mut stream);
                return true;
            }
            match serde_json::from_slice::<Value>(&req.body) {
                Ok(event) => {
                    let ty = event.get("type").and_then(Value::as_str);
                    // Copy edits must use the staged stash/commit routes.
                    if ty == Some("manual_edits") {
                        write_json(
                            &mut stream,
                            400,
                            "Bad Request",
                            &json!({ "error": "manual_edits must POST to /manual-edit-stash, not /events" }),
                        );
                        return true;
                    }
                    if ty == Some("manual_edit_apply") {
                        write_json(
                            &mut stream,
                            400,
                            "Bad Request",
                            &json!({ "error": "manual_edit_apply is disabled; use /manual-edit-stash then /manual-edit-commit" }),
                        );
                        return true;
                    }
                    // `if (msg.type === 'exit') cleanupSvelteComponentSessionsBeforeExit();`
                    if ty == Some("exit") {
                        remove_all_svelte_component_sessions(project_root);
                    }
                    // Checkpoints are journal-only in JS (`!== 'checkpoint'`
                    // gates `enqueueEvent`); with no session store they are
                    // acknowledged and not queued for the agent.
                    if ty != Some("checkpoint") {
                        queue.enqueue_event(event);
                    }
                    write_json(&mut stream, 200, "OK", &json!({ "ok": true }));
                }
                Err(_) => {
                    write_json(
                        &mut stream,
                        400,
                        "Bad Request",
                        &json!({ "error": "Invalid JSON body" }),
                    );
                }
            }
            true
        }
        ("GET", "/poll") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "text/plain",
                    b"Unauthorized",
                );
                return true;
            }
            let deadline = std::time::Instant::now() + DEFAULT_POLL_TIMEOUT;
            let mut parked = false;
            let reply: Value = loop {
                if let Some(entry) = queue.find_available_pending_event() {
                    break queue
                        .lease_event(entry.seq, POLL_LEASE_MS)
                        .unwrap_or(entry.event);
                }
                if queue.is_shutdown() || std::time::Instant::now() >= deadline {
                    break json!({ "type": "timeout" });
                }
                if !parked {
                    queue.poll_started();
                    parked = true;
                }
                thread::sleep(POLL_SLEEP_STEP);
            };
            if parked {
                queue.poll_finished();
            } else {
                queue.broadcast_agent_polling_if_changed();
            }
            write_json(&mut stream, 200, "OK", &reply);
            true
        }
        ("POST", "/poll") => {
            // Acknowledge a previously leased event: body is `{ "id": "..." }`.
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "text/plain",
                    b"Unauthorized",
                );
                return true;
            }
            let parsed = serde_json::from_slice::<Value>(&req.body).ok();
            let id = parsed
                .as_ref()
                .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_owned));
            match id {
                Some(id) => {
                    let Some(body) = parsed.as_ref() else {
                        unreachable!("id was extracted from parsed JSON")
                    };
                    match settle_poll_reply(queue, manual_apply_controller, body, &id) {
                        PollReplyOutcome::Acknowledged(acked) => {
                            // Forward only replies whose queue/controller state
                            // was successfully settled.
                            if acked {
                                queue.publish_sse(poll_reply_broadcast(body, &id));
                            }
                            write_json(&mut stream, 200, "OK", &json!({ "ok": acked }));
                        }
                        PollReplyOutcome::Rejected(status, body) => {
                            let reason = match status {
                                400 => "Bad Request",
                                404 => "Not Found",
                                409 => "Conflict",
                                410 => "Gone",
                                _ => "Bad Request",
                            };
                            write_json(&mut stream, status, reason, &body);
                        }
                    }
                }
                None => {
                    write_json(
                        &mut stream,
                        400,
                        "Bad Request",
                        &json!({ "error": "Missing id" }),
                    );
                }
            }
            true
        }
        ("GET", "/status") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "text/plain",
                    b"Unauthorized",
                );
                return true;
            }
            // Same key names as the historical `live-server.mjs` `/status`
            // response: `status`, `port`, `connectedClients`, `agentPolling`,
            // `pendingEvents`. `activeSessions` and `manualEdits` are not
            // emitted: they depend on `live/session-store.mjs` and
            // `getManualEditStatus`, which are unported. `live-status` falls
            // back to its own session-store view when `activeSessions` is absent.
            write_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "status": "ok",
                    "port": port,
                    "connectedClients": queue.sse_client_count(),
                    "agentPolling": queue.agent_polling_connected(),
                    "pendingEvents": queue.status_summary(),
                }),
            );
            true
        }
        // `/live.js` and `/detect.js` are browser assets: re-served from
        // disk on every request (no-cache, matching JS's fresh
        // `readFileSync` per request for `/live.js`).
        ("GET", "/live.js") => {
            let scripts_dir = match find_scripts_dir(project_root) {
                Some(d) => d,
                None => {
                    write_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        "text/plain",
                        b"scripts dir not found",
                    );
                    return true;
                }
            };
            let resolved = match resolve_live_browser_script_parts(
                &scripts_dir.to_string_lossy(),
                LIVE_BROWSER_SCRIPT_PARTS,
            ) {
                Ok(r) => r,
                Err(e) => {
                    write_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        "text/plain",
                        e.as_bytes(),
                    );
                    return true;
                }
            };
            let parts =
                match read_live_browser_script_parts(&resolved, |p| std::fs::read_to_string(p)) {
                    Ok(p) => p,
                    Err(e) => {
                        let msg = format!("Error reading live browser scripts: {e}");
                        write_response(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            "text/plain",
                            msg.as_bytes(),
                        );
                        return true;
                    }
                };
            let vocab_value = Value::Array(
                live_commands()
                    .into_iter()
                    .map(|c| json!({ "value": c.value, "label": c.label, "icon": c.icon }))
                    .collect::<Vec<_>>(),
            );
            let vocab_json =
                serde_json::to_string(&vocab_value).unwrap_or_else(|_| "[]".to_string());
            let body = assemble_live_browser_script(token, port, &vocab_json, &parts);
            write_response(
                &mut stream,
                200,
                "OK",
                "application/javascript",
                body.as_bytes(),
            );
            true
        }
        ("GET", "/detect.js") | ("GET", "/") => {
            let scripts_dir = find_scripts_dir(project_root);
            let detect_path =
                scripts_dir.map(|d| d.join("detector").join("detect-antipatterns-browser.js"));
            match detect_path.and_then(|p| std::fs::read_to_string(p).ok()) {
                Some(content) => {
                    write_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/javascript",
                        content.as_bytes(),
                    );
                }
                None => {
                    write_response(
                        &mut stream,
                        404,
                        "Not Found",
                        "text/plain",
                        b"Not available",
                    );
                }
            }
            true
        }
        ("POST", "/annotation") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "text/plain",
                    b"Unauthorized",
                );
                return true;
            }
            let event_id = req.query.get("eventId").map(String::as_str).unwrap_or("");
            if !is_valid_event_id(event_id) {
                write_json(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({ "error": "Invalid eventId" }),
                );
                return true;
            }
            if !req.content_type.eq_ignore_ascii_case("image/png") {
                write_json(
                    &mut stream,
                    415,
                    "Unsupported Media Type",
                    &json!({ "error": "Content-Type must be image/png" }),
                );
                return true;
            }
            if req.body.len() > MAX_ANNOTATION_BYTES {
                write_json(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    &json!({ "error": "Payload too large" }),
                );
                return true;
            }
            let abs_path = session_dir.join(format!("{event_id}.png"));
            match std::fs::write(&abs_path, &req.body) {
                Ok(()) => write_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "ok": true, "path": abs_path.to_string_lossy() }),
                ),
                Err(e) => write_json(
                    &mut stream,
                    500,
                    "Internal Server Error",
                    &json!({ "error": format!("Write failed: {e}") }),
                ),
            }
            true
        }
        ("POST", "/manual-edit-stash")
        | ("GET", "/manual-edit-stash")
        | ("POST", "/manual-edit-commit")
        | ("POST", "/manual-edit-repair-decision")
        | ("POST", "/manual-edit-discard")
        | ("POST", "/manual-edit") => {
            // Token is checked inside `handle_manual_edit_route` itself
            // (from the JSON body for POST routes, from the query string for
            // the GET route), matching the JS `createManualEditRoutes`
            // handlers exactly — no separate check needed here.
            if req.path == "/manual-edit-commit" && request_token_matches(&req, token) {
                let mode = std::env::var("IMPECCABLE_LIVE_COPY_AGENT")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                let polling = queue.agent_polling_connected();
                let unavailable = match mode.as_str() {
                    "codex" | "claude" => Some(format!(
                        "{mode} manual-edit provider is not supported by the live server"
                    )),
                    "" | "auto" | "chat" if !polling => {
                        Some("authenticated agent polling is not connected".to_string())
                    }
                    "" | "auto" | "chat" => None,
                    _ => Some(format!("unsupported manual-edit provider: {mode}")),
                };
                if let Some(message) = unavailable {
                    write_json(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &json!({ "error": "unavailable", "message": message }),
                    );
                    return true;
                }
            }
            let is_mutating_manual_route = req.method == "POST"
                && matches!(
                    req.path.as_str(),
                    "/manual-edit-stash"
                        | "/manual-edit-commit"
                        | "/manual-edit-repair-decision"
                        | "/manual-edit-discard"
                );
            let _mutation_guard = if is_mutating_manual_route && request_token_matches(&req, token)
            {
                let Some(guard) = manual_apply_controller.try_begin_mutation() else {
                    write_json(
                        &mut stream,
                        409,
                        "Conflict",
                        &json!({ "error": "manual_edit_busy" }),
                    );
                    return true;
                };
                Some(guard)
            } else {
                None
            };
            let body: Option<Result<Value, String>> = if req.body.is_empty() {
                None
            } else {
                Some(serde_json::from_slice::<Value>(&req.body).map_err(|e| e.to_string()))
            };
            let manual_req = ManualEditRequest {
                method: req.method.clone(),
                path: req.path.clone(),
                query: req
                    .query
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                body,
            };
            let deps = LiveServerManualEditDeps {
                token: token.to_string(),
                project_root: project_root.to_path_buf(),
                queue,
                controller: manual_apply_controller,
            };
            match handle_manual_edit_route(&deps, &manual_req) {
                Some(resp) => {
                    let reason = match resp.status {
                        200 => "OK",
                        202 => "Accepted",
                        400 => "Bad Request",
                        401 => "Unauthorized",
                        404 => "Not Found",
                        409 => "Conflict",
                        410 => "Gone",
                        500 => "Internal Server Error",
                        503 => "Service Unavailable",
                        _ => "",
                    };
                    write_json(&mut stream, resp.status, reason, &resp.body);
                }
                None => {
                    write_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found");
                }
            }
            true
        }
        _ => {
            write_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found");
            true
        }
    }
}

/// `httpServer.listen(state.port, '127.0.0.1', ...)` plus the blocking
/// accept loop and `shutdown()` on `/stop`. Every accepted connection is
/// served on its own scoped thread so a parked long poll or an SSE stream
/// never blocks other requests. `/stop` sets the queue's shutdown flag
/// (which long-lived handlers observe) and opens one throwaway connection to
/// wake the accept loop; the scope then joins all connection threads.
/// An authorized SSE stream is counted; when the last one ends, the exit grace
/// timer runs on a scoped thread (see [`QueueState::run_exit_grace`]).
pub fn serve<'a>(
    listener: TcpListener,
    token: &str,
    queue: &QueueState,
    project_root: &Path,
    manual_apply_controller: &ManualApplyController<QueueCallbacks<'a>>,
    session_dir: &Path,
) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    thread::scope(|scope| {
        for incoming in listener.incoming() {
            if queue.is_shutdown() {
                break;
            }
            let mut stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            scope.spawn(move || {
                let _ = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT));
                let req = match read_request(&mut stream) {
                    Some(r) => r,
                    None => return,
                };
                // Only an authorized stream holds an SSE client slot.
                let sse_stream = is_authorized_sse_request(&req, token);
                if sse_stream {
                    queue.sse_client_connected();
                }
                let keep_running = handle_request(
                    req,
                    &stream,
                    token,
                    queue,
                    project_root,
                    port,
                    manual_apply_controller,
                    session_dir,
                );
                let _ = stream.flush();
                if sse_stream {
                    if let Some(generation) = queue.sse_client_disconnected() {
                        // The last browser left. The grace thread lives in this
                        // scope, so `serve` joins it before returning.
                        scope.spawn(move || queue.run_exit_grace(generation));
                    }
                }
                if !keep_running {
                    queue.request_shutdown();
                    // Wake the accept loop so it observes the flag.
                    let _ = TcpStream::connect(("127.0.0.1", port));
                }
            });
        }
    });
    let _ = remove_live_server_info(project_root);
}
