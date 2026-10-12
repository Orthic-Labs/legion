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
    let mut parts = request_line.trim().split_whitespace();
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
            if !controller.resolve_deferred(id, result) {
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
            write_json(&mut stream, 200, "OK", &json!({ "ok": true }));
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
            write_json(&mut stream, 200, "OK", &json!({ "ok": true }));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_get_request_line_and_query() {
        let raw = b"GET /poll?token=abc HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(raw);
        let req = read_request(&mut cursor).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/poll");
        assert_eq!(req.query.get("token").map(String::as_str), Some("abc"));
    }

    #[test]
    fn parses_post_body_via_content_length() {
        let raw = b"POST /events?token=t HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"id\":\"e1\"}\r\n".to_vec();
        let mut cursor = Cursor::new(raw);
        let req = read_request(&mut cursor).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body.len(), 13);
    }

    #[test]
    fn health_check_returns_ok_json() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let req = Request {
            method: "GET".into(),
            path: "/health".into(),
            query: Default::default(),
            body: vec![],
            content_type: String::new(),
        };
        let mut out = Vec::new();
        let session_dir = std::env::temp_dir();
        let keep_running = handle_request(
            req,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        assert!(keep_running);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("200 OK"));
        assert!(text.contains("\"ok\":true"));
    }

    #[test]
    fn events_post_requires_matching_token() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let req = Request {
            method: "POST".into(),
            path: "/events".into(),
            query: [("token".to_string(), "wrong".to_string())]
                .into_iter()
                .collect(),
            body: b"{}".to_vec(),
            content_type: String::new(),
        };
        let mut out = Vec::new();
        let session_dir = std::env::temp_dir();
        handle_request(
            req,
            &mut out,
            "correct",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("401"));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn events_post_enqueues_and_poll_get_drains() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let post = Request {
            method: "POST".into(),
            path: "/events".into(),
            query: [("token".to_string(), "tok".to_string())]
                .into_iter()
                .collect(),
            body: br#"{"id":"e1","type":"generate"}"#.to_vec(),
            content_type: String::new(),
        };
        let mut out = Vec::new();
        let session_dir = std::env::temp_dir();
        handle_request(
            post,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        assert_eq!(queue.len(), 1);

        let poll = Request {
            method: "GET".into(),
            path: "/poll".into(),
            query: [("token".to_string(), "tok".to_string())]
                .into_iter()
                .collect(),
            body: vec![],
            content_type: String::new(),
        };
        let mut poll_out = Vec::new();
        handle_request(
            poll,
            &mut poll_out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(poll_out).unwrap();
        assert!(text.contains("\"id\":\"e1\""));
        // Leased (has an id) so it remains queued until acked.
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn poll_post_acknowledges_event() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        queue.enqueue_event(json!({"id": "e1", "type": "generate"}));
        let entry = queue.find_available_pending_event().unwrap();
        queue.lease_event(entry.seq, 30_000);

        let ack = Request {
            method: "POST".into(),
            path: "/poll".into(),
            query: [("token".to_string(), "tok".to_string())]
                .into_iter()
                .collect(),
            body: br#"{"id":"e1"}"#.to_vec(),
            content_type: String::new(),
        };
        let mut out = Vec::new();
        let session_dir = std::env::temp_dir();
        handle_request(
            ack,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"ok\":true"));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn manual_apply_reply_is_validated_and_resolves_waiter_before_ack() {
        let root = std::env::temp_dir().join(format!(
            "legion-manual-apply-poll-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let queue = QueueState::new();
        let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &queue });
        let batch = json!({
            "entries": [{
                "id": "entry-1",
                "pageUrl": "http://localhost/page",
                "ops": [{ "file": "src/page.html", "type": "replace", "selector": "#hero", "value": "Updated" }]
            }]
        });

        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                controller.push_batch_in_chunks_and_wait(
                    &batch,
                    Some("http://localhost/page"),
                    None,
                )
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let event = loop {
                if let Some(event) = queue.find_available_pending_event().map(|e| e.event) {
                    break event;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "manual apply event not queued"
                );
                thread::sleep(Duration::from_millis(1));
            };
            let id = event["id"].as_str().unwrap().to_string();
            let malformed = json!({
                "id": id.clone(),
                "data": { "status": "unknown", "appliedEntryIds": [], "failed": [], "files": [], "notes": [] }
            });
            let malformed_req = Request {
                method: "POST".into(),
                path: "/poll".into(),
                query: [("token".to_string(), "tok".to_string())]
                    .into_iter()
                    .collect(),
                body: malformed.to_string().into_bytes(),
                content_type: "application/json".into(),
            };
            let mut malformed_out = Vec::new();
            handle_request(
                malformed_req,
                &mut malformed_out,
                "tok",
                &queue,
                &root,
                0,
                &controller,
                &root,
            );
            assert!(String::from_utf8(malformed_out)
                .unwrap()
                .contains("400 Bad Request"));
            assert!(controller.get_deferred_batch(&id).is_some());
            assert_eq!(queue.len(), 1);

            let reply = json!({
                "id": id.clone(),
                "data": {
                    "status": "done",
                    "appliedEntryIds": ["entry-1"],
                    "failed": [],
                    "files": ["src/page.html"],
                    "notes": []
                }
            });
            let reply_req = Request {
                method: "POST".into(),
                path: "/poll".into(),
                query: [("token".to_string(), "tok".to_string())]
                    .into_iter()
                    .collect(),
                body: reply.to_string().into_bytes(),
                content_type: "application/json".into(),
            };
            let mut reply_out = Vec::new();
            handle_request(
                reply_req,
                &mut reply_out,
                "tok",
                &queue,
                &root,
                0,
                &controller,
                &root,
            );
            let reply_text = String::from_utf8(reply_out).unwrap();
            assert!(reply_text.contains("200 OK"), "{reply_text}");
            assert!(reply_text.contains("\"ok\":true"), "{reply_text}");
            assert_eq!(queue.len(), 0);
            assert!(controller.get_deferred_batch(&id).is_none());
            assert_eq!(waiter.join().unwrap()["status"], "done");
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manual_stash_is_rejected_before_mutation_when_project_is_busy() {
        let root = std::env::temp_dir().join(format!(
            "legion-manual-edit-busy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let queue = QueueState::new();
        let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &queue });
        queue.poll_started();
        let buffer = root
            .join(".impeccable")
            .join("live")
            .join("pending-manual-edits.json");
        let _active_mutation = controller.try_begin_mutation().unwrap();
        let requests = [
            Request {
                method: "POST".into(),
                path: "/manual-edit-stash".into(),
                query: Default::default(),
                body: json!({
                    "token": "tok",
                    "id": "entry-1",
                    "pageUrl": "http://localhost/page",
                    "element": { "tag": "button" },
                    "ops": [{ "type": "setText", "value": "Updated" }]
                })
                .to_string()
                .into_bytes(),
                content_type: "application/json".into(),
            },
            Request {
                method: "POST".into(),
                path: "/manual-edit-commit".into(),
                query: [("token".to_string(), "tok".to_string())]
                    .into_iter()
                    .collect(),
                body: vec![],
                content_type: String::new(),
            },
            Request {
                method: "POST".into(),
                path: "/manual-edit-repair-decision".into(),
                query: Default::default(),
                body: json!({ "token": "tok", "action": "rollback" })
                    .to_string()
                    .into_bytes(),
                content_type: "application/json".into(),
            },
            Request {
                method: "POST".into(),
                path: "/manual-edit-discard".into(),
                query: [("token".to_string(), "tok".to_string())]
                    .into_iter()
                    .collect(),
                body: vec![],
                content_type: String::new(),
            },
        ];
        for req in requests {
            let mut out = Vec::new();
            handle_request(req, &mut out, "tok", &queue, &root, 0, &controller, &root);
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains("409 Conflict"));
            assert!(text.contains("manual_edit_busy"));
            assert!(
                !buffer.exists(),
                "busy mutation must not write the edit buffer"
            );
        }
        queue.poll_finished();
        drop(_active_mutation);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn late_manual_apply_reply_rolls_back_and_returns_gone() {
        let root = std::env::temp_dir().join(format!(
            "legion-manual-apply-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let queue = QueueState::new();
        let controller = ManualApplyController::with_timeouts(
            root.clone(),
            QueueCallbacks { queue: &queue },
            Duration::from_millis(20),
            20,
        );
        let batch = json!({
            "entries": [{
                "id": "entry-timeout",
                "ops": [{ "file": "src/page.html", "type": "replace", "selector": "#hero", "value": "Updated" }]
            }]
        });
        std::thread::scope(|scope| {
            let waiter =
                scope.spawn(|| controller.push_batch_in_chunks_and_wait(&batch, None, None));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let id = loop {
                if let Some(event) = queue.find_available_pending_event() {
                    break event.event["id"].as_str().unwrap().to_string();
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "manual apply event not queued"
                );
                thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(waiter.join().unwrap()["status"], "error");
            assert!(controller.has_timed_out_id(&id));
            let late_reply = json!({ "id": id.clone() });
            let late_request = || Request {
                method: "POST".into(),
                path: "/poll".into(),
                query: [("token".to_string(), "tok".to_string())]
                    .into_iter()
                    .collect(),
                body: late_reply.to_string().into_bytes(),
                content_type: "application/json".into(),
            };
            let _busy_guard = controller.try_begin_timeout_rollback().unwrap();
            let mut late_out = Vec::new();
            handle_request(
                late_request(),
                &mut late_out,
                "tok",
                &queue,
                &root,
                0,
                &controller,
                &root,
            );
            assert!(String::from_utf8(late_out)
                .unwrap()
                .contains("409 Conflict"));
            assert!(controller.has_timed_out_id(&id));
            drop(_busy_guard);
            let mut late_out = Vec::new();
            handle_request(
                late_request(),
                &mut late_out,
                "tok",
                &queue,
                &root,
                0,
                &controller,
                &root,
            );
            assert!(String::from_utf8(late_out).unwrap().contains("410 Gone"));
            assert!(!controller.has_timed_out_id(&id));
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_manual_apply_reply_is_rejected_without_queue_ack() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        queue.enqueue_event(json!({ "id": "orphan-1", "type": "manual_edit_apply" }));
        let entry = queue.find_available_pending_event().unwrap();
        queue.lease_event(entry.seq, 30_000);
        let req = Request {
            method: "POST".into(),
            path: "/poll".into(),
            query: [("token".to_string(), "tok".to_string())]
                .into_iter()
                .collect(),
            body: br#"{"id":"orphan-1"}"#.to_vec(),
            content_type: "application/json".into(),
        };
        let mut out = Vec::new();
        handle_request(
            req,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            Path::new("."),
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("409 Conflict"), "{text}");
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn live_js_500s_when_scripts_dir_is_missing() {
        // `/live.js` is now a real static-asset route (packet r22r24); with
        // no `skills/designer/engine/scripts` directory under the given
        // project root, it fails closed with 500 rather than fabricating a
        // script body — mirrors `assertLiveBrowserScriptParts` raising at
        // startup when a part file is missing.
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let req = Request {
            method: "GET".into(),
            path: "/live.js".into(),
            query: Default::default(),
            body: vec![],
            content_type: String::new(),
        };
        let mut out = Vec::new();
        let dir = std::env::temp_dir().join(format!(
            "legion-r24-live-js-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            {
                static NEXT: ::std::sync::atomic::AtomicU64 =
                    ::std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
            }
        ));
        let session_dir = std::env::temp_dir();
        handle_request(
            req,
            &mut out,
            "tok",
            &queue,
            &dir,
            0,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("500"));
    }

    #[test]
    fn annotation_post_stages_png_to_session_dir() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let session_dir = std::env::temp_dir().join(format!(
            "legion-r24-annotation-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            {
                static NEXT: ::std::sync::atomic::AtomicU64 =
                    ::std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
            }
        ));
        std::fs::create_dir_all(&session_dir).unwrap();
        let req = Request {
            method: "POST".into(),
            path: "/annotation".into(),
            query: [
                ("token".to_string(), "tok".to_string()),
                ("eventId".to_string(), "e1".to_string()),
            ]
            .into_iter()
            .collect(),
            body: b"\x89PNG\r\n\x1a\nfake".to_vec(),
            content_type: "image/png".to_string(),
        };
        let mut out = Vec::new();
        handle_request(
            req,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("200"));
        assert!(text.contains("\"ok\":true"));
        assert!(session_dir.join("e1.png").exists());
        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn stop_route_requires_token_and_signals_shutdown() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let session_dir = std::env::temp_dir();
        let bad = Request {
            method: "GET".into(),
            path: "/stop".into(),
            query: [("token".to_string(), "wrong".to_string())]
                .into_iter()
                .collect(),
            body: vec![],
            content_type: String::new(),
        };
        let mut out = Vec::new();
        assert!(handle_request(
            bad,
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir
        ));

        let good = Request {
            method: "GET".into(),
            path: "/stop".into(),
            query: [("token".to_string(), "tok".to_string())]
                .into_iter()
                .collect(),
            body: vec![],
            content_type: String::new(),
        };
        let mut out2 = Vec::new();
        assert!(!handle_request(
            good,
            &mut out2,
            "tok",
            &queue,
            Path::new("."),
            0,
            &controller,
            &session_dir
        ));
    }

    #[test]
    fn urldecode_handles_percent_and_plus() {
        assert_eq!(urldecode("a%20b+c"), "a b c");
        assert_eq!(urldecode("token%3Dabc"), "token=abc");
    }

    // ---- Designer live-server / browser-client contract tests ----

    fn mk_req(method: &str, path: &str, query: &[(&str, &str)], body: &[u8]) -> Request {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
            content_type: String::new(),
        }
    }

    fn run_req(req: Request, token: &str, queue: &QueueState, root: &Path) -> String {
        let controller =
            ManualApplyController::new(std::path::PathBuf::from("."), QueueCallbacks { queue });
        let session_dir = std::env::temp_dir();
        let mut out = Vec::new();
        handle_request(
            req,
            &mut out,
            token,
            queue,
            root,
            0,
            &controller,
            &session_dir,
        );
        String::from_utf8(out).unwrap()
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-r24-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn installed_package_scripts_dirs_follow_project_candidates() {
        let project = Path::new("/proj");
        let dirs = candidate_scripts_dirs_with(project, Some(Path::new("/opt/legion/bin")));
        assert_eq!(dirs[0], project.join("skills/designer/engine/scripts"));
        assert_eq!(
            dirs[1],
            project.join("node_modules/impeccable/skills/designer/engine/scripts")
        );
        assert_eq!(
            dirs[2],
            Path::new("/opt/legion").join("plugin/skills/designer/engine/scripts")
        );
        assert_eq!(
            dirs[3],
            Path::new("/opt/legion").join("skills/designer/engine/scripts")
        );
        assert_eq!(candidate_scripts_dirs_with(project, None).len(), 2);
    }

    #[test]
    fn events_post_accepts_token_from_json_body_like_the_browser_client() {
        let queue = QueueState::new();
        let body = br#"{"id":"e9","type":"generate","token":"tok"}"#;
        let ok = run_req(
            mk_req("POST", "/events", &[], body),
            "tok",
            &queue,
            Path::new("."),
        );
        assert!(ok.contains("200 OK"), "{ok}");
        assert_eq!(queue.len(), 1);

        let bad = run_req(
            mk_req(
                "POST",
                "/events",
                &[],
                br#"{"id":"e10","type":"generate","token":"nope"}"#,
            ),
            "tok",
            &queue,
            Path::new("."),
        );
        assert!(bad.contains("401"), "{bad}");
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn events_post_acknowledges_checkpoints_without_queueing_them() {
        let queue = QueueState::new();
        let out = run_req(
            mk_req(
                "POST",
                "/events",
                &[],
                br#"{"id":"s1","type":"checkpoint","token":"tok"}"#,
            ),
            "tok",
            &queue,
            Path::new("."),
        );
        assert!(out.contains("200 OK"), "{out}");
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn get_events_streams_sse_headers_and_connected_message() {
        let root = scratch_dir("sse-head");
        let queue = QueueState::new();
        // Already shut down: the stream writes its head + `connected`, then ends.
        queue.request_shutdown();
        let out = run_req(
            mk_req("GET", "/events", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(out.contains("Content-Type: text/event-stream"), "{out}");
        assert!(out.contains("Cache-Control: no-cache"), "{out}");
        assert!(out.contains("Access-Control-Allow-Origin: *"), "{out}");
        assert!(out.contains("data: {"), "{out}");
        assert!(out.contains("\"type\":\"connected\""), "{out}");
        assert!(out.contains("\"hasProjectContext\":false"), "{out}");
        assert!(out.contains("\"activeSessions\":[]"), "{out}");

        let unauth = run_req(
            mk_req("GET", "/events", &[("token", "wrong")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(unauth.contains("401"), "{unauth}");
        assert!(!unauth.contains("text/event-stream"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stream_sse_relays_published_messages_and_keepalive_comments() {
        let root = scratch_dir("sse-relay");
        let queue = QueueState::new();
        let mut out: Vec<u8> = Vec::new();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(60));
                queue.publish_sse(json!({"type": "done", "id": "e1"}));
            });
            stream_sse(
                &mut out,
                &queue,
                &root,
                Duration::from_millis(400),
                Duration::from_millis(30),
                Duration::from_millis(10),
            );
        });
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"type\":\"connected\""), "{text}");
        assert!(
            text.contains("data: {\"type\":\"done\",\"id\":\"e1\"}"),
            "{text}"
        );
        assert!(text.contains(": keepalive\n\n"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn poll_post_ack_forwards_agent_reply_to_sse_clients() {
        let queue = QueueState::new();
        queue.enqueue_event(json!({"id": "e1", "type": "generate"}));
        let entry = queue.find_available_pending_event().unwrap();
        queue.lease_event(entry.seq, 30_000);
        let cursor = queue.sse_cursor();
        let out = run_req(
            mk_req(
                "POST",
                "/poll",
                &[("token", "tok")],
                br#"{"id":"e1","type":"done","file":"a.html","message":"ok"}"#,
            ),
            "tok",
            &queue,
            Path::new("."),
        );
        assert!(out.contains("\"ok\":true"), "{out}");
        let msgs: Vec<_> = queue
            .sse_messages_after(cursor)
            .into_iter()
            .filter(|(_, m)| m["type"] == "done")
            .collect();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].1["id"], "e1");
        assert_eq!(msgs[0].1["file"], "a.html");
        assert_eq!(msgs[0].1["message"], "ok");
    }

    #[test]
    fn poll_reply_broadcast_defaults_type_to_done_and_omits_absent_fields() {
        let msg = poll_reply_broadcast(&json!({"id": "x"}), "x");
        assert_eq!(msg, json!({"type": "done", "id": "x"}));
    }

    fn status_response_body(text: &str) -> Value {
        let body = text.split("\r\n\r\n").nth(1).expect("response body");
        serde_json::from_str(body).expect("json body")
    }

    #[test]
    fn status_route_returns_historical_fields() {
        let queue = QueueState::new();
        queue.enqueue_event(json!({"id": "e1", "type": "generate"}));
        queue.sse_client_connected();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let session_dir = std::env::temp_dir();
        let mut out = Vec::new();
        handle_request(
            mk_req("GET", "/status", &[("token", "tok")], b""),
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            5170,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("200 OK"), "{text}");
        let body = status_response_body(&text);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["port"], 5170);
        assert_eq!(body["connectedClients"], 1);
        assert_eq!(body["agentPolling"], false);
        assert_eq!(body["pendingEvents"][0]["id"], "e1");
        assert_eq!(body["pendingEvents"][0]["type"], "generate");
    }

    #[test]
    fn status_route_reports_agent_polling_while_a_poll_is_parked() {
        let queue = QueueState::new();
        queue.poll_started();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let session_dir = std::env::temp_dir();
        let mut out = Vec::new();
        handle_request(
            mk_req("GET", "/status", &[("token", "tok")], b""),
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            5170,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        let body = status_response_body(&text);
        assert_eq!(body["agentPolling"], true);
        assert_eq!(body["connectedClients"], 0);
    }

    #[test]
    fn status_route_rejects_wrong_token_without_fields() {
        let queue = QueueState::new();
        let controller = ManualApplyController::new(
            std::path::PathBuf::from("."),
            QueueCallbacks { queue: &queue },
        );
        let session_dir = std::env::temp_dir();
        let mut out = Vec::new();
        handle_request(
            mk_req("GET", "/status", &[("token", "nope")], b""),
            &mut out,
            "tok",
            &queue,
            Path::new("."),
            5170,
            &controller,
            &session_dir,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("401"), "{text}");
        assert!(!text.contains("\"port\""), "{text}");
    }

    #[test]
    fn modern_screenshot_route_serves_packaged_asset() {
        let root = scratch_dir("modern-screenshot");
        let scripts = root.join("skills/designer/engine/scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(
            scripts.join("modern-screenshot.umd.js"),
            b"window.modernScreenshot = {};",
        )
        .unwrap();
        let queue = QueueState::new();
        let out = run_req(
            mk_req("GET", "/modern-screenshot.js", &[], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(out.contains("200 OK"), "{out}");
        assert!(
            out.contains("Content-Type: application/javascript"),
            "{out}"
        );
        assert!(out.ends_with("window.modernScreenshot = {};"), "{out}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn modern_screenshot_route_returns_not_found_when_asset_is_absent() {
        let root = scratch_dir("modern-screenshot-absent");
        let queue = QueueState::new();
        let out = run_req(
            mk_req("GET", "/modern-screenshot.js", &[], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(out.contains("404 Not Found"), "{out}");
        assert!(out.ends_with("Not available"), "{out}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn design_system_routes_require_token_and_degrade_when_absent() {
        let root = scratch_dir("ds-absent");
        let queue = QueueState::new();
        let unauth = run_req(
            mk_req("GET", "/design-system.json", &[("token", "bad")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(unauth.contains("401"), "{unauth}");
        let json_out = run_req(
            mk_req("GET", "/design-system.json", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(json_out.contains("404"), "{json_out}");
        assert!(json_out.contains("\"present\":false"), "{json_out}");
        assert!(
            json_out.contains("\"reason\":\"design-system-not-available\""),
            "{json_out}"
        );
        let raw_out = run_req(
            mk_req("GET", "/design-system/raw", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(raw_out.contains("404"), "{raw_out}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn design_system_routes_serve_design_md_and_sidecar_when_present() {
        let root = scratch_dir("ds-present");
        std::fs::write(
            root.join("DESIGN.md"),
            "# Design\n\n## Overview\nA calm system.\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join(".impeccable")).unwrap();
        std::fs::write(
            root.join(".impeccable/design.json"),
            r#"{"schemaVersion":2}"#,
        )
        .unwrap();
        let queue = QueueState::new();
        let raw = run_req(
            mk_req("GET", "/design-system/raw", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(raw.contains("200 OK"), "{raw}");
        assert!(raw.contains("text/markdown"), "{raw}");
        assert!(raw.contains("# Design"), "{raw}");
        let json_out = run_req(
            mk_req("GET", "/design-system.json", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(json_out.contains("200 OK"), "{json_out}");
        assert!(json_out.contains("\"present\":true"), "{json_out}");
        assert!(json_out.contains("\"hasSidecar\":true"), "{json_out}");
        assert!(json_out.contains("\"schemaVersion\":2"), "{json_out}");
        // `parsed` is the real DESIGN.md model, not null.
        assert!(json_out.contains("\"title\":\"Design\""), "{json_out}");
        assert!(
            json_out.contains("\"philosophy\":[\"A calm system.\"]"),
            "{json_out}"
        );
        assert!(!json_out.contains("\"parsed\":null"), "{json_out}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn source_route_requires_token() {
        let root = scratch_dir("source-token");
        std::fs::write(root.join("a.svelte"), "<p>hi</p>").unwrap();
        let queue = QueueState::new();
        let wrong = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "bad"), ("path", "a.svelte")],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(wrong.contains("401"), "{wrong}");
        let missing = run_req(
            mk_req("GET", "/source", &[("path", "a.svelte")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(missing.contains("401"), "{missing}");
        assert!(!wrong.contains("<p>hi</p>") && !missing.contains("<p>hi</p>"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn source_route_serves_project_file_as_html_text() {
        let root = scratch_dir("source-ok");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/v1.svelte"), "<p>variant</p>").unwrap();
        let queue = QueueState::new();
        let out = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "tok"), ("path", "dir/v1.svelte")],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(
            out.contains("Content-Type: text/html; charset=utf-8"),
            "{out}"
        );
        assert!(out.ends_with("<p>variant</p>"), "{out}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn source_route_refuses_paths_outside_project_root() {
        let base = scratch_dir("source-escape");
        let root = base.join("proj");
        std::fs::create_dir_all(&root).unwrap();
        // A sibling whose name shares the root as a string prefix must not pass.
        let sibling = base.join("proj-evil");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("secret.txt"), "SECRET").unwrap();
        let queue = QueueState::new();

        let dotdot = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "tok"), ("path", "../proj-evil/secret.txt")],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(dotdot.contains("400 Bad Request"), "{dotdot}");
        assert!(dotdot.contains("Bad path"), "{dotdot}");
        assert!(!dotdot.contains("SECRET"), "{dotdot}");

        let absolute = sibling.join("secret.txt").to_string_lossy().into_owned();
        let abs = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "tok"), ("path", absolute.as_str())],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(abs.contains("403 Forbidden"), "{abs}");
        assert!(!abs.contains("SECRET"), "{abs}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn source_route_refuses_symlink_that_escapes_project_root() {
        let base = scratch_dir("source-symlink");
        let root = base.join("proj");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(base.join("outside.txt"), "SECRET").unwrap();
        std::os::unix::fs::symlink(base.join("outside.txt"), root.join("link.txt")).unwrap();
        let queue = QueueState::new();
        let out = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "tok"), ("path", "link.txt")],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(out.contains("403 Forbidden"), "{out}");
        assert!(!out.contains("SECRET"), "{out}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn source_route_reports_missing_file_404_and_missing_path_400() {
        let root = scratch_dir("source-missing");
        let queue = QueueState::new();
        let missing = run_req(
            mk_req(
                "GET",
                "/source",
                &[("token", "tok"), ("path", "nope.svelte")],
                b"",
            ),
            "tok",
            &queue,
            &root,
        );
        assert!(missing.contains("404 Not Found"), "{missing}");
        assert!(missing.contains("File not found"), "{missing}");
        let no_path = run_req(
            mk_req("GET", "/source", &[("token", "tok")], b""),
            "tok",
            &queue,
            &root,
        );
        assert!(no_path.contains("400 Bad Request"), "{no_path}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn serve_handles_requests_concurrently_and_stop_ends_the_accept_loop() {
        let root = scratch_dir("serve-concurrent");
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let queue = QueueState::new();
        let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &queue });
        let session_dir = root.join("session");
        std::fs::create_dir_all(&session_dir).unwrap();

        fn get(port: u16, path: &str) -> String {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        }

        thread::scope(|scope| {
            scope.spawn(|| serve(listener, "tok", &queue, &root, &controller, &session_dir));

            // Hold an SSE stream open; it must not block other requests.
            let mut sse = TcpStream::connect(("127.0.0.1", port)).unwrap();
            sse.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            sse.write_all(b"GET /events?token=tok HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut buf = [0u8; 512];
            let n = sse.read(&mut buf).unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(head.contains("text/event-stream"), "{head}");

            let health = get(port, "/health");
            assert!(health.contains("200 OK"), "{health}");

            let stop = get(port, "/stop?token=tok");
            assert!(stop.contains("200 OK"), "{stop}");
            // Leaving the scope joins `serve`: it only returns if /stop
            // ended the accept loop and the SSE connection thread.
        });
        let _ = std::fs::remove_dir_all(&root);
    }
}
