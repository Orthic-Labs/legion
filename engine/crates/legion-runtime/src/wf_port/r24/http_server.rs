//! Synchronous `std::net::TcpListener` HTTP/1.1 server loop, per the port
//! brief's guidance to use `TcpListener` (no `tiny_http` pinned in
//! `engine/Cargo.lock`, checked). Ports `createRequestHandler`'s routing
//! table and `httpServer.listen(...)` from `live-server.mjs`, plus the
//! `shutdown()` cleanup path, for the routes whose behavior is
//! self-contained in this packet (queue state machine + CORS + `/health` +
//! `/stop`). Routes whose response body is assembled by unported sibling
//! `.mjs` modules answer `501 Not Implemented` naming the missing module —
//! see the `mod.rs` doc comment for the exact list.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{json, Value};

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
use crate::wf_port::w2_021::manual_apply::ManualApplyController;
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

/// How long an SSE connection may live before the server ends it (the
/// browser's `EventSource` reconnects on its own).
const SSE_MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// JS `SSE_HEARTBEAT_INTERVAL`.
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
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

/// `/design-system.json`. The `parsed` half of the JS response needs
/// `parseDesignMd`, which has no Rust port; the sidecar half and the
/// presence/staleness flags are produced faithfully. When nothing exists the
/// answer is 404 with `present: false`, which the panel renders as its empty
/// state.
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
            write_json(
                &mut stream,
                404,
                "Not Found",
                &json!({ "error": "unavailable", "reason": "modern-screenshot-not-shipped" }),
            );
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
                    let acked = queue.acknowledge_pending_event(&id);
                    if acked.is_some() {
                        // Forward the agent's reply to the browser via SSE.
                        if let Some(body) = parsed.as_ref() {
                            queue.publish_sse(poll_reply_broadcast(body, &id));
                        }
                    }
                    write_json(&mut stream, 200, "OK", &json!({ "ok": acked.is_some() }));
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
            // Faithful for `pendingEvents`; the other JS `/status` fields
            // (`connectedClients`, `agentPolling`, `activeSessions`,
            // `manualEdits`) depend on SSE-client tracking and
            // `live/session-store.mjs`, both unported — see `queue.rs`'s
            // `status_summary` doc comment.
            write_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "status": "ok",
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
                        410 => "Gone",
                        500 => "Internal Server Error",
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

    #[test]
    fn modern_screenshot_route_reports_not_shipped() {
        let queue = QueueState::new();
        let out = run_req(
            mk_req("GET", "/modern-screenshot.js", &[], b""),
            "tok",
            &queue,
            Path::new("."),
        );
        assert!(out.contains("404"), "{out}");
        assert!(
            out.contains("\"reason\":\"modern-screenshot-not-shipped\""),
            "{out}"
        );
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
        std::fs::write(root.join("DESIGN.md"), "# Design\n").unwrap();
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
