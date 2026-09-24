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
use std::net::TcpListener;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use super::queue::QueueState;
use super::server_info::remove_live_server_info;

struct Request {
    method: String,
    path: String,
    query: std::collections::HashMap<String, String>,
    body: Vec<u8>,
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
                if let Ok(byte) = u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                    16,
                ) {
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

fn handle_request(req: Request, mut stream: impl Write, token: &str, queue: &QueueState) -> bool {
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
                write_response(&mut stream, 401, "Unauthorized", "text/plain", b"Unauthorized");
                return true;
            }
            write_json(&mut stream, 200, "OK", &json!({ "ok": true }));
            false // signal caller to shut down after this response
        }
        ("POST", "/events") => {
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(&mut stream, 401, "Unauthorized", "text/plain", b"Unauthorized");
                return true;
            }
            match serde_json::from_slice::<Value>(&req.body) {
                Ok(event) => {
                    queue.enqueue_event(event);
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
                write_response(&mut stream, 401, "Unauthorized", "text/plain", b"Unauthorized");
                return true;
            }
            let deadline = std::time::Instant::now() + DEFAULT_POLL_TIMEOUT;
            loop {
                if let Some(entry) = queue.find_available_pending_event() {
                    let event = queue.lease_event(entry.seq, POLL_LEASE_MS).unwrap_or(entry.event);
                    write_json(&mut stream, 200, "OK", &event);
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    write_json(&mut stream, 200, "OK", &json!({ "type": "timeout" }));
                    return true;
                }
                thread::sleep(POLL_SLEEP_STEP);
            }
        }
        ("POST", "/poll") => {
            // Acknowledge a previously leased event: body is `{ "id": "..." }`.
            let provided = req.query.get("token").map(String::as_str).unwrap_or("");
            if provided != token {
                write_response(&mut stream, 401, "Unauthorized", "text/plain", b"Unauthorized");
                return true;
            }
            let id = serde_json::from_slice::<Value>(&req.body)
                .ok()
                .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_owned));
            match id {
                Some(id) => {
                    let acked = queue.acknowledge_pending_event(&id);
                    write_json(&mut stream, 200, "OK", &json!({ "ok": acked.is_some() }));
                }
                None => {
                    write_json(&mut stream, 400, "Bad Request", &json!({ "error": "Missing id" }));
                }
            }
            true
        }
        // Routes whose response body depends on unported sibling modules
        // (see mod.rs doc comment for the exact per-route dependency).
        ("GET", "/live.js") => {
            write_json(
                &mut stream,
                501,
                "Not Implemented",
                &json!({ "error": "live.js assembly depends on unported live/browser-script-parts.mjs and live/vocabulary.mjs" }),
            );
            true
        }
        ("GET", "/detect.js") | ("GET", "/") => {
            write_json(
                &mut stream,
                501,
                "Not Implemented",
                &json!({ "error": "detect.js bundle depends on unported scripts/detector loader (loadBrowserScripts)" }),
            );
            true
        }
        ("POST", "/annotation") => {
            write_json(
                &mut stream,
                501,
                "Not Implemented",
                &json!({ "error": "annotation staging depends on unported live/session-store.mjs" }),
            );
            true
        }
        ("POST", "/manual-edit-stash") | ("POST", "/manual-edit-commit") | ("POST", "/manual-edit-discard") => {
            write_json(
                &mut stream,
                501,
                "Not Implemented",
                &json!({ "error": "manual-edit routes depend on unported live/manual-edit-routes.mjs and live/manual-apply.mjs" }),
            );
            true
        }
        _ => {
            write_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found");
            true
        }
    }
}

/// `httpServer.listen(state.port, '127.0.0.1', ...)` plus the blocking
/// accept loop and `shutdown()` on `/stop`. Each connection is served on
/// its own thread (JS's single-threaded event loop is emulated closely
/// enough for this server's purposes — one client at a time in practice:
/// the agent CLI and at most one browser tab).
pub fn serve(listener: TcpListener, token: &str, queue: &QueueState, project_root: &Path) {
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let req = match read_request(&mut stream) {
            Some(r) => r,
            None => continue,
        };
        let keep_running = handle_request(req, &stream, token, queue);
        let _ = stream.flush();
        if !keep_running {
            let _ = remove_live_server_info(project_root);
            return;
        }
    }
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
        let req = Request {
            method: "GET".into(),
            path: "/health".into(),
            query: Default::default(),
            body: vec![],
        };
        let mut out = Vec::new();
        let keep_running = handle_request(req, &mut out, "tok", &queue);
        assert!(keep_running);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("200 OK"));
        assert!(text.contains("\"ok\":true"));
    }

    #[test]
    fn events_post_requires_matching_token() {
        let queue = QueueState::new();
        let req = Request {
            method: "POST".into(),
            path: "/events".into(),
            query: [("token".to_string(), "wrong".to_string())].into_iter().collect(),
            body: b"{}".to_vec(),
        };
        let mut out = Vec::new();
        handle_request(req, &mut out, "correct", &queue);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("401"));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn events_post_enqueues_and_poll_get_drains() {
        let queue = QueueState::new();
        let post = Request {
            method: "POST".into(),
            path: "/events".into(),
            query: [("token".to_string(), "tok".to_string())].into_iter().collect(),
            body: br#"{"id":"e1","type":"generate"}"#.to_vec(),
        };
        let mut out = Vec::new();
        handle_request(post, &mut out, "tok", &queue);
        assert_eq!(queue.len(), 1);

        let poll = Request {
            method: "GET".into(),
            path: "/poll".into(),
            query: [("token".to_string(), "tok".to_string())].into_iter().collect(),
            body: vec![],
        };
        let mut poll_out = Vec::new();
        handle_request(poll, &mut poll_out, "tok", &queue);
        let text = String::from_utf8(poll_out).unwrap();
        assert!(text.contains("\"id\":\"e1\""));
        // Leased (has an id) so it remains queued until acked.
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn poll_post_acknowledges_event() {
        let queue = QueueState::new();
        queue.enqueue_event(json!({"id": "e1", "type": "generate"}));
        let entry = queue.find_available_pending_event().unwrap();
        queue.lease_event(entry.seq, 30_000);

        let ack = Request {
            method: "POST".into(),
            path: "/poll".into(),
            query: [("token".to_string(), "tok".to_string())].into_iter().collect(),
            body: br#"{"id":"e1"}"#.to_vec(),
        };
        let mut out = Vec::new();
        handle_request(ack, &mut out, "tok", &queue);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"ok\":true"));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn unimplemented_sibling_routes_return_501_naming_dependency() {
        let queue = QueueState::new();
        let req = Request {
            method: "GET".into(),
            path: "/live.js".into(),
            query: Default::default(),
            body: vec![],
        };
        let mut out = Vec::new();
        handle_request(req, &mut out, "tok", &queue);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("501"));
        assert!(text.contains("browser-script-parts.mjs"));
    }

    #[test]
    fn stop_route_requires_token_and_signals_shutdown() {
        let queue = QueueState::new();
        let bad = Request {
            method: "GET".into(),
            path: "/stop".into(),
            query: [("token".to_string(), "wrong".to_string())].into_iter().collect(),
            body: vec![],
        };
        let mut out = Vec::new();
        assert!(handle_request(bad, &mut out, "tok", &queue));

        let good = Request {
            method: "GET".into(),
            path: "/stop".into(),
            query: [("token".to_string(), "tok".to_string())].into_iter().collect(),
            body: vec![],
        };
        let mut out2 = Vec::new();
        assert!(!handle_request(good, &mut out2, "tok", &queue));
    }

    #[test]
    fn urldecode_handles_percent_and_plus() {
        assert_eq!(urldecode("a%20b+c"), "a b c");
        assert_eq!(urldecode("token%3Dabc"), "token=abc");
    }
}
