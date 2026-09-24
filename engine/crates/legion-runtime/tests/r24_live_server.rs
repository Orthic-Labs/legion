//! Integration tests for chunk r24 (`live-server.mjs`), exercising the port
//! end-to-end: a real `TcpListener` bound via `find_open_port`, served by
//! `http_server::serve` on a background thread, hit with real TCP
//! connections (no fakes) for the routes that are self-contained in this
//! packet. Detailed unit coverage of the queue state machine and
//! `server.json` lifecycle lives alongside the source in
//! `src/wf_port/r24/queue.rs` and `src/wf_port/r24/server_info.rs`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use legion_runtime::wf_port::r24::manual_edit_deps::QueueCallbacks;
use legion_runtime::wf_port::r24::{find_open_port, http_server, parse_port_arg, QueueState};
use legion_runtime::wf_port::w2_021::manual_apply::ManualApplyController;

fn http_get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    resp
}

fn http_post(port: u16, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    resp
}

#[test]
fn find_open_port_binds_and_returns_a_free_port() {
    let (listener, port) = find_open_port(18_400).unwrap();
    assert!(port >= 18_400);
    drop(listener);
}

#[test]
fn parse_port_arg_reads_flag() {
    let args = vec!["--background".to_string(), "--port=9123".to_string()];
    assert_eq!(parse_port_arg(&args), Some(9123));
    assert_eq!(parse_port_arg(&[]), None);
}

#[test]
fn server_serves_health_events_and_poll_over_real_tcp() {
    let (listener, port) = find_open_port(18_500).unwrap();
    let token = "test-token".to_string();
    let tmp_root = std::env::temp_dir().join(format!("r24-http-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_root).unwrap();

    let handle = {
        let token = token.clone();
        let root = tmp_root.clone();
        thread::spawn(move || {
            let local_queue = QueueState::new();
            local_queue.enqueue_event(serde_json::json!({"id": "seed", "type": "noop"}));
            let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &local_queue });
            http_server::serve(listener, &token, &local_queue, &root, &controller);
        })
    };
    // Give the accept loop a moment to start (best-effort; the connect
    // below will simply retry via std's short backoff otherwise).
    thread::sleep(Duration::from_millis(50));

    let health = http_get(port, "/health");
    assert!(health.contains("200 OK"), "unexpected response: {health}");
    assert!(health.contains("\"ok\":true"));

    let poll = http_get(port, &format!("/poll?token={token}"));
    assert!(poll.contains("200 OK"));
    assert!(poll.contains("\"id\":\"seed\""), "expected seeded event in poll response: {poll}");

    let post = http_post(
        port,
        &format!("/events?token={token}"),
        r#"{"id":"e2","type":"generate"}"#,
    );
    assert!(post.contains("\"ok\":true"), "unexpected /events response: {post}");

    let unauthorized = http_get(port, "/poll?token=wrong");
    assert!(unauthorized.contains("401"));

    // `/live.js` is a real static-asset route now (packet r22r24): with no
    // `skills/designer/engine/scripts` directory under `tmp_root`, it fails
    // closed with 500 rather than a fabricated body.
    let live_js = http_get(port, "/live.js");
    assert!(live_js.contains("500"));

    // A route that genuinely still has no implementation (its dependency,
    // `live/session-store.mjs`, is unported) still answers 501 naming it.
    let not_implemented = http_get(port, "/annotation");
    assert!(not_implemented.contains("501"));
    assert!(not_implemented.contains("session-store.mjs"));

    // Shut the server down via /stop so the background thread exits.
    let stop = http_get(port, &format!("/stop?token={token}"));
    assert!(stop.contains("200 OK"));
    handle.join().unwrap();

    let _ = std::fs::remove_dir_all(&tmp_root);
}
