//! Port of `skills/alchemist/scripts/viewer.py` (chunk w2_002) — "Citadel", a
//! local-only viewer for Alchemist run event logs.
//!
//! The Python original is a stdlib `http.server` that serves one HTML page
//! plus two JSON endpoints (`/api/runs`, `/api/events`) reading the same
//! JSONL event logs the Alchemist worker runner writes. It classifies those
//! events with `parse_events.classify` (`skills/alchemist/scripts/parse_events.py`)
//! so the page and the `--summary` CLI can never disagree about what an event
//! means. `parse_events.py` is not in this chunk's file list, so `classify`
//! and its `iter_events`/`strip_bom` helpers are ported locally here, faithful
//! to the Python source, exactly as `viewer.py` uses them (it never touches
//! `parse_events.run_stream`/`run_summary`, so those are out of scope). When
//! the chunk that owns `parse_events.py` lands its own port, the integrator
//! should re-point this module at the canonical implementation and delete
//! this local copy.
//!
//! This port keeps the runtime to `std` only (no new crate dependency): a
//! minimal single-threaded HTTP/1.1 server built on `std::net::TcpListener`
//! stands in for Python's `ThreadingHTTPServer`. The request-handling and
//! classification logic is exposed as free functions so it is testable
//! without opening a socket; `run_server` is the thin loop that wires them to
//! `TcpStream`s.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// parse_events.py port (the pieces viewer.py actually depends on)
// ---------------------------------------------------------------------------

const TEXT_KEYS: [&str; 4] = ["text", "content", "message", "delta"];

/// Port of `parse_events.first_text`: best-effort extraction of
/// human-readable text from a nested event.
pub fn first_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(first_text).collect::<Vec<_>>().concat(),
        Value::Object(map) => {
            for key in TEXT_KEYS {
                if let Some(v) = map.get(key) {
                    let found = first_text(v);
                    if !found.is_empty() {
                        return found;
                    }
                }
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    // Python slicing `[:400]` counts Unicode code points, not bytes.
    s.chars().take(max).collect()
}

fn as_str_or_join(value: &Value) -> String {
    match value {
        Value::Array(items) => items
            .iter()
            .map(value_to_display_string)
            .collect::<Vec<_>>()
            .join(" "),
        other => value_to_display_string(other),
    }
}

fn value_to_display_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        other => other.to_string(),
    }
}

/// Port of `parse_events.classify`: returns `(kind, detail)`, `kind` being
/// the coarse bucket the UI colours by.
pub fn classify(event: &Value) -> (String, String) {
    let empty = json!({});
    let event_obj = event.as_object();

    // payload = event.get("item") if isinstance(event.get("item"), dict) else event
    let item = event_obj.and_then(|m| m.get("item"));
    let mut payload: &Value = match item {
        Some(v) if v.is_object() => v,
        _ => event,
    };
    // if payload is event and isinstance(event.get("msg"), dict): payload = event["msg"]
    if std::ptr::eq(payload, event) {
        if let Some(msg) = event_obj.and_then(|m| m.get("msg")) {
            if msg.is_object() {
                payload = msg;
            }
        }
    }
    let payload_obj = payload.as_object();

    let msg_type = event_obj
        .and_then(|m| m.get("msg"))
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("type"));

    let kind_value: &Value = payload_obj
        .and_then(|m| m.get("type"))
        .filter(|v| !v.is_null())
        .or_else(|| {
            event_obj
                .and_then(|m| m.get("type"))
                .filter(|v| !v.is_null())
        })
        .or_else(|| {
            event_obj
                .and_then(|m| m.get("event"))
                .filter(|v| !v.is_null())
        })
        .or(msg_type)
        .unwrap_or(&empty);
    let kind_str = if kind_value.is_null() || kind_value == &empty {
        "unknown".to_string()
    } else {
        value_to_display_string(kind_value)
    };
    let lowered = kind_str.to_lowercase();

    if lowered.contains("reason") {
        return ("reasoning".to_string(), truncate_chars(&first_text(payload), 400));
    }
    if lowered.contains("command") || lowered.contains("exec") || lowered.contains("shell") {
        let cmd = payload_obj
            .and_then(|m| m.get("command"))
            .or_else(|| payload_obj.and_then(|m| m.get("cmd")));
        let detail = match cmd {
            Some(v) => as_str_or_join(v),
            None => first_text(payload),
        };
        return ("command".to_string(), truncate_chars(&detail, 400));
    }
    if lowered.contains("patch") || lowered.contains("diff") || lowered.contains("apply") {
        return ("patch".to_string(), truncate_chars(&first_text(payload), 400));
    }
    let event_error = event_obj.and_then(|m| m.get("error")).filter(|v| !v.is_null());
    if lowered.contains("error") || event_error.is_some() {
        let source = event_error.unwrap_or(payload);
        return ("error".to_string(), truncate_chars(&first_text(source), 400));
    }
    if lowered.contains("message") || lowered.contains("agent") || lowered.contains("assistant") {
        return ("assistant".to_string(), first_text(payload));
    }
    if lowered.contains("token") || lowered.contains("usage") {
        let dumped = serde_json::to_string(payload).unwrap_or_default();
        return ("usage".to_string(), truncate_chars(&dumped, 200));
    }
    (kind_str, truncate_chars(&first_text(payload), 400))
}

/// Port of `parse_events.BOM_PREFIXES` + `strip_bom`. Strips a leading BOM,
/// whether it decoded as U+FEFF or the mojibake `ï»¿`, repeatedly (mirrors the
/// Python `while changed` loop).
pub fn strip_bom(line: &str) -> &str {
    let mut s = line;
    loop {
        if let Some(rest) = s.strip_prefix('\u{feff}') {
            s = rest;
            continue;
        }
        if let Some(rest) = s.strip_prefix("ï»¿") {
            s = rest;
            continue;
        }
        break;
    }
    s
}

/// Port of `parse_events.iter_events`. Malformed lines are skipped (the
/// `[non-json] ...` stderr diagnostic the CLI prints is out of scope for the
/// viewer, which never surfaces it either).
pub fn iter_events<R: BufRead>(reader: R) -> Vec<Value> {
    let mut out = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = strip_bom(line.trim()).to_string();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&trimmed) {
            out.push(value);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// viewer.py port proper
// ---------------------------------------------------------------------------

/// One row of `/api/runs`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunInfo {
    pub name: String,
    pub events: usize,
    pub mtime: f64,
}

/// Port of the `/api/runs` handler body: every `*.jsonl` file directly under
/// `runs_dir`, newest `mtime` first, with a best-effort non-blank-line count.
/// Mirrors the Python `try: ... except OSError: events = 0` fallback.
pub fn list_runs(runs_dir: &Path) -> Vec<RunInfo> {
    let mut runs = Vec::new();
    let Ok(entries) = fs::read_dir(runs_dir) else {
        return runs;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let meta = fs::metadata(&path);
        let mtime = meta
            .as_ref()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let events = match fs::File::open(&path) {
            Ok(f) => BufReader::new(f)
                .lines()
                .filter_map(|l| l.ok())
                .filter(|l| !l.trim().is_empty())
                .count(),
            Err(_) => 0,
        };
        runs.push(RunInfo { name, events, mtime });
    }
    runs.sort_by(|a, b| b.mtime.partial_cmp(&a.mtime).unwrap_or(std::cmp::Ordering::Equal));
    runs
}

/// Port of the `/api/events` containment check: "never read outside the
/// runs dir, whatever the caller sends." `name` must resolve (after joining
/// and canonicalising) to a file whose parent directory is `runs_dir`, and
/// the file must exist. Returns `None` for an empty name, a traversal
/// attempt, or a missing/non-file target — matching the Python handler's
/// `return self._json([])` in every one of those cases.
pub fn resolve_target(runs_dir: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    let runs_dir_resolved = fs::canonicalize(runs_dir).ok()?;
    let candidate = runs_dir.join(name);
    let target = fs::canonicalize(&candidate).ok()?;
    if !target.is_file() {
        return None;
    }
    // Python: `RUNS_DIR.resolve() not in target.parents` — i.e. runs_dir must
    // be one of target's ancestors (not necessarily the immediate parent).
    if target.ancestors().skip(1).any(|a| a == runs_dir_resolved) {
        Some(target)
    } else {
        None
    }
}

/// Port of the `/api/events` handler body: classified events from `name`
/// starting at index `from`. Empty when `resolve_target` rejects `name`.
pub fn events_from(runs_dir: &Path, name: &str, from: usize) -> Vec<(String, String)> {
    let Some(target) = resolve_target(runs_dir, name) else {
        return Vec::new();
    };
    let Ok(file) = fs::File::open(&target) else {
        return Vec::new();
    };
    iter_events(BufReader::new(file))
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i >= from)
        .map(|(_, event)| classify(&event))
        .collect()
}

/// The static page. Verbatim port of the Python `PAGE` constant.
pub const PAGE: &str = include_str!("page.html");

// ---------------------------------------------------------------------------
// Minimal std-only HTTP server (stand-in for Python's ThreadingHTTPServer)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Parsed `path?query` split of an HTTP request line's target.
fn split_path_query(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    }
}

/// Minimal `application/x-www-form-urlencoded`-style query parser sufficient
/// for `run=...&from=...` (percent-decodes `%XX` and `+`).
fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((percent_decode(k), percent_decode(v)));
    }
    out
}

fn percent_decode(s: &str) -> String {
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
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
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

fn query_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn write_response(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

/// Handles a single already-accepted connection: reads the request line,
/// dispatches on the three routes `viewer.py`'s `do_GET` recognises, writes
/// the response, and closes the connection (the Python handler is per-request
/// too; keep-alive is not part of the ported behaviour).
fn handle_connection(mut stream: TcpStream, runs_dir: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Drain the rest of the headers (ignored — no body is ever read).
    loop {
        let mut header_line = String::new();
        if reader.read_line(&mut header_line)? == 0 {
            break;
        }
        if header_line == "\r\n" || header_line == "\n" || header_line.is_empty() {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = split_path_query(target);

    match path {
        "/" => write_response(&mut stream, 200, "text/html; charset=utf-8", PAGE.as_bytes()),
        "/api/runs" => {
            let runs = list_runs(runs_dir);
            let body = json!(runs
                .iter()
                .map(|r| json!({"name": r.name, "events": r.events, "mtime": r.mtime}))
                .collect::<Vec<_>>());
            write_response(&mut stream, 200, "application/json", body.to_string().as_bytes())
        }
        "/api/events" => {
            let pairs = parse_query(query);
            let name = query_get(&pairs, "run").unwrap_or("");
            let from: usize = query_get(&pairs, "from").unwrap_or("0").parse().unwrap_or(0);
            let events = events_from(runs_dir, name, from);
            let body = json!(events
                .iter()
                .map(|(kind, detail)| json!({"kind": kind, "detail": detail}))
                .collect::<Vec<_>>());
            write_response(&mut stream, 200, "application/json", body.to_string().as_bytes())
        }
        _ => write_response(&mut stream, 404, "text/plain", b"not found"),
    }
}

/// Port of `viewer.main`'s server loop, minus the `argparse` CLI front end
/// (the host embedding this crate supplies `port`/`runs_dir` directly).
/// Creates `runs_dir` if missing (`RUNS_DIR.mkdir(parents=True, exist_ok=True)`)
/// and serves forever, one connection at a time.
pub fn run_server(port: u16, runs_dir: &Path) -> Result<(), ServeError> {
    fs::create_dir_all(runs_dir)?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    for stream in listener.incoming() {
        let stream = stream?;
        let _ = handle_connection(stream, runs_dir);
    }
    Ok(())
}

/// Default runs directory, mirroring `Path.home() / ".alchemist" / "runs"`
/// with the `ALCHEMIST_RUN_DIR` env override the Python module reads at
/// import time.
pub fn default_runs_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ALCHEMIST_RUN_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".alchemist").join("runs")
}
