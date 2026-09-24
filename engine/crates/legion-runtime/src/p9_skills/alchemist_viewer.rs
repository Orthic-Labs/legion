//! Packet P9-skill-scripts: Rust port of `skills/alchemist/scripts/viewer.py` — the
//! localhost-only "Citadel" page that shows orchestrator<->worker traffic for Alchemist
//! runs, reusing the same `classify()` logic as `parse_events.py` (see
//! [`crate::p9_skills::alchemist`]) so the page and the CLI `--summary` output can never
//! disagree about what an event means.
//!
//! Ported: the `/`, `/api/runs`, `/api/events` route handlers as pure functions over a
//! [`RunsDir`] trait (so tests never touch the filesystem or a socket), the exact JSON
//! shapes, the directory-containment check on `/api/events?run=`, and the embedded `PAGE`
//! HTML/JS verbatim. `run()` wires those handlers to a real `std::net::TcpListener` loop
//! (the network I/O itself, like the JS `ThreadingHTTPServer`, is not exercised by tests —
//! only [`handle_request`] and [`RunsDir`] fakes are).

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use super::alchemist::{classify, iter_events};

/// The embedded single-page viewer, byte-for-byte the same markup/JS as `viewer.py`'s
/// `PAGE` constant.
pub const PAGE: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>Citadel — agent runs</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#111;--dim:#666;--line:#e3e3e6;--card:#fafafa}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--fg:#e8e8ea;--dim:#8b8b93;--line:#2a2d35;--card:#181b21}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:15px;margin:0;font-weight:600}
select,button{font:inherit;padding:4px 8px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px}
main{padding:12px 16px;max-width:1100px}
.ev{border-left:3px solid var(--line);padding:5px 10px;margin:5px 0;background:var(--card);border-radius:0 6px 6px 0;overflow-x:auto}
.k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin-right:8px}
pre{margin:2px 0;white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,Menlo,Consolas,monospace}
.assistant{border-left-color:#3b82f6}.command{border-left-color:#8b5cf6}.patch{border-left-color:#10b981}
.error{border-left-color:#ef4444}.reasoning{border-left-color:#9ca3af;opacity:.75}.usage{opacity:.6}
.empty{color:var(--dim);padding:24px 0}
.count{color:var(--dim);font-size:12px}
</style></head><body>
<header>
  <h1>Citadel</h1>
  <select id="run"></select>
  <label><input type="checkbox" id="live" checked> live</label>
  <span class="count" id="count"></span>
</header>
<main><div id="log" class="empty">Select a run.</div></main>
<script>
const runSel=document.getElementById('run'),log=document.getElementById('log'),
      live=document.getElementById('live'),count=document.getElementById('count');
let current=null,seen=0;
async function loadRuns(){
  const runs=await (await fetch('/api/runs')).json();
  const keep=runSel.value;
  runSel.innerHTML=runs.map(r=>`<option value="${r.name}">${r.name} (${r.events})</option>`).join('');
  if(runs.length===0){log.className='empty';log.textContent='No runs yet. Invoke /alchemist to create one.';return;}
  runSel.value=runs.some(r=>r.name===keep)?keep:runs[0].name;
  if(current!==runSel.value){current=runSel.value;seen=0;log.innerHTML='';}
}
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function loadEvents(){
  if(!runSel.value)return;
  if(current!==runSel.value){current=runSel.value;seen=0;log.innerHTML='';}
  const evs=await (await fetch('/api/events?run='+encodeURIComponent(current)+'&from='+seen)).json();
  if(evs.length){
    log.className='';
    for(const e of evs){
      const d=document.createElement('div');d.className='ev '+e.kind;
      d.innerHTML='<span class="k">'+esc(e.kind)+'</span><pre>'+esc(e.detail||'')+'</pre>';
      log.appendChild(d);
    }
    seen+=evs.length;count.textContent=seen+' events';
    window.scrollTo(0,document.body.scrollHeight);
  }
}
runSel.onchange=()=>{seen=0;log.innerHTML='';loadEvents()};
loadRuns().then(loadEvents);
setInterval(()=>{if(live.checked){loadRuns();loadEvents();}},2000);
</script></body></html>"#;

/// Abstracts the filesystem reads `viewer.py`'s handlers perform, so [`handle_request`] is
/// testable without a real runs directory. Mirrors `RUNS_DIR.glob("*.jsonl")` (for
/// `/api/runs`) and reading one file's JSONL content (for `/api/events`).
pub trait RunsDir {
    /// `(file_name, event_count, mtime_seconds)` for every `*.jsonl` file directly under the
    /// runs dir, in the same "newest mtime first" order `/api/runs` returns.
    fn list_runs(&self) -> Vec<(String, usize, f64)>;
    /// The full JSONL text of `name` if it exists directly under the runs dir; `None`
    /// otherwise (mirrors the containment + `is_file()` check `/api/events` performs before
    /// reading).
    fn read_run(&self, name: &str) -> Option<String>;
}

/// Production [`RunsDir`] backed by a real directory on disk (defaults to
/// `$ALCHEMIST_RUN_DIR` or `~/.alchemist/runs`, matching `RUNS_DIR`'s default and
/// `--runs-dir` override).
pub struct RealRunsDir {
    pub dir: PathBuf,
}

impl RealRunsDir {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Mirrors `Path(os.environ.get("ALCHEMIST_RUN_DIR", Path.home() / ".alchemist" / "runs"))`.
    pub fn default_dir(env_run_dir: Option<&str>, home_dir: &Path) -> PathBuf {
        match env_run_dir {
            Some(d) if !d.is_empty() => PathBuf::from(d),
            _ => home_dir.join(".alchemist").join("runs"),
        }
    }
}

impl RunsDir for RealRunsDir {
    fn list_runs(&self) -> Vec<(String, usize, f64)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let events = std::fs::read_to_string(&path)
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            out.push((name, events, mtime));
        }
        out.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    fn read_run(&self, name: &str) -> Option<String> {
        // Containment check: never read outside the runs dir, whatever the caller sends,
        // mirroring `RUNS_DIR.resolve() not in target.parents`.
        if name.is_empty() || name.contains('/') || name.contains('\\') || name == ".." {
            return None;
        }
        let target = self.dir.join(name);
        if !target.is_file() {
            return None;
        }
        std::fs::read_to_string(target).ok()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandledResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: &'static str,
}

fn json_response(value: Value) -> HandledResponse {
    HandledResponse {
        status: 200,
        body: serde_json::to_vec(&value).unwrap_or_default(),
        content_type: "application/json",
    }
}

/// Handles one GET request the way `Handler.do_GET` does: `/` -> the page, `/api/runs` ->
/// the runs list, `/api/events?run=&from=` -> classified events from `from` onward, anything
/// else -> 404. `path` is the request path only (no scheme/host); `query` are the parsed
/// query-string pairs.
pub fn handle_request(
    path: &str,
    query: &std::collections::HashMap<String, String>,
    runs_dir: &dyn RunsDir,
) -> HandledResponse {
    match path {
        "/" => HandledResponse {
            status: 200,
            body: PAGE.as_bytes().to_vec(),
            content_type: "text/html; charset=utf-8",
        },
        "/api/runs" => {
            let runs: Vec<Value> = runs_dir
                .list_runs()
                .into_iter()
                .map(|(name, events, mtime)| json!({"name": name, "events": events, "mtime": mtime}))
                .collect();
            json_response(Value::Array(runs))
        }
        "/api/events" => {
            let name = query.get("run").cloned().unwrap_or_default();
            let start: usize = query.get("from").and_then(|v| v.parse().ok()).unwrap_or(0);
            let Some(text) = runs_dir.read_run(&name) else {
                return json_response(Value::Array(vec![]));
            };
            let events = iter_events(&text, |_| {});
            let out: Vec<Value> = events
                .into_iter()
                .skip(start)
                .map(|event| {
                    let (kind, detail) = classify(&event);
                    json!({"kind": kind, "detail": detail})
                })
                .collect();
            json_response(Value::Array(out))
        }
        _ => HandledResponse {
            status: 404,
            body: b"not found".to_vec(),
            content_type: "text/plain",
        },
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ViewerArgs {
    pub port: u16,
    pub runs_dir: Option<String>,
}

/// Mirrors `main()`'s `--port`/`--runs-dir` argparse setup (defaults: port 8790, no
/// `--runs-dir` override).
pub fn parse_args(argv: &[String]) -> ViewerArgs {
    let mut port = 8790u16;
    let mut runs_dir = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" => {
                i += 1;
                if let Some(v) = argv.get(i).and_then(|v| v.parse().ok()) {
                    port = v;
                }
            }
            "--runs-dir" => {
                i += 1;
                runs_dir = argv.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }
    ViewerArgs { port, runs_dir }
}

fn parse_query(raw: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("").to_string();
        let v = it.next().unwrap_or("").to_string();
        map.insert(k, v);
    }
    map
}

/// CLI entry point mirroring `viewer.py`'s `main()`: parses `--port`/`--runs-dir`, ensures
/// the runs dir exists, and serves the page/API forever on `127.0.0.1:<port>` over a plain
/// `std::net::TcpListener` loop (replacing `ThreadingHTTPServer`). Not exercised by tests —
/// [`handle_request`] and [`RunsDir`] carry the test coverage; this function is the thin,
/// blocking process-boundary wrapper around them, same as the JS `server.serve_forever()`.
pub fn run(argv: &[String], home_dir: &Path, env_run_dir: Option<&str>) -> i32 {
    let args = parse_args(argv);
    let dir = args
        .runs_dir
        .map(|d| shellexpand_home(&d, home_dir))
        .unwrap_or_else(|| RealRunsDir::default_dir(env_run_dir, home_dir));
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("error: could not create runs dir: {}", dir.display());
        return 1;
    }
    let runs_dir = RealRunsDir::new(dir.clone());
    let listener = match std::net::TcpListener::bind(("127.0.0.1", args.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    println!("Citadel: http://127.0.0.1:{}   runs: {}", args.port, dir.display());
    for stream in listener.incoming().flatten() {
        serve_one(stream, &runs_dir);
    }
    0
}

fn shellexpand_home(path: &str, home_dir: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir.join(rest)
    } else if path == "~" {
        home_dir.to_path_buf()
    } else {
        PathBuf::from(path)
    }
}

fn serve_one(mut stream: std::net::TcpStream, runs_dir: &dyn RunsDir) {
    use std::io::{BufRead, BufReader, Write};
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.trim().split_whitespace();
    let _method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/").to_string();
    // Drain headers.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
    }
    let (path, query_raw) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let query = parse_query(query_raw);
    let resp = handle_request(path, &query, runs_dir);
    let header = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        resp.content_type,
        resp.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&resp.body);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRunsDir {
        runs: Vec<(String, usize, f64)>,
        files: std::collections::HashMap<String, String>,
    }

    impl RunsDir for FakeRunsDir {
        fn list_runs(&self) -> Vec<(String, usize, f64)> {
            self.runs.clone()
        }
        fn read_run(&self, name: &str) -> Option<String> {
            self.files.get(name).cloned()
        }
    }

    fn fake() -> FakeRunsDir {
        let mut files = std::collections::HashMap::new();
        files.insert(
            "run1.jsonl".to_string(),
            "{\"type\":\"agent_message\",\"text\":\"hi\"}\n{\"type\":\"exec_command\",\"command\":\"ls\"}\n".to_string(),
        );
        FakeRunsDir {
            runs: vec![("run1.jsonl".to_string(), 2, 100.0)],
            files,
        }
    }

    #[test]
    fn root_serves_the_page() {
        let resp = handle_request("/", &Default::default(), &fake());
        assert_eq!(resp.status, 200);
        assert!(String::from_utf8(resp.body).unwrap().contains("Citadel"));
    }

    #[test]
    fn api_runs_lists_jsonl_files() {
        let resp = handle_request("/api/runs", &Default::default(), &fake());
        let v: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v[0]["name"], "run1.jsonl");
        assert_eq!(v[0]["events"], 2);
    }

    #[test]
    fn api_events_classifies_from_offset() {
        let mut q = std::collections::HashMap::new();
        q.insert("run".to_string(), "run1.jsonl".to_string());
        q.insert("from".to_string(), "1".to_string());
        let resp = handle_request("/api/events", &q, &fake());
        let v: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["kind"], "command");
    }

    #[test]
    fn api_events_unknown_run_returns_empty_array() {
        let mut q = std::collections::HashMap::new();
        q.insert("run".to_string(), "../etc/passwd".to_string());
        let resp = handle_request("/api/events", &q, &fake());
        assert_eq!(resp.body, b"[]");
    }

    #[test]
    fn unknown_path_is_404() {
        let resp = handle_request("/nope", &Default::default(), &fake());
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn real_runs_dir_rejects_traversal_names() {
        let dir = RealRunsDir::new(std::env::temp_dir());
        assert_eq!(dir.read_run("../secret"), None);
        assert_eq!(dir.read_run(""), None);
    }

    #[test]
    fn parse_args_reads_port_and_runs_dir() {
        let args = parse_args(&["--port".to_string(), "9000".to_string(), "--runs-dir".to_string(), "/tmp/x".to_string()]);
        assert_eq!(args.port, 9000);
        assert_eq!(args.runs_dir.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn parse_args_defaults() {
        let args = parse_args(&[]);
        assert_eq!(args.port, 8790);
        assert_eq!(args.runs_dir, None);
    }

    #[test]
    fn default_dir_prefers_env_var() {
        let home = Path::new("/home/x");
        assert_eq!(
            RealRunsDir::default_dir(Some("/custom/runs"), home),
            PathBuf::from("/custom/runs")
        );
        assert_eq!(RealRunsDir::default_dir(None, home), home.join(".alchemist").join("runs"));
    }
}
