//! Chunk r24: Rust port of `skills/designer/engine/scripts/live-server.mjs`
//! (the local "live variant mode" dev HTTP server).
//!
//! `live-server.mjs` is the root dependency every other unported `live-*.mjs`
//! file blocks on (`full-Q1.md`: "1135-line local dev HTTP server + CDP
//! orchestrator; the root dependency all other `live-*.mjs` files in this
//! list block on"). Per the MANDATORY packet rules, subprocess orchestration,
//! CLI argv handling, and server plumbing are portable and are ported here in
//! full: port auto-detection, `server.json` connection-record lifecycle
//! (read/write/remove/pid-liveness, mirroring
//! `lib/impeccable-paths.mjs::readLiveServerInfo` /
//! `writeLiveServerInfo` / `removeLiveServerInfo` /
//! `isLiveServerPidReachable`), the pending-event/long-poll queue state
//! machine (`enqueueEvent`, `findAvailablePendingEvent`, `leaseEvent`,
//! `acknowledgePendingEvent`, `cancelQueuedAnonymousExitEvents`,
//! `nextLeaseDeadline`), `--help` text, `stop`/`--keep-inject`/`--port=`
//! argv handling, and a real `std::net::TcpListener` HTTP/1.1 server loop
//! (`/health`, `/poll` GET long-poll + POST ack, `/events` POST enqueue,
//! OPTIONS/CORS) wired to that state machine.
//!
//! Follow-up pass (packet r22r24) closed most of the named gaps above now
//! that the sibling modules they depended on exist elsewhere in this crate:
//! - `/live.js` and `/detect.js` now serve real content: `/live.js` is
//!   assembled from disk via `w2_020::browser_script_parts` +
//!   `w2_022::vocabulary::live_commands()` on every request (matching the
//!   JS's no-cache re-read-from-disk behavior exactly); `/detect.js` (and
//!   `/`) serve the detector bundle straight from disk as a static browser
//!   asset (JS: `fs.readFileSync` once at startup and echoed verbatim) —
//!   these files ship to the *browser*, not through this Rust binary, so
//!   "port" means "locate and stream the file", not translate its JS.
//! - `/manual-edit-stash|commit|discard` (plus `-stash` GET and
//!   `-repair-decision`) are wired to `w2_021::manual_edit_routes` via
//!   `manual_edit_deps::LiveServerManualEditDeps` (a `ManualEditRoutesDeps`
//!   + `ManualApplyCallbacks` bridge to this server's `QueueState`).
//!
//! Follow-up pass (packet B1) closed the two remaining named gaps:
//! - `/annotation` now stages the raw PNG body to a per-run session
//!   directory under `getLiveAnnotationsDir` (mirroring
//!   `fs.mkdtempSync(path.join(annotRoot, 'session-'))`), with the same
//!   eventId regex, `Content-Type: image/png` check, and 10 MiB cap as the
//!   JS route; see [`http_server`].
//! - Svelte-component session *cleanup* (`removeAllSvelteComponentSessions`,
//!   called on `exit` events and on shutdown) is ported as
//!   [`remove_all_svelte_component_sessions`]. The stateful *apply* half
//!   (`applyDeferredSvelteComponentAccepts` / `inlineSvelteComponentAccept`,
//!   which rewrites component source CSS/markup) remains out of scope —
//!   `live/svelte-component.mjs`'s CSS-rewrite machinery is a separate,
//!   much larger port, not named by this packet.
//!
//! Still genuinely out of scope, named exactly: `buildManualEditEvidence`
//! (`../live-manual-edit-evidence.mjs`) and `commitManualEdits`
//! (`../live-commit-manual-edits.mjs`), which the manual-edit routes call
//! into — both shell an LLM copy-edit agent.

pub mod design_parser;
pub mod http_server;
pub mod manual_edit_deps;
pub mod queue;
pub mod server_info;

use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use queue::{PendingEventEntry, QueueState};
pub use server_info::{
    is_live_server_pid_reachable, read_live_server_info, remove_live_server_info,
    write_live_server_info, ServerInfo,
};

/// `findOpenPort(start = 8400)` — bind a loopback TCP listener starting at
/// `start`, incrementing on bind failure, exactly mirroring the JS
/// `net.createServer().listen(start, '127.0.0.1')` probe-and-retry loop.
/// Returns the bound listener (still held open) so the caller can reuse it
/// for the real server without a bind-then-rebind race, plus the port
/// number. Ported behavior difference: the JS version closes the probe
/// socket and lets the real `http.createServer().listen()` call race for
/// the same port again; here we hand back the already-bound listener, which
/// is strictly race-free and preserves "the port actually returned is the
/// port actually served" for every caller.
/// `node_modules/.impeccable-live` — `SVELTE_COMPONENT_ROOT` in
/// `live/svelte-component.mjs`.
const SVELTE_COMPONENT_ROOT: &str = "node_modules/.impeccable-live";

/// `removeAllSvelteComponentSessions(cwd)`: rm -rf every non-`__`-prefixed
/// directory directly under `SVELTE_COMPONENT_ROOT`, non-fatal on error
/// (matches the JS `try { fs.rmSync(...) } catch {}` per entry). Called on
/// `exit` events and on server shutdown, same as
/// `cleanupSvelteComponentSessionsBeforeExit()`.
pub fn remove_all_svelte_component_sessions(project_root: &Path) {
    let root = project_root.join(SVELTE_COMPONENT_ROOT);
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("__") {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// `fs.mkdtempSync(path.join(annotRoot, 'session-'))`. `mkdtemp` itself is
/// not in std; this derives an equivalently unguessable-enough (process +
/// wall-clock + atomic counter, same recipe as [`random_token`]) unique
/// suffix and creates the directory, retrying on an (extremely unlikely)
/// collision the way `mkdtemp` would.
pub fn make_session_dir(annot_root: &Path) -> io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(annot_root)?;
    for _ in 0..8 {
        let suffix = random_token();
        let dir = annot_root.join(format!("session-{suffix}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create unique session dir",
    ))
}

pub fn find_open_port(start: u16) -> io::Result<(TcpListener, u16)> {
    let mut port = start;
    loop {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                let bound_port = listener.local_addr()?.port();
                return Ok((listener, bound_port));
            }
            Err(_) => {
                port = port.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "no open port found")
                })?;
            }
        }
    }
}

static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `randomUUID()` equivalent. Node's `crypto.randomUUID()` returns an opaque
/// random v4 UUID used only as an unguessable bearer token; there is no
/// `uuid`/`rand` crate pinned in this workspace (checked: neither appears in
/// `engine/Cargo.lock`), so this derives an equivalently opaque, per-process
/// token from wall-clock nanoseconds, pid, and a process-wide atomic counter
/// hashed through `sha2` (already a `legion-runtime` dependency), formatted
/// with UUID v4 dashes/version/variant bits so it is drop-in interchangeable
/// with the JS token everywhere it's used (URL query param, header
/// comparison, `server.json` field) even though it is not cryptographically
/// derived from an RNG.
pub fn random_token() -> String {
    use sha2::{Digest, Sha256};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = process::id();
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(
        &hex.as_bytes()[..32]
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>(),
    );
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// `--help`/`-h` text, byte-for-byte the same content as the JS source's
/// `console.log` usage block (see lines 991-1020 of `live-server.mjs`).
pub const HELP_TEXT: &str = "Usage: legion script designer/live-server [options]

Start the live variant mode server (zero dependencies).

Commands:
  (default)     Start the server (foreground)
  stop          Stop the server and remove the injected live.js script tag
  stop --keep-inject   Stop the server only (leave the script tag in the HTML entry)

Options:
  --background  Start detached, print connection JSON to stdout, then exit
  --port=PORT   Use a specific port (default: auto-detect starting at 8400)
  --keep-inject Only with stop: skip legion script designer/live-inject --remove
  --help        Show this help

Endpoints:
  /live.js             Browser script (element picker + variant cycling)
  /detect.js           Detection overlay (backwards compatible)
  /design-system.json  Parsed design system for the panel (token-protected)
  /design-system/raw   DESIGN.md verbatim (token-protected)
  /annotation          POST raw image/png to stage a variant screenshot
  /events              SSE stream (server→browser) + POST (browser→server)
  /poll                Long-poll for agent CLI
  /manual-edit-stash   Stage browser copy edits
  /manual-edit-commit  Apply staged browser copy edits
  /manual-edit-discard Discard staged browser copy edits
  /source              Project file reader, project-relative paths (no-HMR fallback)
  /status              Durable recovery status (token-protected)
  /health              Health check";

/// `--port=PORT` argv parsing, matching
/// `args.find(a => a.startsWith('--port=')); parseInt(..., 10)`.
pub fn parse_port_arg(args: &[String]) -> Option<u16> {
    args.iter()
        .find(|a| a.starts_with("--port="))
        .and_then(|a| a.trim_start_matches("--port=").parse::<u16>().ok())
}

/// Result of [`run`], standing in for the JS source's `process.exit(code)`
/// calls so callers (and tests) can observe the outcome without exiting the
/// test process.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    HelpPrinted,
    Stopped {
        server: StopServerState,
        injection: InjectionCleanupState,
    },
    AlreadyRunning {
        port: u16,
        pid: u32,
    },
    ServerExited,
    /// `--background`: the detached child was spawned and (if
    /// `server.json` appeared within the readiness timeout) its connection
    /// info was printed. `ready` is `false` if the timeout elapsed first
    /// (JS gives no explicit timeout for this poll; a bounded wait here
    /// avoids hanging forever if the child fails silently).
    BackgroundStarted {
        port: u16,
        pid: u32,
        ready: bool,
    },
}

/// Server-side result for a stop request. `AcceptedUnconfirmed` preserves the
/// distinction between the handler accepting `/stop` and the listener no
/// longer serving this server's authenticated health metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopServerState {
    Confirmed { port: u16 },
    AcceptedUnconfirmed { port: u16 },
    NotRunning { port: Option<u16> },
    Failed { port: Option<u16>, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionCleanupState {
    Retained,
    Removed(serde_json::Value),
    Failed(serde_json::Value),
}

#[derive(Debug)]
struct StopHttpResponse {
    status: u16,
    json: Option<serde_json::Value>,
}

const STOP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const STOP_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const STOP_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const STOP_RESPONSE_LIMIT: u64 = 8 * 1024;

fn stop_http_request(port: u16, path: &str, token: &str) -> io::Result<StopHttpResponse> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, STOP_CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(STOP_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(STOP_IO_TIMEOUT))?;
    let request = format!(
        "GET {path}?token={token} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;

    let mut bytes = Vec::new();
    stream
        .take(STOP_RESPONSE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > STOP_RESPONSE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stop response exceeded size limit",
        ));
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete HTTP response"))?;
    if header_end > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stop response headers exceeded size limit",
        ));
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response headers"))?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|raw| raw.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    let body = &bytes[header_end + 4..];
    let content_length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing response length"))?;
    if content_length > STOP_RESPONSE_LIMIT as usize || content_length != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid stop response length",
        ));
    }
    let json = serde_json::from_slice(body).ok();
    Ok(StopHttpResponse { status, json })
}

fn stop_metadata_matches(response: &StopHttpResponse, info: &ServerInfo) -> bool {
    let Some(json) = response.json.as_ref() else {
        return false;
    };
    response.status == 200
        && json.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
        && json.get("pid").and_then(serde_json::Value::as_u64) == Some(u64::from(info.pid))
        && json.get("port").and_then(serde_json::Value::as_u64) == Some(u64::from(info.port))
}

fn server_record_for_stop(project_root: &Path) -> Result<Option<ServerInfo>, String> {
    let paths = [
        crate::wf_port::q_q1::paths::get_live_server_path(project_root),
        crate::wf_port::q_q1::paths::get_legacy_live_server_path(project_root),
    ];
    let mut invalid = None;
    for path in paths {
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                invalid = Some(format!("could not read {}: {err}", path.display()));
                continue;
            }
        };
        match serde_json::from_str::<ServerInfo>(&contents) {
            Ok(info) if info.pid > 0 && info.port > 0 && !info.token.is_empty() => {
                return Ok(Some(info));
            }
            Ok(_) => invalid = Some(format!("invalid server metadata in {}", path.display())),
            Err(err) => {
                invalid = Some(format!(
                    "invalid server metadata in {}: {err}",
                    path.display()
                ))
            }
        }
    }
    match invalid {
        Some(message) => Err(message),
        None => Ok(None),
    }
}

fn stop_server(project_root: &Path) -> StopServerState {
    let info = match server_record_for_stop(project_root) {
        Ok(Some(info)) => info,
        Ok(None) => return StopServerState::NotRunning { port: None },
        Err(message) => {
            return StopServerState::Failed {
                port: None,
                message,
            }
        }
    };
    let port = info.port;
    match stop_http_request(port, "/health", &info.token) {
        Ok(response) if stop_metadata_matches(&response, &info) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            return StopServerState::NotRunning { port: Some(port) };
        }
        Ok(_) => {
            return StopServerState::Failed {
                port: Some(port),
                message: "health endpoint did not match recorded server metadata".into(),
            };
        }
        Err(err) => {
            return StopServerState::Failed {
                port: Some(port),
                message: format!("could not verify live server: {err}"),
            };
        }
    }

    match stop_http_request(port, "/stop", &info.token) {
        Ok(response)
            if response.status == 200
                && response
                    .json
                    .as_ref()
                    .and_then(|json| json.get("ok"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                && response
                    .json
                    .as_ref()
                    .and_then(|json| json.get("accepted"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                && response
                    .json
                    .as_ref()
                    .and_then(|json| json.get("pid"))
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(info.pid))
                && response
                    .json
                    .as_ref()
                    .and_then(|json| json.get("port"))
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(info.port)) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            return StopServerState::NotRunning { port: Some(port) };
        }
        Ok(_) => {
            return StopServerState::Failed {
                port: Some(port),
                message: "stop endpoint did not confirm acceptance for recorded server".into(),
            };
        }
        Err(err) => {
            return StopServerState::Failed {
                port: Some(port),
                message: format!("stop request failed: {err}"),
            };
        }
    };
    let deadline = std::time::Instant::now() + STOP_CONFIRM_TIMEOUT;
    while std::time::Instant::now() < deadline {
        match stop_http_request(port, "/health", &info.token) {
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                return StopServerState::Confirmed { port };
            }
            Ok(response) if stop_metadata_matches(&response, &info) => {}
            Ok(_) => return StopServerState::Confirmed { port },
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    StopServerState::AcceptedUnconfirmed { port }
}

/// Stop the server and, unless requested otherwise, remove the live injection
/// from the current project. Injection config resolution does not depend on
/// `server.json`, so this also repairs cleanup after a prior stop removed it.
pub fn stop_running_server(project_root: &Path, keep_inject: bool) -> RunOutcome {
    let env_live_config = env::var("IMPECCABLE_LIVE_CONFIG").ok();
    stop_running_server_with_config(project_root, keep_inject, env_live_config.as_deref())
}

fn stop_running_server_with_config(
    project_root: &Path,
    keep_inject: bool,
    env_live_config: Option<&str>,
) -> RunOutcome {
    let server = stop_server(project_root);
    let injection = if keep_inject {
        InjectionCleanupState::Retained
    } else {
        let report = crate::wf_port::w2_018::inject::remove_project_injection(
            project_root,
            None,
            env_live_config,
        );
        if report.ok {
            InjectionCleanupState::Removed(report.payload)
        } else {
            InjectionCleanupState::Failed(report.payload)
        }
    };
    let server_json = match &server {
        StopServerState::Confirmed { port } => {
            serde_json::json!({ "state": "confirmed", "port": port })
        }
        StopServerState::AcceptedUnconfirmed { port } => {
            serde_json::json!({ "state": "accepted_unconfirmed", "port": port })
        }
        StopServerState::NotRunning { port } => {
            serde_json::json!({ "state": "not_running", "port": port })
        }
        StopServerState::Failed { port, message } => {
            serde_json::json!({ "state": "failed", "port": port, "message": message })
        }
    };
    let injection_json = match &injection {
        InjectionCleanupState::Retained => serde_json::json!({ "state": "retained" }),
        InjectionCleanupState::Removed(payload) => {
            serde_json::json!({ "state": "removed", "result": payload })
        }
        InjectionCleanupState::Failed(payload) => {
            serde_json::json!({ "state": "failed", "result": payload })
        }
    };
    println!(
        "{}",
        serde_json::json!({ "server": server_json, "injection": injection_json })
    );
    RunOutcome::Stopped { server, injection }
}

/// `--background`: mirrors the JS `spawn(process.execPath, [thisFile,
/// ...childArgs], { detached: true, stdio: 'ignore' }); child.unref();` then
/// polling `server.json` for a `pid` different from the parent's own pid
/// (meaning the detached child, not the parent, is now the running server),
/// printing its connection JSON on stdout, for up to 10s.
///
/// This is the `std::process::Command` re-exec named as a gap in
/// `finish-r24.md`: the previous pass deferred it because no concrete CLI
/// binary entry point existed yet to re-exec against. That gap is closed
/// here by re-execing `std::env::current_exe()` (this same running binary)
/// with the child argv — no separate binary path guess needed. One
/// difference from the JS: without `unsafe_code` (forbidden crate-wide)
/// there is no portable way to call `setsid`/detach the child's process
/// group from Rust's `std::process::Command`, so the child is spawned as an
/// ordinary (non-session-leader) child process with its stdio inherited as
/// null handles; it is not killed by this process exiting, which is the
/// behavior `--background` callers actually depend on.
/// Argv prefix that routes the re-executed binary back to this server:
/// `<exe> script designer/live-server ...` (the `script` subcommand
/// dispatches `designer/live-server` to [`run`]).
const BACKGROUND_CHILD_ARGV_PREFIX: [&str; 2] = ["script", "designer/live-server"];

/// Full child argv for `--background`: the dispatch prefix followed by the
/// caller's args minus `--background`.
fn background_child_argv(args: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = BACKGROUND_CHILD_ARGV_PREFIX
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    argv.extend(
        args.iter()
            .filter(|a| a.as_str() != "--background")
            .cloned(),
    );
    argv
}

fn run_background(args: &[String], project_root: &Path) -> RunOutcome {
    let child_args = background_child_argv(args);
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve current executable: {e}");
            return RunOutcome::ServerExited;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| project_root.to_path_buf());
    let parent_pid = process::id();

    let spawn_result = process::Command::new(&exe)
        .args(&child_args)
        .current_dir(&cwd)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .spawn();
    let child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to spawn background live server: {e}");
            return RunOutcome::ServerExited;
        }
    };
    let child_pid = child.id();
    // `child.unref()` in JS just lets the parent event loop exit without
    // waiting on the child; dropping the `Child` handle here has the same
    // effect (no implicit wait-on-drop in `std::process`).
    drop(child);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if let Some((info, _path)) = read_live_server_info(project_root) {
            if info.pid != parent_pid {
                println!(
                    "{}",
                    serde_json::json!({ "pid": info.pid, "port": info.port, "token": info.token })
                );
                return RunOutcome::BackgroundStarted {
                    port: info.port,
                    pid: info.pid,
                    ready: true,
                };
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    eprintln!("Timed out waiting for live server to start.");
    RunOutcome::BackgroundStarted {
        port: 0,
        pid: child_pid,
        ready: false,
    }
}

/// Top-level CLI entry point, equivalent to the module-level script body
/// (argv dispatch: `--help`/`-h`, `stop`, `--background`, otherwise start).
/// `--background` re-execs `std::env::current_exe()` (see
/// [`run_background`]) rather than a separately-tracked binary path.
pub fn run(args: &[String], project_root: &Path) -> RunOutcome {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP_TEXT}");
        return RunOutcome::HelpPrinted;
    }

    if args.iter().any(|a| a == "stop") {
        let keep_inject = args.iter().any(|a| a == "--keep-inject");
        return stop_running_server(project_root, keep_inject);
    }

    if args.iter().any(|a| a == "--background") {
        return run_background(args, project_root);
    }

    if let Some((existing, _path)) = read_live_server_info(project_root) {
        eprintln!(
            "Live server already running on port {} (pid {}).",
            existing.port, existing.pid
        );
        eprintln!("Stop it first with: legion script designer/live-server stop");
        return RunOutcome::AlreadyRunning {
            port: existing.port,
            pid: existing.pid,
        };
    }

    let token = random_token();
    let port_arg = parse_port_arg(args);
    let (listener, port) = match port_arg {
        Some(p) => match TcpListener::bind(("127.0.0.1", p)) {
            Ok(l) => (l, p),
            Err(e) => {
                eprintln!("Failed to bind port {p}: {e}");
                return RunOutcome::ServerExited;
            }
        },
        None => match find_open_port(8400) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Failed to find open port: {e}");
                return RunOutcome::ServerExited;
            }
        },
    };

    let info = ServerInfo {
        pid: process::id(),
        port,
        token: token.clone(),
    };
    if let Err(e) = write_live_server_info(project_root, &info) {
        eprintln!("Failed to write server.json: {e}");
        return RunOutcome::ServerExited;
    }

    println!("\nImpeccable live server running on http://localhost:{port}");
    println!("Token: {token}\n");
    println!("Script: http://localhost:{port}/live.js");
    println!("Inject: managed by legion script designer/live-inject; Astro source tags use is:inline automatically.");
    println!("Stop:   legion script designer/live-server stop");

    // Annotation screenshots live under the project root, sessioned per run
    // (mirrors `state.sessionDir = fs.mkdtempSync(path.join(annotRoot,
    // 'session-'))`).
    let annot_root =
        crate::wf_port::w2_016::impeccable_paths::get_live_annotations_dir(project_root);
    let session_dir = match make_session_dir(&annot_root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to create annotation session dir: {e}");
            return RunOutcome::ServerExited;
        }
    };

    let queue = QueueState::new();
    // One `ManualApplyController` for the server's whole lifetime (mirrors
    // the JS singleton `manualApply` controller created once at module
    // load): its in-memory pending-apply-deferred/timed-out-id state must
    // survive across requests, so it is built here and threaded through
    // `serve`/`handle_request` by reference rather than reconstructed per
    // request (a per-request controller would silently drop that state
    // between requests).
    let callbacks = manual_edit_deps::QueueCallbacks { queue: &queue };
    let manual_apply_controller = crate::wf_port::w2_021::manual_apply::ManualApplyController::new(
        project_root.to_path_buf(),
        callbacks,
    );
    http_server::serve(
        listener,
        &token,
        &queue,
        project_root,
        &manual_apply_controller,
        &session_dir,
    );
    // `shutdown()`: cleanup order mirrors the JS source (Svelte session
    // cleanup, then server.json removal, then the annotation session dir).
    remove_all_svelte_component_sessions(project_root);
    let _ = remove_live_server_info(project_root);
    let _ = std::fs::remove_dir_all(&session_dir);
    RunOutcome::ServerExited
}

/// Read `env::args()` and the current directory the way the JS source reads
/// `process.argv.slice(2)` / `process.cwd()`, then delegate to [`run`]. Not
/// itself unit-tested (it is a thin OS-args adapter); [`run`] is the tested
/// entry point.
pub fn main_cli() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    let cwd = env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    match run(&args, &cwd) {
        RunOutcome::HelpPrinted | RunOutcome::ServerExited => 0,
        RunOutcome::Stopped { server, injection } => {
            let server_ok = matches!(
                server,
                StopServerState::Confirmed { .. } | StopServerState::NotRunning { .. }
            );
            let injection_ok = !matches!(injection, InjectionCleanupState::Failed(_));
            if server_ok && injection_ok {
                0
            } else {
                1
            }
        }
        RunOutcome::AlreadyRunning { .. } => 1,
        RunOutcome::BackgroundStarted { ready, .. } => {
            if ready {
                0
            } else {
                1
            }
        }
    }
}

#[cfg(test)]
mod session_cleanup_tests {
    use super::*;

    #[test]
    fn background_child_argv_routes_back_to_live_server_without_background_flag() {
        let args = vec![
            "--background".to_string(),
            "--port=9123".to_string(),
            "--keep-inject".to_string(),
        ];
        assert_eq!(
            background_child_argv(&args),
            vec![
                "script".to_string(),
                "designer/live-server".to_string(),
                "--port=9123".to_string(),
                "--keep-inject".to_string(),
            ]
        );
        assert_eq!(
            background_child_argv(&[]),
            vec!["script".to_string(), "designer/live-server".to_string()]
        );
    }

    #[test]
    fn help_text_does_not_advertise_unshipped_modern_screenshot() {
        assert!(!HELP_TEXT.contains("modern-screenshot"));
    }

    fn scratch_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "legion-r24-{name}-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write_stop_config(root: &Path) {
        let config = root.join(".impeccable/live/config.json");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            config,
            r#"{"files":["index.html"],"insertAfter":"</body>","commentSyntax":"html"}"#,
        )
        .unwrap();
    }

    #[test]
    fn stop_health_requires_authenticated_server_metadata_not_pid_alone() {
        let info = ServerInfo {
            pid: 41,
            port: 8400,
            token: "secret".into(),
        };
        let matching = StopHttpResponse {
            status: 200,
            json: Some(serde_json::json!({ "ok": true, "pid": 41, "port": 8400 })),
        };
        let wrong_port = StopHttpResponse {
            status: 200,
            json: Some(serde_json::json!({ "ok": true, "pid": 41, "port": 8401 })),
        };
        assert!(stop_metadata_matches(&matching, &info));
        assert!(!stop_metadata_matches(&wrong_port, &info));
    }

    #[test]
    fn stop_reads_metadata_even_when_pid_liveness_would_be_stale() {
        let root = scratch_root("stop-metadata");
        std::fs::create_dir_all(&root).unwrap();
        let info = ServerInfo {
            pid: u32::MAX,
            port: 8400,
            token: "recorded-token".into(),
        };
        let path = crate::wf_port::q_q1::paths::get_live_server_path(&root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&info).unwrap()).unwrap();

        assert_eq!(server_record_for_stop(&root).unwrap(), Some(info));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stop_retries_injection_cleanup_without_server_record() {
        let root = scratch_root("stop-retry-cleanup");
        std::fs::create_dir_all(&root).unwrap();
        write_stop_config(&root);
        std::fs::write(root.join("index.html"), "<html><body>plain</body></html>").unwrap();

        let outcome = stop_running_server_with_config(&root, false, None);

        assert!(matches!(
            outcome,
            RunOutcome::Stopped {
                server: StopServerState::NotRunning { port: None },
                injection: InjectionCleanupState::Removed(_)
            }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stop_keep_inject_flag_survives_dispatch() {
        let root = scratch_root("stop-keep-inject");
        std::fs::create_dir_all(&root).unwrap();
        write_stop_config(&root);
        let content = format!(
            "<html><body><!-- {} --><script src=\"live.js\"></script><!-- {} --></body></html>",
            crate::wf_port::w2_018::inject::MARKER_OPEN_TEXT,
            crate::wf_port::w2_018::inject::MARKER_CLOSE_TEXT,
        );
        std::fs::write(root.join("index.html"), &content).unwrap();

        let args = vec!["stop".to_string(), "--keep-inject".to_string()];
        let outcome = run(&args, &root);

        assert!(matches!(
            outcome,
            RunOutcome::Stopped {
                injection: InjectionCleanupState::Retained,
                ..
            }
        ));
        assert_eq!(
            std::fs::read_to_string(root.join("index.html")).unwrap(),
            content
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stop_without_keep_inject_removes_injection_and_reports_removed() {
        let root = scratch_root("stop-remove-inject");
        std::fs::create_dir_all(&root).unwrap();
        write_stop_config(&root);
        let content = format!(
            "<html><body><!-- {} --><script src=\"live.js\"></script><!-- {} --></body></html>",
            crate::wf_port::w2_018::inject::MARKER_OPEN_TEXT,
            crate::wf_port::w2_018::inject::MARKER_CLOSE_TEXT,
        );
        std::fs::write(root.join("index.html"), &content).unwrap();

        let args = vec!["stop".to_string()];
        let outcome = run(&args, &root);

        assert!(matches!(
            outcome,
            RunOutcome::Stopped {
                injection: InjectionCleanupState::Removed(_),
                ..
            }
        ));
        let after = std::fs::read_to_string(root.join("index.html")).unwrap();
        assert!(!after.contains(crate::wf_port::w2_018::inject::MARKER_OPEN_TEXT));
        assert!(!after.contains("live.js"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn make_session_dir_creates_unique_directory_under_root() {
        let root = scratch_root("mkdtemp");
        let dir = make_session_dir(&root).unwrap();
        assert!(dir.is_dir());
        assert!(dir.starts_with(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removes_non_dunder_svelte_component_sessions_only() {
        let project_root = scratch_root("svelte-cleanup");
        let component_root = project_root.join(SVELTE_COMPONENT_ROOT);
        std::fs::create_dir_all(component_root.join("sess-1")).unwrap();
        std::fs::create_dir_all(component_root.join("__runtime_dir")).unwrap();
        std::fs::write(component_root.join("__runtime.js"), b"// keep").unwrap();

        remove_all_svelte_component_sessions(&project_root);

        assert!(!component_root.join("sess-1").exists());
        assert!(component_root.join("__runtime_dir").exists());
        assert!(component_root.join("__runtime.js").exists());
        let _ = std::fs::remove_dir_all(&project_root);
    }

    #[test]
    fn cleanup_on_missing_root_is_a_no_op() {
        let project_root = scratch_root("svelte-missing");
        // No SVELTE_COMPONENT_ROOT directory exists; must not panic.
        remove_all_svelte_component_sessions(&project_root);
    }
}
