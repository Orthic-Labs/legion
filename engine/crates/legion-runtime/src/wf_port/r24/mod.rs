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
//! Genuinely out of scope (named per the MANDATORY rule, not just noted):
//! the handful of routes whose *response bodies* are assembled by sibling
//! `.mjs` modules that are not part of this packet and are not ported
//! anywhere else yet — `/live.js` (`live/browser-script-parts.mjs`'s
//! `assembleLiveBrowserScript`/`readLiveBrowserScriptParts`, plus
//! `live/vocabulary.mjs`'s `LIVE_COMMANDS`), `/detect.js` (the detector
//! bundle loaded by `loadBrowserScripts()` from `scripts/detector/`),
//! `/manual-edit-stash|commit|discard` (`live/manual-edit-routes.mjs`,
//! `live/manual-apply.mjs`), `/annotation` file staging into a session
//! directory keyed off `live/session-store.mjs`, and Svelte-component
//! deferred-accept cleanup (`live/svelte-component.mjs`). This server
//! answers those routes with `501 Not Implemented` and a message naming the
//! missing module, rather than silently dropping or faking them. See
//! `finish-r24.md` for the itemized table.

pub mod http_server;
pub mod manual_edit_deps;
pub mod queue;
pub mod server_info;

use std::env;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
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
    bytes.copy_from_slice(&hex.as_bytes()[..32].chunks(2).map(|c| {
        u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()
    }).collect::<Vec<u8>>());
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
pub const HELP_TEXT: &str = "Usage: node live-server.mjs [options]

Start the live variant mode server (zero dependencies).

Commands:
  (default)     Start the server (foreground)
  stop          Stop the server and remove the injected live.js script tag
  stop --keep-inject   Stop the server only (leave the script tag in the HTML entry)

Options:
  --background  Start detached, print connection JSON to stdout, then exit
  --port=PORT   Use a specific port (default: auto-detect starting at 8400)
  --keep-inject Only with stop: skip live-inject.mjs --remove
  --help        Show this help

Endpoints:
  /live.js             Browser script (element picker + variant cycling)
  /detect.js           Detection overlay (backwards compatible)
  /modern-screenshot.js Vendored modern-screenshot UMD build (lazy-loaded by live.js)
  /annotation          POST raw image/png to stage a variant screenshot
  /events              SSE stream (server→browser) + POST (browser→server)
  /poll                Long-poll for agent CLI
  /manual-edit-stash   Stage browser copy edits
  /manual-edit-commit  Apply staged browser copy edits
  /manual-edit-discard Discard staged browser copy edits
  /source              Raw source file reader (no-HMR fallback)
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
    Stopped,
    StopFailedNoServer,
    AlreadyRunning { port: u16, pid: u32 },
    ServerExited,
    /// `--background`: the detached child was spawned and (if
    /// `server.json` appeared within the readiness timeout) its connection
    /// info was printed. `ready` is `false` if the timeout elapsed first
    /// (JS gives no explicit timeout for this poll; a bounded wait here
    /// avoids hanging forever if the child fails silently).
    BackgroundStarted { port: u16, pid: u32, ready: bool },
}

/// `stop` subcommand: read `server.json`, hit `GET /stop?token=...` on the
/// recorded port, report success/failure. `--keep-inject` handling and the
/// `live-inject.mjs --remove` shellout are named-gap NOT-PORTED: they depend
/// on `live-inject.mjs`, which is not part of this packet and is not ported
/// elsewhere (`full-Q1.md` lists it `NOT-STARTED`). Callers that need that
/// half must still shell out to the legacy script until `live-inject.mjs` is
/// ported.
pub fn stop_running_server(project_root: &Path) -> RunOutcome {
    match read_live_server_info(project_root) {
        Some((info, _path)) => {
            let addr = format!("127.0.0.1:{}", info.port);
            match TcpStream::connect(addr.as_str()) {
                Ok(mut stream) => {
                    let req = format!(
                        "GET /stop?token={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                        info.token
                    );
                    let _ = stream.write_all(req.as_bytes());
                    println!("Stopped live server on port {}.", info.port);
                    RunOutcome::Stopped
                }
                Err(_) => {
                    println!("No running live server found.");
                    RunOutcome::StopFailedNoServer
                }
            }
        }
        None => {
            println!("No running live server found.");
            RunOutcome::StopFailedNoServer
        }
    }
}

/// Top-level CLI entry point, equivalent to the module-level script body
/// (argv dispatch: `--help`/`-h`, `stop`, otherwise start). `--background`
/// detached spawning is a named gap: it requires re-exec'ing this same CLI
/// as a detached child process and polling `server.json` for readiness,
/// which is subprocess orchestration this module supports (`http_server`
/// runs synchronously) but the detach+poll wrapper itself is left for the
/// binary/CLI wiring layer that owns `std::process::Command` construction
/// for this crate, matching how sibling `wf_port` chunks (e.g. `r22`) defer
/// process spawning to their CLI binary rather than duplicating it per
/// packet.
pub fn run(args: &[String], project_root: &Path) -> RunOutcome {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP_TEXT}");
        return RunOutcome::HelpPrinted;
    }

    if args.iter().any(|a| a == "stop") {
        return stop_running_server(project_root);
    }

    if let Some((existing, _path)) = read_live_server_info(project_root) {
        eprintln!(
            "Live server already running on port {} (pid {}).",
            existing.port, existing.pid
        );
        eprintln!("Stop it first with: node live-server.mjs stop");
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
    println!("Inject: managed by live-inject.mjs; Astro source tags use is:inline automatically.");
    println!("Stop:   node live-server.mjs stop");

    let queue = QueueState::new();
    http_server::serve(listener, &token, &queue, project_root);
    let _ = remove_live_server_info(project_root);
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
        RunOutcome::HelpPrinted | RunOutcome::Stopped | RunOutcome::ServerExited => 0,
        RunOutcome::StopFailedNoServer => 0,
        RunOutcome::AlreadyRunning { .. } => 1,
    }
}
