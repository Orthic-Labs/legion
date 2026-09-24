//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/transcript-handoff.py`'s
//! `argparse` surface (`bootstrap` / `continuity` subcommands), matching stdout
//! shape and exit codes byte-for-byte where the underlying logic is pure Rust.
//!
//! `continuity` shells out to an external `membrane` binary exactly as the
//! Python did (`subprocess.run([bin, "continuity", "--json"], ...)`), via the
//! [`ContinuityRunner`] trait so tests can fake the process.

use std::path::PathBuf;
use std::time::Duration;

use super::pointer::{build_pointer, paste_prompt, Platform};

/// Abstraction over spawning the `membrane` subprocess, mirroring Python's
/// `subprocess.run([executable, "continuity", "--json"], input=..., capture_output=True, timeout=...)`.
pub trait ContinuityRunner {
    /// Runs `executable continuity --json`, writing `payload` to stdin.
    /// Returns `(exit_code, stdout)` on a clean spawn+wait, or `Err(())` if the
    /// process could not even be spawned (Python's `FileNotFoundError`/`OSError`).
    fn run(&self, executable: &str, payload: &str, timeout: Duration) -> Result<(i32, String), ()>;
}

/// Production runner: real `std::process::Command`.
pub struct RealContinuityRunner;

impl ContinuityRunner for RealContinuityRunner {
    fn run(&self, executable: &str, payload: &str, timeout: Duration) -> Result<(i32, String), ()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(executable)
            .arg("continuity")
            .arg("--json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| ())?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload.as_bytes());
        }
        // No portable process timeout in stable std; best-effort wait (the
        // legacy Python default timeout is 120s, which is not a hard
        // guarantee in this port either way for interactive callers).
        let _ = timeout;
        let output = child.wait_with_output().map_err(|_| ())?;
        let code = output.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok((code, stdout))
    }
}

fn membrane_unavailable(pointer: &serde_json::Value, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "handoff.context-result.v1",
        "status": "unavailable",
        "reason": reason,
        "pointer": pointer,
    })
}

/// Python: `request_continuity(pointer, command=None, timeout=120)`.
pub fn request_continuity<R: ContinuityRunner>(
    runner: &R,
    pointer: &serde_json::Value,
    command: Option<&str>,
    env_membrane_bin: Option<&str>,
    timeout: Duration,
) -> serde_json::Value {
    let executable = command
        .map(str::to_string)
        .or_else(|| env_membrane_bin.map(str::to_string))
        .unwrap_or_else(|| "membrane".to_string());
    let payload = serde_json::json!({
        "operation": "membrane_continuity",
        "pointer": pointer,
    })
    .to_string();
    let (code, stdout) = match runner.run(&executable, &payload, timeout) {
        Ok(v) => v,
        Err(()) => return membrane_unavailable(pointer, "membrane-unavailable"),
    };
    if code != 0 {
        return membrane_unavailable(pointer, "membrane-continuity-failed");
    }
    let response: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => return membrane_unavailable(pointer, "membrane-response-invalid"),
    };
    let schema_ok = response
        .as_object()
        .and_then(|o| o.get("schema"))
        .and_then(|s| s.as_str())
        .map(|s| s == "membrane.context-packet.v1" || s == "handoff.context-result.v1")
        .unwrap_or(false);
    if !response.is_object() || !schema_ok {
        return membrane_unavailable(pointer, "membrane-response-schema-invalid");
    }
    response
}

fn pointer_to_json(p: &super::pointer::SourcePointer) -> serde_json::Value {
    serde_json::json!({
        "schema": p.schema,
        "platform": p.platform,
        "session_id": p.session_id,
        "workspace": p.workspace,
        "source_path": p.source_path,
        "cutoff_bytes": p.cutoff_bytes,
        "sha256": p.sha256,
        "last_complete_row": p.last_complete_row,
        "last_complete_offset": p.last_complete_offset,
        "last_event_type": p.last_event_type,
        "last_event_timestamp": p.last_event_timestamp,
        "selection_method": p.selection_method,
        "created_at": p.created_at,
    })
}

/// I/O seam the CLI needs beyond argv parsing: stdout/stderr, cwd, home,
/// env var lookup, today's date, and the continuity subprocess runner.
pub struct RunEnv<'a, R: ContinuityRunner> {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub today: String,
    pub env_membrane_bin: Option<String>,
    pub runner: &'a R,
}

/// Python: `main()`. Returns the process exit code; writes to `out`/`err`
/// exactly as the Python `print(...)` calls did (stdout unless noted).
pub fn run<R: ContinuityRunner>(
    argv: &[String],
    env: &RunEnv<R>,
    out: &mut dyn std::io::Write,
) -> i32 {
    if argv.is_empty() {
        let _ = writeln!(out, "FAIL: a command is required (bootstrap|continuity)");
        return 2;
    }
    match argv[0].as_str() {
        "bootstrap" => run_bootstrap(&argv[1..], env, out),
        "continuity" => run_continuity(&argv[1..], env, out),
        other => {
            let _ = writeln!(out, "FAIL: unrecognized command: {other}");
            2
        }
    }
}

fn run_bootstrap<R: ContinuityRunner>(
    args: &[String],
    env: &RunEnv<R>,
    out: &mut dyn std::io::Write,
) -> i32 {
    let mut platform: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut home: PathBuf = env.home.clone();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--platform" => {
                i += 1;
                platform = args.get(i).cloned();
            }
            "--session-id" => {
                i += 1;
                session_id = args.get(i).cloned();
            }
            "--workspace" => {
                i += 1;
                workspace = args.get(i).cloned();
            }
            "--home" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    home = PathBuf::from(v);
                }
            }
            "--json" => json = true,
            other => {
                let _ = writeln!(out, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let platform = match platform.as_deref().map(Platform::parse) {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            let _ = writeln!(out, "FAIL: {e}");
            return 2;
        }
        None => {
            let _ = writeln!(out, "FAIL: --platform is required");
            return 2;
        }
    };
    match build_pointer(
        platform,
        session_id.as_deref(),
        workspace.as_deref(),
        &home,
        None,
    ) {
        Ok(pointer) => {
            if json {
                let v = pointer_to_json(&pointer);
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                let _ = writeln!(out, "{}", paste_prompt(&pointer, &env.cwd, &env.today));
            }
            0
        }
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            1
        }
    }
}

fn run_continuity<R: ContinuityRunner>(
    args: &[String],
    env: &RunEnv<R>,
    out: &mut dyn std::io::Write,
) -> i32 {
    let mut pointer_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut membrane_bin: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pointer" => {
                i += 1;
                pointer_path = args.get(i).map(PathBuf::from);
            }
            "--output" => {
                i += 1;
                output_path = args.get(i).map(PathBuf::from);
            }
            "--membrane-bin" => {
                i += 1;
                membrane_bin = args.get(i).cloned();
            }
            other => {
                let _ = writeln!(out, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let pointer_path = match pointer_path {
        Some(p) => p,
        None => {
            let _ = writeln!(out, "FAIL: --pointer is required");
            return 2;
        }
    };
    let text = match std::fs::read_to_string(&pointer_path) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    };
    let pointer: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    };
    let schema_ok = pointer
        .as_object()
        .and_then(|o| o.get("schema"))
        .and_then(|s| s.as_str())
        == Some("handoff.source-pointer.v1");
    if !pointer.is_object() || !schema_ok {
        let _ = writeln!(out, "FAIL: invalid source pointer");
        return 1;
    }
    let result = request_continuity(
        env.runner,
        &pointer,
        membrane_bin.as_deref(),
        env.env_membrane_bin.as_deref(),
        Duration::from_secs(120),
    );
    if let Some(output_path) = &output_path {
        if let Some(parent) = output_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                let _ = writeln!(out, "FAIL: {e}");
                return 1;
            }
        }
        let body = format!("{}\n", serde_json::to_string_pretty(&result).unwrap());
        if let Err(e) = std::fs::write(output_path, body) {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    }
    let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result).unwrap());
    let unavailable = result
        .as_object()
        .and_then(|o| o.get("status"))
        .and_then(|s| s.as_str())
        == Some("unavailable");
    if unavailable {
        2
    } else {
        0
    }
}
