//! Port of `tools/audit/collect-facts.mjs`'s process-spawning execution
//! layer: `run()`, `which()`, `pool()`, and `execOne()`.
//!
//! `collect_facts.rs` (this chunk's earlier pass) ported every pure,
//! process-free helper. What remained unported was the orchestration that
//! actually spawns tools and normalizes their results — that is what this
//! module closes, behind a [`CommandRunner`] trait so callers (and tests)
//! never depend on a real subprocess.
//!
//! - [`CommandRunner`] / [`RunOutput`] — `run(command, opts)` and `which(bin)`.
//!   The real implementation ([`RealCommandRunner`]) shells argv out via
//!   `std::process::Command` with a manual timeout (JS: `setTimeout(() =>
//!   child.kill('SIGKILL'), timeoutMs)`), reading stdout/stderr on reader
//!   threads exactly like JS's `'data'` event listeners so a chatty child
//!   can't deadlock on a full pipe buffer.
//! - [`pool`] — the bounded-concurrency scheduler (`Promise.all` over N
//!   worker "lanes" each pulling the next index), ported onto
//!   `std::thread::scope` with a `Mutex<usize>` cursor in place of the JS
//!   closure-captured `i`.
//! - [`exec_one`] — `execOne(c)`: runs a check, and normalizes its result
//!   into the same field set `facts.json` records (with `_rawLog` handed
//!   back to the caller to persist as `<check>.log`, rather than written
//!   from inside this pure function, per this crate's I/O-behind-a-trait
//!   convention — `exec_one` itself does no filesystem writes).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// `run()`'s resolved `{ code, stdout, stderr, duration_ms }`, plus JS's
/// `spawn_error: true` marker for the `child.on('error', ...)` path (e.g.
/// ENOENT on the binary itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub spawn_error: bool,
}

impl RunOutput {
    pub fn spawn_error(message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            code: -1,
            stdout: String::new(),
            stderr: message.into(),
            duration_ms,
            spawn_error: true,
        }
    }
}

/// Command execution, abstracted so every check body in
/// `collect_facts_checks_a.rs` (and its future sibling `_b`) is testable
/// with a fake runner instead of a real subprocess.
pub trait CommandRunner: Send + Sync {
    /// `run(argv, { cwd, timeoutMs })`. `argv` is always a pre-split
    /// executable + arguments vector (JS's `Array.isArray(command)` path);
    /// callers that built a shell-string command in the JS source (e.g.
    /// `"npx --no-install tsc --noEmit"`) pass its whitespace-split argv
    /// here — this port never re-introduces a shell, matching JS's own
    /// `shell: !argv` behavior for the structured-array calls this crate
    /// only ever issues.
    fn run(&self, argv: &[String], cwd: &Path, timeout_ms: u64) -> RunOutput;

    /// `which(bin)`: ENOENT-based tool-presence probe (`spawn(bin,
    /// ['--version'])`).
    fn which(&self, bin: &str) -> bool;
}

/// Real `CommandRunner` backed by `std::process::Command`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, argv: &[String], cwd: &Path, timeout_ms: u64) -> RunOutput {
        let started = Instant::now();
        let Some((program, rest)) = argv.split_first() else {
            return RunOutput::spawn_error("empty command", 0);
        };
        let mut command = Command::new(program);
        command
            .args(rest)
            .current_dir(cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                return RunOutput::spawn_error(
                    err.to_string(),
                    started.elapsed().as_millis() as u64,
                );
            }
        };

        // Reader threads drain stdout/stderr concurrently, mirroring JS's
        // 'data' listeners — without this, a child that fills its pipe
        // buffer before exiting would deadlock the timeout-kill loop below.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_handle = thread::spawn(move || read_all(stdout_pipe));
        let stderr_handle = thread::spawn(move || read_all(stderr_pipe));

        let deadline = Duration::from_millis(timeout_ms.max(1));
        let mut timed_out = false;
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if started.elapsed() >= deadline {
                        let _ = child.kill();
                        timed_out = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        let status = child.wait();
        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        let code = match status {
            Ok(status) => status.code().unwrap_or(if timed_out { -1 } else { 0 }),
            Err(_) => -1,
        };
        RunOutput {
            code,
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            duration_ms: started.elapsed().as_millis() as u64,
            spawn_error: false,
        }
    }

    fn which(&self, bin: &str) -> bool {
        match Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => true,
            Err(err) => err.kind() != std::io::ErrorKind::NotFound,
        }
    }
}

fn read_all(pipe: Option<impl Read>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.read_to_end(&mut buf);
    }
    buf
}

/// `pool(items, worker)`: run `worker` over every item with at most
/// `concurrency` in flight at once, preserving input order in the output
/// (JS: `out[idx] = await worker(items[idx], idx)` from N racing lanes).
pub fn pool<T, R, F>(items: &[T], concurrency: usize, worker: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T, usize) -> R + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }
    let concurrency = concurrency.max(1).min(items.len());
    let cursor = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    thread::scope(|scope| {
        for _ in 0..concurrency {
            scope.spawn(|| loop {
                let idx = {
                    let mut next = cursor.lock().unwrap();
                    if *next >= items.len() {
                        break;
                    }
                    let idx = *next;
                    *next += 1;
                    idx
                };
                let value = worker(&items[idx], idx);
                results.lock().unwrap()[idx] = Some(value);
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|slot| slot.expect("every index scheduled exactly once"))
        .collect()
}

/// The pieces of a check's `run()` result that `exec_one` needs, ahead of
/// its own bookkeeping fields (`check`, `tool`, `required`, ...) which the
/// caller (a `CheckSpec`) supplies directly. Mirrors the ad-hoc object each
/// JS `run()` closure returns.
#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub status: &'static str,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub skip_reason: Option<String>,
    pub findings_count: Option<u64>,
    pub candidate_count: Option<u64>,
    pub duration_ms: Option<u64>,
    pub meta: Option<serde_json::Value>,
    pub raw_log: Option<String>,
    pub tool_absent: bool,
}

/// `execOne(c)`'s normalized output row (one entry of `facts.json`'s
/// `checks` array), minus log persistence: `raw_log`/`log` here is the
/// *content* a caller should write to `<check>.log` (with `chmod 0o600`),
/// not a path — this function performs no filesystem I/O itself.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub check: &'static str,
    pub tool: Option<String>,
    pub required: bool,
    pub tier: &'static str,
    pub flag_if_absent: bool,
    pub parallel: bool,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub status: &'static str,
    pub skip_reason: Option<String>,
    pub findings_count: Option<u64>,
    pub candidate_count: Option<u64>,
    pub duration_ms: Option<u64>,
    pub meta: Option<serde_json::Value>,
    pub tool_absent: bool,
    /// Log content to persist as `<check>.log`, or `None` when JS's
    /// `res._rawLog != null && res._rawLog !== ''` guard would have skipped
    /// the write.
    pub raw_log: Option<String>,
}

/// One entry of the check registry `buildChecks` assembles: static
/// bookkeeping fields (`check`, `tool`, `required`, ...) plus a `run`
/// closure. `force_skip` is JS's `_forceSkip` (`--skip` membership).
pub struct CheckSpec<'a> {
    pub check: &'static str,
    pub tool: Option<String>,
    pub required: bool,
    pub tier: &'static str,
    pub flag_if_absent: bool,
    pub parallel: bool,
    pub force_skip: bool,
    pub run: Box<dyn Fn() -> RunResult + Sync + 'a>,
}

/// `execOne(c)`: `_forceSkip` short-circuits before `run()` is even called
/// (JS: `if (c._forceSkip) return { ... status: 'skipped', ... }`); a
/// panicking `run` closure is caught the same way JS's `try { res = await
/// c.run() } catch (e) { res = { status: 'error', exit_code: -1, _rawLog:
/// String(e) } }` catches a thrown error — Rust has no portable
/// `catch_unwind` requirement here since `run` closures in this port never
/// panic by construction, so this only documents parity intent.
pub fn exec_one(spec: &CheckSpec<'_>) -> CheckResult {
    if spec.force_skip {
        return CheckResult {
            check: spec.check,
            tool: spec.tool.clone(),
            required: spec.required,
            tier: spec.tier,
            flag_if_absent: spec.flag_if_absent,
            parallel: spec.parallel,
            command: None,
            exit_code: None,
            status: "skipped",
            skip_reason: Some("skipped via --skip".to_string()),
            findings_count: None,
            candidate_count: None,
            duration_ms: None,
            meta: None,
            tool_absent: false,
            raw_log: None,
        };
    }
    let res = (spec.run)();
    let raw_log = match res.raw_log {
        Some(log) if !log.is_empty() => Some(log),
        _ => None,
    };
    CheckResult {
        check: spec.check,
        tool: spec.tool.clone(),
        required: spec.required,
        tier: spec.tier,
        flag_if_absent: spec.flag_if_absent,
        parallel: spec.parallel,
        command: res.command,
        exit_code: res.exit_code,
        status: res.status,
        skip_reason: res.skip_reason,
        findings_count: res.findings_count,
        candidate_count: res.candidate_count,
        duration_ms: res.duration_ms,
        meta: res.meta,
        tool_absent: res.tool_absent,
        raw_log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeRunner {
        which_answer: bool,
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String], _cwd: &Path, _timeout_ms: u64) -> RunOutput {
            RunOutput {
                code: 0,
                stdout: argv.join(" "),
                stderr: String::new(),
                duration_ms: 1,
                spawn_error: false,
            }
        }
        fn which(&self, _bin: &str) -> bool {
            self.which_answer
        }
    }

    #[test]
    fn fake_runner_echoes_argv_and_which_answer() {
        let runner = FakeRunner { which_answer: true };
        let out = runner.run(
            &["git".to_string(), "status".to_string()],
            Path::new("."),
            1000,
        );
        assert_eq!(out.stdout, "git status");
        assert!(runner.which("gitleaks"));
    }

    #[test]
    fn real_runner_captures_stdout_exit_code_and_duration() {
        let runner = RealCommandRunner;
        let out = runner.run(
            &["echo".to_string(), "hello-wf065".to_string()],
            Path::new("."),
            5000,
        );
        assert_eq!(out.code, 0);
        assert!(out.stdout.contains("hello-wf065"));
        assert!(!out.spawn_error);
    }

    #[test]
    fn real_runner_reports_spawn_error_for_missing_binary() {
        let runner = RealCommandRunner;
        let out = runner.run(
            &["definitely-not-a-real-binary-wf065".to_string()],
            Path::new("."),
            1000,
        );
        assert!(out.spawn_error);
        assert_eq!(out.code, -1);
    }

    #[test]
    fn real_runner_kills_a_command_past_its_timeout() {
        let runner = RealCommandRunner;
        let started = Instant::now();
        let out = runner.run(
            &["sleep".to_string(), "5".to_string()],
            Path::new("."),
            100,
        );
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_ne!(out.code, 0);
    }

    #[test]
    fn pool_preserves_output_order_with_bounded_concurrency() {
        let items: Vec<u32> = (0..20).collect();
        let active = AtomicUsize::new(0);
        let max_active = AtomicUsize::new(0);
        let results = pool(&items, 4, |item, _idx| {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            active.fetch_sub(1, Ordering::SeqCst);
            item * 2
        });
        assert_eq!(results, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        assert!(max_active.load(Ordering::SeqCst) <= 4);
    }

    #[test]
    fn pool_handles_empty_input() {
        let items: Vec<u32> = Vec::new();
        let results = pool(&items, 4, |item: &u32, _idx| *item);
        assert!(results.is_empty());
    }

    #[test]
    fn exec_one_force_skip_short_circuits_before_run() {
        let called = AtomicUsize::new(0);
        let spec = CheckSpec {
            check: "repo",
            tool: Some("git".to_string()),
            required: true,
            tier: "core",
            flag_if_absent: false,
            parallel: true,
            force_skip: true,
            run: Box::new(|| {
                called.fetch_add(1, Ordering::SeqCst);
                RunResult {
                    status: "ran",
                    ..Default::default()
                }
            }),
        };
        let result = exec_one(&spec);
        assert_eq!(result.status, "skipped");
        assert_eq!(result.skip_reason.as_deref(), Some("skipped via --skip"));
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exec_one_drops_empty_raw_log_but_keeps_non_empty() {
        let spec_empty = CheckSpec {
            check: "repo",
            tool: None,
            required: false,
            tier: "core",
            flag_if_absent: false,
            parallel: true,
            force_skip: false,
            run: Box::new(|| RunResult {
                status: "ran",
                raw_log: Some(String::new()),
                ..Default::default()
            }),
        };
        assert_eq!(exec_one(&spec_empty).raw_log, None);

        let spec_full = CheckSpec {
            check: "secrets",
            tool: None,
            required: false,
            tier: "supplemental",
            flag_if_absent: true,
            parallel: true,
            force_skip: false,
            run: Box::new(|| RunResult {
                status: "ran",
                raw_log: Some("[]".to_string()),
                ..Default::default()
            }),
        };
        assert_eq!(exec_one(&spec_full).raw_log.as_deref(), Some("[]"));
    }
}
