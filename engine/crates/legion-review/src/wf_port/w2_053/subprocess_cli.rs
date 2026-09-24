//! Port of `src/lib/review/providers/subprocess_cli.py`
//! (`SubprocessProvider`, one-shot CLI jurors).
//!
//! **Ported faithfully (pure, process-free):**
//! - `{model}` / `{prompt}` command-template substitution and the
//!   stdin-vs-argv decision (`prompt_via_stdin = "{prompt}" not in
//!   " ".join(command_template)`) — [`build_command`], [`prompt_via_stdin`]
//! - the non-zero-exit error message, including the 4000-char stderr/stdout
//!   cap (`(proc.stderr or proc.stdout or "")[:4000]`) — [`exit_error_message`]
//! - the executable-resolution fallback order on Windows
//!   (`name`, then `name.cmd`/`.exe`/`.bat`/`.ps1`) — [`windows_executable_candidates`]
//!   and [`resolve_executable`], the latter now doing the actual PATH walk
//!   `shutil.which` performs (checked against `$PATH`/`Path::exists` with a
//!   Unix executable-bit check; last resort is `name` itself, matching
//!   `return name`).
//! - `subprocess.run` itself, per packet R61 / the port brief's mandate that
//!   subprocess orchestration is portable: [`CommandRunner`] is the
//!   `std::process::Command` boundary (mirroring the w2_020 `ProcessRunner`
//!   precedent), [`StdCommandRunner`] is the real implementation (spawn +
//!   capture stdout/stderr + a `timeout_s` deadline enforced with a
//!   watcher thread and `Child::kill`, since stable `std::process` has no
//!   built-in wait-with-timeout), and [`SubprocessProvider::call`] is the
//!   full `call()` port (error mapping, the `[:4000]` cap, `FileNotFoundError`
//!   -> "CLI not found").
//!
//! **Not ported:** the `agent_spawn.ensure_directive` best-effort import
//! used to prepend the machine-minimal JSON-mode directive (`try: ... except
//! Exception: user_enforced = user` — that module does not exist anywhere
//! in this repository, Python or otherwise, so the `except` branch is the
//! only reachable behavior here; [`SubprocessProvider::call`] takes
//! `user_enforced` pre-resolved by the caller, matching that fallback
//! exactly). Image forwarding is the same acknowledged no-op as the Python
//! (`_ = images`).

/// Port of `prompt_via_stdin = "{prompt}" not in " ".join(command_template)`.
pub fn prompt_via_stdin(command_template: &[String]) -> bool {
    !command_template.join(" ").contains("{prompt}")
}

/// Port of the Windows-only fallback candidate order in
/// `_resolve_executable`: `name`, then `name.cmd`, `name.exe`, `name.bat`,
/// `name.ps1`. Each candidate is what the caller passes to a `shutil.which`
/// equivalent (`which::which` or similar); the first one that resolves
/// wins, and if none does, the Python returns `name` itself as "last
/// resort" (callers should fall back to `name` — `command_template[0]` —
/// when every candidate here misses, matching `return name`).
pub fn windows_executable_candidates(name: &str) -> Vec<String> {
    vec![
        name.to_string(),
        format!("{name}.cmd"),
        format!("{name}.exe"),
        format!("{name}.bat"),
        format!("{name}.ps1"),
    ]
}

/// Port of the `cmd` construction loop in `call`: substitutes `{model}` and
/// `{prompt}` into each `command_template` piece (element 0 is left as-is —
/// executable resolution is a separate, platform-dependent step the caller
/// applies to `cmd[0]`; the Python resolves it inline via
/// `_resolve_executable(piece)`, which this function does not perform since
/// it requires filesystem/PATH access).
///
/// Matches Python's `if/elif` order: a piece containing `{model}` is model-
/// substituted even if it also happens to contain `{prompt}` (mutually
/// exclusive in practice, but the precedence is preserved exactly).
pub fn build_command(command_template: &[String], model: &str, full_prompt: &str) -> Vec<String> {
    command_template
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            if i == 0 {
                piece.clone()
            } else if piece.contains("{model}") {
                piece.replace("{model}", model)
            } else if piece.contains("{prompt}") {
                piece.replace("{prompt}", full_prompt)
            } else {
                piece.clone()
            }
        })
        .collect()
}

/// Cap applied to stderr/stdout on a non-zero exit, port of the literal
/// `4000` in `call`'s error-message construction (raised from 500 -> 4000
/// on 2026-05-05, per the Python comment, to match `engine.py` response
/// clipping).
pub const EXIT_ERROR_CAP: usize = 4000;

/// Port of `err = (proc.stderr or proc.stdout or "")[:4000]` plus the
/// message format `f"{self.name}/{model} exit {proc.returncode}: {err}"`.
/// Python's `str[:4000]` slices by Unicode code point; this slices by
/// `char`, matching that (not by byte, which could split a multi-byte
/// char).
pub fn exit_error_message(provider_name: &str, model: &str, returncode: i32, stderr: &str, stdout: &str) -> String {
    let raw: &str = if !stderr.is_empty() {
        stderr
    } else {
        stdout
    };
    let capped: String = raw.chars().take(EXIT_ERROR_CAP).collect();
    format!("{provider_name}/{model} exit {returncode}: {capped}")
}

/// Port of the `timeout_s` construction default: `int(config.get("timeout_s", 180))`.
pub const DEFAULT_TIMEOUT_S: u64 = 180;

/// Port of `full_prompt = f"{system}\n\n---\n\n{user_enforced}"` (with
/// `user_enforced` already resolved by the caller — the `ensure_directive`
/// best-effort call is outside this chunk's owned paths, see module docs).
pub fn build_full_prompt(system: &str, user_enforced: &str) -> String {
    format!("{system}\n\n---\n\n{user_enforced}")
}

// ─── R61: process runner + resolve_executable + SubprocessProvider::call ──

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Port of `ProviderError` (`src/lib/review/providers/base.py`), scoped to
/// what this file raises: a plain message plus the `is_quota` flag (`status`
/// is never set by `subprocess_cli.py`, so it is omitted here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub message: String,
    pub is_quota: bool,
}

impl ProviderError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), is_quota: false }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ProviderError {}

/// Captured child-process outcome, port of the fields of `subprocess.run`'s
/// `CompletedProcess` that `call()` reads.
#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub stdout: String,
    pub stderr: String,
    pub returncode: i32,
}

/// Outcome of attempting to run a command, port of the three exceptions
/// `call()` catches: `subprocess.TimeoutExpired`, `FileNotFoundError`, and
/// any other `Exception`.
#[derive(Debug, Clone)]
pub enum RunError {
    Timeout,
    NotFound,
    Other(String),
}

/// Port of the `subprocess.run(...)` boundary: spawn `cmd[0]` with the rest
/// as argv, optionally feeding `stdin` text, capturing stdout/stderr as
/// text, bounded by `timeout_s`. Mirrors the w2_020 `ProcessRunner`
/// precedent so tests supply a fake instead of spawning a real child.
pub trait CommandRunner {
    fn run(&self, cmd: &[String], stdin: Option<&str>, timeout_s: u64) -> Result<RunOutput, RunError>;
}

/// Real implementation: `std::process::Command`, with `timeout_s` enforced
/// by a watcher thread (`mpsc::Receiver::recv_timeout` + `Child::kill` on
/// expiry) since stable `std::process::Child` has no wait-with-timeout.
/// Errors and text decoding mirror the Python's `encoding="utf-8",
/// errors="replace"` (`String::from_utf8_lossy`).
pub struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn run(&self, cmd: &[String], stdin: Option<&str>, timeout_s: u64) -> Result<RunOutput, RunError> {
        use std::io::Read;

        let Some((exe, rest)) = cmd.split_first() else {
            return Err(RunError::Other("empty command".to_string()));
        };
        let mut command = Command::new(exe);
        command.args(rest);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RunError::NotFound),
            Err(e) => return Err(RunError::Other(e.to_string())),
        };

        if let Some(text) = stdin {
            use std::io::Write;
            if let Some(mut pipe) = child.stdin.take() {
                // Best-effort write, matching subprocess.run's behavior when
                // the child exits early and closes its stdin pipe.
                let _ = pipe.write_all(text.as_bytes());
            }
            // Drop the pipe (end-of-input) so a child reading to EOF on
            // stdin does not block forever.
        }

        // Read stdout/stderr on their own threads so a child that fills a
        // pipe buffer before exiting cannot deadlock the poll loop below
        // (the classic `subprocess` pitfall `wait_with_output` avoids
        // internally; done manually here since `try_wait` — needed for the
        // timeout poll — takes `&mut self` and can't be combined with the
        // self-consuming `wait_with_output`).
        let mut stdout_pipe = child.stdout.take();
        let stdout_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = stdout_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });
        let mut stderr_pipe = child.stderr.take();
        let stderr_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = stderr_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_s);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        // Port of subprocess.run's TimeoutExpired handling:
                        // the child is killed and reaped, not left running.
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(RunError::Timeout);
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => break Err(RunError::Other(e.to_string())),
            }
        };

        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();

        status.map(|status| RunOutput {
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            returncode: status.code().unwrap_or(-1),
        })
    }
}

/// Port of `shutil.which(name)`: search each `$PATH` directory for `name`
/// as a file (on Unix, additionally requiring at least one executable bit
/// via `PermissionsExt::mode() & 0o111`; Windows has no such bit, so
/// existence alone matches `shutil.which`'s own PATHEXT-aware behavior for
/// the exact-name case).
fn which(name: &str) -> Option<PathBuf> {
    // An already-qualified path (contains a separator) is used as-is,
    // matching shutil.which's own short-circuit for that case.
    if name.contains(std::path::MAIN_SEPARATOR) || name.contains('/') {
        let p = Path::new(name);
        return if is_executable_file(p) { Some(p.to_path_buf()) } else { None };
    }
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// Port of `_resolve_executable(name)`: `shutil.which(name)` first; on
/// Windows, if that misses, try [`windows_executable_candidates`]'s
/// `.cmd`/`.exe`/`.bat`/`.ps1` suffixes via `shutil.which`; if every
/// candidate misses, return `name` unchanged ("last resort — let subprocess
/// raise FileNotFoundError").
pub fn resolve_executable(name: &str) -> String {
    if let Some(found) = which(name) {
        return found.to_string_lossy().into_owned();
    }
    if cfg!(windows) {
        for candidate in windows_executable_candidates(name).into_iter().skip(1) {
            if let Some(found) = which(&candidate) {
                return found.to_string_lossy().into_owned();
            }
        }
    }
    name.to_string()
}

/// Port of the `SubprocessProvider` class: one-shot CLI juror config plus
/// [`SubprocessProvider::call`], the full `call()` method.
pub struct SubprocessProvider {
    pub name: String,
    pub command_template: Vec<String>,
    pub timeout_s: u64,
    pub prompt_via_stdin: bool,
}

impl SubprocessProvider {
    /// Port of `__init__`: `timeout_s` defaults to `180`
    /// (`int(config.get("timeout_s", 180))`), and `prompt_via_stdin` is
    /// derived from `command_template` per [`prompt_via_stdin`].
    pub fn new(name: impl Into<String>, command_template: Vec<String>, timeout_s: Option<u64>) -> Self {
        let stdin_route = prompt_via_stdin(&command_template);
        Self {
            name: name.into(),
            command_template,
            timeout_s: timeout_s.unwrap_or(DEFAULT_TIMEOUT_S),
            prompt_via_stdin: stdin_route,
        }
    }

    /// Port of `call(self, model, system, user, max_tokens=2048,
    /// images=None)`. `user_enforced` is the caller-resolved
    /// `ensure_directive(user, mode="json")` result (see module docs — that
    /// import always fails in this repo, so callers pass `user` unchanged,
    /// matching the Python's `except Exception: user_enforced = user`
    /// fallback exactly). `images` is accepted and ignored, matching the
    /// Python's acknowledged-but-not-forwarded `_ = images`.
    pub fn call(
        &self,
        runner: &dyn CommandRunner,
        model: &str,
        system: &str,
        user_enforced: &str,
        _images: Option<&[()]>,
    ) -> Result<String, ProviderError> {
        let full_prompt = build_full_prompt(system, user_enforced);
        let mut cmd = build_command(&self.command_template, model, &full_prompt);
        if let Some(first) = cmd.first_mut() {
            *first = resolve_executable(first);
        }

        let stdin = if self.prompt_via_stdin { Some(full_prompt.as_str()) } else { None };
        match runner.run(&cmd, stdin, self.timeout_s) {
            Ok(output) => {
                if output.returncode != 0 {
                    Err(ProviderError::new(exit_error_message(
                        &self.name,
                        model,
                        output.returncode,
                        &output.stderr,
                        &output.stdout,
                    )))
                } else {
                    Ok(output.stdout)
                }
            }
            Err(RunError::Timeout) => Err(ProviderError {
                message: format!("{}/{model} timeout after {}s", self.name, self.timeout_s),
                is_quota: false,
            }),
            Err(RunError::NotFound) => {
                let argv0 = cmd.first().cloned().unwrap_or_default();
                Err(ProviderError::new(format!("{}: CLI not found ({argv0})", self.name)))
            }
            Err(RunError::Other(e)) => Err(ProviderError::new(format!("{}/{model} error: {e}", self.name))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_via_stdin_true_when_template_has_no_prompt_placeholder() {
        let template = vec!["codex".to_string(), "exec".to_string(), "-".to_string()];
        assert!(prompt_via_stdin(&template));
    }

    #[test]
    fn prompt_via_stdin_false_when_template_has_prompt_placeholder() {
        let template = vec!["mycli".to_string(), "{prompt}".to_string()];
        assert!(!prompt_via_stdin(&template));
    }

    #[test]
    fn windows_candidates_in_order() {
        assert_eq!(
            windows_executable_candidates("gemini"),
            vec!["gemini", "gemini.cmd", "gemini.exe", "gemini.bat", "gemini.ps1"],
        );
    }

    #[test]
    fn build_command_substitutes_model_and_prompt_leaves_argv0() {
        let template = vec![
            "codex".to_string(),
            "exec".to_string(),
            "-m".to_string(),
            "{model}".to_string(),
            "-".to_string(),
        ];
        let cmd = build_command(&template, "gpt-5.5", "SYSTEM\n\n---\n\nUSER");
        assert_eq!(cmd, vec!["codex", "exec", "-m", "gpt-5.5", "-"]);
    }

    #[test]
    fn build_command_substitutes_prompt_placeholder() {
        let template = vec!["mycli".to_string(), "{prompt}".to_string()];
        let cmd = build_command(&template, "m", "the full prompt");
        assert_eq!(cmd, vec!["mycli", "the full prompt"]);
    }

    #[test]
    fn build_command_model_takes_precedence_over_prompt_in_same_piece() {
        // Mirrors the Python's if/elif order: a piece matching "{model}" is
        // never also prompt-substituted, even in the contrived case both
        // placeholders appear in one piece.
        let template = vec!["cli".to_string(), "{model}-{prompt}".to_string()];
        let cmd = build_command(&template, "M", "P");
        assert_eq!(cmd, vec!["cli", "M-{prompt}"]);
    }

    #[test]
    fn exit_error_message_prefers_stderr_over_stdout() {
        let msg = exit_error_message("codex", "gpt-5.5", 1, "boom", "should not appear");
        assert_eq!(msg, "codex/gpt-5.5 exit 1: boom");
    }

    #[test]
    fn exit_error_message_falls_back_to_stdout_when_stderr_empty() {
        let msg = exit_error_message("codex", "gpt-5.5", 2, "", "stdout text");
        assert_eq!(msg, "codex/gpt-5.5 exit 2: stdout text");
    }

    #[test]
    fn exit_error_message_empty_when_both_streams_empty() {
        let msg = exit_error_message("codex", "gpt-5.5", 3, "", "");
        assert_eq!(msg, "codex/gpt-5.5 exit 3: ");
    }

    #[test]
    fn exit_error_message_caps_at_4000_chars() {
        let long = "x".repeat(5000);
        let msg = exit_error_message("codex", "m", 1, &long, "");
        // "codex/m exit 1: " prefix + 4000 capped chars.
        let prefix = "codex/m exit 1: ";
        assert_eq!(msg.len(), prefix.len() + EXIT_ERROR_CAP);
        assert!(msg.ends_with(&"x".repeat(EXIT_ERROR_CAP)));
    }

    #[test]
    fn full_prompt_join_format() {
        assert_eq!(
            build_full_prompt("SYS", "USER"),
            "SYS\n\n---\n\nUSER",
        );
    }

    struct FakeRunner {
        result: std::cell::RefCell<Option<Result<RunOutput, RunError>>>,
        last_cmd: std::cell::RefCell<Vec<String>>,
        last_stdin: std::cell::RefCell<Option<String>>,
    }

    impl FakeRunner {
        fn new(result: Result<RunOutput, RunError>) -> Self {
            Self {
                result: std::cell::RefCell::new(Some(result)),
                last_cmd: std::cell::RefCell::new(Vec::new()),
                last_stdin: std::cell::RefCell::new(None),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, cmd: &[String], stdin: Option<&str>, _timeout_s: u64) -> Result<RunOutput, RunError> {
            *self.last_cmd.borrow_mut() = cmd.to_vec();
            *self.last_stdin.borrow_mut() = stdin.map(str::to_string);
            self.result.borrow_mut().take().expect("run called once")
        }
    }

    #[test]
    fn provider_call_returns_stdout_on_success() {
        let provider = SubprocessProvider::new(
            "codex",
            vec!["codex".to_string(), "exec".to_string(), "-m".to_string(), "{model}".to_string(), "-".to_string()],
            None,
        );
        let runner = FakeRunner::new(Ok(RunOutput {
            stdout: "the answer".to_string(),
            stderr: String::new(),
            returncode: 0,
        }));
        let out = provider.call(&runner, "gpt-5.5", "SYS", "USER", None).unwrap();
        assert_eq!(out, "the answer");
        assert_eq!(provider.timeout_s, DEFAULT_TIMEOUT_S);
        assert!(provider.prompt_via_stdin);
        assert_eq!(*runner.last_stdin.borrow(), Some("SYS\n\n---\n\nUSER".to_string()));
    }

    #[test]
    fn provider_call_nonzero_exit_caps_and_prefers_stderr() {
        let provider = SubprocessProvider::new("codex", vec!["codex".to_string(), "{prompt}".to_string()], Some(90));
        let runner = FakeRunner::new(Ok(RunOutput {
            stdout: "ignored".to_string(),
            stderr: "boom".to_string(),
            returncode: 3,
        }));
        let err = provider.call(&runner, "gpt-5.5", "SYS", "USER", None).unwrap_err();
        assert_eq!(err.message, "codex/gpt-5.5 exit 3: boom");
        assert!(!err.is_quota);
        assert_eq!(provider.timeout_s, 90);
        assert!(!provider.prompt_via_stdin);
        assert_eq!(*runner.last_cmd.borrow(), vec!["codex", "SYS\n\n---\n\nUSER"]);
    }

    #[test]
    fn provider_call_maps_timeout_and_not_found() {
        let provider = SubprocessProvider::new("codex", vec!["codex".to_string(), "-".to_string()], Some(5));
        let timeout_runner = FakeRunner::new(Err(RunError::Timeout));
        let err = provider.call(&timeout_runner, "m", "S", "U", None).unwrap_err();
        assert_eq!(err.message, "codex/m timeout after 5s");
        assert!(!err.is_quota);

        let missing_runner = FakeRunner::new(Err(RunError::NotFound));
        let err = provider.call(&missing_runner, "m", "S", "U", None).unwrap_err();
        assert!(err.message.starts_with("codex: CLI not found ("));
    }

    #[test]
    fn provider_call_maps_other_error() {
        let provider = SubprocessProvider::new("codex", vec!["codex".to_string(), "-".to_string()], Some(5));
        let runner = FakeRunner::new(Err(RunError::Other("pipe broke".to_string())));
        let err = provider.call(&runner, "m", "S", "U", None).unwrap_err();
        assert_eq!(err.message, "codex/m error: pipe broke");
    }

    #[test]
    fn resolve_executable_falls_back_to_name_when_not_on_path() {
        // Nonexistent binary name: `which` never finds it and no Windows
        // suffix candidate exists either, so the Python's "last resort"
        // `return name` path is exercised.
        let resolved = resolve_executable("definitely-not-a-real-cli-xyz123");
        assert_eq!(resolved, "definitely-not-a-real-cli-xyz123");
    }

    #[test]
    fn std_command_runner_captures_output_and_exit_code() {
        // "sh -c" is available in this repo's CI/dev environments; the
        // real-transport smoke exercises spawn + capture + exit code
        // without depending on codex/gemini being installed.
        if which("sh").is_none() {
            return;
        }
        let runner = StdCommandRunner;
        let out = runner
            .run(&["sh".to_string(), "-c".to_string(), "echo hi; exit 7".to_string()], None, 10)
            .expect("sh should run");
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.returncode, 7);
    }

    #[test]
    fn std_command_runner_reports_not_found() {
        let runner = StdCommandRunner;
        let err = runner.run(&["definitely-not-a-real-cli-xyz123".to_string()], None, 5);
        assert!(matches!(err, Err(RunError::NotFound)));
    }
}
