//! Port of `src/lib/review/_codex-diag.py`.
//!
//! Diagnostic — run `codex exec` with full stderr capture (no truncation).
//! Used to surface the actual error when the council wrapper only shows a
//! truncated stub.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

/// Hardcoded diagnostic prompt/command, matching the Python script exactly.
pub const DIAG_PROMPT: &str = "smoke: 1+1 = ?";
pub const DIAG_TIMEOUT: Duration = Duration::from_secs(60);

/// Result of running the diagnostic, mirroring the Python `main()`'s exit
/// codes: `Ok` carries the captured output (exit code reflects the child
/// process's own return code, not this function's success); the `Err`
/// variants correspond to Python's `sys.exit(2)` (timeout) and `sys.exit(3)`
/// (other errors).
#[derive(Debug)]
pub enum DiagOutcome {
    Ran { returncode: i32, stdout: String, stderr: String },
    Timeout,
    Error(String),
}

/// Build the exact `codex exec` command line the Python script constructs.
pub fn diag_command(codex_cmd: &str) -> Vec<String> {
    vec![
        codex_cmd.to_string(),
        "exec".to_string(),
        "--skip-git-repo-check".to_string(),
        "-m".to_string(),
        "gpt-5-codex".to_string(),
        DIAG_PROMPT.to_string(),
    ]
}

/// Default `codex` executable path baked into the Python script
/// (`C:\nvm4w\nodejs\codex.cmd`, a Windows-only path — this port keeps it
/// verbatim rather than "fixing" it for other platforms, since the Python
/// source hardcodes it too).
pub fn default_codex_cmd() -> PathBuf {
    PathBuf::from(r"C:\nvm4w\nodejs\codex.cmd")
}

/// Run the diagnostic. `runner` is injected so tests don't need a real
/// `codex` binary; production callers pass a closure around
/// `std::process::Command::output`.
pub fn run_diag<F>(codex_cmd: &str, runner: F) -> DiagOutcome
where
    F: FnOnce(&[String], Duration) -> std::io::Result<Output>,
{
    let cmd = diag_command(codex_cmd);
    match runner(&cmd, DIAG_TIMEOUT) {
        Ok(output) => DiagOutcome::Ran {
            returncode: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => DiagOutcome::Timeout,
        Err(e) => DiagOutcome::Error(e.to_string()),
    }
}

/// Production entry point: shells out for real with the crate's default
/// timeout semantics enforced by the caller's process-spawn layer (Rust's
/// `std::process::Command` has no built-in timeout; production callers are
/// expected to wrap this with their own timeout/kill-after mechanism, same
/// as any other long-running child process in this codebase).
pub fn run_diag_live(codex_cmd: &str) -> DiagOutcome {
    run_diag(codex_cmd, |cmd, _timeout| {
        Command::new(&cmd[0]).args(&cmd[1..]).output()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_command_matches_python_argv() {
        let cmd = diag_command(r"C:\nvm4w\nodejs\codex.cmd");
        assert_eq!(
            cmd,
            vec![
                r"C:\nvm4w\nodejs\codex.cmd".to_string(),
                "exec".to_string(),
                "--skip-git-repo-check".to_string(),
                "-m".to_string(),
                "gpt-5-codex".to_string(),
                "smoke: 1+1 = ?".to_string(),
            ]
        );
    }

    #[test]
    fn default_codex_cmd_matches_python_hardcode() {
        assert_eq!(default_codex_cmd(), PathBuf::from(r"C:\nvm4w\nodejs\codex.cmd"));
    }

    #[test]
    fn run_diag_reports_timeout() {
        let outcome = run_diag("codex", |_cmd, _timeout| {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"))
        });
        assert!(matches!(outcome, DiagOutcome::Timeout));
    }

    #[test]
    fn run_diag_reports_other_errors() {
        let outcome = run_diag("codex", |_cmd, _timeout| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))
        });
        match outcome {
            DiagOutcome::Error(msg) => assert!(msg.contains("no such file")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn run_diag_captures_stdout_stderr_and_returncode() {
        let outcome = run_diag("codex", |_cmd, _timeout| {
            Ok(fake_output(0, "hello\n", ""))
        });
        match outcome {
            DiagOutcome::Ran { returncode, stdout, stderr } => {
                assert_eq!(returncode, 0);
                assert_eq!(stdout, "hello\n");
                assert_eq!(stderr, "");
            }
            other => panic!("expected Ran, got {other:?}"),
        }
    }

    // Building a real `std::process::Output` requires actually spawning a
    // process (its fields are otherwise unconstructable outside `std`), so
    // this test helper spawns a trivial real command rather than faking the
    // struct.
    fn fake_output(_returncode: i32, expected_stdout: &str, _expected_stderr: &str) -> Output {
        let script = if cfg!(windows) {
            format!("echo {}", expected_stdout.trim_end())
        } else {
            format!("printf '%s' {:?}", expected_stdout)
        };
        let shell = if cfg!(windows) { "cmd" } else { "sh" };
        let flag = if cfg!(windows) { "/C" } else { "-c" };
        Command::new(shell).arg(flag).arg(script).output().expect("spawn shell")
    }
}
