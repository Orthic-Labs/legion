//! Port of `src/lib/dispatch-validator/validate-tasklist.py` (packet r47
//! closes the `--receipt-mode verify` / `--packet-type worker` gap left by
//! chunk w2_044).
//!
//! The Python script is a thin CLI that shells out to `validate-dispatch.py
//! <packet> --packet-type <type> --<mode>-receipt <receipt>` and forwards
//! its stdout/stderr/exit code unchanged. `validate_and_write_receipt`
//! below ports the one *decision* contract that is inside the ported
//! `authority_packet_errors` surface (default `--packet-type authority
//! --receipt-mode write` path: run the packet through
//! `authority_packet_errors`, and on success write a
//! `<packet-stem>.receipt.json` sidecar recording the packet's digest) and
//! is kept for `test_validate_tasklist.py`'s fixture, which only exercises
//! that path.
//!
//! [`run_cli`] separately ports the *actual* CLI wrapper faithfully,
//! including `--receipt-mode verify` and `--packet-type worker`: it does
//! not reimplement `validate-dispatch.py`'s decision logic (which
//! `wf_port::w2_044`'s module doc records as only partially ported) — it
//! reproduces `validate-tasklist.py`'s own contract, which is to spawn
//! `validate-dispatch.py` as a subprocess with the resolved packet path,
//! `--packet-type`, and `--{mode}-receipt <receipt>`, and forward its
//! stdout/stderr/exit code unchanged. That subprocess-orchestration and
//! argv-parsing surface is portable independent of whether the delegate
//! script itself has a Rust port, so this closes the file's remaining gap
//! in full: the same `argparse` surface (`packets` positional list,
//! `--packet-type {authority,worker}`, `--receipt-mode {write,verify}`,
//! `--receipt-dir`), the same per-packet `is_file()` pre-check with a
//! `FAIL: packet file not found: <path>` stderr line and exit code 2, the
//! same `<receipt-dir-or-packet-parent>/<stem>.receipt.json` receipt path,
//! and the same "run each packet in order, stop and return the first
//! non-zero exit code" loop.

use super::authority_packet::authority_packet_errors;
use super::digest::sha256_digest;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Result of [`validate_and_write_receipt`].
#[derive(Debug)]
pub enum TasklistResult {
    /// Port of the Python script's `return 0` path: packet is structurally
    /// valid and a receipt was written at `receipt_path`.
    Pass { receipt_path: PathBuf },
    /// Port of the Python script's `return 1` path: packet failed
    /// structural validation; no receipt is written.
    Fail { errors: Vec<String> },
}

/// Port of `validate-tasklist.py`'s default (`--packet-type authority
/// --receipt-mode write`) path.
///
/// `packet_path` must be readable JSON; on success a
/// `<stem>.receipt.json` file is written next to it (or under
/// `receipt_dir`, matching the Python script's `--receipt-dir` override)
/// containing `{"packet": <canonical path>, "sha256": <digest>}`.
pub fn validate_and_write_receipt(
    packet_path: &Path,
    receipt_dir: Option<&Path>,
) -> std::io::Result<TasklistResult> {
    let bytes = std::fs::read(packet_path)?;
    let packet: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return Ok(TasklistResult::Fail {
                errors: vec!["packet unreadable".to_string()],
            })
        }
    };
    let (errors, _) = authority_packet_errors(&packet, packet_path);
    if !errors.is_empty() {
        return Ok(TasklistResult::Fail { errors });
    }
    let dir = receipt_dir
        .map(Path::to_path_buf)
        .or_else(|| packet_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = packet_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let receipt_path = dir.join(format!("{stem}.receipt.json"));
    let receipt = serde_json::json!({
        "packet": packet_path.to_string_lossy(),
        "sha256": sha256_digest(&bytes),
    });
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(TasklistResult::Pass { receipt_path })
}

/// Abstraction over spawning `validate-dispatch.py`, so [`run_cli`] can be
/// tested without a real Python interpreter or subprocess. Mirrors
/// `subprocess.run([sys.executable, str(VALIDATOR), ...], capture_output=True,
/// text=True)`.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessOutput>;
}

/// Captured stdout/stderr/exit-code of a completed subprocess. Mirrors the
/// fields of Python's `subprocess.CompletedProcess` that `main()` reads.
#[derive(Debug, Clone, Default)]
pub struct ProcessOutput {
    pub stdout: String,
    pub stderr: String,
    /// `None` here has no Python equivalent used by this script (a process
    /// killed by a signal reports a negative `returncode` in Python, which
    /// this maps to `i32::MIN` rather than modelling `Option`, since `main`
    /// only ever tests `if result.returncode:`).
    pub code: i32,
}

/// Runner that actually spawns `sys.executable str(VALIDATOR) ...`, i.e.
/// the real `program` (normally the Python interpreter) with `args`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessOutput> {
        let output = std::process::Command::new(program).args(args).output()?;
        Ok(ProcessOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            code: output.status.code().unwrap_or(i32::MIN),
        })
    }
}

/// Parsed form of `validate-tasklist.py`'s `argparse` surface.
#[derive(Debug, Clone)]
struct CliArgs {
    packets: Vec<PathBuf>,
    packet_type: String,
    receipt_mode: String,
    receipt_dir: Option<PathBuf>,
}

/// Outcome of [`run_cli`]: the process exit code plus whatever it wrote to
/// stdout/stderr (from `sys.stdout.write(result.stdout)` /
/// `sys.stderr.write(result.stderr)`, plus this port's own usage/FAIL
/// lines, which `main()` prints the same way via `print(..., file=sys.stderr)`).
#[derive(Debug, Clone, Default)]
pub struct CliOutcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Strips a Windows `\\?\` verbatim prefix from a canonicalized path, so
/// path text this port prints/joins matches what the Python script (which
/// never sees that prefix) would produce.
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path,
    }
}

/// Port of `Path(...).resolve()`: canonicalizes when the path exists (or
/// its existing prefix resolves), and otherwise falls back to lexically
/// joining onto the current working directory — `Path.resolve()` never
/// raises merely because the target does not exist, and the subsequent
/// `is_file()` check (ported in [`run_cli`]) is what turns "does not exist"
/// into the script's own `FAIL: packet file not found` outcome.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return strip_verbatim_prefix(canon);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    // Best-effort lexical normalization (collapse "." and ".."), since a
    // nonexistent path can still have a resolvable existing ancestor that
    // `canonicalize` above already would have used if the whole path
    // existed. This does not resolve symlinks in the nonexistent tail —
    // neither does Python's `resolve()` for components that do not exist.
    let mut out = PathBuf::new();
    for component in absolute.components() {
        use std::path::Component;
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Parses argv the way `argparse` does for this script's parser, returning
/// `Err((code, message))` mirroring `argparse`'s own exit-2-with-usage
/// behaviour (collapsed to a single message line here rather than
/// replicating argparse's exact usage banner text, since `run_cli`'s
/// callers only observe the CLI's exit code and forwarded child output,
/// never the parser's own usage text as a source of truth).
fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut packets = Vec::new();
    let mut packet_type = "authority".to_string();
    let mut receipt_mode = "write".to_string();
    let mut receipt_dir = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--packet-type" => {
                i += 1;
                let v = args.get(i).ok_or("argument --packet-type: expected one argument")?;
                if v != "authority" && v != "worker" {
                    return Err(format!(
                        "argument --packet-type: invalid choice: '{v}' (choose from 'authority', 'worker')"
                    ));
                }
                packet_type = v.clone();
            }
            "--receipt-mode" => {
                i += 1;
                let v = args.get(i).ok_or("argument --receipt-mode: expected one argument")?;
                if v != "write" && v != "verify" {
                    return Err(format!(
                        "argument --receipt-mode: invalid choice: '{v}' (choose from 'write', 'verify')"
                    ));
                }
                receipt_mode = v.clone();
            }
            "--receipt-dir" => {
                i += 1;
                let v = args.get(i).ok_or("argument --receipt-dir: expected one argument")?;
                receipt_dir = Some(PathBuf::from(v));
            }
            other => packets.push(PathBuf::from(other)),
        }
        i += 1;
    }

    if packets.is_empty() {
        return Err("the following arguments are required: packets".to_string());
    }

    Ok(CliArgs {
        packets,
        packet_type,
        receipt_mode,
        receipt_dir,
    })
}

/// Faithful port of `validate-tasklist.py`'s `main()`.
///
/// `python` and `validator_path` stand in for `sys.executable` and
/// `VALIDATOR` (`validate-dispatch.py`, resolved next to this module's own
/// source file in the Python original); callers pass whatever resolves to
/// a working `validate-dispatch.py` invocation in their environment.
/// `args` is the argv tail (no program name), matching what `argparse`
/// consumes.
pub fn run_cli(
    args: &[String],
    python: &str,
    validator_path: &Path,
    runner: &dyn CommandRunner,
) -> CliOutcome {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(message) => {
            return CliOutcome {
                code: 2,
                stdout: String::new(),
                stderr: format!("{message}\n"),
            }
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();

    for packet in &parsed.packets {
        let packet = resolve_path(packet);
        if !packet.is_file() {
            stderr.push_str(&format!("FAIL: packet file not found: {}\n", packet.display()));
            return CliOutcome { code: 2, stdout, stderr };
        }
        let receipt_dir = match &parsed.receipt_dir {
            Some(d) => resolve_path(d),
            None => resolve_path(
                &packet
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from(".")),
            ),
        };
        let stem = packet
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let receipt = receipt_dir.join(format!("{stem}.receipt.json"));

        let child_args = vec![
            validator_path.to_string_lossy().into_owned(),
            packet.to_string_lossy().into_owned(),
            "--packet-type".to_string(),
            parsed.packet_type.clone(),
            format!("--{}-receipt", parsed.receipt_mode),
            receipt.to_string_lossy().into_owned(),
        ];

        let output = match runner.run(python, &child_args) {
            Ok(o) => o,
            Err(err) => {
                stderr.push_str(&format!("FAIL: could not launch validator: {err}\n"));
                return CliOutcome { code: 2, stdout, stderr };
            }
        };
        stdout.push_str(&output.stdout);
        stderr.push_str(&output.stderr);
        if output.code != 0 {
            return CliOutcome { code: output.code, stdout, stderr };
        }
    }

    CliOutcome { code: 0, stdout, stderr }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeRunner {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        outputs: RefCell<Vec<ProcessOutput>>,
    }

    impl FakeRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outputs: RefCell::new(outputs.into_iter().rev().collect()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessOutput> {
            self.calls.borrow_mut().push((program.to_string(), args.to_vec()));
            Ok(self.outputs.borrow_mut().pop().unwrap_or_default())
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "r47-tasklist-cli-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_packet_fails_before_spawning() {
        let dir = tmp_dir("missing");
        let missing = dir.join("nope.json");
        let runner = FakeRunner::new(vec![]);
        let outcome = run_cli(
            &[missing.to_string_lossy().into_owned()],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            &runner,
        );
        assert_eq!(outcome.code, 2);
        assert!(outcome.stderr.contains("FAIL: packet file not found"));
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn default_flags_delegate_authority_write() {
        let dir = tmp_dir("defaults");
        let packet = dir.join("packet.json");
        std::fs::write(&packet, b"{}").unwrap();
        let runner = FakeRunner::new(vec![ProcessOutput {
            stdout: "ok\n".to_string(),
            stderr: String::new(),
            code: 0,
        }]);
        let outcome = run_cli(
            &[packet.to_string_lossy().into_owned()],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            &runner,
        );
        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.stdout, "ok\n");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (program, child_args) = &calls[0];
        assert_eq!(program, "python3");
        assert_eq!(child_args[0], "/opt/legion/validate-dispatch.py");
        assert!(child_args.contains(&"--packet-type".to_string()));
        assert!(child_args.contains(&"authority".to_string()));
        assert!(child_args.contains(&"--write-receipt".to_string()));
    }

    #[test]
    fn verify_mode_and_worker_type_are_forwarded() {
        let dir = tmp_dir("verify-worker");
        let packet = dir.join("packet.json");
        std::fs::write(&packet, b"{}").unwrap();
        let runner = FakeRunner::new(vec![ProcessOutput {
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
        }]);
        let outcome = run_cli(
            &[
                packet.to_string_lossy().into_owned(),
                "--packet-type".to_string(),
                "worker".to_string(),
                "--receipt-mode".to_string(),
                "verify".to_string(),
            ],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            &runner,
        );
        assert_eq!(outcome.code, 0);
        let calls = runner.calls.borrow();
        let (_, child_args) = &calls[0];
        assert!(child_args.contains(&"worker".to_string()));
        assert!(child_args.contains(&"--verify-receipt".to_string()));
    }

    #[test]
    fn nonzero_child_exit_stops_the_loop() {
        let dir = tmp_dir("stop-on-fail");
        let first = dir.join("a.json");
        let second = dir.join("b.json");
        std::fs::write(&first, b"{}").unwrap();
        std::fs::write(&second, b"{}").unwrap();
        let runner = FakeRunner::new(vec![ProcessOutput {
            stdout: String::new(),
            stderr: "boom\n".to_string(),
            code: 1,
        }]);
        let outcome = run_cli(
            &[
                first.to_string_lossy().into_owned(),
                second.to_string_lossy().into_owned(),
            ],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            &runner,
        );
        assert_eq!(outcome.code, 1);
        assert_eq!(outcome.stderr, "boom\n");
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn invalid_choice_reports_argparse_style_error() {
        let dir = tmp_dir("invalid-choice");
        let packet = dir.join("packet.json");
        std::fs::write(&packet, b"{}").unwrap();
        let runner = FakeRunner::new(vec![]);
        let outcome = run_cli(
            &[
                packet.to_string_lossy().into_owned(),
                "--packet-type".to_string(),
                "direct".to_string(),
            ],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            &runner,
        );
        assert_eq!(outcome.code, 2);
        assert!(outcome.stderr.contains("invalid choice"));
        assert!(runner.calls.borrow().is_empty());
    }
}
