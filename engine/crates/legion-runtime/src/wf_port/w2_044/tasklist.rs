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
//! `--packet-type {authority,worker,legacy}`, `--receipt-mode {write,verify}`,
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
                errors: unreadable_packet_errors(&bytes),
            });
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

/// Errors for input that is not a JSON authority packet. Legacy Markdown is
/// only accepted by the explicit `--packet-type legacy` CLI path below.
fn unreadable_packet_errors(_bytes: &[u8]) -> Vec<String> {
    vec!["packet unreadable".to_string()]
}

// ---------------------------------------------------------------------------
// Legacy Markdown tasklist timing checks.
//
// Port of the timing checks in `skills/tasklist/engine/validate-tasklist-legacy.py`
// (`validate()`): per-task time span and basis checks, the clock-gap and
// total-minutes timeline checks, the lines-per-minute plausibility checks, and
// the parallelizable-flag checks against span overlap. Thresholds, labels and
// messages are the Python source's own.
// ---------------------------------------------------------------------------

/// Python `TASK_RE` base pattern: `### Task N — name` heading.
const LEGACY_TASK_PATTERN: &str = r"(?m)^### Task (\d+) — (.+)$";
/// Python `TIME_SPAN_RE`: elapsed-clock span from minute 0.
const LEGACY_TIME_SPAN_PATTERN: &str = r"^minute\s+(\d+)-(\d+)\s*(?:\(.*\))?$";
/// Python `BASIS_PART_RE`: one `label=minutes` activity.
const LEGACY_BASIS_PART_PATTERN: &str = r"^([A-Za-z][A-Za-z _-]*)=(\d+(?:\.\d+)?)$";
/// Python `BANNED_BASIS_LABELS`: labels that hide work rather than describe it.
const LEGACY_BANNED_BASIS_LABELS: [&str; 8] = [
    "overhead",
    "buffer",
    "contingency",
    "misc",
    "miscellaneous",
    "padding",
    "slack",
    "other",
];
/// Python `CODE_BASIS_LABELS`: labels counted as code generation.
const LEGACY_CODE_BASIS_LABELS: [&str; 6] = [
    "code",
    "coding",
    "codegen",
    "write",
    "implement",
    "implementation",
];

fn compile_pattern(pattern: &str) -> Option<regex::Regex> {
    regex::Regex::new(pattern).ok()
}

/// True when `text` uses the legacy Markdown tasklist format, detected by at
/// least one `### Task N — name` heading. The current format is a JSON
/// authority packet and never matches.
pub fn is_legacy_tasklist(text: &str) -> bool {
    compile_pattern(LEGACY_TASK_PATTERN).is_some_and(|re| re.is_match(text))
}

/// One legacy task block, holding only the fields the timing checks read.
struct LegacyTask {
    time_span: String,
    basis: String,
    parallelizable: String,
}

/// Port of Python `field(text, label)`: the trimmed value of a
/// `- **Label:** value` line, or empty when absent.
fn legacy_field(text: &str, label: &str) -> String {
    let pattern = format!(r"(?m)^- \*\*{}:\*\* (.+)$", regex::escape(label));
    compile_pattern(&pattern)
        .and_then(|re| re.captures(text))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

/// Port of Python `marker(value, prefix)`.
fn legacy_marker(value: &str, prefix: &str) -> String {
    value
        .strip_prefix(prefix)
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default()
}

/// Port of Python `parse_tasks`: each block runs from its heading to the next
/// task heading, or to `\n## 4.` (or end of text) for the last task.
fn parse_legacy_tasks(text: &str) -> Vec<LegacyTask> {
    let Some(re) = compile_pattern(LEGACY_TASK_PATTERN) else {
        return Vec::new();
    };
    let heads: Vec<regex::Captures<'_>> = re.captures_iter(text).collect();
    let mut tasks = Vec::with_capacity(heads.len());
    for (index, head) in heads.iter().enumerate() {
        let Some(whole) = head.get(0) else {
            continue;
        };
        let end = match heads.get(index + 1).and_then(|next| next.get(0)) {
            Some(next) => next.start(),
            None => text[whole.end()..]
                .find("\n## 4.")
                .map(|offset| whole.end() + offset)
                .unwrap_or(text.len()),
        };
        let block = &text[whole.start()..end];
        tasks.push(LegacyTask {
            time_span: legacy_field(block, "Time span"),
            basis: legacy_field(block, "Basis"),
            parallelizable: legacy_field(block, "Parallelizable"),
        });
    }
    tasks
}

/// Python `str.isdigit()` followed by `int(...)`: plain ASCII digits that fit
/// in an `i64`. Returns `None` for anything else.
fn parse_digits(raw: &str) -> Option<i64> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<i64>().ok()
}

/// Python `repr(float)` for the values these messages print (`12.0`, `7.5`).
fn py_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        format!("{value}")
    }
}

/// Python `repr(str)` for the short ASCII labels these messages print.
fn py_repr(value: &str) -> String {
    format!("'{value}'")
}

/// Port of the Markdown timing checks in `validate-tasklist-legacy.py`.
///
/// Returns `None` when `text` is not the legacy format, so the current JSON
/// format is never affected. For legacy input it returns the defects in the
/// Python source's order (per-task checks, then lines and rate, then total
/// minutes, clock gaps and parallel-lane overlap).
///
/// Difference from the Python source: spans and parallel flags are keyed by
/// task number, not by GoalRoute step id. This helper validates timing only;
/// the explicit legacy CLI path also delegates to the existing legacy
/// dispatch validator for its other checks.
pub fn legacy_tasklist_timing_errors(text: &str) -> Option<Vec<String>> {
    if !is_legacy_tasklist(text) {
        return None;
    }
    let tasks = parse_legacy_tasks(text);
    let mut errors: Vec<String> = Vec::new();
    // (task label, start, end) in task order, for spans that match the format.
    let mut spans: Vec<(String, i64, i64)> = Vec::new();
    // (task label, parallel flag) for flags that are exactly yes or no.
    let mut parallel: Vec<(String, bool)> = Vec::new();
    let mut code_basis_minutes = 0.0_f64;
    let time_span_re = compile_pattern(LEGACY_TIME_SPAN_PATTERN);
    let basis_part_re = compile_pattern(LEGACY_BASIS_PART_PATTERN);

    for (index, task) in tasks.iter().enumerate() {
        let n = index + 1;
        let span: Option<(i64, i64)> = time_span_re
            .as_ref()
            .and_then(|re| re.captures(task.time_span.trim()))
            .and_then(|caps| {
                let start = caps.get(1)?.as_str().parse::<i64>().ok()?;
                let end = caps.get(2)?.as_str().parse::<i64>().ok()?;
                Some((start, end))
            });
        match span {
            None => errors.push(format!(
                "Task {n} time span must be an elapsed-clock span from minute 0, formatted as \"minute START-END\" (not a duration, not a low/high range)"
            )),
            Some((start, end)) => {
                if end <= start {
                    errors.push(format!("Task {n} time span must end after it starts"));
                }
                spans.push((n.to_string(), start, end));
            }
        }

        let parts: Vec<&str> = task
            .basis
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            errors.push(format!("Task {n} must name what its minutes are spent on"));
        }
        let mut basis_total = 0.0_f64;
        for part in &parts {
            let Some(caps) = basis_part_re.as_ref().and_then(|re| re.captures(part)) else {
                errors.push(format!(
                    "Task {n} basis part {} must be formatted as label=minutes",
                    py_repr(part)
                ));
                continue;
            };
            let label = caps
                .get(1)
                .map(|m| m.as_str().trim().to_lowercase())
                .unwrap_or_default();
            let minutes: f64 = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<f64>().ok())
                .unwrap_or(0.0);
            if LEGACY_BANNED_BASIS_LABELS.contains(&label.as_str()) {
                errors.push(format!(
                    "Task {n} basis label {} is a generic bucket; name the actual activity (inspect, compile, test, deploy, smoke, report)",
                    py_repr(&label)
                ));
            }
            basis_total += minutes;
            if LEGACY_CODE_BASIS_LABELS.contains(&label.as_str()) {
                code_basis_minutes += minutes;
            }
        }
        if let Some((start, end)) = span {
            if !parts.is_empty() {
                let span_length = end - start;
                if (basis_total - span_length as f64).abs() > 0.5 {
                    errors.push(format!(
                        "Task {n} named minutes sum to {basis_total} but its span is {span_length} minutes long"
                    ));
                }
            }
        }

        match task.parallelizable.trim().to_lowercase().as_str() {
            "yes" => parallel.push((n.to_string(), true)),
            "no" => parallel.push((n.to_string(), false)),
            _ => errors.push(format!("Task {n} parallelizable must be yes or no")),
        }
    }

    // Document-level lines-per-minute and code-minute plausibility.
    let files_raw = legacy_marker(&legacy_field(text, "Files touched"), "FILES_TOUCHED:");
    let lines_raw = legacy_marker(&legacy_field(text, "Lines changed"), "LINES_CHANGED:");
    let rate_raw = legacy_marker(&legacy_field(text, "Rate"), "LINES_PER_MINUTE:");
    match parse_digits(&files_raw) {
        Some(files) if files >= 1 => {}
        _ => errors.push("Files touched must be a positive integer".to_string()),
    }
    match parse_digits(&lines_raw) {
        Some(lines) if lines >= 1 => {}
        _ => errors.push("Lines changed must be a positive integer".to_string()),
    }
    let rate = rate_raw.parse::<f64>().unwrap_or(0.0);
    if rate <= 0.0 {
        errors.push("Lines per minute must be a positive number".to_string());
    } else if rate < 10.0 {
        // Measured reality: an agent emits tens of lines per minute. A low rate is how a plan
        // smuggles inspection and verification time into "typing" and inflates the total.
        errors.push(format!(
            "Lines per minute ({}) is implausibly slow for code generation; bill inspection, compile, and test time as named parts instead",
            py_float(rate)
        ));
    }
    // Declared code-generation minutes must follow from lines and rate.
    if let Some(lines) = parse_digits(&lines_raw) {
        if rate > 0.0 {
            let expected_code_minutes = lines as f64 / rate;
            if code_basis_minutes != 0.0
                && (code_basis_minutes - expected_code_minutes).abs()
                    > f64::max(2.0, 0.5 * expected_code_minutes)
            {
                errors.push(format!(
                    "Declared code minutes ({code_basis_minutes}) do not follow from {lines_raw} lines / {} per minute (~{:.0})",
                    py_float(rate),
                    expected_code_minutes
                ));
            }
        }
    }

    // Timeline: total minutes, first start, clock gaps, and parallel-lane overlap.
    let total_raw = legacy_marker(&legacy_field(text, "Total minutes"), "TOTAL_MINUTES:");
    match parse_digits(&total_raw) {
        Some(total) if total >= 1 => {
            if !spans.is_empty() {
                let mut sorted: Vec<(i64, i64)> =
                    spans.iter().map(|(_, start, end)| (*start, *end)).collect();
                sorted.sort();
                if let Some(&(first_start, _)) = sorted.first() {
                    if first_start != 0 {
                        errors.push(format!(
                            "First step must start at minute 0, found {first_start}"
                        ));
                    }
                }
                let finish = spans.iter().map(|(_, _, end)| *end).max().unwrap_or(0);
                if total != finish {
                    errors.push(format!(
                        "Total minutes ({total}) must equal the last minute any step is still running ({finish})"
                    ));
                }
                let mut covered_to = 0_i64;
                for (start, end) in &sorted {
                    if *start > covered_to {
                        errors.push(format!(
                            "Clock gap: nothing runs between minute {covered_to} and {start}"
                        ));
                        break;
                    }
                    covered_to = covered_to.max(*end);
                }
                for (label, start, end) in &spans {
                    let overlaps = spans.iter().any(|(other, other_start, other_end)| {
                        other != label && *start < *other_end && *other_start < *end
                    });
                    let flag = parallel
                        .iter()
                        .find(|(name, _)| name == label)
                        .map(|(_, flag)| *flag);
                    if flag == Some(true) && !overlaps {
                        errors.push(format!(
                            "Step {label} is flagged parallelizable but its span overlaps no other step"
                        ));
                    }
                    if flag == Some(false) && overlaps {
                        errors.push(format!(
                            "Step {label} is flagged serial but its span overlaps another step"
                        ));
                    }
                }
            }
        }
        _ => errors.push("Total minutes must be a positive integer".to_string()),
    }

    Some(errors)
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
                let v = args
                    .get(i)
                    .ok_or("argument --packet-type: expected one argument")?;
                if v != "authority" && v != "worker" && v != "legacy" {
                    return Err(format!(
                        "argument --packet-type: invalid choice: '{v}' (choose from 'authority', 'worker', 'legacy')"
                    ));
                }
                packet_type = v.clone();
            }
            "--receipt-mode" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("argument --receipt-mode: expected one argument")?;
                if v != "write" && v != "verify" {
                    return Err(format!(
                        "argument --receipt-mode: invalid choice: '{v}' (choose from 'write', 'verify')"
                    ));
                }
                receipt_mode = v.clone();
            }
            "--receipt-dir" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("argument --receipt-dir: expected one argument")?;
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
            };
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();

    for packet in &parsed.packets {
        let packet = resolve_path(packet);
        if !packet.is_file() {
            stderr.push_str(&format!(
                "FAIL: packet file not found: {}\n",
                packet.display()
            ));
            return CliOutcome {
                code: 2,
                stdout,
                stderr,
            };
        }
        if parsed.packet_type == "legacy" {
            let text = match std::fs::read_to_string(&packet) {
                Ok(text) => text,
                Err(err) => {
                    return CliOutcome {
                        code: 1,
                        stdout: format!("FAIL: legacy tasklist is not readable UTF-8: {err}\n"),
                        stderr,
                    };
                }
            };
            let errors = match legacy_tasklist_timing_errors(&text) {
                Some(errors) => errors,
                None => {
                    return CliOutcome {
                        code: 1,
                        stdout: "FAIL: legacy tasklist format was not detected\n".to_string(),
                        stderr,
                    };
                }
            };
            if !errors.is_empty() {
                let mut output = format!(
                    "FAIL: legacy tasklist timing validation found {} defect(s)\n",
                    errors.len()
                );
                for error in errors {
                    output.push_str(&format!("- {error}\n"));
                }
                return CliOutcome {
                    code: 1,
                    stdout: output,
                    stderr,
                };
            }
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
                return CliOutcome {
                    code: 2,
                    stdout,
                    stderr,
                };
            }
        };
        stdout.push_str(&output.stdout);
        stderr.push_str(&output.stderr);
        if output.code != 0 {
            return CliOutcome {
                code: output.code,
                stdout,
                stderr,
            };
        }
    }

    CliOutcome {
        code: 0,
        stdout,
        stderr,
    }
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
            self.calls
                .borrow_mut()
                .push((program.to_string(), args.to_vec()));
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

    fn legacy_fixture(tasks: &[(&str, &str, &str)], total: &str) -> String {
        let mut text = String::from(
            "# Tasklist\n- **Files touched:** FILES_TOUCHED:2\n- **Lines changed:** LINES_CHANGED:120\n- **Rate:** LINES_PER_MINUTE:12\n",
        );
        text.push_str(&format!("- **Total minutes:** TOTAL_MINUTES:{total}\n\n"));
        for (index, (span, basis, parallel)) in tasks.iter().enumerate() {
            text.push_str(&format!(
                "### Task {} — step {}\n- **Time span:** {span}\n- **Basis:** {basis}\n- **Parallelizable:** {parallel}\n\n",
                index + 1,
                index + 1
            ));
        }
        text.push_str("## 4. Recovery & TRUE_BLOCKER\n");
        text
    }

    fn run_legacy_cli(text: &str, tag: &str, runner: &FakeRunner) -> CliOutcome {
        let dir = tmp_dir(tag);
        let packet = dir.join("legacy.md");
        std::fs::write(&packet, text).unwrap();
        run_cli(
            &[
                packet.to_string_lossy().into_owned(),
                "--packet-type".to_string(),
                "legacy".to_string(),
            ],
            "python3",
            Path::new("/opt/legion/validate-dispatch.py"),
            runner,
        )
    }

    #[test]
    fn explicit_legacy_rejects_clock_gap_before_dispatch() {
        let text = legacy_fixture(
            &[
                ("minute 0-5", "compile=5", "no"),
                ("minute 7-10", "test=3", "no"),
            ],
            "10",
        );
        let runner = FakeRunner::new(vec![]);
        let outcome = run_legacy_cli(&text, "legacy-gap", &runner);
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("Clock gap: nothing runs between minute 5 and 7"));
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn explicit_legacy_rejects_unrecognized_format_before_dispatch() {
        let runner = FakeRunner::new(vec![]);
        let outcome = run_legacy_cli("# no task headings\n", "legacy-unrecognized", &runner);
        assert_eq!(outcome.code, 1);
        assert_eq!(
            outcome.stdout,
            "FAIL: legacy tasklist format was not detected\n"
        );
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn explicit_legacy_rejects_serial_lane_overlap_before_dispatch() {
        let text = legacy_fixture(
            &[
                ("minute 0-10", "compile=10", "no"),
                ("minute 5-10", "test=5", "no"),
            ],
            "10",
        );
        let runner = FakeRunner::new(vec![]);
        let outcome = run_legacy_cli(&text, "legacy-overlap", &runner);
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("flagged serial but its span overlaps"));
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn explicit_legacy_accepts_parallel_lanes_then_delegates_legacy_checks() {
        let text = legacy_fixture(
            &[
                ("minute 0-10", "compile=10", "yes"),
                ("minute 5-10", "test=5", "yes"),
            ],
            "10",
        );
        let runner = FakeRunner::new(vec![ProcessOutput {
            stdout: "legacy dispatch checked\n".to_string(),
            stderr: String::new(),
            code: 0,
        }]);
        let outcome = run_legacy_cli(&text, "legacy-parallel", &runner);
        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.stdout, "legacy dispatch checked\n");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1.contains(&"legacy".to_string()));
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

#[cfg(test)]
mod legacy_timing_tests {
    use super::*;

    /// Builds a legacy Markdown tasklist: `tasks` is (time span, basis,
    /// parallelizable) per task, and the document-level fields are passed in
    /// raw so each test can break exactly one of them.
    fn legacy_doc(
        tasks: &[(&str, &str, &str)],
        files: &str,
        lines: &str,
        rate: &str,
        total: &str,
    ) -> String {
        let mut text = String::from("# Tasklist\n");
        text.push_str(&format!("- **Files touched:** FILES_TOUCHED:{files}\n"));
        text.push_str(&format!("- **Lines changed:** LINES_CHANGED:{lines}\n"));
        text.push_str(&format!("- **Rate:** LINES_PER_MINUTE:{rate}\n"));
        text.push_str(&format!("- **Total minutes:** TOTAL_MINUTES:{total}\n\n"));
        for (index, (span, basis, parallel)) in tasks.iter().enumerate() {
            let n = index + 1;
            text.push_str(&format!(
                "### Task {n} — step {n}\n- **Time span:** {span}\n- **Basis:** {basis}\n- **Parallelizable:** {parallel}\n\n"
            ));
        }
        text.push_str("## 4. Recovery & TRUE_BLOCKER\n");
        text
    }

    /// Runs the timing checks, failing the test if the text is not detected as legacy.
    fn errors_of(text: &str) -> Vec<String> {
        legacy_tasklist_timing_errors(text)
            .unwrap_or_else(|| panic!("text was not detected as the legacy format"))
    }

    fn has(errors: &[String], needle: &str) -> bool {
        errors.iter().any(|e| e.contains(needle))
    }

    #[test]
    fn valid_legacy_document_has_no_timing_errors() {
        let text = legacy_doc(
            &[
                ("minute 0-5", "compile=5", "no"),
                ("minute 5-15", "code=10", "no"),
            ],
            "2",
            "120",
            "12",
            "15",
        );
        assert_eq!(errors_of(&text), Vec::<String>::new());
    }

    #[test]
    fn current_json_format_is_not_legacy() {
        assert!(!is_legacy_tasklist("{\"schema\":1}"));
        assert!(legacy_tasklist_timing_errors("{\"schema\":1}").is_none());
    }

    #[test]
    fn time_span_must_use_elapsed_clock_format() {
        let text = legacy_doc(
            &[("minute 0 to 5", "compile=5", "no")],
            "2",
            "120",
            "12",
            "5",
        );
        let errors = errors_of(&text);
        assert!(has(
            &errors,
            "Task 1 time span must be an elapsed-clock span from minute 0"
        ));
    }

    #[test]
    fn time_span_must_end_after_it_starts() {
        let text = legacy_doc(&[("minute 5-5", "compile=0", "no")], "2", "120", "12", "5");
        assert!(has(
            &errors_of(&text),
            "Task 1 time span must end after it starts"
        ));
    }

    #[test]
    fn clock_gap_between_steps_is_reported() {
        let text = legacy_doc(
            &[
                ("minute 0-5", "compile=5", "no"),
                ("minute 7-10", "test=3", "no"),
            ],
            "2",
            "120",
            "12",
            "10",
        );
        assert!(has(
            &errors_of(&text),
            "Clock gap: nothing runs between minute 5 and 7"
        ));
    }

    #[test]
    fn first_step_must_start_at_minute_zero() {
        let text = legacy_doc(&[("minute 2-10", "test=8", "no")], "2", "120", "12", "10");
        assert!(has(
            &errors_of(&text),
            "First step must start at minute 0, found 2"
        ));
    }

    #[test]
    fn total_minutes_must_equal_last_running_minute() {
        let text = legacy_doc(&[("minute 0-10", "test=10", "no")], "2", "120", "12", "12");
        assert!(has(
            &errors_of(&text),
            "Total minutes (12) must equal the last minute any step is still running (10)"
        ));
    }

    #[test]
    fn named_minutes_must_sum_to_span_length() {
        let text = legacy_doc(&[("minute 0-5", "compile=3", "no")], "2", "120", "12", "5");
        assert!(has(
            &errors_of(&text),
            "Task 1 named minutes sum to 3 but its span is 5 minutes long"
        ));
    }

    #[test]
    fn generic_basis_label_is_rejected() {
        let text = legacy_doc(&[("minute 0-5", "overhead=5", "no")], "2", "120", "12", "5");
        assert!(has(
            &errors_of(&text),
            "Task 1 basis label 'overhead' is a generic bucket"
        ));
    }

    #[test]
    fn basis_part_must_be_label_equals_minutes() {
        let text = legacy_doc(&[("minute 0-5", "compile", "no")], "2", "120", "12", "5");
        assert!(has(
            &errors_of(&text),
            "Task 1 basis part 'compile' must be formatted as label=minutes"
        ));
    }

    #[test]
    fn implausibly_slow_rate_is_reported() {
        let text = legacy_doc(&[("minute 0-24", "code=24", "no")], "2", "120", "5", "24");
        assert!(has(
            &errors_of(&text),
            "Lines per minute (5.0) is implausibly slow for code generation"
        ));
    }

    #[test]
    fn non_positive_rate_is_reported() {
        let text = legacy_doc(&[("minute 0-5", "compile=5", "no")], "2", "120", "0", "5");
        assert!(has(
            &errors_of(&text),
            "Lines per minute must be a positive number"
        ));
    }

    #[test]
    fn declared_code_minutes_must_follow_from_lines_and_rate() {
        // 120 lines at 12 per minute is about 10 minutes; 20 declared is outside tolerance.
        let text = legacy_doc(&[("minute 0-20", "code=20", "no")], "2", "120", "12", "20");
        assert!(has(
            &errors_of(&text),
            "Declared code minutes (20) do not follow from 120 lines / 12.0 per minute (~10)"
        ));
    }

    #[test]
    fn zero_lines_changed_is_reported() {
        let text = legacy_doc(&[("minute 0-5", "compile=5", "no")], "2", "0", "12", "5");
        assert!(has(
            &errors_of(&text),
            "Lines changed must be a positive integer"
        ));
    }

    #[test]
    fn parallel_flag_without_overlap_is_reported() {
        let text = legacy_doc(
            &[
                ("minute 0-5", "compile=5", "yes"),
                ("minute 5-10", "test=5", "no"),
            ],
            "2",
            "120",
            "12",
            "10",
        );
        assert!(has(
            &errors_of(&text),
            "Step 1 is flagged parallelizable but its span overlaps no other step"
        ));
    }

    #[test]
    fn serial_flag_with_overlap_is_reported() {
        let text = legacy_doc(
            &[
                ("minute 0-10", "compile=10", "no"),
                ("minute 5-10", "test=5", "no"),
            ],
            "2",
            "120",
            "12",
            "10",
        );
        let errors = errors_of(&text);
        assert!(has(
            &errors,
            "Step 1 is flagged serial but its span overlaps another step"
        ));
        assert!(has(
            &errors,
            "Step 2 is flagged serial but its span overlaps another step"
        ));
    }

    #[test]
    fn parallel_flags_that_overlap_are_accepted() {
        let text = legacy_doc(
            &[
                ("minute 0-10", "compile=10", "yes"),
                ("minute 5-10", "test=5", "yes"),
            ],
            "2",
            "120",
            "12",
            "10",
        );
        let errors = errors_of(&text);
        assert!(!has(&errors, "parallelizable but"));
        assert!(!has(&errors, "flagged serial"));
    }

    #[test]
    fn parallelizable_must_be_yes_or_no() {
        let text = legacy_doc(
            &[("minute 0-5", "compile=5", "maybe")],
            "2",
            "120",
            "12",
            "5",
        );
        assert!(has(
            &errors_of(&text),
            "Task 1 parallelizable must be yes or no"
        ));
    }

    #[test]
    fn unreadable_legacy_packet_is_not_authority_json() {
        let text = legacy_doc(&[("minute 0-5", "compile=3", "no")], "2", "120", "12", "5");
        let errors = unreadable_packet_errors(text.as_bytes());
        assert_eq!(errors, vec!["packet unreadable"]);
    }

    #[test]
    fn non_legacy_unreadable_input_keeps_original_error() {
        assert_eq!(
            unreadable_packet_errors(b"not a packet at all"),
            vec!["packet unreadable".to_string()]
        );
    }

    #[test]
    fn legacy_markdown_is_rejected_by_authority_receipt_helper() {
        let dir = std::env::temp_dir().join(format!("w2-044-legacy-timing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.tasklist.md");
        let text = legacy_doc(
            &[
                ("minute 0-5", "compile=5", "no"),
                ("minute 5-15", "code=10", "no"),
            ],
            "2",
            "120",
            "12",
            "15",
        );
        std::fs::write(&path, text.as_bytes()).unwrap();
        let result = validate_and_write_receipt(&path, None).unwrap();
        match result {
            TasklistResult::Fail { errors } => assert_eq!(errors, vec!["packet unreadable"]),
            TasklistResult::Pass { .. } => panic!("Markdown must not pass as authority JSON"),
        }
        assert!(!dir.join("legacy.tasklist.receipt.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
