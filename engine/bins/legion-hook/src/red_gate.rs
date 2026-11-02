//! After a failed build, load the debugger before the next run (fix plan B2).
//! Check id `red-gate`, PreToolUse of a shell tool.
//!
//! The evidence ledger (`<state>/evidence/<session>.jsonl`, one row per tool
//! result, written by `evidence`) says whether the newest qualification run
//! failed. A qualification-class command is
//!
//! - `rightkit-gate` / `rightkit-host-gate` other than `check` (and `help`,
//!   `status`, `--help` and similar non-runs);
//! - `gh run watch ... --exit-status`, `gh run rerun`, `gh workflow run`;
//! - not `rustright cargo build|test|clippy|check`: iterative compile errors while
//!   editing do not count (fix plan B2).
//!
//! A row counts as failed when the command failed (non-zero exit or a failure
//! event), or when it was piped (the pipe hides the exit code) and its output
//! shows a failure. A `gh run view --json ... conclusion` row whose output says
//! `failure` or `timed_out` also counts as a failed run, and `success` as a
//! passed one. Only the newest such row matters, so a passing run resets the
//! check. Human turns do not reset it; a failure older than 24 hours is
//! ignored.
//!
//! While the newest result is a failure and the lead's transcript shows no
//! `Skill` call (or typed `/command`) for `legion:debugger` timestamped after
//! that row, the next qualification-class command and the next `git push` are
//! denied (`ARC_DEBUGGER_FIRST`). A rejected push, a failed `check` and every
//! other command do not count.
//!
//! Fail open: no ledger, no failing row, no readable transcript, a debugger
//! load whose transcript line has no timestamp (it cannot be ordered), a Codex
//! frame (it has no Skill tool) or a subagent frame (its Skill calls are not in
//! the lead's transcript) allows the call. `LEGION_HOOK_OFF` naming `red-gate`
//! disables the check.
//!
//! The `Skill` tool is not in the PreToolUse or PostToolUse matcher of
//! `hooks/hooks.json`, which is why the debugger load is read from the
//! transcript rather than observed here.

use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::protocol::{HookRequest, HookResponse};
use crate::skills_gate::{
    agent_id, check_disabled, now_secs, session_id, skill_arg_matches, state_root, str_field,
    tool_input, tool_name,
};
use crate::words::{
    command_strings, program_name, shell_script, shell_segments, strip_wrappers, SHELL_TOOLS,
};

pub const CHECK: &str = "red-gate";
pub const CODE: &str = "ARC_DEBUGGER_FIRST";
const MESSAGE: &str = "Last build/CI run failed. Load legion:debugger and state the root cause in one line, then rerun.";

const DEBUGGER_SKILL: &str = "legion:debugger";
const EVIDENCE_FOLDER: &str = "evidence";
const FAILURE_TTL_SECS: u64 = 24 * 3600;
const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TRANSCRIPT_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SHELL_DEPTH: u8 = 3;

/// First argument of a gate run that is not a build or package run.
const GATE_NON_RUNS: [&str; 8] = [
    "check",
    "help",
    "status",
    "version",
    "doctor",
    "list",
    "inventory",
    "explain",
];

/// `rustright cargo <sub>` subcommands that count as a build run.
// Iterative compile and test errors while editing do not count as a red run
// (fix plan B2); only gate, package and CI runs do.
const CARGO_SUBCOMMANDS: [&str; 0] = [];

// ---------------------------------------------------------------------------
// Command classes (pure)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Class {
    /// A build, package or CI run.
    qualification: bool,
    /// A `git push` (it triggers CI).
    ci_push: bool,
    /// `gh run view --json ... conclusion` (reads a CI result).
    conclusion_view: bool,
}

impl Class {
    fn merge(&mut self, other: Class) {
        self.qualification |= other.qualification;
        self.ci_push |= other.ci_push;
        self.conclusion_view |= other.conclusion_view;
    }
}

fn gate_runs(args: &[String]) -> bool {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h" | "--version" | "-V"))
    {
        return false;
    }
    match args.iter().find(|arg| !arg.starts_with('-')) {
        Some(first) => !GATE_NON_RUNS.contains(&first.as_str()),
        None => !args.is_empty(),
    }
}

fn rustright_cargo(args: &[String]) -> bool {
    let positional: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| !arg.starts_with('-') && !arg.starts_with('+'))
        .collect();
    positional.first() == Some(&"cargo")
        && positional
            .get(1)
            .is_some_and(|sub| CARGO_SUBCOMMANDS.contains(sub))
}

fn gh_class(args: &[String]) -> Class {
    let mut positional: Vec<&str> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if matches!(arg.as_str(), "-R" | "--repo" | "--hostname") {
            iter.next();
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        positional.push(arg.as_str());
        if positional.len() == 2 {
            break;
        }
    }
    let mut class = Class::default();
    match positional.as_slice() {
        ["run", "watch"] => {
            class.qualification = args.iter().any(|arg| arg == "--exit-status");
        }
        ["run", "rerun"] | ["workflow", "run"] => class.qualification = true,
        ["run", "view"] => {
            class.conclusion_view = args.iter().any(|arg| arg.starts_with("--json"))
                && args.iter().any(|arg| arg.contains("conclusion"));
        }
        _ => {}
    }
    class
}

/// `git [global flags] push ...`, except a dry run or a branch delete.
fn git_push(args: &[String]) -> bool {
    let mut iter = args.iter();
    let mut subcommand: Option<&str> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" => {
                iter.next();
            }
            flag if flag.starts_with('-') => {}
            word => {
                subcommand = Some(word);
                break;
            }
        }
    }
    if subcommand != Some("push") {
        return false;
    }
    !iter.any(|arg| matches!(arg.as_str(), "--dry-run" | "-n" | "--delete" | "-d"))
}

/// Which classes `command` belongs to (any segment, nested shells included).
fn classify(command: &str, depth: u8) -> Class {
    let mut class = Class::default();
    for segment in shell_segments(command) {
        let words = strip_wrappers(&segment.words);
        let Some((program, args)) = words.split_first() else {
            continue;
        };
        match program_name(program).as_str() {
            "rightkit-gate" | "rightkit-host-gate" => {
                if gate_runs(args) {
                    class.qualification = true;
                }
            }
            "rustright" => {
                if rustright_cargo(args) {
                    class.qualification = true;
                }
            }
            "gh" => class.merge(gh_class(args)),
            "git" => {
                if git_push(args) {
                    class.ci_push = true;
                }
            }
            "bash" | "sh" | "zsh" | "dash" | "ksh" => {
                if depth < MAX_SHELL_DEPTH {
                    if let Some(script) = shell_script(args) {
                        class.merge(classify(script, depth + 1));
                    }
                }
            }
            _ => {}
        }
    }
    class
}

/// Would this command be denied while the last run is red?
fn gated(command: &str) -> bool {
    let class = classify(command, 0);
    class.qualification || class.ci_push
}

// ---------------------------------------------------------------------------
// The evidence ledger
// ---------------------------------------------------------------------------

struct Row {
    t: u64,
    tool: String,
    command: String,
    failed: bool,
    failure_seen: bool,
    tail: String,
}

/// One ledger line as a row. Turn markers, rows without a command and garbage
/// are `None`.
fn parse_row(line: &str) -> Option<Row> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let object = value.as_object()?;
    if object.contains_key("marker") {
        return None;
    }
    Some(Row {
        t: object.get("t")?.as_u64()?,
        tool: object.get("tool")?.as_str()?.to_owned(),
        command: object.get("command")?.as_str()?.to_owned(),
        failed: object
            .get("failed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        failure_seen: object
            .get("failure_seen")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        tail: object
            .get("tail")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Failed,
    Passed,
}

const FAILED_CONCLUSIONS: [&str; 3] = [
    "\"conclusion\":\"failure\"",
    "\"conclusion\":\"timed_out\"",
    "\"conclusion\":\"startup_failure\"",
];

/// The run result a row records, or `None` when the row is not a run result.
fn row_outcome(row: &Row) -> Option<Outcome> {
    if !SHELL_TOOLS.contains(&row.tool.as_str()) {
        return None;
    }
    let class = classify(&row.command, 0);
    if class.qualification {
        // A pipe (`| tail`) hides the exit code, so trust the output then.
        let masked = row.command.contains('|') && row.failure_seen;
        return Some(if row.failed || masked {
            Outcome::Failed
        } else {
            Outcome::Passed
        });
    }
    if class.conclusion_view {
        let compact: String = row.tail.chars().filter(|c| !c.is_whitespace()).collect();
        if FAILED_CONCLUSIONS
            .iter()
            .any(|marker| compact.contains(marker))
        {
            return Some(Outcome::Failed);
        }
        if compact.contains("\"conclusion\":\"success\"") {
            return Some(Outcome::Passed);
        }
    }
    None
}

/// When the newest run result failed: that row's time (epoch seconds).
fn failing_row_time(ledger: &str, now: u64) -> Option<u64> {
    for line in ledger.lines().rev() {
        if !line.contains("\"command\":\"") {
            continue;
        }
        let Some(row) = parse_row(line) else {
            continue;
        };
        match row_outcome(&row) {
            Some(Outcome::Failed) => {
                return if now.saturating_sub(row.t) <= FAILURE_TTL_SECS {
                    Some(row.t)
                } else {
                    None
                };
            }
            Some(Outcome::Passed) => return None,
            None => {}
        }
    }
    None
}

/// Same name mapping as the evidence ledger writer.
fn safe_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect()
}

fn read_ledger(root: &Path, session: &str) -> Option<String> {
    let path = root
        .join(EVIDENCE_FOLDER)
        .join(format!("{}.jsonl", safe_name(session)));
    if fs::metadata(&path).ok()?.len() > MAX_LEDGER_BYTES {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------------------
// The transcript: was the debugger loaded after the failure?
// ---------------------------------------------------------------------------

/// Day count since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-02T10:00:00(.123)(Z|+hh:mm)` as epoch seconds.
fn parse_iso_secs(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse().ok() };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = text.get(19..)?;
    if let Some(fraction) = rest.strip_prefix('.') {
        rest = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest.chars().next() {
        Some(sign @ ('+' | '-')) => {
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest
                .get(4..6)
                .and_then(|part| part.parse().ok())
                .unwrap_or(0);
            let value = hours * 3600 + minutes * 60;
            if sign == '+' {
                value
            } else {
                -value
            }
        }
        _ => 0,
    };
    let secs =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(secs).ok()
}

fn line_timestamp(value: &Value) -> Option<u64> {
    match value.get("timestamp")? {
        Value::String(text) => parse_iso_secs(text),
        Value::Number(number) => {
            let n = number.as_u64()?;
            Some(if n > 100_000_000_000 { n / 1000 } else { n })
        }
        _ => None,
    }
}

/// `<command-name>/legion:debugger</command-name>` in a typed slash command.
fn names_debugger_command(text: &str) -> bool {
    const OPEN: &str = "<command-name>";
    const CLOSE: &str = "</command-name>";
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else {
            break;
        };
        if skill_arg_matches(DEBUGGER_SKILL, &after[..end]) {
            return true;
        }
        rest = &after[end..];
    }
    false
}

fn item_loads_debugger(item: &Value) -> bool {
    match item.get("type").and_then(Value::as_str) {
        Some("tool_use") => {
            item.get("name").and_then(Value::as_str) == Some("Skill")
                && item
                    .get("input")
                    .and_then(|input| input.get("skill"))
                    .and_then(Value::as_str)
                    .is_some_and(|arg| skill_arg_matches(DEBUGGER_SKILL, arg))
        }
        Some("text") => item
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(names_debugger_command),
        _ => false,
    }
}

fn line_loads_debugger(value: &Value) -> bool {
    match value
        .get("message")
        .and_then(|message| message.get("content"))
    {
        Some(Value::Array(items)) => items.iter().any(item_loads_debugger),
        Some(Value::String(text)) => names_debugger_command(text),
        _ => false,
    }
}

/// Does the transcript hold a `legion:debugger` load timestamped after
/// `after`? `None` when it cannot be read or is too large to scan.
fn debugger_loaded_after(path: &Path, after: u64) -> Option<bool> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_TRANSCRIPT_SCAN_BYTES {
        return None;
    }
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer).ok()? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buffer);
        if !line.contains("debugger")
            || !(line.contains("\"Skill\"") || line.contains("<command-name>"))
        {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if !line_loads_debugger(&value) {
            continue;
        }
        match line_timestamp(&value) {
            Some(t) if t > after => return Some(true),
            Some(_) => {}
            // A load that cannot be placed in time: do not guess, allow.
            None => return None,
        }
    }
    Some(false)
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// True when the last run is red and the debugger was not loaded since.
/// Anything unreadable is "no".
fn should_deny(root: &Path, session: &str, transcript: Option<&Path>, now: u64) -> bool {
    let Some(ledger) = read_ledger(root, session) else {
        return false;
    };
    let Some(failed_at) = failing_row_time(&ledger, now) else {
        return false;
    };
    let Some(transcript) = transcript else {
        return false;
    };
    debugger_loaded_after(transcript, failed_at) == Some(false)
}

/// PreToolUse of a shell tool: deny the next qualification-class command or
/// `git push` after a failed run until `legion:debugger` is loaded
/// (`ARC_DEBUGGER_FIRST`). Returns `None` to allow.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK) || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    if !SHELL_TOOLS.contains(&tool.as_str()) {
        return None;
    }
    // A subagent's Skill calls are not in the lead's transcript, and Codex has
    // no Skill tool: neither can be asked to load a skill, so neither is gated.
    if agent_id(payload).is_some() || payload.contains_key("turn_id") {
        return None;
    }
    let commands = command_strings(tool_input(payload)?);
    if !commands.iter().any(|command| gated(command)) {
        return None;
    }
    let session = session_id(payload)?;
    let root = state_root()?;
    let transcript = str_field(payload, &["transcript_path", "transcriptPath"]).map(PathBuf::from);
    if !should_deny(&root, &session, transcript.as_deref(), now_secs()) {
        return None;
    }
    Some(HookResponse::denied(
        request.event_type.clone(),
        CODE,
        MESSAGE,
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-red-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, lines: &[String]) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write file");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn iso(text: &str) -> u64 {
        parse_iso_secs(text).expect("valid timestamp")
    }

    fn row(t: u64, command: &str, failed: bool) -> String {
        let exit = if failed { 1 } else { 0 };
        json!({
            "t": t,
            "tool": "Bash",
            "command": command,
            "exit": exit,
            "failed": failed,
            "edit": false,
            "path": null,
            "tail": "",
            "ids": [],
            "success_seen": false,
            "failure_seen": false,
        })
        .to_string()
    }

    fn row_with_output(t: u64, command: &str, tail: &str, failure_seen: bool) -> String {
        json!({
            "t": t,
            "tool": "Bash",
            "command": command,
            "exit": 0,
            "failed": false,
            "tail": tail,
            "failure_seen": failure_seen,
        })
        .to_string()
    }

    fn skill_line(timestamp: &str, skill: &str) -> String {
        json!({
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Skill", "input": {"skill": skill}}
            ]},
        })
        .to_string()
    }

    fn typed_line(timestamp: &str, name: &str) -> String {
        json!({
            "type": "user",
            "timestamp": timestamp,
            "message": {
                "role": "user",
                "content": format!("<command-message>x</command-message>\n<command-name>{name}</command-name>"),
            },
        })
        .to_string()
    }

    fn chat_line(timestamp: &str, text: &str) -> String {
        json!({
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
        })
        .to_string()
    }

    // --- command classes ---

    #[test]
    fn qualification_commands_are_recognised() {
        for command in [
            "rightkit-gate --to dev -- --platform mac",
            "cd repo && rightkit-host-gate --no-broker abc",
            "env FOO=1 rightkit-gate --to dev 2>&1 | tail -n 5",
            "/usr/local/bin/rightkit-gate --to prod",
            "gh run watch 123 --exit-status",
            "gh -R Orthic-Labs/legion run watch 1 --exit-status",
            "gh run rerun 5 --failed",
            "gh workflow run ci.yml",
            "bash -lc 'rightkit-gate --to dev'",
        ] {
            assert!(classify(command, 0).qualification, "{command}");
            assert!(gated(command), "{command}");
        }
    }

    #[test]
    fn other_commands_are_not_qualification_runs() {
        for command in [
            "rightkit-gate check --commit abc --full-a",
            "rightkit-gate --help",
            "rightkit-gate status",
            "rightkit-gate",
            "gh run watch 123",
            "gh run view 1 --log-failed",
            "gh pr list",
            "rustright cargo test -p legion-hook",
            "rustright cargo +1.98.0 clippy --all-targets",
            "rustright cargo build",
            "rustright cargo check",
            "rustright cargo fmt",
            "rustright cargo --version",
            "rustright owns audio",
            "cargo build",
            "git status",
            "echo rightkit-gate",
            "ls",
        ] {
            let class = classify(command, 0);
            assert!(!class.qualification, "{command}");
            assert!(!gated(command), "{command}");
        }
    }

    #[test]
    fn pushes_are_ci_triggers_except_dry_runs_and_deletes() {
        for command in [
            "git push",
            "git push origin main",
            "git -C /r push origin claude/x",
            "git -c core.x=1 push --force-with-lease",
            "cd r && git add -A && git commit -m x && git push",
        ] {
            assert!(classify(command, 0).ci_push, "{command}");
            assert!(gated(command), "{command}");
        }
        for command in [
            "git push --dry-run",
            "git push origin --delete old",
            "git pull",
            "git status push",
        ] {
            assert!(!classify(command, 0).ci_push, "{command}");
        }
    }

    #[test]
    fn conclusion_reads_are_recognised_but_not_gated() {
        let command = "gh run view 12 --json status,conclusion -q .conclusion";
        let class = classify(command, 0);
        assert!(class.conclusion_view);
        assert!(!gated(command));
        assert!(!classify("gh run view 12 --log", 0).conclusion_view);
    }

    // --- the ledger ---

    #[test]
    fn newest_qualification_result_decides() {
        let now = 10_000;
        let red = [row(100, "rightkit-gate --to dev", true)].join("\n");
        assert_eq!(failing_row_time(&red, now), Some(100));

        let reset = [
            row(100, "rightkit-gate --to dev", true),
            row(200, "rightkit-gate --to dev", false),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&reset, now), None);

        let red_again = [
            row(100, "rightkit-gate --to dev", false),
            row(200, "gh run watch 5 --exit-status", true),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&red_again, now), Some(200));
    }

    #[test]
    fn local_checks_pushes_and_other_commands_do_not_count() {
        let now = 10_000;
        let ledger = [
            row(100, "rightkit-gate --to dev", false),
            row(150, "rightkit-gate check --commit abc", true),
            row(160, "git push origin main", true),
            row(170, "cargo test", true),
            row(180, "ls /missing", true),
            row(190, "gh run view 1 --log-failed", true),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&ledger, now), None);
        assert_eq!(failing_row_time("", now), None);
    }

    #[test]
    fn markers_and_garbage_lines_are_skipped() {
        let now = 10_000;
        let ledger = [
            row(100, "rightkit-gate --to dev", true),
            json!({"marker": "turn", "t": 120, "id": "1", "prompt": "go on"}).to_string(),
            "not json".to_owned(),
            json!({"t": 130, "tool": "Edit", "command": null, "failed": false}).to_string(),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&ledger, now), Some(100));
    }

    #[test]
    fn a_piped_run_that_shows_a_failure_counts_and_a_plain_one_does_not() {
        let now = 10_000;
        let piped = row_with_output(
            100,
            "rightkit-gate --to dev 2>&1 | tail -n 20",
            "test result: FAILED",
            true,
        );
        assert_eq!(failing_row_time(&piped, now), Some(100));
        let plain = row_with_output(100, "rightkit-gate --to dev", "1 failed earlier", true);
        assert_eq!(failing_row_time(&plain, now), None);
    }

    #[test]
    fn a_failed_ci_conclusion_counts_and_a_success_resets() {
        let now = 10_000;
        let command = "gh run view 9 --json conclusion";
        let failed = row_with_output(100, command, "{\"conclusion\": \"failure\"}", false);
        assert_eq!(failing_row_time(&failed, now), Some(100));
        let ledger = [
            failed.clone(),
            row_with_output(200, command, "{\"conclusion\":\"success\"}", false),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&ledger, now), None);
        let pending = [
            failed,
            row_with_output(200, command, "{\"conclusion\":\"\"}", false),
        ]
        .join("\n");
        assert_eq!(failing_row_time(&pending, now), Some(100));
    }

    #[test]
    fn an_old_failure_is_ignored() {
        let ledger = row(100, "rightkit-gate --to dev", true);
        assert_eq!(failing_row_time(&ledger, 100 + FAILURE_TTL_SECS), Some(100));
        assert_eq!(failing_row_time(&ledger, 101 + FAILURE_TTL_SECS), None);
    }

    // --- timestamps ---

    #[test]
    fn timestamps_parse_to_epoch_seconds() {
        assert_eq!(iso("2001-09-09T01:46:40Z"), 1_000_000_000);
        assert_eq!(iso("2001-09-09T01:46:40.123Z"), 1_000_000_000);
        assert_eq!(iso("2001-09-09T07:16:40+05:30"), 1_000_000_000);
        assert_eq!(iso("2001-09-08T20:46:40-05:00"), 1_000_000_000);
        assert_eq!(iso("1970-01-01T00:00:00Z"), 0);
        for bad in [
            "",
            "yesterday",
            "2001-13-09T01:46:40Z",
            "2001-09-09 25:00:00Z",
        ] {
            assert_eq!(parse_iso_secs(bad), None, "{bad}");
        }
        assert_eq!(
            line_timestamp(&json!({"timestamp": 1_000_000_000_000u64})),
            Some(1_000_000_000)
        );
    }

    // --- the transcript ---

    #[test]
    fn debugger_loads_after_the_failure_are_found() {
        let dir = TestDir::new("transcript");
        let failed_at = iso("2026-11-02T10:00:00Z");
        let after = dir.write(
            "after.jsonl",
            &[
                chat_line("2026-11-02T09:00:00Z", "start"),
                skill_line("2026-11-02T10:00:30Z", "legion:debugger"),
            ],
        );
        assert_eq!(debugger_loaded_after(&after, failed_at), Some(true));

        let bare = dir.write(
            "bare.jsonl",
            &[skill_line("2026-11-02T10:00:30Z", "debugger")],
        );
        assert_eq!(debugger_loaded_after(&bare, failed_at), Some(true));

        let before = dir.write(
            "before.jsonl",
            &[skill_line("2026-11-02T09:59:00Z", "legion:debugger")],
        );
        assert_eq!(debugger_loaded_after(&before, failed_at), Some(false));

        let same_second = dir.write(
            "same.jsonl",
            &[skill_line("2026-11-02T10:00:00Z", "legion:debugger")],
        );
        assert_eq!(debugger_loaded_after(&same_second, failed_at), Some(false));

        let other = dir.write(
            "other.jsonl",
            &[
                skill_line("2026-11-02T10:00:30Z", "legion:designer"),
                chat_line("2026-11-02T10:00:40Z", "the debugger said \"Skill\""),
            ],
        );
        assert_eq!(debugger_loaded_after(&other, failed_at), Some(false));

        let typed = dir.write(
            "typed.jsonl",
            &[typed_line("2026-11-02T10:01:00Z", "/legion:debugger")],
        );
        assert_eq!(debugger_loaded_after(&typed, failed_at), Some(true));

        let untimed = dir.write(
            "untimed.jsonl",
            &[json!({
                "type": "assistant",
                "message": {"content": [
                    {"type": "tool_use", "name": "Skill", "input": {"skill": "legion:debugger"}}
                ]},
            })
            .to_string()],
        );
        assert_eq!(debugger_loaded_after(&untimed, failed_at), None);

        assert_eq!(
            debugger_loaded_after(&dir.path().join("missing.jsonl"), failed_at),
            None
        );
    }

    // --- the decision ---

    fn state_with(dir: &TestDir, ledger: &[String]) -> PathBuf {
        dir.write("state/evidence/s1.jsonl", ledger);
        dir.path().join("state")
    }

    #[test]
    fn red_then_rerun_is_denied_until_the_debugger_is_loaded() {
        let dir = TestDir::new("decision");
        let failed_at = iso("2026-11-02T10:00:00Z");
        let now = failed_at + 120;
        let root = state_with(&dir, &[row(failed_at, "rightkit-gate --to dev", true)]);

        let none = dir.write(
            "t/none.jsonl",
            &[chat_line("2026-11-02T10:00:10Z", "diagnosing")],
        );
        assert!(should_deny(&root, "s1", Some(&none), now));

        let loaded = dir.write(
            "t/loaded.jsonl",
            &[
                chat_line("2026-11-02T10:00:10Z", "diagnosing"),
                skill_line("2026-11-02T10:00:20Z", "legion:debugger"),
            ],
        );
        assert!(!should_deny(&root, "s1", Some(&loaded), now));

        // Fail open: no transcript, unreadable transcript, other session.
        assert!(!should_deny(&root, "s1", None, now));
        assert!(!should_deny(
            &root,
            "s1",
            Some(&dir.path().join("t/gone.jsonl")),
            now
        ));
        assert!(!should_deny(&root, "other", Some(&none), now));
    }

    #[test]
    fn a_green_run_after_the_red_one_resets_the_gate() {
        let dir = TestDir::new("green");
        let failed_at = iso("2026-11-02T10:00:00Z");
        let root = state_with(
            &dir,
            &[
                row(failed_at, "rightkit-gate --to dev", true),
                row(failed_at + 300, "rightkit-gate --to dev", false),
            ],
        );
        let none = dir.write("t/none.jsonl", &[chat_line("2026-11-02T10:00:10Z", "x")]);
        assert!(!should_deny(&root, "s1", Some(&none), failed_at + 600));
    }

    #[test]
    fn a_failed_local_check_never_arms_the_gate() {
        let dir = TestDir::new("check");
        let failed_at = iso("2026-11-02T10:00:00Z");
        let root = state_with(
            &dir,
            &[row(failed_at, "rightkit-gate check --commit abc", true)],
        );
        let none = dir.write("t/none.jsonl", &[chat_line("2026-11-02T10:00:10Z", "x")]);
        assert!(!should_deny(&root, "s1", Some(&none), failed_at + 60));
    }

    fn request(payload: Value) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload,
        }
    }

    #[test]
    fn pre_tool_ignores_other_tools_commands_subagents_and_codex() {
        let bash = |command: &str| {
            request(json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }))
        };
        assert!(pre_tool(&bash("ls -la")).is_none());
        assert!(pre_tool(&bash("rightkit-gate check --commit abc")).is_none());
        let read = request(json!({
            "session_id": "s1",
            "tool_name": "Read",
            "tool_input": {"file_path": "/x"},
        }));
        assert!(pre_tool(&read).is_none());
        let subagent = request(json!({
            "session_id": "s1",
            "agent_id": "a1",
            "tool_name": "Bash",
            "tool_input": {"command": "rightkit-gate --to dev"},
        }));
        assert!(pre_tool(&subagent).is_none());
        let codex = request(json!({
            "session_id": "s1",
            "turn_id": "t1",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "rightkit-gate --to dev"},
        }));
        assert!(pre_tool(&codex).is_none());
        let mut post = bash("rightkit-gate --to dev");
        post.event_type = "PostToolUse".to_owned();
        assert!(pre_tool(&post).is_none());
    }

    #[test]
    fn the_denial_names_the_debugger() {
        assert!(MESSAGE.contains("legion:debugger"));
        assert!(MESSAGE.starts_with("Last build/CI run failed."));
        assert_eq!(CODE, "ARC_DEBUGGER_FIRST");
    }
}
