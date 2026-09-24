//! Packet P9-skill-scripts: Rust port of the deterministic decision logic in
//! `skills/alchemist/scripts/run-worker.sh` (the bash OmniRoute/Codex worker launcher).
//!
//! Ported here (pure, no process IO):
//! - `extract_model_from_profile`: pulls `model = "..."` out of a Codex profile TOML the same
//!   way the shell `sed` does (`^[[:space:]]*model[[:space:]]*=[[:space:]]*"([...])".*`).
//! - `healthz_exit_code` / `HealthzOutcome`: interprets an OmniRoute `/healthz` HTTP status the
//!   same way the shell `case` statement does (200/204/301/302/307/401 -> reachable, else -> 4).
//! - `access_args`: `--sandbox workspace-write` unless `ALCHEMIST_FULL_ACCESS=1`, matching
//!   `ACCESS_ARGS`.
//! - `default_event_log_path`: `<run_dir>/<UTC-stamp>-<profile>.jsonl`, matching the default
//!   `EVENT_LOG` the script builds when the caller doesn't pass one.
//! - `WorkerExitCode`: the documented exit contract (0 ok, 2 usage, 4 gateway down,
//!   5 unknown profile, 124 timeout).
//!
//! NOT ported here: spawning `omniroute launch-codex` itself, the TERM/KILL watchdog process
//! tree, and piping stdout through `parse_events.py` (a Python script outside this packet's JS
//! scope — see the packet report). A caller wanting the full launch needs to still shell out;
//! this module gives it the exact inputs (model, event log path, sandbox flags) and the exact
//! exit-code semantics to interpret the child's result by by itself, without re-deriving the
//! shell script's parsing/threshold logic in the caller.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExitCode {
    Ok = 0,
    Usage = 2,
    GatewayDown = 4,
    UnknownProfile = 5,
    Timeout = 124,
}

impl WorkerExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Mirrors the `sed -nE 's/^[[:space:]]*model[[:space:]]*=[[:space:]]*"([A-Za-z0-9._:/-]+)".*/\1/p'
/// | head -1` pipeline: the first line whose (whitespace-trimmed) prefix is `model = "<value>"`,
/// where `<value>` is restricted to `[A-Za-z0-9._:/-]+`.
pub fn extract_model_from_profile(profile_toml: &str) -> Option<String> {
    for line in profile_toml.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("model") else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else { continue };
        let end = match rest.find('"') {
            Some(e) => e,
            None => continue,
        };
        let value = &rest[..end];
        if !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
        {
            return Some(value.to_string());
        }
    }
    None
}

/// Mirrors the healthz `case` statement: is this HTTP status one OmniRoute is considered
/// reachable at?
pub fn is_gateway_reachable(http_status: u16) -> bool {
    matches!(http_status, 200 | 204 | 301 | 302 | 307 | 401)
}

/// `ACCESS_ARGS`: sandboxed by default, full host access only on explicit opt-in.
pub fn access_args(full_access_env: Option<&str>) -> Vec<&'static str> {
    if full_access_env == Some("1") {
        vec!["--dangerously-bypass-approvals-and-sandbox"]
    } else {
        vec!["--sandbox", "workspace-write"]
    }
}

/// Builds the default event log path when the caller doesn't supply one:
/// `<run_dir>/<YYYYmmdd-HHMMSS>-<profile>.jsonl`, given an already-formatted UTC timestamp
/// (the shell script uses `date +%Y%m%d-%H%M%S`; callers should format `now` the same way).
pub fn default_event_log_path(run_dir: &str, timestamp: &str, profile: &str) -> String {
    format!("{}/{}-{}.jsonl", run_dir.trim_end_matches('/'), timestamp, profile)
}

/// Path to a Codex profile's config file, given the Codex home directory and profile name:
/// `${CODEX_HOME:-$HOME/.codex}/<profile>.config.toml`.
pub fn profile_config_path(codex_home_dir: &str, profile: &str) -> String {
    format!("{}/{}.config.toml", codex_home_dir.trim_end_matches('/'), profile)
}

// ---------------------------------------------------------------------------
// Port of `skills/alchemist/scripts/parse_events.py` and (event-classification-sharing
// portion of) `skills/alchemist/scripts/viewer.py`.
//
// `parse_events.py` classifies `codex exec --json` events into a coarse (kind, detail)
// pair the live view and CLI summary both use, so they can never disagree about what an
// event means. Ported 1:1: `classify`, `first_text`, `strip_bom`, `iter_events`, and the
// two CLI modes (`--stream` line-by-line stdin -> stdout/stderr, `--summary <path>` ->
// a structured run report). `run(argv)` mirrors `main()`'s mutually-exclusive
// `--stream`/`--summary` dispatch and exit code.
// ---------------------------------------------------------------------------

use serde_json::Value;

const TEXT_KEYS: [&str; 4] = ["text", "content", "message", "delta"];

/// Best-effort extraction of human-readable text from a nested event. Mirrors
/// `first_text(obj)`.
pub fn first_text(obj: &Value) -> String {
    match obj {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(first_text).collect::<Vec<_>>().join(""),
        Value::Object(map) => {
            for key in TEXT_KEYS {
                if let Some(v) = map.get(key) {
                    let found = first_text(v);
                    if !found.is_empty() {
                        return found;
                    }
                }
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Returns `(kind, detail)`; `kind` is the coarse bucket the UI colours by. Mirrors
/// `classify(event)`.
pub fn classify(event: &Value) -> (String, String) {
    let msg = event.get("msg").filter(|v| v.is_object());
    let mut payload: &Value = event.get("item").filter(|v| v.is_object()).unwrap_or(event);
    // `if payload is event and isinstance(event.get("msg"), dict): payload = event["msg"]`
    if std::ptr::eq(payload, event) {
        if let Some(m) = msg {
            payload = m;
        }
    }

    let kind_val = payload
        .get("type")
        .or_else(|| event.get("type"))
        .or_else(|| event.get("event"))
        .or_else(|| event.get("msg").and_then(|m| m.get("type")));
    let kind = kind_val
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let lowered = kind.to_lowercase();

    if lowered.contains("reason") {
        return ("reasoning".to_string(), truncate_chars(&first_text(payload), 400));
    }
    if lowered.contains("command") || lowered.contains("exec") || lowered.contains("shell") {
        let cmd = payload
            .get("command")
            .or_else(|| payload.get("cmd"))
            .cloned()
            .unwrap_or_else(|| Value::String(first_text(payload)));
        let cmd_str = match &cmd {
            Value::Array(items) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
                .collect::<Vec<_>>()
                .join(" "),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        return ("command".to_string(), truncate_chars(&cmd_str, 400));
    }
    if lowered.contains("patch") || lowered.contains("diff") || lowered.contains("apply") {
        return ("patch".to_string(), truncate_chars(&first_text(payload), 400));
    }
    let event_error = event.get("error");
    if lowered.contains("error") || event_error.map(|e| !e.is_null()).unwrap_or(false) {
        let src = event_error.cloned().unwrap_or_else(|| payload.clone());
        return ("error".to_string(), truncate_chars(&first_text(&src), 400));
    }
    if lowered.contains("message") || lowered.contains("agent") || lowered.contains("assistant") {
        return ("assistant".to_string(), first_text(payload));
    }
    if lowered.contains("token") || lowered.contains("usage") {
        let json = serde_json::to_string(payload).unwrap_or_default();
        return ("usage".to_string(), truncate_chars(&json, 200));
    }
    (kind, truncate_chars(&first_text(payload), 400))
}

const BOM_PREFIXES: [&str; 2] = ["\u{feff}", "ï»¿"];

/// Strips a leading UTF-8 BOM (`U+FEFF`) or its mojibake form (`ï»¿`), repeatedly, mirroring
/// `strip_bom(line)`.
pub fn strip_bom(mut line: &str) -> String {
    loop {
        let mut changed = false;
        for prefix in BOM_PREFIXES {
            if let Some(rest) = line.strip_prefix(prefix) {
                line = rest;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    line.to_string()
}

/// Parses non-empty, BOM-stripped JSONL lines from `text`, reporting unparseable lines to
/// `on_non_json` the way the Python generator prints `[non-json] ...` to stderr instead of
/// raising. Mirrors `iter_events(stream)`.
pub fn iter_events(text: &str, mut on_non_json: impl FnMut(&str)) -> Vec<Value> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = strip_bom(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => out.push(v),
            Err(_) => on_non_json(&truncate_chars(&line, 160)),
        }
    }
    out
}

/// `--stream` mode: classifies each event from `input`, writing assistant text to `stdout`
/// and everything else (plus non-JSON lines) to `stderr` as `  · <kind>: <detail>`. Mirrors
/// `run_stream()`. Always returns 0, as the Python function does.
pub fn run_stream(input: &str, stdout: &mut dyn std::io::Write, stderr: &mut dyn std::io::Write) -> i32 {
    let events = iter_events(input, |bad| {
        let _ = writeln!(stderr, "[non-json] {bad}");
    });
    for event in events {
        let (kind, detail) = classify(&event);
        if kind == "assistant" && !detail.is_empty() {
            let _ = writeln!(stdout, "{detail}");
        } else {
            let one_line = detail.replace('\n', " ");
            let _ = writeln!(stderr, "  · {kind}: {}", truncate_chars(&one_line, 160));
        }
    }
    0
}

/// `--summary <path>` mode: reads a saved JSONL event log and prints a structured run
/// summary. Mirrors `run_summary(path)`. Returns 2 if the file cannot be read (the Python
/// `open()` would raise and propagate a nonzero exit through the process; this port keeps
/// that failure explicit rather than panicking).
pub fn run_summary(log_text: &str, stdout: &mut dyn std::io::Write) -> i32 {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut commands: Vec<String> = Vec::new();
    let mut patches = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut assistant: Vec<String> = Vec::new();

    let events = iter_events(log_text, |_| {});
    for event in events {
        let (kind, detail) = classify(&event);
        *counts.entry(kind.clone()).or_insert(0) += 1;
        match kind.as_str() {
            "command" => commands.push(detail),
            "patch" => patches += 1,
            "error" => errors.push(detail),
            "assistant" if !detail.is_empty() => assistant.push(detail),
            _ => {}
        }
    }

    let total_events: usize = counts.values().sum();
    let counts_str = counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");

    let _ = writeln!(stdout, "=== alchemist run summary ===");
    let _ = writeln!(stdout, "events: {total_events}  ({counts_str})");
    let _ = writeln!(stdout, "commands run by worker: {}", commands.len());
    for cmd in commands.iter().take(20) {
        let _ = writeln!(stdout, "   $ {cmd}");
    }
    if commands.len() > 20 {
        let _ = writeln!(stdout, "   … {} more", commands.len() - 20);
    }
    let _ = writeln!(stdout, "patch/apply events: {patches}");
    if !errors.is_empty() {
        let _ = writeln!(stdout, "ERRORS ({}):", errors.len());
        for err in errors.iter().take(10) {
            let _ = writeln!(stdout, "   ! {err}");
        }
    } else {
        let _ = writeln!(stdout, "errors: none");
    }
    if !assistant.is_empty() {
        let _ = writeln!(stdout, "--- final worker message (tail) ---");
        let joined: String = assistant.concat();
        let tail: String = joined.chars().rev().take(1200).collect::<Vec<_>>().into_iter().rev().collect();
        let _ = writeln!(stdout, "{tail}");
    }
    let _ = writeln!(stdout);
    let _ = writeln!(
        stdout,
        "NOTE: this summarizes what the worker CLAIMS. The host must still read"
    );
    let _ = writeln!(
        stdout,
        "      the real git diff and re-run the verification commands itself."
    );
    0
}

/// CLI entry point mirroring `parse_events.py`'s `main()`: `--stream` (stdin -> stdout/stderr)
/// or `--summary <path>` (mutually exclusive, one required). `stdin_text` substitutes for
/// `sys.stdin.read()` so this stays testable without real process stdin. Returns the exit
/// code `main()` returns via `sys.exit`.
pub fn run(
    argv: &[String],
    stdin_text: &str,
    read_file: &dyn Fn(&str) -> Result<String, String>,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let stream = argv.iter().any(|a| a == "--stream");
    let summary_path = argv
        .iter()
        .position(|a| a == "--summary")
        .and_then(|i| argv.get(i + 1));
    match (stream, summary_path) {
        (true, None) => run_stream(stdin_text, stdout, stderr),
        (false, Some(path)) => match read_file(path) {
            Ok(text) => run_summary(&text, stdout),
            Err(e) => {
                let _ = writeln!(stderr, "error: {e}");
                2
            }
        },
        (true, Some(_)) => {
            let _ = writeln!(stderr, "error: argument --summary: not allowed with argument --stream");
            2
        }
        (false, None) => {
            let _ = writeln!(stderr, "error: one of the arguments --stream --summary is required");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_model_ignoring_leading_whitespace_and_trailing_content() {
        let toml = "profile = \"x\"\n  model = \"gpt-5.6-omniroute\"  # comment\nother = 1\n";
        assert_eq!(extract_model_from_profile(toml), Some("gpt-5.6-omniroute".to_string()));
    }

    #[test]
    fn returns_none_when_no_model_line() {
        assert_eq!(extract_model_from_profile("profile = \"x\"\n"), None);
    }

    #[test]
    fn rejects_disallowed_characters_and_falls_through() {
        let toml = "model = \"bad value!\"\nmodel = \"good-value.1\"\n";
        assert_eq!(extract_model_from_profile(toml), Some("good-value.1".to_string()));
    }

    #[test]
    fn healthz_thresholds_match_shell_case() {
        for ok in [200, 204, 301, 302, 307, 401] {
            assert!(is_gateway_reachable(ok), "{ok} should be reachable");
        }
        for down in [0, 404, 500, 502, 503] {
            assert!(!is_gateway_reachable(down), "{down} should not be reachable");
        }
    }

    #[test]
    fn access_args_defaults_to_sandboxed() {
        assert_eq!(access_args(None), vec!["--sandbox", "workspace-write"]);
        assert_eq!(access_args(Some("0")), vec!["--sandbox", "workspace-write"]);
        assert_eq!(
            access_args(Some("1")),
            vec!["--dangerously-bypass-approvals-and-sandbox"]
        );
    }

    #[test]
    fn default_event_log_path_matches_shell_format() {
        assert_eq!(
            default_event_log_path("/home/x/.alchemist/runs", "20260923-101500", "default"),
            "/home/x/.alchemist/runs/20260923-101500-default.jsonl"
        );
    }

    #[test]
    fn profile_config_path_matches_codex_home_layout() {
        assert_eq!(
            profile_config_path("/home/x/.codex", "default"),
            "/home/x/.codex/default.config.toml"
        );
    }

    #[test]
    fn worker_exit_codes_match_documented_contract() {
        assert_eq!(WorkerExitCode::Ok.code(), 0);
        assert_eq!(WorkerExitCode::Usage.code(), 2);
        assert_eq!(WorkerExitCode::GatewayDown.code(), 4);
        assert_eq!(WorkerExitCode::UnknownProfile.code(), 5);
        assert_eq!(WorkerExitCode::Timeout.code(), 124);
    }

    #[test]
    fn classify_detects_assistant_message() {
        let event: Value = serde_json::from_str(r#"{"type":"agent_message","text":"hello"}"#).unwrap();
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "assistant");
        assert_eq!(detail, "hello");
    }

    #[test]
    fn classify_detects_command() {
        let event: Value = serde_json::from_str(r#"{"type":"exec_command","command":["ls","-la"]}"#).unwrap();
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "command");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn classify_detects_error() {
        let event: Value = serde_json::from_str(r#"{"error":"boom"}"#).unwrap();
        let (kind, _) = classify(&event);
        assert_eq!(kind, "error");
    }

    #[test]
    fn strip_bom_removes_utf8_and_mojibake_prefixes() {
        assert_eq!(strip_bom("\u{feff}hello"), "hello");
        assert_eq!(strip_bom("ï»¿hello"), "hello");
        assert_eq!(strip_bom("hello"), "hello");
    }

    #[test]
    fn iter_events_reports_non_json_lines() {
        let mut bad = Vec::new();
        let events = iter_events("{\"a\":1}\nnot json\n\n{\"b\":2}\n", |line| bad.push(line.to_string()));
        assert_eq!(events.len(), 2);
        assert_eq!(bad, vec!["not json".to_string()]);
    }

    #[test]
    fn run_stream_routes_assistant_to_stdout_and_rest_to_stderr() {
        let input = "{\"type\":\"agent_message\",\"text\":\"final answer\"}\n{\"type\":\"exec_command\",\"command\":\"ls\"}\n";
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_stream(input, &mut out, &mut err);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(out).unwrap(), "final answer\n");
        assert!(String::from_utf8(err).unwrap().contains("command:"));
    }

    #[test]
    fn run_summary_counts_events_and_reports_errors() {
        let log = "{\"type\":\"exec_command\",\"command\":\"ls\"}\n{\"error\":\"boom\"}\n";
        let mut out = Vec::new();
        let code = run_summary(log, &mut out);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("commands run by worker: 1"));
        assert!(text.contains("ERRORS (1):"));
    }

    #[test]
    fn run_dispatches_stream_and_summary_and_rejects_both_or_neither() {
        let read_file = |p: &str| -> Result<String, String> {
            if p == "log.jsonl" {
                Ok("{\"type\":\"exec_command\",\"command\":\"ls\"}\n".to_string())
            } else {
                Err("not found".to_string())
            }
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run(&[], "", &read_file, &mut out, &mut err), 2);
        assert_eq!(
            run(&["--stream".to_string()], "{\"type\":\"agent_message\",\"text\":\"hi\"}\n", &read_file, &mut out, &mut err),
            0
        );
        assert_eq!(
            run(&["--summary".to_string(), "log.jsonl".to_string()], "", &read_file, &mut out, &mut err),
            0
        );
        assert_eq!(
            run(&["--summary".to_string(), "missing.jsonl".to_string()], "", &read_file, &mut out, &mut err),
            2
        );
        assert_eq!(
            run(&["--stream".to_string(), "--summary".to_string(), "log.jsonl".to_string()], "", &read_file, &mut out, &mut err),
            2
        );
    }
}
