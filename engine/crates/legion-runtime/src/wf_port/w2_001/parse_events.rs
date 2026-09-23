//! Port of `skills/alchemist/scripts/parse_events.py`.
//!
//! Modes ported 1:1:
//!   * `--stream`  -> [`stream_line`], applied per input line by the caller
//!     (the Python version reads stdin in a loop; Rust callers own their own
//!     I/O loop and call `stream_line` per line).
//!   * `--summary` -> [`run_summary`], which formats the same report the
//!     Python `run_summary()` prints, given the full JSONL text.
//!
//! `classify()` and `first_text()` are ported field-for-field, including the
//! same 400/200/160-char truncation lengths and the same detection order
//! (reasoning -> command -> patch -> error -> assistant/agent -> usage/token
//! -> fallback to the raw kind).

use serde_json::Value;

const TEXT_KEYS: [&str; 4] = ["text", "content", "message", "delta"];

/// Port of `first_text()`: best-effort extraction of human-readable text
/// from a nested event value.
pub fn first_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(first_text).collect::<Vec<_>>().concat(),
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

/// Truncate to at most `max` `char`s (matches Python's `str[:n]`, which
/// slices by code point, not byte).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Python truthiness for a decoded JSON value (used for `event.get("error")`,
/// which Python evaluates as a truthiness check, not a null check).
fn is_python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Port of `classify()`. Returns `(kind, detail)`; `kind` is the coarse
/// bucket the UI colours by.
pub fn classify(event: &Value) -> (String, String) {
    let item = event.get("item").filter(|v| v.is_object());
    let msg = event.get("msg").filter(|v| v.is_object());
    // payload = event.item if event.item is a dict else event; if that left
    // payload as event itself, and event.msg is a dict, payload = event.msg.
    let payload: &Value = if let Some(i) = item {
        i
    } else if let Some(m) = msg {
        m
    } else {
        event
    };

    let kind_value = payload
        .get("type")
        .filter(|v| !v.is_null())
        .or_else(|| event.get("type").filter(|v| !v.is_null()))
        .or_else(|| event.get("event").filter(|v| !v.is_null()))
        .or_else(|| {
            event
                .get("msg")
                .and_then(|m| m.get("type"))
                .filter(|v| !v.is_null())
        });
    let kind = match kind_value {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "unknown".to_string(),
    };
    let lowered = kind.to_lowercase();

    if lowered.contains("reason") {
        return ("reasoning".to_string(), truncate_chars(&first_text(payload), 400));
    }
    if lowered.contains("command") || lowered.contains("exec") || lowered.contains("shell") {
        let cmd_value = payload.get("command").or_else(|| payload.get("cmd"));
        let cmd = match cmd_value {
            Some(Value::Array(items)) => items
                .iter()
                .map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" "),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => first_text(payload),
        };
        return ("command".to_string(), truncate_chars(&cmd, 400));
    }
    if lowered.contains("patch") || lowered.contains("diff") || lowered.contains("apply") {
        return ("patch".to_string(), truncate_chars(&first_text(payload), 400));
    }
    let event_error = event.get("error").filter(|v| is_python_truthy(v));
    if lowered.contains("error") || event_error.is_some() {
        let source = event_error.unwrap_or(payload);
        return ("error".to_string(), truncate_chars(&first_text(source), 400));
    }
    if lowered.contains("message") || lowered.contains("agent") || lowered.contains("assistant") {
        return ("assistant".to_string(), first_text(payload));
    }
    if lowered.contains("token") || lowered.contains("usage") {
        let json_str = serde_json::to_string(payload).unwrap_or_default();
        return ("usage".to_string(), truncate_chars(&json_str, 200));
    }
    (kind, truncate_chars(&first_text(payload), 400))
}

/// Port of `BOM_PREFIXES` / `strip_bom()`. Strips both the real U+FEFF BOM
/// and the mojibake "ï»¿" a Windows-ANSI-page fallback decode can produce,
/// repeatedly (matches the Python `while changed` loop).
pub fn strip_bom(line: &str) -> String {
    let mut line = line.to_string();
    loop {
        if let Some(rest) = line.strip_prefix('\u{feff}') {
            line = rest.to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("ï»¿") {
            line = rest.to_string();
            continue;
        }
        break;
    }
    line
}

/// Result of parsing one JSONL line: either a decoded event, or a
/// non-JSON warning line (what `iter_events` prints to stderr as
/// `[non-json] ...`).
pub enum ParsedLine {
    Event(Value),
    NonJson(String),
}

/// Port of `iter_events()`: strips a leading BOM and surrounding
/// whitespace, skips blank lines, and yields either a decoded `Value` or a
/// `[non-json] <line[:160]>` warning for a line that fails to parse.
pub fn iter_events(text: &str) -> Vec<ParsedLine> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = strip_bom(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => out.push(ParsedLine::Event(v)),
            Err(_) => out.push(ParsedLine::NonJson(format!(
                "[non-json] {}",
                truncate_chars(&line, 160)
            ))),
        }
    }
    out
}

/// One line of `--stream` output, mirroring `run_stream()`: either
/// assistant text destined for stdout, or a progress line for stderr.
pub struct StreamLine {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

/// Port of the per-event body of `run_stream()`. Non-JSON lines should be
/// surfaced by the caller directly from `ParsedLine::NonJson` (already
/// formatted); this only handles a decoded event.
pub fn stream_line(event: &Value) -> StreamLine {
    let (kind, detail) = classify(event);
    if kind == "assistant" && !detail.is_empty() {
        StreamLine {
            stdout: Some(detail),
            stderr: None,
        }
    } else {
        let collapsed = detail.replace('\n', " ");
        StreamLine {
            stdout: None,
            stderr: Some(format!("  · {kind}: {}", truncate_chars(&collapsed, 160))),
        }
    }
}

/// Port of `run_summary()`: given the full text of a saved JSONL event log,
/// returns the exact report `--summary` prints to stdout.
pub fn run_summary(text: &str) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut commands: Vec<String> = Vec::new();
    let mut patches = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut assistant: Vec<String> = Vec::new();

    for parsed in iter_events(text) {
        let event = match parsed {
            ParsedLine::Event(v) => v,
            ParsedLine::NonJson(_) => continue,
        };
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

    let mut out = String::new();
    out.push_str("=== alchemist run summary ===\n");
    let total: usize = counts.values().sum();
    let counts_str = counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("events: {total}  ({counts_str})\n"));
    out.push_str(&format!("commands run by worker: {}\n", commands.len()));
    for cmd in commands.iter().take(20) {
        out.push_str(&format!("   $ {cmd}\n"));
    }
    if commands.len() > 20 {
        out.push_str(&format!("   … {} more\n", commands.len() - 20));
    }
    out.push_str(&format!("patch/apply events: {patches}\n"));
    if !errors.is_empty() {
        out.push_str(&format!("ERRORS ({}):\n", errors.len()));
        for err in errors.iter().take(10) {
            out.push_str(&format!("   ! {err}\n"));
        }
    } else {
        out.push_str("errors: none\n");
    }
    if !assistant.is_empty() {
        out.push_str("--- final worker message (tail) ---\n");
        let joined = assistant.concat();
        out.push_str(&truncate_tail_chars(&joined, 1200));
        out.push('\n');
    }
    out.push('\n');
    out.push_str("NOTE: this summarizes what the worker CLAIMS. The host must still read\n");
    out.push_str("      the real git diff and re-run the verification commands itself.\n");
    out
}

/// Python's `s[-1200:]`: the last 1200 chars (not bytes).
fn truncate_tail_chars(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        chars[chars.len() - max..].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_text_prefers_text_key_and_recurses_lists() {
        assert_eq!(first_text(&json!("hi")), "hi");
        assert_eq!(first_text(&json!([{"text": "a"}, {"content": "b"}])), "ab");
        assert_eq!(first_text(&json!({"message": {"delta": "d"}})), "d");
        assert_eq!(first_text(&json!({"other": "x"})), "");
    }

    #[test]
    fn classify_reasoning() {
        let event = json!({"msg": {"type": "agent_reasoning", "text": "thinking..."}});
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "reasoning");
        assert_eq!(detail, "thinking...");
    }

    #[test]
    fn classify_command_joins_array_argv() {
        let event = json!({"item": {"type": "command_execution", "command": ["ls", "-la"]}});
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "command");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn classify_patch() {
        let event = json!({"item": {"type": "patch_apply", "text": "diff --git a b"}});
        let (kind, _) = classify(&event);
        assert_eq!(kind, "patch");
    }

    #[test]
    fn classify_error_from_top_level_error_field() {
        let event = json!({"type": "turn_completed", "error": {"message": "boom"}});
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "error");
        assert_eq!(detail, "boom");
    }

    #[test]
    fn classify_assistant_message() {
        let event = json!({"msg": {"type": "agent_message", "message": "hello there"}});
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "assistant");
        assert_eq!(detail, "hello there");
    }

    #[test]
    fn classify_usage_truncates_json_to_200_chars() {
        let event = json!({"item": {"type": "token_count", "input_tokens": 1, "output_tokens": 2}});
        let (kind, detail) = classify(&event);
        assert_eq!(kind, "usage");
        assert!(detail.starts_with('{'));
    }

    #[test]
    fn classify_unknown_falls_back_to_raw_kind() {
        let event = json!({"type": "session_configured"});
        let (kind, _) = classify(&event);
        assert_eq!(kind, "session_configured");
    }

    #[test]
    fn classify_missing_kind_is_unknown() {
        let event = json!({"foo": "bar"});
        let (kind, _) = classify(&event);
        assert_eq!(kind, "unknown");
    }

    #[test]
    fn strip_bom_removes_real_bom_and_mojibake_repeatedly() {
        assert_eq!(strip_bom("\u{feff}{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("ï»¿{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("\u{feff}ï»¿{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn iter_events_skips_blank_lines_and_flags_non_json() {
        let text = "\n{\"type\":\"a\"}\nnot json\n  \n{\"type\":\"b\"}\n";
        let parsed = iter_events(text);
        assert_eq!(parsed.len(), 3);
        assert!(matches!(parsed[0], ParsedLine::Event(_)));
        assert!(matches!(parsed[1], ParsedLine::NonJson(_)));
        assert!(matches!(parsed[2], ParsedLine::Event(_)));
        if let ParsedLine::NonJson(msg) = &parsed[1] {
            assert_eq!(msg, "[non-json] not json");
        }
    }

    #[test]
    fn stream_line_routes_assistant_to_stdout_and_rest_to_stderr() {
        let assistant = json!({"msg": {"type": "agent_message", "message": "hi"}});
        let line = stream_line(&assistant);
        assert_eq!(line.stdout.as_deref(), Some("hi"));
        assert!(line.stderr.is_none());

        let other = json!({"type": "session_configured"});
        let line = stream_line(&other);
        assert!(line.stdout.is_none());
        assert_eq!(line.stderr.as_deref(), Some("  · session_configured: "));
    }

    #[test]
    fn run_summary_matches_python_report_shape() {
        let text = concat!(
            "{\"msg\":{\"type\":\"agent_reasoning\",\"text\":\"plan\"}}\n",
            "{\"item\":{\"type\":\"command_execution\",\"command\":\"cargo test\"}}\n",
            "{\"item\":{\"type\":\"patch_apply\",\"text\":\"diff\"}}\n",
            "{\"type\":\"turn_error\",\"error\":{\"message\":\"boom\"}}\n",
            "{\"msg\":{\"type\":\"agent_message\",\"message\":\"done.\"}}\n",
        );
        let report = run_summary(text);
        assert!(report.contains("=== alchemist run summary ==="));
        assert!(report.contains("events: 5"));
        assert!(report.contains("commands run by worker: 1"));
        assert!(report.contains("$ cargo test"));
        assert!(report.contains("patch/apply events: 1"));
        assert!(report.contains("ERRORS (1):"));
        assert!(report.contains("! boom"));
        assert!(report.contains("--- final worker message (tail) ---"));
        assert!(report.contains("done."));
        assert!(report.contains(
            "NOTE: this summarizes what the worker CLAIMS. The host must still read"
        ));
    }

    #[test]
    fn run_summary_reports_no_errors_when_none_seen() {
        let text = "{\"msg\":{\"type\":\"agent_message\",\"message\":\"ok\"}}\n";
        let report = run_summary(text);
        assert!(report.contains("errors: none"));
        assert!(!report.contains("ERRORS ("));
    }
}
