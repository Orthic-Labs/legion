//! Evidence ledger and claim check: a claim word needs a successful matching tool row after the last edit.

use std::fs;

use serde_json::{json, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, edit_path, ledger, mode, now_secs, off, session_id, state_dir};
use crate::state::{str_field, tool_input, tool_name, write_atomic, Mode, Payload};
use crate::transcript::human;

const ANY: &[&str] = &[];
const TEST: &[&str] = &[
    "test", "check", "clippy", "build", "lint", "gate", "gh run", "pytest", "tsc",
];
const INSTALL: &[&str] = &["install", "version", "setup", "--to dev", "which"];
const RELEASE: &[&str] = &[
    "curl", "release", "wrangler", "gh api", "publish", "fetch", "browser", "chrome",
];
/// Claim words, and the words that make a tool row evidence for them (`ANY`: any real tool run).
const CLAIMS: [(&str, &[&str]); 9] = [
    ("done", ANY),
    ("fixed", ANY),
    ("works", ANY),
    ("green", TEST),
    ("passing", TEST),
    ("installed", INSTALL),
    ("live", RELEASE),
    ("deployed", RELEASE),
    ("published", RELEASE),
];
/// A sentence with one of these tokens is a plan or a doubt, not a claim.
const HEDGES: [&str; 6] = ["will", "ll", "next", "plan", "hypothesis", "not"];

fn head_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn tail_chars(text: &str, max: usize) -> String {
    text.chars()
        .skip(text.chars().count().saturating_sub(max))
        .collect()
}

fn failed(payload: &Payload, failure_event: bool) -> bool {
    let response = payload.get("tool_response");
    let flag = |key: &str| response.and_then(|r| r.get(key)) == Some(&Value::Bool(true));
    let code = response.and_then(|r| r.get("exit_code").or(r.get("exitCode")));
    failure_event
        || flag("is_error")
        || flag("interrupted")
        || code.and_then(Value::as_i64).is_some_and(|code| code != 0)
}

/// The ledger row of one tool result: command, outcome, edited path and the last 300 output chars.
fn ledger_row(payload: &Payload, failure_event: bool) -> Option<Value> {
    let input = tool_input(payload);
    let command = input.and_then(crate::command_text);
    let command = command.or_else(|| str_field(input?, &["skill"]));
    let response = payload.get("tool_response");
    let part = |key: &str| {
        response
            .and_then(|r| r.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let text = response.and_then(Value::as_str).unwrap_or("");
    let error = str_field(payload, &["error"]).unwrap_or_default();
    let output = [text, part("stdout"), part("stderr"), error.as_str()];
    let path = edit_path(payload).map(|path| path.to_string_lossy().into_owned());
    Some(json!({
        "t": now_secs(),
        "tool": tool_name(payload)?,
        "command": command.map(|command| head_chars(&command, 500)),
        "failed": failed(payload, failure_event),
        "edit": path.is_some(),
        "path": path,
        "tail": tail_chars(&output.join("\n"), 300),
    }))
}

/// Append a ledger line; past 4 MB the older half of the file is dropped.
fn append(session: &str, row: &Value) -> Option<()> {
    let path = state_dir("evidence")?.join(format!("{session}.jsonl"));
    append_line(&path, &row.to_string())?;
    if fs::metadata(&path).ok()?.len() > 4 << 20 {
        let text = fs::read_to_string(&path).ok()?;
        let lines: Vec<&str> = text.lines().collect();
        write_atomic(
            &path,
            format!("{}\n", lines[lines.len() / 2..].join("\n")).as_bytes(),
        )?;
    }
    Some(())
}

/// PostToolUse and PostToolUseFailure: one ledger row per tool result.
pub fn observe_post_tool(request: &HookRequest) {
    let failure_event = matches!(
        request.event_type.as_str(),
        "PostToolUseFailure" | "post-effect-failure"
    );
    if !request.is_post_effect() || off("evidence") {
        return;
    }
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    if let (Some(session), Some(row)) = (session_id(payload), ledger_row(payload, failure_event)) {
        append(&session, &row);
    }
}

/// UserPromptSubmit: a turn marker; rows after the newest marker are "this turn".
pub fn mark_turn_start(request: &HookRequest) {
    if !matches!(
        request.event_type.as_str(),
        "UserPromptSubmit" | "user-prompt-submit"
    ) || off("evidence")
    {
        return;
    }
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    let prompt = str_field(payload, &["prompt", "user_prompt", "userPrompt"]);
    if let (Some(session), Some(prompt)) = (session_id(payload), prompt.filter(|text| human(text)))
    {
        let skills = crate::skills::named(payload, &prompt);
        let prompt = head_chars(&prompt, 200);
        let row = json!({"marker": "turn", "t": now_secs(), "prompt": prompt, "skills": skills});
        append(&session, &row);
    }
}

/// Claim words in unhedged sentences outside code fences, with the evidence each needs.
fn claims(message: &str) -> Vec<(&'static str, &'static [&'static str])> {
    let (mut found, mut fenced) = (Vec::new(), false);
    for line in message.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        for sentence in line.split(['.', '!', '?', ';']).filter(|_| !fenced) {
            let lower = sentence.to_lowercase();
            let tokens: Vec<&str> = lower.split(|c: char| !c.is_alphanumeric()).collect();
            let doubtful = lower.contains("n't") || lower.contains("working on");
            if doubtful || tokens.iter().any(|token| HEDGES.contains(token)) {
                continue;
            }
            for (word, words) in CLAIMS {
                if tokens.contains(&word) && !found.iter().any(|(seen, _)| *seen == word) {
                    found.push((word, words));
                }
            }
        }
    }
    found
}

/// Does this ledger row show a successful run (not an edit) that matches the evidence words?
pub fn counts(row: &Value, words: &[&str]) -> bool {
    let tool = row["tool"].as_str().unwrap_or("");
    if row["failed"] == true || row["edit"] == true {
        return false;
    }
    if words.is_empty() {
        let quiet = matches!(
            tool,
            "Skill" | "ToolSearch" | "Agent" | "SendMessage" | "TodoWrite"
        );
        return !quiet && !tool.starts_with("Task") && !matches!(tool, "Read" | "Grep" | "Glob");
    }
    let haystack = format!("{tool} {}", row["command"].as_str().unwrap_or("")).to_lowercase();
    words.iter().any(|word| haystack.contains(word))
}

/// Claim words this turn's ledger rows do not back: no matching successful row after the last edit.
fn unsupported(message: &str, entries: &[Value]) -> Vec<&'static str> {
    let start = entries.iter().rposition(|entry| entry["marker"] == "turn");
    let rows = &entries[start.map_or(0, |index| index + 1)..];
    let last_edit = rows
        .iter()
        .rposition(|row| row["edit"] == true && row["failed"] != true);
    let after = &rows[last_edit.map_or(0, |index| index + 1)..];
    let backed = |words: &[&str]| after.iter().any(|row| counts(row, words));
    let missing = claims(message)
        .into_iter()
        .filter(|(_, words)| !backed(words));
    missing.map(|(word, _)| word).collect()
}

fn reason(missing: &[&str]) -> String {
    let list = missing
        .iter()
        .map(|word| format!("'{word}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("You said {list} with no matching successful tool output after your last edit this turn. Run the real check, or say 'not verified'.")
}

/// The ledger, the unbacked claims of the final message, and whether this is a re-entered stop.
fn stop_view(request: &HookRequest) -> Option<(String, Vec<Value>, Vec<&'static str>, bool)> {
    if mode("LEGION_EVIDENCE_MODE") == Mode::Off || off("evidence") {
        return None;
    }
    let payload = request.payload.as_object()?;
    let message = str_field(payload, &["last_assistant_message", "lastAssistantText"])?;
    let session = session_id(payload)?;
    let entries = ledger(&session);
    let missing = unsupported(&message, &entries);
    let active = payload.get("stop_hook_active") == Some(&Value::Bool(true));
    Some((session, entries, missing, active))
}

/// The id of the newest turn marker: when `t` of the marker.
pub fn turn_id(entries: &[Value]) -> String {
    let marker = entries.iter().rev().find(|entry| entry["marker"] == "turn");
    marker.map_or("0".to_owned(), |entry| entry["t"].to_string())
}

/// Stop: a claim the ledger does not back is logged (shadow) or sent back once per turn (enforce).
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let (session, entries, missing, active) = stop_view(request)?;
    let dir = state_dir("evidence")?;
    let blocked = dir.join(format!("{session}.blocked"));
    let turn = turn_id(&entries);
    let seen = fs::read_to_string(&blocked).is_ok_and(|text| text == turn);
    if active || missing.is_empty() || seen {
        return None;
    }
    if mode("LEGION_EVIDENCE_MODE") == Mode::Shadow {
        append_line(
            &dir.join("shadow.jsonl"),
            &json!({"t": now_secs(), "session": session, "claims": missing}).to_string(),
        );
        return None;
    }
    write_atomic(&blocked, turn.as_bytes());
    Some(HookResponse::denied(
        request.event_type.clone(),
        "ARC_EVIDENCE_REQUIRED",
        reason(&missing),
        "strong",
    ))
}

/// For the stop that follows a block: the claim is still unbacked, so say so to Adrian.
pub fn unresolved_note(request: &HookRequest) -> Option<String> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let (session, entries, missing, active) = stop_view(request)?;
    let blocked = state_dir("evidence")?.join(format!("{session}.blocked"));
    let blocked_now = fs::read_to_string(blocked).is_ok_and(|text| text == turn_id(&entries));
    (active && blocked_now && !missing.is_empty())
        .then(|| format!("UNRESOLVED: {}", reason(&missing)))
}
