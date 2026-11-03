//! Stop check for approval requests: a final message with an `APPROVAL REQUEST` block must be
//! complete, backed by a Class A run after the last edit, and carry `verdict: will pass`.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::evidence::turn_id;
use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, ledger, mode, now_secs, off, session_id, state_dir};
use crate::state::{str_field, write_atomic, Mode, Payload};

/// The text of every fenced block in `text` whose first line is `header`, without that line.
fn blocks(text: &str, header: &str) -> Vec<String> {
    let (mut found, mut lines) = (Vec::new(), text.lines());
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```") {
            let body: Vec<&str> = lines
                .by_ref()
                .take_while(|line| !line.trim_start().starts_with("```"))
                .collect();
            if body
                .first()
                .is_some_and(|first| first.trim().eq_ignore_ascii_case(header))
            {
                found.push(body[1..].join("\n"));
            }
        }
    }
    found
}

/// The value of a `name: value` line of a block (empty when absent).
fn field(block: &str, name: &str) -> String {
    let prefix = format!("{name}:");
    let line = block
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()));
    line.map_or(String::new(), |value| {
        value.trim().trim_matches('`').to_owned()
    })
}

/// The commands of a block: the text after `commands:` on its line, and the bullet lines below it.
fn commands(block: &str) -> Vec<&str> {
    let (mut found, mut listing) = (Vec::new(), false);
    for line in block.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("commands:") {
            (listing, found) = (true, vec![rest]);
        } else if listing && line.starts_with(['-', '*']) {
            found.push(line[1..].trim());
        } else if !line.is_empty() {
            listing = false;
        }
    }
    let cleaned = found.into_iter().map(clean);
    cleaned.filter(|command| !command.is_empty()).collect()
}

/// A command as written in a block: without code ticks or a `$ ` prompt.
fn clean(command: &str) -> &str {
    command.trim().trim_matches('`').trim_start_matches("$ ")
}

fn approval_file(payload: &Payload) -> Option<PathBuf> {
    Some(state_dir("approvals")?.join(format!("{}.json", session_id(payload)?)))
}

/// Shadow mode logs a refusal and allows; enforce mode returns the denial.
fn refuse(request: &HookRequest, near: &Path, code: &str, reason: String) -> Option<HookResponse> {
    if mode("LEGION_APPROVALS_MODE") == Mode::Shadow {
        let row = json!({"t": now_secs(), "code": code, "reason": reason});
        append_line(&near.with_file_name("shadow.jsonl"), &row.to_string());
        return None;
    }
    Some(HookResponse::denied(
        request.event_type.clone(),
        code,
        reason,
        "strong",
    ))
}

/// Is there a successful Class A run in the ledger after the last edit (scratch edits excluded)?
fn class_a_after_edit(rows: &[Value]) -> bool {
    let tmp = |row: &Value| {
        row["path"]
            .as_str()
            .is_some_and(|path| path.contains("/scratch/") || path.starts_with("/tmp/"))
    };
    let edit = rows
        .iter()
        .rposition(|row| row["edit"] == true && !tmp(row));
    let passed = |row: &Value| {
        let command = row["command"].as_str().unwrap_or("");
        row["failed"] != true
            && (command.contains("gate check") || command.contains("preflight.mjs"))
    };
    rows[edit.map_or(0, |index| index + 1)..].iter().any(passed)
}

/// Stop: a final message with an `APPROVAL REQUEST` block needs every field, a Class A run after the
/// last edit and `verdict: will pass`. Sent back once; shadow mode only logs.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    let stop = matches!(request.event_type.as_str(), "Stop" | "stop");
    if off("approvals") || mode("LEGION_APPROVALS_MODE") == Mode::Off || !stop {
        return None;
    }
    let payload = request.payload.as_object()?;
    let message = str_field(payload, &["last_assistant_message", "lastAssistantText"])?;
    let block = blocks(&message, "APPROVAL REQUEST").pop()?;
    let verdict = field(&block, "verdict").to_lowercase();
    let will_pass = verdict.starts_with("will pass");
    let class_a = class_a_after_edit(&ledger(&session_id(payload)?));
    let problems = [
        (field(&block, "repo").is_empty(), "repo:"),
        (field(&block, "commit").is_empty(), "commit:"),
        (field(&block, "class-a").is_empty(), "class-a:"),
        (commands(&block).is_empty(), "commands:"),
        (
            !will_pass,
            "verdict: will pass (or check everything and fix it first)",
        ),
        (!class_a, "a successful Class A run after your last edit"),
    ];
    let missing: Vec<_> = problems.iter().filter(|(bad, _)| *bad).collect();
    let texts: Vec<&str> = missing.iter().map(|problem| problem.1).collect();
    let marker = approval_file(payload)?.with_extension("blocked");
    let turn = turn_id(&ledger(&session_id(payload)?));
    let seen = fs::read_to_string(&marker).is_ok_and(|text| text == turn);
    if missing.is_empty() || seen || payload.get("stop_hook_active") == Some(&Value::Bool(true)) {
        return None;
    }
    write_atomic(&marker, turn.as_bytes());
    let reason = format!("Your APPROVAL REQUEST is incomplete: {}", texts.join("; "));
    refuse(request, &marker, "ARC_APPROVAL_REQUEST_INCOMPLETE", reason)
}
