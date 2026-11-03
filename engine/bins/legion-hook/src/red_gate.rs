//! After a failed qualification run, `legion:debugger` must be loaded before the next run or push.

use serde_json::Value;

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{ledger, now_secs, off, session_id, tool_input};

const MESSAGE: &str = "The last build or CI run failed. Load legion:debugger and state the root cause in one line before the next run or push.";

/// Whether a command is a qualification run (a gate `--to` run other than `check`, `gh run watch
/// --exit-status`, `gh run rerun`, `gh workflow run`) and whether it is a `git push`. Cargo runs are neither.
fn kind(command: &str) -> (bool, bool) {
    let (mut run, mut push) = (false, false);
    for segment in crate::command_segments(command) {
        let words = crate::shell_words(crate::unwrap_shell_command(crate::strip_command_prefixes(
            &segment,
        )));
        let program = words.first().map_or("", |word| crate::program_name(word));
        let target = words.iter().enumerate().find_map(|(index, word)| {
            let value = (word == "--to").then(|| words.get(index + 1)).flatten();
            word.strip_prefix("--to=").or(value.map(String::as_str))
        });
        run |= matches!(program, "rightkit-gate" | "rightkit-host-gate")
            && target.is_some_and(|to| to != "check");
        if let Some((sub, rest)) = crate::program_subcommand(&words, "gh", &["-R", "--repo"]) {
            let first = rest.first().map(String::as_str);
            let watch = first == Some("watch") && rest.iter().any(|word| word == "--exit-status");
            run |= (sub == "run" && (first == Some("rerun") || watch))
                || (sub == "workflow" && first == Some("run"));
        }
        let git = crate::program_subcommand(&words, "git", &crate::GIT_VALUE_FLAGS);
        push |= git.is_some_and(|(sub, _)| sub == "push");
    }
    (run, push)
}

/// Is the newest qualification run in the ledger a failure under 24 h old, with no `legion:debugger`
/// skill call or typed prompt after it?
fn red(rows: &[Value], now: u64) -> bool {
    let is_run = |row: &Value| {
        row["command"]
            .as_str()
            .is_some_and(|command| kind(command).0)
    };
    let Some(index) = rows.iter().rposition(is_run) else {
        return false;
    };
    let fresh = now.saturating_sub(rows[index]["t"].as_u64().unwrap_or(0)) <= 24 * 3600;
    let names = |row: &Value| {
        ["command", "prompt"].iter().any(|key| {
            row[*key]
                .as_str()
                .is_some_and(|text| text.contains("legion:debugger"))
        })
    };
    rows[index]["failed"] == true && fresh && !rows[index + 1..].iter().any(names)
}

/// PreToolUse of a shell tool: deny the next qualification run or `git push` while the last run is red.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if off("red-gate") || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let codex = payload.get("legion_host").and_then(|host| host.as_str()) == Some("codex");
    // A subagent's skill calls and Codex (no Skill tool) cannot satisfy this gate.
    if codex || payload.contains_key("agent_id") {
        return None;
    }
    let (run, push) = kind(&crate::command_text(tool_input(payload)?)?);
    if !(run || push) || !red(&ledger(&session_id(payload)?), now_secs()) {
        return None;
    }
    Some(HookResponse::denied(
        request.event_type.clone(),
        "ARC_DEBUGGER_FIRST",
        MESSAGE,
        "strong",
    ))
}
