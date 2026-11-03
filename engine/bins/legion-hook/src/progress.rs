//! Tier-0 Stop checks that need no model: a stalled session, open task items, and "ready" with no read-back.
//!
//! All three share one per-session `progress/<session>.blocked` file keyed on the turn marker `t`, so the
//! three together block at most once per human turn. Every read or write failure allows the stop, and a
//! re-entered stop (`stop_hook_active`) is never blocked. Kill switches: `progress-stall`, `task-open`,
//! `build-readback` in `LEGION_HOOK_OFF`.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::write_atomic;
use crate::state::{ledger, off, session_id, state_dir, str_field, tool_input, tool_name};

/// Words that name a blocker, so a stop with open items is a report and not an abandonment.
const BLOCKERS: [&str; 5] = [
    "blocked",
    "blocker",
    "waiting on",
    "needs adrian",
    "need adrian",
];
/// Phrases that tell Adrian a build is ready to try.
const READY: [&str; 4] = ["test it", "ready for you", "ready to test", "installed"];
/// A sentence with one of these tokens is a plan or a doubt, not a ready claim.
const HEDGES: [&str; 8] = [
    "will", "ll", "not", "if", "once", "after", "before", "until",
];
/// A command that reads an installed version or hash must also name where the build is installed.
const WHERE: [&str; 8] = [
    "/applications/",
    "program files",
    "appdata",
    "right-ctl",
    "legion --version",
    "installed",
    ".local/bin",
    "/usr/local/bin",
];

type Hit = (&'static str, String);

fn file(session: &str, suffix: &str) -> Option<PathBuf> {
    Some(state_dir("progress")?.join(format!("{session}.{suffix}")))
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).ok();
    text.and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

fn id_text(value: &Value) -> Option<String> {
    let number = value.as_u64().map(|number| number.to_string());
    value.as_str().map(str::to_owned).or(number)
}

fn texts(value: &Value) -> Vec<String> {
    let items = value.as_array().into_iter().flatten();
    items.filter_map(id_text).collect()
}

/// Set one plan step (1-based `index`) to `status`; an unknown step changes nothing.
fn set_step(plan: &mut [String], index: Option<&Value>, status: &str) {
    let slot = index.and_then(Value::as_u64).and_then(|n| n.checked_sub(1));
    let slot = slot.and_then(|n| usize::try_from(n).ok());
    if let Some(step) = slot.and_then(|n| plan.get_mut(n)) {
        status.clone_into(step);
    }
}

/// Apply one `update_plan` call (a whole new list, or advance, done and start edits) to the plan statuses.
fn apply_plan(plan: &mut Vec<String>, input: &serde_json::Map<String, Value>) {
    if let Some(items) = input.get("items").and_then(Value::as_array) {
        let status = |item: &Value| item["status"].as_str().unwrap_or("pending").to_owned();
        *plan = items.iter().map(status).collect();
    }
    if input.get("advance") == Some(&Value::Bool(true)) {
        if let Some(step) = plan.iter_mut().find(|step| *step == "in_progress") {
            "completed".clone_into(step);
        }
        if let Some(step) = plan.iter_mut().find(|step| *step == "pending") {
            "in_progress".clone_into(step);
        }
    }
    for number in input
        .get("done")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        set_step(plan, Some(number), "completed");
    }
    set_step(plan, input.get("start"), "in_progress");
}

/// PostToolUse: keep a minimal task state per session from the task tools and the app's plan tools, because the
/// evidence ledger does not keep their input. `created` counts TaskCreate calls (ids run 1..), `closed` holds the
/// ids marked completed or deleted, and `plan` holds the statuses of the plan list.
pub fn observe_post_tool(request: &HookRequest) {
    let _ = record(request);
}

fn record(request: &HookRequest) -> Option<()> {
    if !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect") || off("task-open") {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    let wrap = tool.ends_with("ccd_turn__wrap_up");
    let plan_tool = tool.ends_with("update_plan");
    if !(wrap || plan_tool || matches!(tool.as_str(), "TaskCreate" | "TaskUpdate")) {
        return None;
    }
    let path = file(&session_id(payload)?, "tasks")?;
    let state = read_json(&path);
    let mut closed = texts(&state["closed"]);
    let mut plan = texts(&state["plan"]);
    let mut created = state["created"].as_u64().unwrap_or(0);
    let input = tool_input(payload);
    if tool == "TaskCreate" {
        created += 1;
    } else if tool == "TaskUpdate" {
        let input = input?;
        let id = input.get("taskId").or(input.get("id")).and_then(id_text)?;
        closed.retain(|seen| *seen != id);
        if matches!(
            input.get("status").and_then(Value::as_str),
            Some("completed" | "deleted")
        ) {
            closed.push(id);
        }
    } else if wrap {
        plan.iter_mut()
            .for_each(|step| "completed".clone_into(step));
    } else {
        apply_plan(&mut plan, input?);
    }
    let state = json!({"created": created, "closed": closed, "plan": plan});
    write_atomic(&path, state.to_string().as_bytes())
}

/// Items still open: created tasks not closed, plus plan steps not completed. Zero when nothing is known.
fn open_items(session: &str) -> usize {
    let state = file(session, "tasks").map_or(Value::Null, |path| read_json(&path));
    let closed = texts(&state["closed"]);
    let created = state["created"].as_u64().unwrap_or(0);
    let tasks = (1..=created).filter(|id| !closed.contains(&id.to_string()));
    let steps = texts(&state["plan"]);
    tasks.count() + steps.iter().filter(|step| *step != "completed").count()
}

/// Did a row move the work: a successful edit, or a successful command-like tool run?
fn moved(row: &Value) -> bool {
    (row["edit"] == true && row["failed"] != true) || crate::evidence::counts(row, &[])
}

/// Record this Stop (turn, ledger length, message hash, streak); true on the third stop of one human turn that
/// repeats the same message with no moving row between them.
fn stalled(session: &str, entries: &[Value], turn: &str, message: &str) -> bool {
    let run = || -> Option<bool> {
        let path = file(session, "stall")?;
        let prior = read_json(&path);
        let mut hasher = DefaultHasher::new();
        message.trim().hash(&mut hasher);
        let hash = hasher.finish().to_string();
        let old_len = prior["len"]
            .as_u64()
            .and_then(|len| usize::try_from(len).ok());
        let old_len = old_len.filter(|len| *len <= entries.len());
        let quiet = old_len.is_some_and(|len| !entries[len..].iter().any(moved));
        let same =
            prior["t"].as_str() == Some(turn) && prior["hash"].as_str() == Some(hash.as_str());
        let before = prior["streak"].as_u64().unwrap_or(0);
        let streak = if same && quiet { before + 1 } else { 1 };
        let state = json!({"t": turn, "len": entries.len(), "hash": hash, "streak": streak});
        write_atomic(&path, state.to_string().as_bytes())?;
        Some(streak >= 3)
    };
    run().unwrap_or(false)
}

fn open_hit(session: &str, marker: &Value, lower: &str) -> Option<Hit> {
    let question = marker["prompt"]
        .as_str()
        .is_some_and(|prompt| prompt.contains('?'));
    if off("task-open") || question || lower.trim_end().ends_with('?') {
        return None;
    }
    if BLOCKERS.iter().any(|word| lower.contains(word)) {
        return None;
    }
    let open = open_items(session);
    let reason = format!(
        "{open} task items are still open; continue the next ready item or name the blocker."
    );
    (open > 0).then_some(("ARC_TASKS_OPEN", reason))
}

/// "Ready" or "installed" about a build, in a sentence that is not a plan or a doubt.
fn says_ready(lower: &str) -> bool {
    let (mut fenced, mut said) = (false, false);
    for line in lower.lines() {
        fenced ^= line.trim_start().starts_with("```");
        for sentence in line.split(['.', '!', '?', ';']).filter(|_| !fenced) {
            let mut tokens = sentence.split(|c: char| !c.is_alphanumeric());
            let hedged = sentence.contains("n't") || tokens.any(|token| HEDGES.contains(&token));
            said |= !hedged && READY.iter().any(|phrase| sentence.contains(phrase));
        }
    }
    said
}

fn build_hit(rows: &[Value], lower: &str) -> Option<Hit> {
    if off("build-readback") || !lower.contains("build") || !says_ready(lower) {
        return None;
    }
    let read_back = rows.iter().any(|row| {
        let command = row["command"].as_str().unwrap_or("").to_lowercase();
        let reads = ["version", "shasum", "sha256"]
            .iter()
            .any(|word| command.contains(word));
        row["failed"] != true && reads && WHERE.iter().any(|place| command.contains(place))
    });
    let reason = "Read back the installed build's version or hash and compare it to the commit before saying ready.";
    (!read_back).then(|| ("ARC_BUILD_READBACK", reason.to_owned()))
}

/// Stop: the first of the three checks that fires sends the turn back once per human turn.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let payload = request.payload.as_object()?;
    if payload.get("stop_hook_active") == Some(&Value::Bool(true)) {
        return None;
    }
    let message = str_field(payload, &["last_assistant_message", "lastAssistantText"])?;
    let session = session_id(payload)?;
    let entries = ledger(&session);
    let start = entries
        .iter()
        .rposition(|entry| entry["marker"] == "turn")?;
    let turn = entries[start]["t"].to_string();
    let stall = !off("progress-stall") && stalled(&session, &entries, &turn, &message);
    let blocked = file(&session, "blocked")?;
    if fs::read_to_string(&blocked).is_ok_and(|seen| seen == turn) {
        return None;
    }
    let lower = message.to_lowercase();
    let reason = "No progress across three stops with the same message; switch to a ready item, or state the blocker once and stop.";
    let stalled_hit = stall.then(|| ("ARC_NO_PROGRESS", reason.to_owned()));
    let hit = stalled_hit
        .or_else(|| open_hit(&session, &entries[start], &lower))
        .or_else(|| build_hit(&entries[start + 1..], &lower))?;
    write_atomic(&blocked, turn.as_bytes())?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        hit.0,
        hit.1,
        "strong",
    ))
}
