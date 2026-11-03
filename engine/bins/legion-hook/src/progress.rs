//! Tier-0 Stop checks that need no model: a stalled session, open task items, and "ready" with no read-back.
//!
//! All three share one per-session `progress/<session>.blocked` file keyed on the turn marker `t`, so the
//! three together block at most once per human turn. Every read or write failure allows the stop, and a
//! re-entered stop (`stop_hook_active`) is never blocked. Kill switches: `progress-stall`, `task-open`,
//! `build-readback` in `LEGION_HOOK_OFF`.

use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, now_secs, write_atomic};
use crate::state::{ledger, off, session_id, state_dir, str_field, tool_input, tool_name};

/// Words that name a blocker, so a stop with open items is a report and not an abandonment.
const BLOCKERS: [&str; 10] = [
    "blocked",
    "blocker",
    "waiting on",
    "waiting for",
    "needs adrian",
    "need adrian",
    "running",
    "in the background",
    "pending agent",
    "background",
];
/// Phrases that tell Adrian a build is ready to try.
const READY: [&str; 4] = ["test it", "ready for you", "ready to test", "installed"];
/// A sentence with one of these tokens is a plan or a doubt, not a ready claim.
const HEDGES: [&str; 12] = [
    "will", "ll", "not", "if", "once", "after", "before", "until", "no", "nothing", "never",
    "without",
];
/// A ready claim must sit in a sentence about a build or an install.
const BUILD: [&str; 4] = ["build", "builds", "install", "installed"];
/// Commands that read a version or a hash back.
const READS: [&str; 6] = [
    "version",
    "shasum",
    "sha256",
    "get-filehash",
    "b3sum",
    "codesign -dv",
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
    let items = input.get("items").or(input.get("plan"));
    if let Some(items) = items.and_then(Value::as_array) {
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

/// PostToolUse: append one event per task or plan tool call (and per background launch) to the session's event
/// files, because the evidence ledger does not keep their input. Appends never race; `open_items` replays them.
pub fn observe_post_tool(request: &HookRequest) {
    let _ = record(request);
}

/// The task id a TaskCreate response names ("Task #N created ..."), when it names one.
fn created_id(payload: &serde_json::Map<String, Value>) -> Option<String> {
    let response = payload
        .get("tool_response")
        .or_else(|| payload.get("toolResponse"))?;
    let text = response
        .as_str()
        .map_or_else(|| response.to_string(), str::to_owned);
    let after = text.split_once('#')?.1;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

fn record(request: &HookRequest) -> Option<()> {
    if !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect") || off("task-open") {
        return None;
    }
    let payload = request.payload.as_object()?;
    if payload.contains_key("agent_id") || payload.contains_key("agentId") {
        return None;
    }
    let tool = tool_name(payload)?;
    let session = session_id(payload)?;
    let at = now_secs();
    let input = tool_input(payload);
    if input.and_then(|input| input.get("run_in_background")) == Some(&Value::Bool(true)) {
        let _ = file(&session, "bg")
            .and_then(|path| append_line(&path, &json!({"at": at}).to_string()));
    }
    let event = if tool == "TaskCreate" {
        json!({"at": at, "k": "create", "id": created_id(payload)})
    } else if tool == "TaskUpdate" {
        let input = input?;
        let id = input.get("taskId").or(input.get("id")).and_then(id_text)?;
        json!({"at": at, "k": "update", "id": id, "status": input.get("status")})
    } else if tool.ends_with("ccd_turn__wrap_up") {
        json!({"at": at, "k": "wrap"})
    } else if tool.ends_with("update_plan") {
        json!({"at": at, "k": "plan", "input": input?})
    } else {
        return None;
    };
    append_line(&file(&session, "tasks.jsonl")?, &event.to_string())
}

/// Items still open from events recorded at or after `since` (the current human turn's start): created tasks not
/// closed, plus plan steps not completed. Zero when nothing was recorded this turn.
fn open_items(session: &str, since: u64) -> usize {
    let path = file(session, "tasks.jsonl");
    let text = path.and_then(|path| fs::read_to_string(path).ok());
    let mut tasks: BTreeSet<String> = BTreeSet::new();
    let mut plan: Vec<String> = Vec::new();
    let mut created = 0u64;
    let events = text.unwrap_or_default();
    let events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok());
    for event in events {
        if event["at"].as_u64().is_none_or(|at| at < since) {
            continue;
        }
        match event["k"].as_str() {
            Some("create") => {
                created += 1;
                let id = id_text(&event["id"]).unwrap_or_else(|| created.to_string());
                tasks.insert(id);
            }
            Some("update") => {
                let id = id_text(&event["id"]);
                match (id, event["status"].as_str()) {
                    (Some(id), Some("completed" | "deleted")) => {
                        tasks.remove(&id);
                    }
                    (Some(id), Some(_)) => {
                        tasks.insert(id);
                    }
                    _ => {}
                }
            }
            Some("plan") => {
                if let Some(input) = event["input"].as_object() {
                    apply_plan(&mut plan, input);
                }
            }
            Some("wrap") => plan
                .iter_mut()
                .for_each(|step| "completed".clone_into(step)),
            _ => {}
        }
    }
    tasks.len() + plan.iter().filter(|step| *step != "completed").count()
}

/// Did this turn launch a subagent or a background run, so a stop with open items is a wait and not an abandonment?
fn waiting_on_background(session: &str, rows: &[Value], since: u64) -> bool {
    let agent = rows
        .iter()
        .any(|row| matches!(row["tool"].as_str(), Some("Agent" | "Task")));
    let path = file(session, "bg");
    let text = path.and_then(|path| fs::read_to_string(path).ok());
    let background = text.unwrap_or_default().lines().any(|line| {
        let row: Value = serde_json::from_str(line).unwrap_or(Value::Null);
        row["at"].as_u64().is_some_and(|at| at >= since)
    });
    agent || background
}

/// Did a row move the work: a successful edit, or a successful command-like tool run?
fn moved(row: &Value) -> bool {
    (row["edit"] == true && row["failed"] != true) || crate::evidence::counts(row, &[])
}

/// Record this Stop (turn, ledger length, message hash, streak); true on the third stop of one human turn that
/// repeats the same message with no moving row between them.
fn stalled(session: &str, entries: &[Value], turn: &str, message: &str) -> bool {
    stall_streak(session, entries, turn, message).unwrap_or(false)
}

fn stall_streak(session: &str, entries: &[Value], turn: &str, message: &str) -> Option<bool> {
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
    let same = prior["t"].as_str() == Some(turn) && prior["hash"].as_str() == Some(hash.as_str());
    let before = prior["streak"].as_u64().unwrap_or(0);
    let streak = if same && quiet { before + 1 } else { 1 };
    let state = json!({"t": turn, "len": entries.len(), "hash": hash, "streak": streak});
    write_atomic(&path, state.to_string().as_bytes())?;
    Some(streak >= 3)
}

fn open_hit(session: &str, entries: &[Value], start: usize, lower: &str) -> Option<Hit> {
    let marker = &entries[start];
    let question = marker["prompt"]
        .as_str()
        .is_some_and(|prompt| prompt.contains('?'));
    if off("task-open") || question || lower.trim_end().ends_with('?') {
        return None;
    }
    if BLOCKERS.iter().any(|word| lower.contains(word)) {
        return None;
    }
    let since = marker["t"].as_u64()?;
    if waiting_on_background(session, &entries[start + 1..], since) {
        return None;
    }
    let open = open_items(session, since);
    let reason = format!(
        "{open} task items are still open; continue the next ready item or name the blocker."
    );
    (open > 0).then_some(("ARC_TASKS_OPEN", reason))
}

/// Does `phrase` (space-separated words) occur in `tokens` as a whole-word sequence?
fn has_phrase(tokens: &[&str], phrase: &str) -> bool {
    let words: Vec<&str> = phrase.split(' ').collect();
    tokens
        .windows(words.len())
        .any(|window| window == words.as_slice())
}

/// "Ready" or "installed" about a build, in a sentence that is not a plan or a doubt.
fn says_ready(lower: &str) -> bool {
    let (mut fenced, mut said) = (false, false);
    for line in lower.lines() {
        fenced ^= line.trim_start().starts_with("```");
        for sentence in line.split(['.', '!', '?', ';']).filter(|_| !fenced) {
            let split = sentence.split(|c: char| !c.is_alphanumeric());
            let tokens: Vec<&str> = split.filter(|token| !token.is_empty()).collect();
            let hedged = sentence.contains("n't") || tokens.iter().any(|t| HEDGES.contains(t));
            let build = tokens.iter().any(|t| BUILD.contains(t));
            let ready = READY.iter().any(|phrase| has_phrase(&tokens, phrase));
            said |= !hedged && build && ready;
        }
    }
    said
}

fn build_hit(rows: &[Value], lower: &str) -> Option<Hit> {
    if off("build-readback") || !says_ready(lower) {
        return None;
    }
    let read_back = rows.iter().any(|row| {
        let command = row["command"].as_str().unwrap_or("").to_lowercase();
        let reads = READS.iter().any(|word| command.contains(word));
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
        .or_else(|| open_hit(&session, &entries, start, &lower))
        .or_else(|| build_hit(&entries[start + 1..], &lower))?;
    write_atomic(&blocked, turn.as_bytes())?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        hit.0,
        hit.1,
        "strong",
    ))
}
