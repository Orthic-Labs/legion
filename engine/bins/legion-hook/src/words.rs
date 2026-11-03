//! Adrian's words, held by the machine: every typed prompt is recorded, standing orders are kept
//! and delivered to every chat, and agents cannot write into the state folder.

use std::path::Path;
use std::{env::var, fs};

use serde_json::{json, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, edit_path, now_secs, off, session_id, state_root, str_field};
use crate::state::{write_atomic, Payload};
use crate::transcript::human;

/// Words that open a standing-order clause.
const OPENERS: &str =
    "from now on|always|never|no more|every time|standing rule|pass this to all|all chats";
const BUDGET: usize = 4096;
const PROTECTED: &str = "The state folder holds Adrian's recorded words and standing orders; agents cannot write there.";

struct Order {
    id: u64,
    session: String,
    text: String,
    /// Orders this record drops; a record that drops is not itself an order.
    drop: Vec<u64>,
}

/// Does a clause of the prompt start with a standing-order opener? Questions and "never mind" do not.
fn is_order(prompt: &str) -> bool {
    prompt
        .split_inclusive(['.', '!', '?', '\n', ';', ':'])
        .any(|clause| {
            let lower = clause.trim().to_lowercase();
            let lower = lower.trim_start_matches("please ");
            let opens = OPENERS.split('|').any(|opener| lower.starts_with(opener));
            opens && !clause.ends_with('?') && !lower.starts_with("never mind")
        })
}

/// The text of a standing order: after `/order`, or a prompt with an opener clause.
fn order_text(prompt: &str) -> Option<String> {
    if let Some(body) = prompt.trim_start().strip_prefix("/order ") {
        return Some(body.trim().to_owned());
    }
    is_order(prompt).then(|| prompt.trim().to_owned())
}

/// Order ids in "drop order 3", "drop orders 2 and 5", "drop standing order #3".
fn drops(prompt: &str) -> Vec<u64> {
    let lower = prompt.to_lowercase();
    let rest = lower
        .split_once("drop ")
        .map(|(_, rest)| rest.trim_start_matches("standing "));
    let Some(rest) = rest.and_then(|rest| rest.strip_prefix("order")) else {
        return Vec::new();
    };
    let split = |c: char| c.is_whitespace() || matches!(c, 's' | ',' | '#' | '&' | '.');
    let ids = rest
        .split(split)
        .filter(|id| !id.is_empty() && *id != "and");
    ids.map_while(|id| id.parse().ok()).collect()
}

fn orders(path: &Path) -> Vec<Order> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let parse = |line: &str| {
        let record: Value = serde_json::from_str(line).ok()?;
        let dropped = record["drop"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_u64).collect());
        Some(Order {
            id: record["id"].as_u64()?,
            session: record["session_id"].as_str()?.to_owned(),
            text: record["text"].as_str()?.to_owned(),
            drop: dropped.unwrap_or_default(),
        })
    };
    text.lines().filter_map(parse).collect()
}

/// Orders no later record has dropped.
fn live(all: &[Order]) -> Vec<&Order> {
    let killed: Vec<u64> = all.iter().flat_map(|order| order.drop.clone()).collect();
    all.iter()
        .filter(|order| order.drop.is_empty() && !killed.contains(&order.id))
        .collect()
}

/// Record the prompt as a standing order, or as a drop of earlier orders, when it is one.
fn record_order(root: &Path, session: &str, prompt: &str, now: u64) {
    let dropped = drops(prompt);
    let text = if dropped.is_empty() {
        order_text(prompt)
    } else {
        Some(prompt.to_owned())
    };
    let Some(text) = text else {
        return;
    };
    let path = root.join("standing-orders.jsonl");
    let known = orders(&path);
    let next = known.iter().map(|order| order.id).max().unwrap_or(0) + 1;
    let text: String = text.chars().take(2000).collect();
    let record =
        json!({"id": next, "t": now, "session_id": session, "text": text, "drop": dropped});
    append_line(&path, &record.to_string());
}

/// The header and the orders newest first, as many as fit in 4 KB.
fn render(header: &str, mut shown: Vec<&Order>) -> Option<String> {
    shown.sort_by_key(|order| std::cmp::Reverse(order.id));
    let mut out = header.to_owned();
    for order in &shown {
        let line = format!("\n#{}: {}", order.id, order.text);
        if out.len() + line.len() > BUDGET {
            break;
        }
        out.push_str(&line);
    }
    (!shown.is_empty()).then_some(out)
}

/// At session start every live order; at a prompt the live orders other chats added since this
/// session last looked. Marks everything as seen.
fn context(root: &Path, session: Option<&str>, startup: bool) -> Option<String> {
    let all = orders(&root.join("standing-orders.jsonl"));
    let newest = all.iter().map(|order| order.id).max()?;
    let seen_file = session.map(|session| root.join("words").join(format!("{session}.seen")));
    let seen = seen_file.as_ref().and_then(|f| fs::read_to_string(f).ok());
    let seen: u64 = seen.and_then(|text| text.trim().parse().ok()).unwrap_or(0);
    if let Some(file) = &seen_file {
        write_atomic(file, newest.to_string().as_bytes());
    }
    let fresh =
        |order: &&Order| startup || (order.id > seen && Some(order.session.as_str()) != session);
    let shown: Vec<&Order> = live(&all).into_iter().filter(fresh).collect();
    let header = if startup {
        "Adrian's standing orders, his own words recorded by the hook, each holding until he drops it:"
    } else {
        "New standing orders Adrian typed in another chat, his own words; follow them from now on:"
    };
    render(header, shown)
}

fn is_event(request: &HookRequest, names: [&str; 2]) -> bool {
    names.contains(&request.event_type.as_str()) && !off("words")
}

/// UserPromptSubmit: record the prompt verbatim, and as a standing order when it is one.
pub fn on_user_prompt(request: &HookRequest) {
    let (Some(payload), Some(root)) = (request.payload.as_object(), state_root()) else {
        return;
    };
    let prompt =
        str_field(payload, &["prompt", "user_prompt", "userPrompt"]).filter(|text| human(text));
    let (Some(prompt), Some(session)) = (prompt, session_id(payload)) else {
        return;
    };
    if !is_event(request, ["UserPromptSubmit", "user-prompt-submit"]) {
        return;
    }
    let cwd = str_field(payload, &["cwd", "workdir"]).unwrap_or_default();
    let record = json!({"t": now_secs(), "session_id": session, "cwd": cwd, "prompt": prompt});
    let file = root.join("words").join(format!("{session}.jsonl"));
    append_line(&file, &record.to_string());
    if !off("orders") {
        record_order(&root, &session, &prompt, now_secs());
    }
}

/// SessionStart (startup, resume, clear, compact): every live standing order, verbatim.
pub fn context_for_session_start(request: &HookRequest) -> Option<String> {
    if !is_event(request, ["SessionStart", "session-start"]) || off("orders") {
        return None;
    }
    let session = session_id(request.payload.as_object()?);
    context(&state_root()?, session.as_deref(), true)
}

/// UserPromptSubmit: standing orders added by other chats since this session last saw them.
pub fn context_for_prompt(request: &HookRequest) -> Option<String> {
    if !is_event(request, ["UserPromptSubmit", "user-prompt-submit"]) || off("orders") {
        return None;
    }
    let session = session_id(request.payload.as_object()?)?;
    context(&state_root()?, Some(session.as_str()), false)
}

/// Add `extra` to a response's additional context, or build an allow response that carries it.
pub fn attach_context(
    response: Option<HookResponse>,
    extra: Option<String>,
    event_type: &str,
) -> Option<HookResponse> {
    let Some(extra) = extra else {
        return response;
    };
    let fallback = || HookResponse::allowed(event_type.to_owned(), "standing orders delivered");
    let mut response = response.unwrap_or_else(fallback);
    response.additional_context = Some(match response.additional_context.take() {
        Some(existing) => format!("{existing}\n\n{extra}"),
        None => extra,
    });
    Some(response)
}

/// Does the command redirect into, or `tee`, `cp`, `mv` or `rm`, a path under the state root?
fn writes_root(command: &str, root: &str, home: &str) -> bool {
    let names = |word: &str| {
        let expanded = word
            .replace("${HOME}", home)
            .replace("$HOME", home)
            .replace('~', home);
        expanded.replace('\\', "/").contains(root)
    };
    crate::command_segments(command).iter().any(|segment| {
        let words = crate::shell_words(crate::strip_command_prefixes(segment));
        let program = words.first().map_or("", |word| crate::program_name(word));
        let redirected = words.iter().enumerate().any(|(index, word)| {
            let tail = word.rsplit('>').next().unwrap_or("");
            let target = if tail.is_empty() {
                words.get(index + 1).map_or("", |next| next.as_str())
            } else {
                tail
            };
            word.contains('>') && names(target)
        });
        redirected
            || (matches!(program, "tee" | "cp" | "mv" | "rm")
                && words.iter().skip(1).any(|word| names(word)))
    })
}

/// PreToolUse: deny edits and shell writes that reach the state folder, so an agent cannot forge a turn.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if off("words") || !request.is_pre_effect() {
        return None;
    }
    let payload: &Payload = request.payload.as_object()?;
    let root = state_root()?.to_string_lossy().replace('\\', "/");
    let home = var("HOME").or(var("USERPROFILE")).unwrap_or_default();
    let inside = |path: String| path == root || path.starts_with(&format!("{root}/"));
    let edited =
        edit_path(payload).is_some_and(|path| inside(path.to_string_lossy().replace('\\', "/")));
    let command = crate::state::tool_input(payload).and_then(crate::command_text);
    if !edited && !command.is_some_and(|command| writes_root(&command, &root, &home)) {
        return None;
    }
    let event = request.event_type.clone();
    Some(HookResponse::denied(
        event,
        "ARC_WORDS_PROTECTED",
        PROTECTED,
        "strong",
    ))
}
