//! Adrian's words, held by the machine (fix plan M1). Two check ids:
//!
//! - `words`: every genuine typed user turn is appended verbatim to
//!   `<state>/words/<session>.jsonl` (`{t, session_id, cwd, prompt}`), and
//!   `PreToolUse` denies agent writes into the state folder (`~/.legion`, or
//!   `$LEGION_STATE_DIR`) so an agent cannot forge a turn or an order
//!   (`ARC_WORDS_PROTECTED`).
//! - `orders`: a turn that is a standing order is appended to
//!   `<state>/standing-orders.jsonl` (`{id, t, session_id, cwd, text}`). The
//!   file is append-only: "drop order N" and "replace order N with ..." append
//!   a record that names the old id (`drop` / `supersedes`), and an order is
//!   live while no later record names it. `SessionStart` injects every live
//!   order; `UserPromptSubmit` injects the orders other chats added since this
//!   session last saw them. Detection is deterministic and uses no model.
//!
//! Prompts that are not Adrian typing (Pulse relays, task notifications,
//! system reminders, side-session events) are never recorded.
//!
//! Every entry point fails open: an unreadable file or a missing field means
//! "record nothing / inject nothing / allow". `LEGION_HOOK_OFF` (a comma list)
//! naming `words` or `orders` disables that check.
//!
//! The shell lexer and wrapper helpers below are `pub(crate)` because
//! `red_gate` classifies commands with them.

use std::{
    fs,
    io::{self, Write},
    path::Path,
    thread,
    time::Duration,
};

use serde_json::{json, Map, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::skills_gate::{
    check_disabled, now_secs, session_id, state_root, str_field, tool_input, tool_name,
    write_atomic,
};

pub const CHECK_WORDS: &str = "words";
pub const CHECK_ORDERS: &str = "orders";
pub const PROTECTED_CODE: &str = "ARC_WORDS_PROTECTED";

const WORDS_FOLDER: &str = "words";
const ORDERS_FILE: &str = "standing-orders.jsonl";
const LOCK_FILE: &str = "standing-orders.lock";
const MAX_WORDS_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ORDERS_FILE_BYTES: u64 = 8 * 1024 * 1024;
const CONTEXT_BUDGET: usize = 4096;
const ORDER_STORE_CHARS: usize = 2000;
const ORDER_SHOW_CHARS: usize = 1000;
const SHORT_PROMPT_CHARS: usize = 1500;
const MAX_ORDER_PARAGRAPHS: usize = 3;
const MAX_SHELL_DEPTH: u8 = 3;

/// Shell-like tools (Claude Code and Codex names).
pub(crate) const SHELL_TOOLS: [&str; 6] = [
    "Bash",
    "PowerShell",
    "exec_command",
    "shell",
    "shell_command",
    "local_shell",
];

/// Prompt prefixes (lowercase) that are not Adrian typing.
const SYNTHETIC_PREFIXES: [&str; 6] = [
    "[pulse chat",
    "<task-notification",
    "<system-reminder",
    "<side-sessions-event",
    "[request interrupted",
    "<local-command",
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn is_user_prompt_event(event_type: &str) -> bool {
    matches!(event_type, "UserPromptSubmit" | "user-prompt-submit")
}

fn is_session_start_event(event_type: &str) -> bool {
    matches!(event_type, "SessionStart" | "session-start")
}

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

fn truncate_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

fn cap_bytes(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

/// Append one line with a single `write_all` on an append-mode handle.
fn append_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut data = String::with_capacity(line.len() + 1);
    data.push_str(line);
    data.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(data.as_bytes())
}

/// Run `body` while holding `<dir>/standing-orders.lock` (best effort): the
/// lock is a `create_new` file, a lock older than five seconds is stolen, and
/// after about 500 ms the body runs without it.
fn with_lock<T>(dir: &Path, body: impl FnOnce() -> T) -> T {
    let lock = dir.join(LOCK_FILE);
    let _ = fs::create_dir_all(dir);
    let mut held = false;
    for _ in 0..50 {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(_) => {
                held = true;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&lock)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= Duration::from_secs(5));
                if stale {
                    let _ = fs::remove_file(&lock);
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            Err(_) => break,
        }
    }
    let result = body();
    if held {
        let _ = fs::remove_file(&lock);
    }
    result
}

// ---------------------------------------------------------------------------
// Dates (no date crate in this binary)
// ---------------------------------------------------------------------------

/// Civil date for a day count since 1970-01-01 (proleptic Gregorian).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `YYYY-MM-DD` (UTC) for epoch seconds.
fn format_date(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

// ---------------------------------------------------------------------------
// Recognising Adrian's turns and standing orders (pure)
// ---------------------------------------------------------------------------

/// The prompt text exactly as the host sent it (not trimmed), or `None` when
/// it is blank.
fn raw_prompt(payload: &Map<String, Value>) -> Option<String> {
    ["prompt", "user_prompt", "userPrompt"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
        .filter(|text| !text.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// Pulse relays, task notifications, system reminders and similar host
/// messages are not Adrian typing.
fn prompt_is_synthetic(prompt: &str) -> bool {
    let head: String = prompt
        .trim_start()
        .chars()
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    SYNTHETIC_PREFIXES
        .iter()
        .any(|prefix| head.starts_with(*prefix))
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Phrases that mark a standing order wherever they appear.
const STRONG_PHRASES: &[&[&str]] = &[
    &["from", "now", "on"],
    &["standing", "rule"],
    &["standing", "order"],
    &["pass", "this", "to", "all"],
    &["pass", "this", "on", "to", "all"],
    &["every", "chat"],
    &["all", "chats"],
];

/// Words that may precede a directive at the start of a clause.
const FILLERS: [&str; 9] = [
    "please", "and", "but", "also", "so", "then", "ok", "okay", "now",
];

/// Words that make a following "always" or "never" an instruction.
const AUXILIARIES: [&str; 8] = [
    "must", "should", "shall", "to", "agents", "chats", "just", "please",
];

fn contains_phrase(tokens: &[String], phrase: &[&str]) -> bool {
    if phrase.is_empty() || tokens.len() < phrase.len() {
        return false;
    }
    tokens.windows(phrase.len()).any(|window| {
        window
            .iter()
            .zip(phrase)
            .all(|(token, word)| token.as_str() == *word)
    })
}

/// Clauses of `text` and whether each ended in a question mark.
fn clauses(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if matches!(c, '.' | '!' | '?' | '\n' | ';' | ':') {
            if !current.trim().is_empty() {
                out.push((std::mem::take(&mut current), c == '?'));
            } else {
                current.clear();
            }
        } else {
            current.push(c);
        }
    }
    if !current.trim().is_empty() {
        out.push((current, false));
    }
    out
}

/// "Always ...", "Never ...", "Every time ...", "No more ..." at the start of
/// a clause, or "must/should/to always|never".
fn weak_directive(t: &[String]) -> bool {
    let mut i = 0;
    while i < t.len() && FILLERS.contains(&t[i].as_str()) {
        i += 1;
    }
    if i < t.len() {
        let first = t[i].as_str();
        let second = t.get(i + 1).map(String::as_str);
        if first == "always" || (first == "never" && second != Some("mind")) {
            return true;
        }
        if (first == "every" && second == Some("time")) || (first == "no" && second == Some("more"))
        {
            return true;
        }
    }
    (1..t.len()).any(|j| {
        matches!(t[j].as_str(), "always" | "never") && AUXILIARIES.contains(&t[j - 1].as_str())
    })
}

fn qualifies(text: &str) -> bool {
    let all = tokens(text);
    if STRONG_PHRASES
        .iter()
        .any(|phrase| contains_phrase(&all, phrase))
    {
        return true;
    }
    clauses(text)
        .iter()
        .any(|(clause, question)| !*question && weak_directive(&tokens(clause)))
}

fn paragraphs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                out.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        out.push(current.join("\n"));
    }
    out
}

/// The part of a turn that is the order: the whole turn when it is short,
/// otherwise only the paragraphs that qualify.
fn order_text(prompt: &str) -> Option<String> {
    if !qualifies(prompt) {
        return None;
    }
    if prompt.chars().count() <= SHORT_PROMPT_CHARS {
        return Some(prompt.to_owned());
    }
    let picked: Vec<String> = paragraphs(prompt)
        .into_iter()
        .filter(|paragraph| qualifies(paragraph))
        .take(MAX_ORDER_PARAGRAPHS)
        .collect();
    if picked.is_empty() {
        None
    } else {
        Some(picked.join("\n\n"))
    }
}

fn cap_order_text(text: &str) -> String {
    let trimmed = text.trim();
    let kept = truncate_chars(trimmed, ORDER_STORE_CHARS);
    if kept.len() < trimmed.len() {
        format!("{kept}\n[truncated; the full turn is in the words log]")
    } else {
        kept.to_owned()
    }
}

fn tag_text<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(&text[start..end])
}

/// The text after a leading `/order` command (typed, or expanded by the host
/// into `<command-name>/order</command-name><command-args>...`).
fn order_command_body(prompt: &str) -> Option<String> {
    let trimmed = prompt.trim_start();
    if let Some(rest) = trimmed.strip_prefix("/order") {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return Some(rest.trim().to_owned());
        }
    }
    if !trimmed.starts_with("<command-") {
        return None;
    }
    let name = tag_text(trimmed, "command-name")?;
    if name.trim().trim_start_matches('/') != "order" {
        return None;
    }
    Some(
        tag_text(trimmed, "command-args")
            .unwrap_or("")
            .trim()
            .to_owned(),
    )
}

/// True when `lower[index..]` starts a clause: start of text, after sentence
/// punctuation or a newline, or after a filler word such as "please".
fn at_clause_start(lower: &str, index: usize) -> bool {
    let before = lower[..index].trim_end_matches([' ', '\t']);
    if before.is_empty() || before.ends_with(['\n', '.', '!', ';', ':']) {
        return true;
    }
    let last_word = before
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("");
    FILLERS.contains(&last_word)
}

/// Order ids in "3", "3, 5", "#3 and #5".
fn parse_ids(text: &str) -> Vec<u64> {
    let mut ids = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, ',' | '#' | '&'));
        if let Some(after) = rest.strip_prefix("and") {
            if after.starts_with(char::is_whitespace) || after.starts_with('#') {
                rest = after;
                continue;
            }
        }
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        match digits.parse::<u64>() {
            Ok(id) => ids.push(id),
            Err(_) => break,
        }
        rest = &rest[digits.len()..];
        if ids.len() >= 16 {
            break;
        }
    }
    ids
}

/// "drop order 3", "drop orders 2 and 5", "drop standing order #3".
fn parse_drop(body: &str) -> Option<Vec<u64>> {
    let lower = body.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find("drop") {
        let index = from + found;
        from = index + 4;
        if index > 0 && lower.as_bytes()[index - 1].is_ascii_alphanumeric() {
            continue;
        }
        if !at_clause_start(&lower, index) {
            continue;
        }
        let mut rest = lower[index + 4..].trim_start();
        if let Some(after) = rest.strip_prefix("standing") {
            rest = after.trim_start();
        }
        let Some(after) = rest.strip_prefix("order") else {
            continue;
        };
        let after = after.strip_prefix('s').unwrap_or(after);
        let ids = parse_ids(after);
        if !ids.is_empty() {
            return Some(ids);
        }
    }
    None
}

/// Skip whitespace in `lower` from `cursor`, then match `word`; returns the
/// cursor after the word.
fn eat(lower: &str, cursor: usize, word: &str) -> Option<usize> {
    let rest = &lower[cursor..];
    let trimmed = rest.trim_start();
    let skipped = rest.len() - trimmed.len();
    trimmed
        .strip_prefix(word)
        .map(|_| cursor + skipped + word.len())
}

/// "replace order 4 with <text>" (also "replace order 4: <text>").
fn parse_replace(body: &str) -> Option<(u64, String)> {
    let lower = body.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find("replace") {
        let index = from + found;
        from = index + 7;
        if index > 0 && lower.as_bytes()[index - 1].is_ascii_alphanumeric() {
            continue;
        }
        if !at_clause_start(&lower, index) {
            continue;
        }
        let mut cursor = index + 7;
        if let Some(next) = eat(&lower, cursor, "standing") {
            cursor = next;
        }
        let Some(next) = eat(&lower, cursor, "order") else {
            continue;
        };
        cursor = next;
        let after = &lower[cursor..];
        let trimmed = after.trim_start_matches(|c: char| c.is_whitespace() || c == '#');
        let skipped = after.len() - trimmed.len();
        let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
        let Ok(target) = digits.parse::<u64>() else {
            continue;
        };
        cursor += skipped + digits.len();
        let tail = lower[cursor..].trim_start();
        cursor += lower[cursor..].len() - tail.len();
        let replacement = if tail.starts_with("with")
            && tail[4..]
                .chars()
                .next()
                .map_or(true, |c| !c.is_alphanumeric())
        {
            &body[cursor + 4..]
        } else if tail.starts_with(':') {
            &body[cursor + 1..]
        } else {
            continue;
        };
        let text = replacement
            .trim_start_matches(|c: char| c == ':' || c.is_whitespace())
            .trim();
        if text.is_empty() {
            continue;
        }
        return Some((target, text.to_owned()));
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Directive {
    None,
    Order(String),
    Drop(Vec<u64>),
    Replace(u64, String),
}

/// What an Adrian turn means for the standing orders.
fn classify(prompt: &str) -> Directive {
    let (body, explicit) = match order_command_body(prompt) {
        Some(rest) => (rest, true),
        None => (prompt.trim().to_owned(), false),
    };
    if body.is_empty() {
        return Directive::None;
    }
    if !body.ends_with('?') {
        if let Some((target, text)) = parse_replace(&body) {
            return Directive::Replace(target, cap_order_text(&text));
        }
        if let Some(ids) = parse_drop(&body) {
            return Directive::Drop(ids);
        }
    }
    if explicit {
        return Directive::Order(cap_order_text(&body));
    }
    match order_text(&body) {
        Some(text) => Directive::Order(cap_order_text(&text)),
        None => Directive::None,
    }
}

// ---------------------------------------------------------------------------
// The standing-orders log
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Order {
    id: u64,
    t: u64,
    session: String,
    text: String,
    supersedes: Vec<u64>,
    dropped: Vec<u64>,
}

fn id_list(value: Option<&Value>) -> Vec<u64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn parse_order_line(line: &str) -> Option<Order> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let id = value.get("id")?.as_u64()?;
    Some(Order {
        id,
        t: value.get("t").and_then(Value::as_u64).unwrap_or(0),
        session: value
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        text: value
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        supersedes: id_list(value.get("supersedes")),
        dropped: id_list(value.get("drop")),
    })
}

/// All records, oldest first. A missing file is an empty log; an unreadable or
/// oversized one is `None` so callers do nothing rather than guess.
fn read_orders(path: &Path) -> Option<Vec<Order>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    if meta.len() > MAX_ORDERS_FILE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    Some(
        String::from_utf8_lossy(&bytes)
            .lines()
            .filter_map(parse_order_line)
            .collect(),
    )
}

/// Orders no later record has dropped or superseded.
fn live_orders(entries: &[Order]) -> Vec<&Order> {
    let mut killed: Vec<u64> = Vec::new();
    for entry in entries {
        killed.extend(entry.supersedes.iter().copied());
        killed.extend(entry.dropped.iter().copied());
    }
    entries
        .iter()
        .filter(|entry| entry.dropped.is_empty() && !killed.contains(&entry.id))
        .collect()
}

fn order_record(
    id: u64,
    t: u64,
    session: &str,
    cwd: &str,
    text: &str,
    supersedes: &[u64],
    dropped: &[u64],
) -> String {
    let mut record = json!({
        "id": id,
        "t": t,
        "session_id": session,
        "cwd": cwd,
        "text": text,
    });
    if let Some(object) = record.as_object_mut() {
        if !supersedes.is_empty() {
            object.insert("supersedes".into(), json!(supersedes));
        }
        if !dropped.is_empty() {
            object.insert("drop".into(), json!(dropped));
        }
    }
    record.to_string()
}

fn words_path(root: &Path, session: &str) -> std::path::PathBuf {
    root.join(WORDS_FOLDER)
        .join(format!("{}.jsonl", safe_name(session)))
}

fn seen_path(root: &Path, session: &str) -> std::path::PathBuf {
    root.join(WORDS_FOLDER)
        .join(format!("{}.seen", safe_name(session)))
}

fn read_seen(root: &Path, session: &str) -> Option<u64> {
    fs::read_to_string(seen_path(root, session))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn write_seen(root: &Path, session: &str, id: u64) -> io::Result<()> {
    write_atomic(&seen_path(root, session), format!("{id}\n").as_bytes())
}

// ---------------------------------------------------------------------------
// UserPromptSubmit: record
// ---------------------------------------------------------------------------

fn record_words(root: &Path, session: &str, cwd: &str, prompt: &str, now: u64) -> io::Result<()> {
    let path = words_path(root, session);
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_WORDS_FILE_BYTES) {
        return Ok(());
    }
    let line = json!({
        "t": now,
        "session_id": session,
        "cwd": cwd,
        "prompt": prompt,
    })
    .to_string();
    append_line(&path, &line)
}

fn record_directive(
    root: &Path,
    session: &str,
    cwd: &str,
    prompt: &str,
    now: u64,
) -> io::Result<()> {
    let directive = classify(prompt);
    if directive == Directive::None {
        return Ok(());
    }
    let path = root.join(ORDERS_FILE);
    let note = cap_order_text(prompt);
    with_lock(root, || -> io::Result<()> {
        let Some(entries) = read_orders(&path) else {
            return Ok(());
        };
        let live_ids: Vec<u64> = live_orders(&entries).iter().map(|order| order.id).collect();
        let id = entries.iter().map(|order| order.id).max().unwrap_or(0) + 1;
        let record = match directive {
            Directive::Order(text) => order_record(id, now, session, cwd, &text, &[], &[]),
            Directive::Replace(target, text) => {
                if !live_ids.contains(&target) {
                    return Ok(());
                }
                order_record(id, now, session, cwd, &text, &[target], &[])
            }
            Directive::Drop(targets) => {
                let hit: Vec<u64> = targets
                    .into_iter()
                    .filter(|target| live_ids.contains(target))
                    .collect();
                if hit.is_empty() {
                    return Ok(());
                }
                order_record(id, now, session, cwd, &note, &[], &hit)
            }
            Directive::None => return Ok(()),
        };
        append_line(&path, &record)
    })
}

/// UserPromptSubmit: record the turn verbatim, and record it again as a
/// standing order (or a drop / replace) when it is one. Observation only: the
/// lead calls this first, then `context_for_prompt`, then the other checks.
pub fn on_user_prompt(request: &HookRequest) {
    if !is_user_prompt_event(&request.event_type) {
        return;
    }
    let words_on = !check_disabled(CHECK_WORDS);
    let orders_on = !check_disabled(CHECK_ORDERS);
    if !words_on && !orders_on {
        return;
    }
    if let Some(root) = state_root() {
        on_user_prompt_in(&root, request, now_secs(), words_on, orders_on);
    }
}

fn on_user_prompt_in(
    root: &Path,
    request: &HookRequest,
    now: u64,
    words_on: bool,
    orders_on: bool,
) {
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    let Some(prompt) = raw_prompt(payload) else {
        return;
    };
    if prompt_is_synthetic(&prompt) {
        return;
    }
    let Some(session) = session_id(payload) else {
        return;
    };
    let cwd = str_field(payload, &["cwd", "workdir"]).unwrap_or_default();
    if words_on {
        let _ = record_words(root, &session, &cwd, &prompt, now);
    }
    if orders_on {
        let _ = record_directive(root, &session, &cwd, &prompt, now);
    }
}

// ---------------------------------------------------------------------------
// Delivery: SessionStart and UserPromptSubmit context
// ---------------------------------------------------------------------------

const SESSION_HEADER: &str = "Adrian's standing orders. His own words, recorded verbatim by the hook, newest first; each holds until he drops it:";
const PROMPT_HEADER: &str = "New standing order(s) Adrian typed in another chat. His own words, recorded verbatim by the hook; follow them from now on:";

fn order_line(order: &Order) -> String {
    let mut text = truncate_chars(&order.text, ORDER_SHOW_CHARS).to_owned();
    if text.len() < order.text.len() {
        text.push_str(" [truncated]");
    }
    let replaces = if order.supersedes.is_empty() {
        String::new()
    } else {
        let ids: Vec<String> = order.supersedes.iter().map(|id| format!("#{id}")).collect();
        format!(", replaces {}", ids.join(" "))
    };
    format!(
        "#{} ({}{}): {}",
        order.id,
        format_date(order.t),
        replaces,
        text.replace('\n', "\n  ")
    )
}

fn hidden_footer(count: usize, path: &Path) -> String {
    format!(
        "({count} older standing order(s) not shown; all are in {})",
        path.display()
    )
}

/// `header`, then orders newest first until the 4 KB budget is used, then a
/// line counting the orders left out.
fn render_orders(header: &str, items: &[&Order], path: &Path) -> String {
    let mut sorted: Vec<&Order> = items.to_vec();
    sorted.sort_by(|a, b| b.id.cmp(&a.id));
    let reserve = hidden_footer(sorted.len(), path).len() + 1;
    let mut out = String::from(header);
    let mut shown = 0usize;
    for order in &sorted {
        let line = order_line(order);
        if shown > 0 && out.len() + 1 + line.len() + reserve > CONTEXT_BUDGET {
            break;
        }
        out.push('\n');
        out.push_str(&line);
        shown += 1;
    }
    let hidden = sorted.len() - shown;
    if hidden > 0 {
        out.push('\n');
        out.push_str(&hidden_footer(hidden, path));
    }
    cap_bytes(out, CONTEXT_BUDGET)
}

/// SessionStart (startup, resume, clear, compact): every live order, verbatim
/// with its date, at most 4 KB. The lead appends this to the SessionStart
/// context. Marks the session as having seen every order so far.
pub fn context_for_session_start(request: &HookRequest) -> Option<String> {
    if check_disabled(CHECK_ORDERS) || !is_session_start_event(&request.event_type) {
        return None;
    }
    let root = state_root()?;
    let session = request.payload.as_object().and_then(session_id);
    context_for_session_start_in(&root, session.as_deref())
}

fn context_for_session_start_in(root: &Path, session: Option<&str>) -> Option<String> {
    let path = root.join(ORDERS_FILE);
    let entries = read_orders(&path)?;
    let max_id = entries.iter().map(|order| order.id).max()?;
    if let Some(session) = session {
        let _ = write_seen(root, session, max_id);
    }
    let live = live_orders(&entries);
    if live.is_empty() {
        return None;
    }
    Some(render_orders(SESSION_HEADER, &live, &path))
}

/// UserPromptSubmit: orders other chats added since this session last saw
/// them, plus a note for orders they dropped. Orders typed in this chat are
/// never echoed back. Advances this session's last-seen id.
pub fn context_for_prompt(request: &HookRequest) -> Option<String> {
    if check_disabled(CHECK_ORDERS) || !is_user_prompt_event(&request.event_type) {
        return None;
    }
    let payload = request.payload.as_object()?;
    let session = session_id(payload)?;
    let root = state_root()?;
    context_for_prompt_in(&root, &session)
}

fn context_for_prompt_in(root: &Path, session: &str) -> Option<String> {
    let path = root.join(ORDERS_FILE);
    let entries = read_orders(&path)?;
    let max_id = entries.iter().map(|order| order.id).max()?;
    let last = read_seen(root, session).unwrap_or(0);
    if max_id <= last {
        return None;
    }
    let fresh: Vec<&Order> = live_orders(&entries)
        .into_iter()
        .filter(|order| order.id > last && order.session != session)
        .collect();
    let mut dropped: Vec<u64> = entries
        .iter()
        .filter(|entry| entry.id > last && entry.session != session)
        .flat_map(|entry| entry.dropped.iter().copied())
        .filter(|id| *id <= last)
        .collect();
    dropped.sort_unstable();
    dropped.dedup();
    let _ = write_seen(root, session, max_id);
    let mut parts: Vec<String> = Vec::new();
    if !fresh.is_empty() {
        parts.push(render_orders(PROMPT_HEADER, &fresh, &path));
    }
    if !dropped.is_empty() {
        let ids: Vec<String> = dropped.iter().map(|id| format!("#{id}")).collect();
        parts.push(format!(
            "Adrian dropped standing order(s) {} in another chat; they no longer apply.",
            ids.join(" ")
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Add `extra` to `response`'s additional context, or build an allow response
/// that carries it. Lets the lead merge this module's context with another
/// check's response without caring which one fired.
pub fn attach_context(
    response: Option<HookResponse>,
    extra: Option<String>,
    event_type: &str,
) -> Option<HookResponse> {
    let Some(extra) = extra else {
        return response;
    };
    Some(match response {
        Some(mut response) => {
            let combined = match response.additional_context.take() {
                Some(existing) => format!("{existing}\n\n{extra}"),
                None => extra,
            };
            response.additional_context = Some(combined);
            response
        }
        None => HookResponse::allowed(event_type.to_owned(), "standing orders delivered")
            .with_additional_context(extra),
    })
}

// ---------------------------------------------------------------------------
// Shell lexing (shared with `red_gate`)
// ---------------------------------------------------------------------------

/// One simple command: its words, and the targets of its output redirects
/// (`>`, `>>`, `>|`, `&>`, `<>`, and `>&file`; `2>&1` and input redirects are
/// not targets).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) words: Vec<String>,
    pub(crate) redirects: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    None,
    Write,
    Dup,
    Read,
}

struct Lexer {
    segments: Vec<Segment>,
    segment: Segment,
    current: String,
    in_word: bool,
    pending: Pending,
}

impl Lexer {
    fn flush_word(&mut self) {
        if !self.in_word {
            return;
        }
        let word = std::mem::take(&mut self.current);
        self.in_word = false;
        match std::mem::replace(&mut self.pending, Pending::None) {
            Pending::None => self.segment.words.push(word),
            Pending::Write => self.segment.redirects.push(word),
            Pending::Dup => {
                if !(word == "-" || word.chars().all(|c| c.is_ascii_digit())) {
                    self.segment.redirects.push(word);
                }
            }
            Pending::Read => {}
        }
    }

    fn end_segment(&mut self) {
        self.flush_word();
        self.pending = Pending::None;
        let segment = std::mem::take(&mut self.segment);
        if !segment.words.is_empty() || !segment.redirects.is_empty() {
            self.segments.push(segment);
        }
    }
}

/// Split a shell command into simple commands. Quotes group words (their
/// contents are never operators), `;` `|` `&` `(` `)` backticks and newlines
/// end a command, redirect operators are recognised outside quotes, and
/// heredoc bodies are skipped. Variables are not expanded here.
pub(crate) fn shell_segments(command: &str) -> Vec<Segment> {
    let chars: Vec<char> = command.chars().collect();
    let mut lexer = Lexer {
        segments: Vec::new(),
        segment: Segment::default(),
        current: String::new(),
        in_word: false,
        pending: Pending::None,
    };
    let mut heredocs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                lexer.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    lexer.current.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                lexer.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\'
                        && i + 1 < chars.len()
                        && matches!(chars[i + 1], '"' | '\\' | '$' | '`')
                    {
                        lexer.current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        lexer.current.push(chars[i]);
                        i += 1;
                    }
                }
                i += 1;
            }
            '\\' => {
                if i + 1 < chars.len() && chars[i + 1] != '\n' {
                    lexer.current.push(chars[i + 1]);
                    lexer.in_word = true;
                }
                i += 2;
            }
            ' ' | '\t' | '\r' => {
                lexer.flush_word();
                i += 1;
            }
            '\n' => {
                lexer.end_segment();
                i += 1;
                for delimiter in std::mem::take(&mut heredocs) {
                    while i < chars.len() {
                        let start = i;
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        let line: String = chars[start..i].iter().collect();
                        i = (i + 1).min(chars.len());
                        if line.trim() == delimiter {
                            break;
                        }
                    }
                }
            }
            ';' | '|' | '(' | ')' | '`' => {
                lexer.end_segment();
                i += 1;
            }
            '&' => {
                if chars.get(i + 1) == Some(&'>') {
                    lexer.flush_word();
                    lexer.pending = Pending::Write;
                    i += 2;
                    if chars.get(i) == Some(&'>') {
                        i += 1;
                    }
                } else {
                    lexer.end_segment();
                    i += 1;
                }
            }
            '>' => {
                if lexer.in_word && lexer.current.chars().all(|ch| ch.is_ascii_digit()) {
                    lexer.current.clear();
                    lexer.in_word = false;
                } else {
                    lexer.flush_word();
                }
                i += 1;
                let mut pending = Pending::Write;
                match chars.get(i).copied() {
                    Some('>') | Some('|') => i += 1,
                    Some('&') => {
                        i += 1;
                        pending = Pending::Dup;
                    }
                    _ => {}
                }
                lexer.pending = pending;
            }
            '<' => {
                lexer.flush_word();
                if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') {
                    i += 2;
                    if chars.get(i) == Some(&'-') {
                        i += 1;
                    }
                    while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                        i += 1;
                    }
                    let mut delimiter = String::new();
                    while i < chars.len()
                        && !chars[i].is_whitespace()
                        && !";|&()<>".contains(chars[i])
                    {
                        if !matches!(chars[i], '\'' | '"' | '\\') {
                            delimiter.push(chars[i]);
                        }
                        i += 1;
                    }
                    if !delimiter.is_empty() {
                        heredocs.push(delimiter);
                    }
                } else if chars.get(i + 1) == Some(&'<') {
                    i += 3;
                    lexer.pending = Pending::Read;
                } else if chars.get(i + 1) == Some(&'>') {
                    i += 2;
                    lexer.pending = Pending::Write;
                } else {
                    i += 1;
                    lexer.pending = Pending::Read;
                }
            }
            '#' if !lexer.in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            _ => {
                lexer.current.push(c);
                lexer.in_word = true;
                i += 1;
            }
        }
    }
    lexer.end_segment();
    lexer.segments
}

const WRAPPERS: [&str; 9] = [
    "sudo", "doas", "command", "env", "time", "exec", "nohup", "builtin", "timeout",
];

pub(crate) fn is_env_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Lowercase program name without directory or `.exe`.
pub(crate) fn program_name(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    base.to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_owned()
}

/// The command a segment runs: leading `VAR=value` words and wrappers such as
/// `sudo`, `env`, `time` and `timeout 5` are skipped.
pub(crate) fn strip_wrappers(words: &[String]) -> &[String] {
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if is_env_assignment(word) {
            i += 1;
            continue;
        }
        let name = program_name(word);
        if WRAPPERS.contains(&name.as_str()) {
            i += 1;
            while i < words.len() && words[i].starts_with('-') {
                i += 1;
            }
            if name == "timeout"
                && i < words.len()
                && words[i].starts_with(|c: char| c.is_ascii_digit())
            {
                i += 1;
            }
            continue;
        }
        break;
    }
    &words[i..]
}

/// The script after `-c` (or a cluster such as `-lc`) of `bash`, `sh`, `zsh`.
pub(crate) fn shell_script(args: &[String]) -> Option<&str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let cluster = arg.strip_prefix('-')?;
        if !cluster.is_empty()
            && cluster.chars().all(|c| c.is_ascii_alphabetic())
            && cluster.contains('c')
        {
            return iter.next().map(String::as_str);
        }
    }
    None
}

/// Command lines in a shell tool input: `command`/`cmd` as a string, or an
/// argv array (joined, plus each element that is itself a command line).
pub(crate) fn command_strings(input: &Map<String, Value>) -> Vec<String> {
    for key in ["command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) => return vec![text.clone()],
            Some(Value::Array(parts)) => {
                let words: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
                if words.is_empty() {
                    continue;
                }
                let mut out = vec![words.join(" ")];
                out.extend(
                    words
                        .iter()
                        .filter(|word| word.contains(char::is_whitespace))
                        .map(|word| (*word).to_owned()),
                );
                return out;
            }
            _ => {}
        }
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// PreToolUse: agents cannot write into the state folder
// ---------------------------------------------------------------------------

type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

struct Ctx<'a> {
    env: EnvLookup<'a>,
    roots: &'a [String],
}

fn home_of(env: EnvLookup<'_>) -> Option<String> {
    env("HOME")
        .filter(|home| !home.trim().is_empty())
        .or_else(|| env("USERPROFILE").filter(|home| !home.trim().is_empty()))
}

fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

/// Lexical normal form for comparison: `/` separators, lowercase, no `.`,
/// `..` or empty components, no trailing slash.
fn norm_path(path: &str) -> String {
    let unified = path.replace('\\', "/").to_lowercase();
    let bytes = unified.as_bytes();
    let (prefix, rest) = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'/'
    {
        (unified[..3].to_owned(), &unified[3..])
    } else if let Some(rest) = unified.strip_prefix('/') {
        ("/".to_owned(), rest)
    } else {
        (String::new(), unified.as_str())
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("{prefix}{}", parts.join("/"))
}

fn component_count(normalized: &str) -> usize {
    normalized
        .split('/')
        .filter(|part| !part.is_empty() && !part.ends_with(':'))
        .count()
}

/// Normalised forms of the folders agents may not write: `~/.legion` and
/// `$LEGION_STATE_DIR`, each also in its canonical (symlink-resolved) form.
fn protected_roots(env: EnvLookup<'_>) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    if let Some(home) = home_of(env) {
        raw.push(format!("{home}/.legion"));
    }
    if let Some(dir) = env("LEGION_STATE_DIR").filter(|dir| !dir.trim().is_empty()) {
        raw.push(dir);
    }
    let mut roots: Vec<String> = Vec::new();
    for item in &raw {
        let mut forms = vec![norm_path(item)];
        if let Ok(canonical) = fs::canonicalize(item) {
            forms.push(norm_path(
                canonical.to_string_lossy().trim_start_matches(r"\\?\"),
            ));
        }
        for form in forms {
            if component_count(&form) >= 2 && !roots.contains(&form) {
                roots.push(form);
            }
        }
    }
    roots
}

/// Expand `~`, `$NAME` and `${NAME}` from `env`. `None` when a variable is
/// unset (the shell would expand it to something we cannot know).
fn expand(word: &str, env: EnvLookup<'_>) -> Option<String> {
    let mut out = String::new();
    let mut rest = word;
    if rest == "~" || rest.starts_with("~/") || rest.starts_with("~\\") {
        out.push_str(&home_of(env)?);
        rest = &rest[1..];
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '$' {
            out.push(c);
            i += 1;
            continue;
        }
        let (name, next) = if chars.get(i + 1) == Some(&'{') {
            let close = chars[i + 2..].iter().position(|&x| x == '}')? + i + 2;
            (chars[i + 2..close].iter().collect::<String>(), close + 1)
        } else {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            (chars[i + 1..j].iter().collect::<String>(), j)
        };
        if name.is_empty() {
            out.push('$');
            i += 1;
            continue;
        }
        out.push_str(&env(&name)?);
        i = next;
    }
    Some(out)
}

/// A normalised absolute path for `word`, joined to `base` when relative. A
/// glob or brace keeps only the part before it.
fn resolve(word: &str, base: Option<&str>, env: EnvLookup<'_>) -> Option<String> {
    if word.is_empty() {
        return None;
    }
    let expanded = expand(word, env)?;
    let cut = match expanded.find(['*', '?', '[', '{']) {
        Some(index) => &expanded[..index],
        None => expanded.as_str(),
    };
    let absolute = if is_absolute(cut) {
        cut.to_owned()
    } else {
        format!("{}/{}", base?, cut)
    };
    Some(norm_path(&absolute))
}

fn under_root(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        path == root
            || path
                .strip_prefix(root.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn touches(word: &str, base: Option<&str>, ctx: &Ctx<'_>) -> bool {
    resolve(word, base, ctx.env).is_some_and(|path| under_root(&path, ctx.roots))
}

fn first_touch(words: Vec<&str>, base: Option<&str>, ctx: &Ctx<'_>) -> Option<String> {
    words
        .into_iter()
        .find(|word| touches(word, base, ctx))
        .map(str::to_owned)
}

/// Words that are not option flags (everything after `--` is a word).
fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut literal = false;
    for arg in args {
        if !literal && arg == "--" {
            literal = true;
            continue;
        }
        if !literal && arg.starts_with('-') && arg.len() > 1 {
            continue;
        }
        out.push(arg.as_str());
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg.as_str() == flag)
}

/// The directory named by `-t DIR`, `--target-directory[=]DIR` or
/// `-Destination DIR`.
fn target_dir(args: &[String]) -> Option<&str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let lowered = arg.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "-t" | "--target-directory" | "-destination"
        ) {
            return iter.next().map(String::as_str);
        }
        if let Some(value) = arg.strip_prefix("--target-directory=") {
            return Some(value);
        }
    }
    None
}

/// `sed -i`, `sed --in-place`, `perl -pi`: an in-place edit.
fn in_place(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg.starts_with("--in-place")
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('i'))
    })
}

/// The first word of `command` (any segment, nested shells included) that
/// would write inside a protected root.
fn analyze(command: &str, cwd: Option<&str>, depth: u8, ctx: &Ctx<'_>) -> Option<String> {
    let mut base: Option<String> = cwd.map(str::to_owned);
    for segment in shell_segments(command) {
        for target in &segment.redirects {
            if touches(target, base.as_deref(), ctx) {
                return Some(target.clone());
            }
        }
        let words = strip_wrappers(&segment.words);
        let Some((program, args)) = words.split_first() else {
            continue;
        };
        let name = program_name(program);
        match name.as_str() {
            "cd" | "pushd" | "set-location" | "sl" => {
                let target = positionals(args).first().map(|dir| (*dir).to_owned());
                base = match target {
                    Some(dir) if dir == "-" => None,
                    Some(dir) => resolve(&dir, base.as_deref(), ctx.env),
                    None => home_of(ctx.env).map(|home| norm_path(&home)),
                };
            }
            "tee" | "tee-object" => {
                if let Some(hit) = first_touch(positionals(args), base.as_deref(), ctx) {
                    return Some(hit);
                }
            }
            "cp" | "install" | "ln" | "rsync" | "copy-item" | "cpi" => {
                let found = positionals(args);
                let mut targets: Vec<&str> = Vec::new();
                if let Some(dir) = target_dir(args) {
                    targets.push(dir);
                } else if name == "install" && has_flag(args, "-d") {
                    targets.extend(found.iter().copied());
                } else if found.len() >= 2 {
                    if let Some(last) = found.last() {
                        targets.push(last);
                    }
                }
                if let Some(hit) = first_touch(targets, base.as_deref(), ctx) {
                    return Some(hit);
                }
            }
            "mv" | "move-item" | "mi" => {
                let mut targets = positionals(args);
                if let Some(dir) = target_dir(args) {
                    targets.push(dir);
                }
                if let Some(hit) = first_touch(targets, base.as_deref(), ctx) {
                    return Some(hit);
                }
            }
            "rm" | "truncate" | "touch" | "shred" | "unlink" | "remove-item" | "ri" | "del"
            | "erase" | "set-content" | "add-content" | "out-file" | "clear-content"
            | "new-item" | "rename-item" | "ni" | "sc" | "ac" => {
                if let Some(hit) = first_touch(positionals(args), base.as_deref(), ctx) {
                    return Some(hit);
                }
            }
            "dd" => {
                let hit = args
                    .iter()
                    .filter_map(|arg| arg.strip_prefix("of="))
                    .find(|target| touches(target, base.as_deref(), ctx));
                if let Some(hit) = hit {
                    return Some(hit.to_owned());
                }
            }
            "sed" | "gsed" | "perl" => {
                if in_place(args) {
                    if let Some(hit) = first_touch(positionals(args), base.as_deref(), ctx) {
                        return Some(hit);
                    }
                }
            }
            "bash" | "sh" | "zsh" | "dash" | "ksh" => {
                if depth < MAX_SHELL_DEPTH {
                    if let Some(script) = shell_script(args) {
                        if let Some(hit) = analyze(script, base.as_deref(), depth + 1, ctx) {
                            return Some(hit);
                        }
                    }
                }
            }
            "eval" => {
                if depth < MAX_SHELL_DEPTH {
                    let script = args.join(" ");
                    if let Some(hit) = analyze(&script, base.as_deref(), depth + 1, ctx) {
                        return Some(hit);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// File paths named by a Codex `apply_patch` body.
fn patch_paths(input: &Map<String, Value>) -> Vec<String> {
    let mut texts: Vec<String> = Vec::new();
    for key in ["input", "patch", "command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) => texts.push(text.clone()),
            Some(Value::Array(items)) => {
                let parts: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                texts.push(parts.join("\n"));
            }
            _ => {}
        }
    }
    let mut paths = Vec::new();
    for text in &texts {
        for line in text.lines() {
            let line = line.trim();
            for prefix in [
                "*** Update File:",
                "*** Add File:",
                "*** Delete File:",
                "*** Move to:",
            ] {
                if let Some(rest) = line.strip_prefix(prefix) {
                    let path = rest.trim();
                    if !path.is_empty() {
                        paths.push(path.to_owned());
                    }
                }
            }
        }
    }
    paths
}

fn is_write_tool(tool: &str) -> bool {
    matches!(
        tool,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "apply_patch" | "ApplyPatch"
    )
}

/// The path or word a tool call would write inside a protected root.
fn protected_target(
    tool: &str,
    input: &Map<String, Value>,
    cwd: Option<&str>,
    ctx: &Ctx<'_>,
) -> Option<String> {
    match tool {
        write if is_write_tool(write) => {
            for key in ["file_path", "filePath", "path", "notebook_path"] {
                if let Some(path) = input.get(key).and_then(Value::as_str) {
                    if touches(path, cwd, ctx) {
                        return Some(path.to_owned());
                    }
                }
            }
            patch_paths(input)
                .into_iter()
                .find(|path| touches(path, cwd, ctx))
        }
        other if SHELL_TOOLS.contains(&other) => command_strings(input)
            .iter()
            .find_map(|command| analyze(command, cwd, 0, ctx)),
        _ => None,
    }
}

/// PreToolUse: deny `Write`, `Edit`, `MultiEdit`, `NotebookEdit`,
/// `apply_patch` and shell redirects, `tee`, `cp`, `mv` (and a few equal
/// write forms) into `~/.legion` or `$LEGION_STATE_DIR`, so an agent cannot
/// forge Adrian's words or orders. Code `ARC_WORDS_PROTECTED`.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK_WORDS) || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    if !is_write_tool(&tool) && !SHELL_TOOLS.contains(&tool.as_str()) {
        return None;
    }
    let input = tool_input(payload)?;
    let cwd = str_field(payload, &["cwd", "workdir"]);
    let env = |key: &str| std::env::var(key).ok();
    let roots = protected_roots(&env);
    if roots.is_empty() {
        return None;
    }
    let ctx = Ctx {
        env: &env,
        roots: &roots,
    };
    let target = protected_target(&tool, input, cwd.as_deref(), &ctx)?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        PROTECTED_CODE,
        format!(
            "{tool} to {target} is blocked: the Legion state folder holds Adrian's recorded words and standing orders, and only the hook writes there. Ask Adrian to say it in chat."
        ),
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-words-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn prompt_request(session: &str, prompt: &str) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "UserPromptSubmit".to_owned(),
            payload: json!({"session_id": session, "cwd": "/work", "prompt": prompt}),
        }
    }

    fn typed(root: &Path, session: &str, prompt: &str, now: u64) {
        on_user_prompt_in(root, &prompt_request(session, prompt), now, true, true);
    }

    fn orders_file(root: &Path) -> Vec<Order> {
        read_orders(&root.join(ORDERS_FILE)).expect("orders readable")
    }

    fn order(id: u64, t: u64, text: &str) -> Order {
        Order {
            id,
            t,
            session: "s".into(),
            text: text.into(),
            supersedes: Vec::new(),
            dropped: Vec::new(),
        }
    }

    // --- dates ---

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(1_000_000_000), "2001-09-09");
        assert_eq!(format_date(1_700_000_000), "2023-11-14");
    }

    // --- recognising turns and orders ---

    #[test]
    fn synthetic_prompts_are_not_adrian() {
        for text in [
            "[Pulse Chat from mac] do it",
            "  <task-notification>done</task-notification>",
            "<system-reminder>x</system-reminder>",
            "<side-sessions-event>x</side-sessions-event>",
            "[Request interrupted by user]",
        ] {
            assert!(prompt_is_synthetic(text), "{text}");
        }
        assert!(!prompt_is_synthetic("From now on use pnpm"));
        assert!(!prompt_is_synthetic("the [Pulse Chat idea"));
    }

    #[test]
    fn standing_order_phrases_are_detected() {
        for text in [
            "From now on, run builds only through the gate.",
            "Never push to main without asking.",
            "Always load the skill first",
            "No more asking Astra",
            "Every time I say ship it, run the checklist.",
            "this is a standing rule: use pnpm",
            "pass this to all active chats: no force pushes",
            "tell every chat to use pnpm",
            "You must always call the Skill tool",
            "and never edit the installed app",
            "make sure to always run rustfmt",
        ] {
            assert!(
                matches!(classify(text), Directive::Order(_)),
                "should be an order: {text}"
            );
        }
    }

    #[test]
    fn ordinary_turns_are_not_orders() {
        for text in [
            "show me the logs",
            "this never works",
            "I never said that",
            "Never mind, I found it",
            "should we always rebase?",
            "it fails every time",
            "there are no more errors",
            "",
        ] {
            assert_eq!(classify(text), Directive::None, "{text}");
        }
    }

    #[test]
    fn order_command_takes_the_text_after_it() {
        assert_eq!(
            classify("/order use pnpm only"),
            Directive::Order("use pnpm only".into())
        );
        assert_eq!(
            classify(
                "<command-name>/order</command-name>\n<command-args>use pnpm only</command-args>"
            ),
            Directive::Order("use pnpm only".into())
        );
        assert_eq!(classify("/order"), Directive::None);
        assert_eq!(classify("/orders list"), Directive::None);
    }

    #[test]
    fn drop_and_replace_are_parsed() {
        assert_eq!(classify("drop order 3"), Directive::Drop(vec![3]));
        assert_eq!(
            classify("Please drop orders 2 and 5."),
            Directive::Drop(vec![2, 5])
        );
        assert_eq!(classify("drop standing order #7"), Directive::Drop(vec![7]));
        assert_eq!(
            classify("replace order 4 with: always run rustfmt"),
            Directive::Replace(4, "always run rustfmt".into())
        );
        assert_eq!(
            classify("Replace order 4 with never use npm"),
            Directive::Replace(4, "never use npm".into())
        );
        assert_eq!(classify("should I drop order 3?"), Directive::None);
        assert_eq!(classify("replace order 4 without it"), Directive::None);
    }

    #[test]
    fn long_turns_keep_only_the_qualifying_paragraphs() {
        let filler = "log line\n".repeat(400);
        let prompt = format!("{filler}\nFrom now on, use pnpm.\n\n{filler}");
        let Directive::Order(text) = classify(&prompt) else {
            panic!("expected an order");
        };
        assert_eq!(text, "From now on, use pnpm.");
        assert_eq!(classify(&filler), Directive::None);
    }

    // --- the log ---

    #[test]
    fn every_genuine_turn_is_recorded_verbatim_and_synthetic_ones_are_not() {
        let dir = TestDir::new("words");
        typed(dir.path(), "s1", "  fix the build \n", 100);
        typed(dir.path(), "s1", "[Pulse Chat from dell] hi", 101);
        typed(
            dir.path(),
            "s1",
            "<task-notification>x</task-notification>",
            102,
        );
        let text = fs::read_to_string(words_path(dir.path(), "s1")).expect("words log");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(value["prompt"], "  fix the build \n");
        assert_eq!(value["session_id"], "s1");
        assert_eq!(value["cwd"], "/work");
        assert_eq!(value["t"], 100);
        assert!(!dir.path().join(ORDERS_FILE).exists());
    }

    #[test]
    fn kill_switches_are_independent() {
        let dir = TestDir::new("switch");
        let request = prompt_request("s1", "Never push to main.");
        on_user_prompt_in(dir.path(), &request, 100, false, true);
        assert!(!words_path(dir.path(), "s1").exists());
        assert_eq!(orders_file(dir.path()).len(), 1);
        let other = TestDir::new("switch2");
        on_user_prompt_in(other.path(), &request, 100, true, false);
        assert!(words_path(other.path(), "s1").exists());
        assert!(!other.path().join(ORDERS_FILE).exists());
    }

    #[test]
    fn orders_get_sequential_ids_and_drop_and_replace_supersede() {
        let dir = TestDir::new("orders");
        typed(dir.path(), "s1", "From now on, use pnpm.", 100);
        typed(dir.path(), "s1", "/order never edit the installed app", 200);
        typed(dir.path(), "s2", "fix the build", 300);
        let entries = orders_file(dir.path());
        assert_eq!(entries.iter().map(|o| o.id).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(entries[0].text, "From now on, use pnpm.");
        assert_eq!(entries[1].text, "never edit the installed app");

        typed(
            dir.path(),
            "s2",
            "replace order 1 with: always use pnpm exec",
            400,
        );
        typed(dir.path(), "s2", "drop order 2", 500);
        typed(dir.path(), "s2", "drop order 9", 600);
        let entries = orders_file(dir.path());
        assert_eq!(entries.len(), 4);
        let live: Vec<u64> = live_orders(&entries).iter().map(|o| o.id).collect();
        assert_eq!(live, vec![3]);
        assert_eq!(entries[2].supersedes, vec![1]);
        assert_eq!(entries[3].dropped, vec![2]);
        // A second drop of an order that is already gone records nothing.
        typed(dir.path(), "s2", "drop order 1", 700);
        assert_eq!(orders_file(dir.path()).len(), 4);
    }

    // --- delivery ---

    #[test]
    fn session_start_lists_live_orders_newest_first_with_dates() {
        let dir = TestDir::new("start");
        typed(dir.path(), "s1", "From now on, use pnpm.", 1_000_000_000);
        typed(
            dir.path(),
            "s1",
            "Never edit the installed app.",
            1_700_000_000,
        );
        let text = context_for_session_start_in(dir.path(), Some("s9")).expect("context");
        assert!(text.starts_with("Adrian's standing orders."));
        let newest = text.find("#2 (2023-11-14)").expect("newest order");
        let oldest = text.find("#1 (2001-09-09)").expect("oldest order");
        assert!(newest < oldest);
        assert!(text.contains("Never edit the installed app."));
        assert!(text.len() <= CONTEXT_BUDGET);
        // The session start counts as having seen both orders.
        assert_eq!(read_seen(dir.path(), "s9"), Some(2));
        assert_eq!(context_for_prompt_in(dir.path(), "s9"), None);
    }

    #[test]
    fn session_start_without_orders_is_empty() {
        let dir = TestDir::new("empty");
        assert_eq!(context_for_session_start_in(dir.path(), Some("s1")), None);
        typed(dir.path(), "s1", "From now on, use pnpm.", 100);
        typed(dir.path(), "s1", "drop order 1", 200);
        assert_eq!(context_for_session_start_in(dir.path(), Some("s2")), None);
    }

    #[test]
    fn context_is_trimmed_to_four_kilobytes_newest_first() {
        let dir = TestDir::new("trim");
        let long = "x".repeat(700);
        let orders: Vec<Order> = (1..=40).map(|id| order(id, 1_700_000_000, &long)).collect();
        let refs: Vec<&Order> = orders.iter().collect();
        let text = render_orders(SESSION_HEADER, &refs, &dir.path().join(ORDERS_FILE));
        assert!(text.len() <= CONTEXT_BUDGET, "{}", text.len());
        assert!(text.contains("#40 ("));
        assert!(!text.contains("#1 ("));
        assert!(text.contains("older standing order(s) not shown"));
        let shown = text.matches("\n#").count();
        let footer = text.lines().last().expect("footer line");
        let hidden: usize = footer
            .trim_start_matches('(')
            .split(' ')
            .next()
            .and_then(|count| count.parse().ok())
            .expect("hidden count");
        assert_eq!(shown + hidden, 40);
    }

    #[test]
    fn prompt_context_delivers_other_chats_orders_once() {
        let dir = TestDir::new("prompt");
        typed(dir.path(), "s1", "From now on, use pnpm.", 1_700_000_000);
        // The chat that typed it never gets it echoed back.
        assert_eq!(context_for_prompt_in(dir.path(), "s1"), None);
        let text = context_for_prompt_in(dir.path(), "s2").expect("other chat gets it");
        assert!(text.contains("#1 (2023-11-14): From now on, use pnpm."));
        assert_eq!(context_for_prompt_in(dir.path(), "s2"), None);
        typed(
            dir.path(),
            "s1",
            "Never edit the installed app.",
            1_700_000_100,
        );
        let text = context_for_prompt_in(dir.path(), "s2").expect("second order");
        assert!(text.contains("#2 "));
        assert!(!text.contains("#1 "));
    }

    #[test]
    fn prompt_context_reports_drops_and_replacements() {
        let dir = TestDir::new("update");
        typed(dir.path(), "s1", "From now on, use pnpm.", 100);
        typed(dir.path(), "s1", "Never edit the installed app.", 110);
        let _ = context_for_prompt_in(dir.path(), "s2");
        typed(dir.path(), "s1", "drop order 2", 200);
        typed(
            dir.path(),
            "s1",
            "replace order 1 with: always use pnpm exec",
            210,
        );
        let text = context_for_prompt_in(dir.path(), "s2").expect("update");
        assert!(text.contains("#4 (1970-01-01, replaces #1): always use pnpm exec"));
        assert!(text.contains("dropped standing order(s) #2"));
    }

    #[test]
    fn attach_context_merges_or_creates_a_response() {
        let made = attach_context(None, Some("orders".into()), "UserPromptSubmit").expect("made");
        assert!(made.allowed);
        assert_eq!(made.additional_context.as_deref(), Some("orders"));
        let base =
            HookResponse::allowed("UserPromptSubmit", "named").with_additional_context("skill");
        let merged =
            attach_context(Some(base), Some("orders".into()), "UserPromptSubmit").expect("merged");
        assert_eq!(
            merged.additional_context.as_deref(),
            Some("skill\n\norders")
        );
        let untouched = attach_context(None, None, "UserPromptSubmit");
        assert!(untouched.is_none());
    }

    // --- the shell lexer ---

    #[test]
    fn lexer_finds_redirect_targets_and_ignores_fd_dups_and_quotes() {
        let seg = shell_segments("echo hi > out.txt 2>&1");
        assert_eq!(seg.len(), 1);
        assert_eq!(seg[0].words, vec!["echo", "hi"]);
        assert_eq!(seg[0].redirects, vec!["out.txt"]);
        let seg = shell_segments("echo '> a' \"> b\" >>c");
        assert_eq!(seg[0].words, vec!["echo", "> a", "> b"]);
        assert_eq!(seg[0].redirects, vec!["c"]);
        let seg = shell_segments("cmd &> all.log; other <in.txt");
        assert_eq!(seg[0].redirects, vec!["all.log"]);
        assert!(seg[1].redirects.is_empty());
        assert_eq!(seg[1].words, vec!["other"]);
        let seg = shell_segments("cat > f <<'EOF'\n> not a redirect\nEOF\nls");
        assert_eq!(seg.len(), 2);
        assert_eq!(seg[0].redirects, vec!["f"]);
        assert_eq!(seg[1].words, vec!["ls"]);
    }

    #[test]
    fn wrappers_and_env_assignments_are_skipped() {
        let words: Vec<String> = ["FOO=1", "sudo", "-n", "timeout", "5", "cp", "a", "b"]
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
        assert_eq!(strip_wrappers(&words)[0], "cp");
        assert_eq!(program_name("/usr/bin/Git.exe"), "git");
    }

    // --- the protected folder ---

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key: &str| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn hit(command: &str, cwd: Option<&str>) -> Option<String> {
        let env = env_of(&[("HOME", "/Users/a"), ("LEGION_STATE_DIR", "/var/tmp/state")]);
        let roots = protected_roots(&env);
        let ctx = Ctx {
            env: &env,
            roots: &roots,
        };
        analyze(command, cwd, 0, &ctx)
    }

    #[test]
    fn writes_into_the_state_folder_are_caught() {
        for command in [
            "echo hi > ~/.legion/words/x.jsonl",
            "echo hi >> $HOME/.legion/standing-orders.jsonl",
            "echo hi >${HOME}/.legion/standing-orders.jsonl",
            "echo hi | tee -a /Users/a/.legion/standing-orders.jsonl",
            "cp forged.jsonl ~/.legion/words/",
            "mv ~/.legion/standing-orders.jsonl /tmp/gone",
            "cd ~/.legion && echo x > standing-orders.jsonl",
            "cd /Users/a/.legion; rm standing-orders.jsonl",
            "bash -lc 'echo x > ~/.legion/a'",
            "sed -i s/a/b/ ~/.legion/standing-orders.jsonl",
            "rm -f ~/.legion/standing-orders.jsonl",
            "dd if=x of=~/.legion/words/a.jsonl",
            "FOO=1 sudo tee ~/.legion/x",
            "cat > ~/.legion/x <<'EOF'\nhello\nEOF",
            "echo hi > /var/tmp/state/words/a.jsonl",
            "echo hi > $LEGION_STATE_DIR/standing-orders.jsonl",
            "echo hi > ~/.legion/../.legion/x",
            "install -d ~/.legion/words",
            "cp -t ~/.legion/words forged.jsonl",
        ] {
            assert!(hit(command, None).is_some(), "should deny: {command}");
        }
    }

    #[test]
    fn reads_and_other_folders_are_allowed() {
        for command in [
            "cat ~/.legion/standing-orders.jsonl",
            "ls -la ~/.legion",
            "cp ~/.legion/x ./y",
            "echo hi > /tmp/x 2>&1",
            "echo '> ~/.legion/x'",
            "grep -r word ~/.legion/words | tee /tmp/out",
            "echo x > .legion/y",
            "cargo test 2>&1 | tail -n 20",
            "echo hi > /Users/a/.legionx/y",
            "echo hi > $UNSET_VAR/.legion/y",
        ] {
            assert_eq!(hit(command, Some("/Users/a/proj")), None, "{command}");
        }
    }

    #[test]
    fn relative_targets_resolve_against_the_working_folder() {
        assert!(hit("echo x > standing-orders.jsonl", Some("/Users/a/.legion")).is_some());
        assert!(hit("echo x > words/s.jsonl", Some("/Users/a/.legion")).is_some());
        assert!(hit("echo x > ../.legion/y", Some("/Users/a/proj")).is_some());
        assert_eq!(hit("echo x > y", Some("/Users/a/proj")), None);
    }

    #[test]
    fn file_tools_are_checked_by_path() {
        let env = env_of(&[("HOME", "/Users/a")]);
        let roots = protected_roots(&env);
        let ctx = Ctx {
            env: &env,
            roots: &roots,
        };
        let input = |value: Value| value.as_object().cloned().expect("object");
        let write = input(json!({"file_path": "/Users/a/.legion/words/x.jsonl", "content": "x"}));
        assert!(protected_target("Write", &write, None, &ctx).is_some());
        let edit = input(json!({"file_path": "/Users/a/proj/main.rs"}));
        assert_eq!(protected_target("Edit", &edit, None, &ctx), None);
        let relative = input(json!({"file_path": "standing-orders.jsonl"}));
        assert!(protected_target("MultiEdit", &relative, Some("/Users/a/.legion"), &ctx).is_some());
        let patch = input(json!({
            "command": "*** Begin Patch\n*** Update File: /Users/a/.legion/standing-orders.jsonl\n*** End Patch"
        }));
        assert!(protected_target("apply_patch", &patch, None, &ctx).is_some());
        let shell = input(json!({"command": "echo x > ~/.legion/a"}));
        assert!(protected_target("Bash", &shell, None, &ctx).is_some());
        assert!(protected_target("PowerShell", &shell, None, &ctx).is_some());
        assert_eq!(protected_target("Read", &write, None, &ctx), None);
    }

    #[test]
    fn pre_tool_allows_files_outside_the_state_folder() {
        let request = HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload: json!({
                "tool_name": "Write",
                "tool_input": {"file_path": "/Users/a/proj/x.rs", "content": ""},
            }),
        };
        // Outside the state folder the check allows.
        assert!(pre_tool(&request).is_none());
    }
}
