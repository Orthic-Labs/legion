//! Tier 0 evidence ledger and claim check (check id `evidence`).
//!
//! Two halves, both deterministic and model-free:
//!
//! * **Ledger.** `observe_post_tool` appends one JSON line per tool result to
//!   `<state>/evidence/<session_id>.jsonl`; `mark_turn_start` appends a turn
//!   marker line on UserPromptSubmit. The file is capped at 5 MB by dropping
//!   the oldest lines (the latest turn marker is kept).
//! * **Claim check.** `stop_check` reads the final assistant message and the
//!   ledger rows since the last turn marker. A claim word (green, installed,
//!   live, fixed, done ...) needs a matching successful command after the last
//!   edit. SHAs, run ids, issue refs and backticked paths in the message must
//!   appear in this turn's output; three or more that do not also block.
//!
//! Payload shapes assumed (UNVERIFIED until a live run):
//!
//! * Claude Code `PostToolUse` Bash: `tool_response` is an object with
//!   `stdout`, `stderr`, `interrupted` and no exit code (a nonzero exit is
//!   delivered as `PostToolUseFailure` with `error: "Exit code N\n..."`).
//! * Codex shell results may carry `Exit code: N` text or `exit_code` /
//!   `metadata.exit_code`; both are parsed when present.
//! * `Stop` carries `last_assistant_message` and `stop_hook_active`.
//! * `UserPromptSubmit` carries `prompt`.
//!
//! Every entry point fails open: any unreadable file or missing field means
//! "allow". `LEGION_HOOK_OFF` (comma list) containing `evidence` disables it.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Map, Value};

use crate::protocol::{HookRequest, HookResponse};

pub const CHECK_ID: &str = "evidence";
pub const BLOCK_CODE: &str = "ARC_EVIDENCE_REQUIRED";
pub const LEDGER_CAP_BYTES: u64 = 5 * 1024 * 1024;

const EVIDENCE_DIRECTORY: &str = "evidence";
const SHADOW_FILE: &str = "shadow.jsonl";
const KILL_ENV: &str = "LEGION_HOOK_OFF";
const MODE_ENV: &str = "LEGION_EVIDENCE_MODE";
const COMMAND_LIMIT: usize = 500;
const TAIL_LIMIT: usize = 300;
const PROMPT_LIMIT: usize = 4000;
const SCAN_LIMIT_CHARS: usize = 200_000;
const UNGROUNDED_BLOCK_THRESHOLD: usize = 3;
const REPORTED_LIST_LIMIT: usize = 8;
const IDS_SHA_LIMIT: usize = 60;
const IDS_NUMBER_LIMIT: usize = 20;
const IDS_ISSUE_LIMIT: usize = 30;
const IDS_PATH_LIMIT: usize = 40;
const EDIT_TOOLS: [&str; 5] = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];
const TURN_MARKER: &[u8] = br#""marker":"turn""#;
const LAST_MESSAGE_KEYS: [&str; 3] = [
    "last_assistant_message",
    "lastAssistantMessage",
    "lastAssistantText",
];

/// Enforcement mode. The first release ships in shadow mode: a would-block is
/// logged to `<state>/evidence/shadow.jsonl` and the stop is allowed. The lead
/// flips `DEFAULT_MODE` (or sets `LEGION_EVIDENCE_MODE=enforce`) to block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Off,
    Shadow,
    Enforce,
}

pub const DEFAULT_MODE: Mode = Mode::Shadow;

fn mode_from(value: Option<&str>) -> Mode {
    match value
        .map(|text| text.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("shadow") | Some("log") => Mode::Shadow,
        Some("enforce") | Some("block") | Some("on") => Mode::Enforce,
        Some("off") => Mode::Off,
        _ => DEFAULT_MODE,
    }
}

fn killed(list: &str) -> bool {
    list.split(',')
        .any(|item| item.trim().eq_ignore_ascii_case(CHECK_ID))
}

fn disabled() -> bool {
    std::env::var(KILL_ENV)
        .map(|value| killed(&value))
        .unwrap_or(false)
}

fn state_dir() -> Option<PathBuf> {
    crate::skills_gate::state_root()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

fn session_id(payload: &Value) -> Option<String> {
    let object = payload.as_object()?;
    first_string(object, &["session_id", "sessionId", "conversation_id"])
}

fn safe_name(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(128)
        .collect()
}

fn evidence_dir(state: &Path) -> PathBuf {
    state.join(EVIDENCE_DIRECTORY)
}

fn ledger_path(state: &Path, session: &str) -> PathBuf {
    evidence_dir(state).join(format!("{}.jsonl", safe_name(session)))
}

fn blocked_path(state: &Path, session: &str) -> PathBuf {
    evidence_dir(state).join(format!("{}.blocked", safe_name(session)))
}

// ---------------------------------------------------------------------------
// Text utilities
// ---------------------------------------------------------------------------

fn truncate_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

fn tail_chars(text: &str, max: usize) -> String {
    let total = text.chars().count();
    if total <= max {
        return text.to_owned();
    }
    text.chars().skip(total - max).collect()
}

fn word_list(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .collect()
}

fn push_unique(list: &mut Vec<String>, item: String, limit: usize) {
    if list.len() < limit && !list.contains(&item) {
        list.push(item);
    }
}

fn extend_unique(list: &mut Vec<String>, items: Vec<String>, limit: usize) {
    for item in items {
        push_unique(list, item, limit);
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn write_atomic(path: &Path, contents: &[u8]) -> Option<()> {
    let parent = path.parent()?;
    fs::create_dir_all(parent).ok()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let temp = parent.join(format!(".{name}.{}.tmp", process::id()));
    fs::write(&temp, contents).ok()?;
    if fs::rename(&temp, path).is_err() {
        let _ = fs::remove_file(&temp);
        return None;
    }
    Some(())
}

/// Append one line (single `write_all` on an append-mode handle, so concurrent
/// hooks do not lose each other's rows), then trim the oldest lines when the
/// file passes `cap`. Trimming keeps the newest turn marker.
fn append_capped(path: &Path, line: &str, cap: u64) -> Option<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    let mut data = String::with_capacity(line.len() + 1);
    data.push_str(line);
    data.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    file.write_all(data.as_bytes()).ok()?;
    drop(file);
    if fs::metadata(path).ok()?.len() > cap {
        trim_oldest(path, cap);
    }
    Some(())
}

fn trim_oldest(path: &Path, cap: u64) {
    let Ok(data) = fs::read(path) else {
        return;
    };
    let target = (cap / 5 * 4) as usize;
    if data.len() <= target || data.is_empty() {
        return;
    }
    let mut start = data.len() - target;
    if data[start - 1] != b'\n' {
        start = match data[start..].iter().position(|byte| *byte == b'\n') {
            Some(offset) => start + offset + 1,
            None => data.len(),
        };
    }
    if start >= data.len() {
        // One oversized line: keep at least the newest line.
        start = data[..data.len() - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() - start + 512);
    if !contains_bytes(&data[start..], TURN_MARKER) {
        let marker_line = data[..start]
            .split(|byte| *byte == b'\n')
            .rev()
            .find(|line| contains_bytes(line, TURN_MARKER));
        if let Some(line) = marker_line {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    out.extend_from_slice(&data[start..]);
    let _ = write_atomic(path, &out);
}

// ---------------------------------------------------------------------------
// Identifier extraction (shared by the ledger writer and the claim check)
// ---------------------------------------------------------------------------

const PATH_EXTENSIONS: &[&str] = &[
    "rs", "toml", "md", "json", "jsonl", "py", "ts", "tsx", "js", "jsx", "mjs", "sh", "yml",
    "yaml", "swift", "kt", "kts", "lock", "txt", "html", "css", "plist", "sql", "cfg", "ini", "c",
    "h", "cpp", "go", "java", "ps1", "bat",
];

fn looks_like_uuid(window: &[u8]) -> bool {
    window.len() == 36
        && window.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Blank out UUIDs so their hex groups are not read as commit hashes.
fn strip_uuids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut index = 0;
    while index + 36 <= bytes.len() {
        if looks_like_uuid(&bytes[index..index + 36]) {
            out.push_str(&text[last..index]);
            out.push(' ');
            index += 36;
            last = index;
        } else {
            index += 1;
        }
    }
    out.push_str(&text[last..]);
    out
}

fn is_sha_token(token: &str) -> bool {
    (7..=40).contains(&token.len())
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        && token.bytes().any(|byte| byte.is_ascii_digit())
        && token
            .bytes()
            .any(|byte| matches!(byte, b'a'..=b'f' | b'A'..=b'F'))
}

fn sha_tokens(text: &str, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in text.split(|character: char| !character.is_ascii_alphanumeric()) {
        if out.len() >= limit {
            break;
        }
        if is_sha_token(token) {
            push_unique(&mut out, token.to_ascii_lowercase(), limit);
        }
    }
    out
}

fn long_numbers(text: &str, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in text.split(|character: char| !character.is_ascii_alphanumeric()) {
        if out.len() >= limit {
            break;
        }
        if (8..=20).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_digit()) {
            push_unique(&mut out, token.to_owned(), limit);
        }
    }
    out
}

/// GitHub run ids: eight or more digits right after "run"/"runs" (optionally
/// "run id", "run #"), which also covers `.../actions/runs/<id>` URLs.
fn run_ids(text: &str) -> Vec<String> {
    let tokens: Vec<&str> = text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    let mut out: Vec<String> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if !(token.eq_ignore_ascii_case("run") || token.eq_ignore_ascii_case("runs")) {
            continue;
        }
        for next in tokens.iter().skip(index + 1).take(3) {
            if next.len() >= 8 && next.bytes().all(|byte| byte.is_ascii_digit()) {
                push_unique(&mut out, (*next).to_owned(), 200);
                break;
            }
            let filler = ["id", "ids", "number", "no"]
                .iter()
                .any(|word| next.eq_ignore_ascii_case(word));
            if !filler {
                break;
            }
        }
    }
    out
}

/// `#123` style issue references (not `&#39;` entities, not `abc#1`).
fn issue_refs(text: &str, limit: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut index = 0;
    while index < bytes.len() && out.len() < limit {
        let standalone = bytes[index] == b'#'
            && (index == 0
                || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'&'));
        if !standalone {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let glued = end < bytes.len() && bytes[end].is_ascii_alphanumeric();
        if end > start && end - start <= 6 && !glued {
            push_unique(&mut out, format!("#{}", &text[start..end]), limit);
        }
        index = end.max(index + 1);
    }
    out
}

fn has_known_extension(token: &str) -> bool {
    match token.rsplit_once('.') {
        Some((stem, extension)) => {
            let lowered = extension.to_ascii_lowercase();
            !stem.is_empty() && PATH_EXTENSIONS.contains(&lowered.as_str())
        }
        None => false,
    }
}

/// `file.rs:12:3` -> `file.rs`.
fn strip_line_suffix(token: &str) -> &str {
    let mut current = token;
    loop {
        match current.rfind(':') {
            Some(index)
                if index > 0
                    && !current[index + 1..].is_empty()
                    && current[index + 1..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit()) =>
            {
                current = &current[..index];
            }
            _ => return current,
        }
    }
}

/// Lenient path detector for tool output (only widens the grounding set).
fn path_tokens(text: &str, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let separators = |character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\''
                    | '`'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '<'
                    | '>'
                    | ','
                    | ';'
                    | '='
                    | '{'
                    | '}'
                    | '|'
            )
    };
    for raw in text.split(separators) {
        if out.len() >= limit {
            break;
        }
        let trimmed = raw.trim_end_matches(|character: char| matches!(character, ':' | '.' | ','));
        let token = strip_line_suffix(trimmed.split('#').next().unwrap_or(trimmed));
        if token.len() < 3 || token.len() > 200 || token.contains("://") || token.starts_with("//")
        {
            continue;
        }
        let has_separator = token.contains('/') || token.contains('\\');
        let path_like = if has_separator {
            token
                .chars()
                .any(|character| character.is_ascii_alphanumeric())
        } else {
            has_known_extension(token)
        };
        if path_like {
            push_unique(&mut out, token.to_owned(), limit);
        }
    }
    out
}

/// Strict detector for a backticked span in the assistant message.
fn normalize_path_span(span: &str) -> Option<String> {
    let trimmed = span.trim();
    if trimmed.len() < 3
        || trimmed.len() > 200
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains("://")
        || trimmed.contains("::")
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
    {
        return None;
    }
    let placeholder = trimmed.chars().any(|character| {
        matches!(
            character,
            '*' | '{'
                | '}'
                | '<'
                | '>'
                | '('
                | ')'
                | '='
                | '|'
                | '$'
                | '&'
                | ','
                | ';'
                | '"'
                | '\''
                | '['
                | ']'
                | '?'
                | '!'
        )
    });
    if placeholder {
        return None;
    }
    let without_fragment = trimmed.split('#').next().unwrap_or(trimmed);
    let stripped = strip_line_suffix(without_fragment);
    let path = stripped.strip_prefix("./").unwrap_or(stripped);
    if path.len() < 3 {
        return None;
    }
    let slashes = path
        .chars()
        .filter(|character| *character == '/' || *character == '\\')
        .count();
    let anchored = path.starts_with('/')
        || path.starts_with('~')
        || path.starts_with('.')
        || path.ends_with('/')
        || slashes >= 2;
    let first_segment_marked = path.split('/').next().map_or(false, |first| {
        first.contains(|character: char| matches!(character, '-' | '_' | '.'))
    });
    let qualifies =
        has_known_extension(path) || (slashes >= 1 && (anchored || first_segment_marked));
    if qualifies {
        Some(path.to_owned())
    } else {
        None
    }
}

fn strip_fenced_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn backticked_paths(message: &str) -> Vec<String> {
    let unfenced = strip_fenced_blocks(message);
    let mut out: Vec<String> = Vec::new();
    for span in unfenced.split('`').skip(1).step_by(2) {
        if let Some(path) = normalize_path_span(span) {
            push_unique(&mut out, path, 200);
        }
    }
    out
}

/// Text inside double quotes is removed from the scan text and returned as
/// spans (the message's own quoted user words). An unclosed quote is left in
/// place so one stray `"` never hides the rest of the message.
fn split_quotes(message: &str) -> (String, Vec<String>) {
    let mut stripped = String::with_capacity(message.len());
    let mut spans: Vec<String> = Vec::new();
    let mut open: Option<usize> = None;
    for (index, character) in message.char_indices() {
        match open {
            None => {
                if character == '"' || character == '\u{201c}' {
                    open = Some(index + character.len_utf8());
                    stripped.push(' ');
                } else {
                    stripped.push(character);
                }
            }
            Some(start) => {
                if character == '"' || character == '\u{201d}' {
                    spans.push(message[start..index].to_owned());
                    open = None;
                }
            }
        }
    }
    if let Some(start) = open {
        stripped.push_str(&message[start..]);
    }
    (stripped, spans)
}

fn quoted_text(message: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in message.lines() {
        if let Some(rest) = line.trim_start().strip_prefix('>') {
            out.push(rest.trim().to_owned());
        }
    }
    out.extend(split_quotes(message).1);
    out
}

/// SHAs, run ids, issue refs and paths found in tool output or a command, kept
/// compact so grounding survives the 300-char tail.
fn row_ids(texts: &[&str]) -> Vec<String> {
    let mut shas: Vec<String> = Vec::new();
    let mut numbers: Vec<String> = Vec::new();
    let mut issues: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for text in texts {
        if text.is_empty() {
            continue;
        }
        let scan = strip_uuids(&tail_chars(text, SCAN_LIMIT_CHARS));
        extend_unique(&mut shas, sha_tokens(&scan, IDS_SHA_LIMIT), IDS_SHA_LIMIT);
        extend_unique(
            &mut numbers,
            long_numbers(&scan, IDS_NUMBER_LIMIT),
            IDS_NUMBER_LIMIT,
        );
        extend_unique(
            &mut issues,
            issue_refs(&scan, IDS_ISSUE_LIMIT),
            IDS_ISSUE_LIMIT,
        );
        extend_unique(
            &mut paths,
            path_tokens(&scan, IDS_PATH_LIMIT),
            IDS_PATH_LIMIT,
        );
    }
    let mut ids = shas;
    ids.extend(numbers);
    ids.extend(issues);
    ids.extend(paths);
    ids
}

/// Does `text` contain `number` as a whole digit run?
fn contains_number_token(text: &str, number: &str) -> bool {
    text.match_indices(number).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + number.len()..].chars().next();
        !before.map_or(false, |character| character.is_ascii_digit())
            && !after.map_or(false, |character| character.is_ascii_digit())
    })
}

// ---------------------------------------------------------------------------
// Ledger rows
// ---------------------------------------------------------------------------

fn command_of(input: &Map<String, Value>) -> Option<String> {
    for key in ["command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => return Some(text.clone()),
            Some(Value::Array(items)) => {
                let parts: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                if !parts.is_empty() {
                    return Some(parts.join(" "));
                }
            }
            _ => {}
        }
    }
    None
}

fn patch_first_path(text: &str) -> Option<String> {
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
                    return Some(path.to_owned());
                }
            }
        }
    }
    None
}

fn flag_set(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| object.get(*key).and_then(Value::as_bool) == Some(true))
}

fn exit_from_text(text: &str) -> Option<i64> {
    for line in text.lines().take(3) {
        let lowered = line.trim().to_ascii_lowercase();
        if let Some(rest) = lowered.strip_prefix("exit code") {
            let digits: String = rest
                .trim_start_matches(|character: char| {
                    character == ':' || character == '=' || character.is_whitespace()
                })
                .chars()
                .take_while(|character| character.is_ascii_digit() || *character == '-')
                .collect();
            if let Ok(code) = digits.parse::<i64>() {
                return Some(code);
            }
        }
    }
    None
}

fn exit_from_value(value: &Value, depth: u8) -> Option<i64> {
    if depth > 3 {
        return None;
    }
    match value {
        Value::Object(map) => {
            for key in [
                "exit_code",
                "exitCode",
                "returncode",
                "returnCode",
                "return_code",
            ] {
                if let Some(code) = map.get(key).and_then(Value::as_i64) {
                    return Some(code);
                }
            }
            for key in ["metadata", "result", "output"] {
                if let Some(code) = map
                    .get(key)
                    .and_then(|inner| exit_from_value(inner, depth + 1))
                {
                    return Some(code);
                }
            }
            None
        }
        Value::String(text) => {
            let trimmed = text.trim_start();
            if trimmed.starts_with('{') {
                if let Ok(inner) = serde_json::from_str::<Value>(trimmed) {
                    return exit_from_value(&inner, depth + 1);
                }
            }
            exit_from_text(trimmed)
        }
        _ => None,
    }
}

fn collect_strings(value: &Value, out: &mut String, limit: usize, depth: u8) {
    if depth > 6 || out.len() >= limit {
        return;
    }
    match value {
        Value::String(text) => {
            if !out.is_empty() {
                out.push('\n');
            }
            let remaining = limit.saturating_sub(out.len());
            out.push_str(truncate_chars(text, remaining));
        }
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out, limit, depth + 1);
            }
        }
        Value::Object(map) => {
            for (_, item) in map {
                collect_strings(item, out, limit, depth + 1);
            }
        }
        _ => {}
    }
}

/// (stdout, stderr) text of a tool result, whatever its shape.
fn output_texts(object: &Map<String, Value>, response: Option<&Value>) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(value) = response {
        match value {
            Value::String(text) => stdout = tail_chars(text, SCAN_LIMIT_CHARS),
            Value::Object(map) => {
                if let Some(text) = map.get("stdout").and_then(Value::as_str) {
                    stdout = tail_chars(text, SCAN_LIMIT_CHARS);
                }
                if let Some(text) = map.get("stderr").and_then(Value::as_str) {
                    stderr = tail_chars(text, SCAN_LIMIT_CHARS);
                }
                if stdout.is_empty() && stderr.is_empty() {
                    collect_strings(value, &mut stdout, SCAN_LIMIT_CHARS, 0);
                }
            }
            Value::Array(_) => collect_strings(value, &mut stdout, SCAN_LIMIT_CHARS, 0),
            _ => {}
        }
    }
    if let Some(text) = object.get("error").and_then(Value::as_str) {
        if !stderr.is_empty() {
            stderr.push('\n');
        }
        stderr.push_str(&tail_chars(text, SCAN_LIMIT_CHARS));
    }
    (stdout, stderr)
}

/// Output that plainly shows a failed run even when the command exited 0 (for
/// example `cargo test | tail`).
fn shows_failure(lowered: &str) -> bool {
    const MARKERS: [&str; 8] = [
        "test result: failed",
        "could not compile",
        "build failed",
        "tests failed",
        "test failed",
        "error[e0",
        "traceback (most recent call last)",
        "npm err!",
    ];
    if MARKERS.iter().any(|marker| lowered.contains(*marker)) {
        return true;
    }
    let tokens: Vec<&str> = lowered
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    tokens.windows(2).any(|pair| {
        matches!(pair[1], "failed" | "failures" | "failure" | "failing")
            && pair[0].parse::<u64>().map_or(false, |count| count > 0)
    })
}

/// Build the ledger row for one PostToolUse / PostToolUseFailure frame.
/// `None` when the frame carries no tool name.
pub fn ledger_row(request: &HookRequest, now: u64) -> Option<Value> {
    let object = request.payload.as_object()?;
    let tool = first_string(object, &["tool_name", "toolName"])?;
    let input = object
        .get("tool_input")
        .or_else(|| object.get("toolInput"))
        .and_then(Value::as_object);
    let response = object
        .get("tool_response")
        .or_else(|| object.get("toolResponse"));
    let failure_event = matches!(
        request.event_type.as_str(),
        "PostToolUseFailure" | "post-effect-failure"
    );

    let command = input.and_then(command_of);
    let exit = response
        .and_then(|value| exit_from_value(value, 0))
        .or_else(|| {
            object
                .get("error")
                .and_then(Value::as_str)
                .and_then(|text| exit_from_text(text.trim_start()))
        })
        .or_else(|| {
            ["exit_code", "exitCode"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_i64))
        });
    let flagged = response.and_then(Value::as_object).map_or(false, |map| {
        flag_set(map, &["interrupted", "is_error", "isError"])
    }) || flag_set(object, &["is_interrupt", "is_error"]);
    let failed = failure_event || flagged || exit.map_or(false, |code| code != 0);

    let edit = EDIT_TOOLS.contains(&tool.as_str());
    let patch_source = command.clone().or_else(|| {
        input.and_then(|map| {
            ["input", "patch"]
                .iter()
                .find_map(|key| map.get(*key).and_then(Value::as_str))
                .map(str::to_owned)
        })
    });
    let path = input
        .and_then(|map| {
            [
                "file_path",
                "filePath",
                "path",
                "notebook_path",
                "notebookPath",
            ]
            .iter()
            .find_map(|key| map.get(*key).and_then(Value::as_str))
            .map(str::to_owned)
        })
        .or_else(|| {
            if edit {
                patch_source.as_deref().and_then(patch_first_path)
            } else {
                None
            }
        });

    let (stdout, stderr) = output_texts(object, response);
    let mut tail = tail_chars(&stdout, TAIL_LIMIT);
    let error_tail = tail_chars(&stderr, TAIL_LIMIT);
    if !error_tail.trim().is_empty() {
        if !tail.is_empty() && !tail.ends_with('\n') {
            tail.push('\n');
        }
        tail.push_str("[stderr] ");
        tail.push_str(&error_tail);
    }
    let lowered = format!("{stdout}\n{stderr}").to_lowercase();
    let success_seen = lowered.contains("success") || lowered.contains('\u{2713}');
    let failure_seen = shows_failure(&lowered);

    let ids = row_ids(&[
        command.as_deref().unwrap_or(""),
        stdout.as_str(),
        stderr.as_str(),
    ]);
    let stored_command = command
        .as_deref()
        .map(|text| truncate_chars(text, COMMAND_LIMIT).to_owned());

    Some(json!({
        "t": now,
        "tool": tool,
        "command": stored_command,
        "exit": exit,
        "failed": failed,
        "edit": edit,
        "path": path,
        "tail": tail,
        "ids": ids,
        "success_seen": success_seen,
        "failure_seen": failure_seen,
    }))
}

/// PostToolUse / PostToolUseFailure: append one ledger row. Observation only.
pub fn observe_post_tool(request: &HookRequest) {
    if disabled() {
        return;
    }
    if let Some(state) = state_dir() {
        let _ = observe_post_tool_in(&state, request, now_secs());
    }
}

pub fn observe_post_tool_in(state: &Path, request: &HookRequest, now: u64) -> Option<()> {
    if !request.is_post_effect() {
        return None;
    }
    let session = session_id(&request.payload)?;
    let row = ledger_row(request, now)?;
    append_capped(
        &ledger_path(state, &session),
        &row.to_string(),
        LEDGER_CAP_BYTES,
    )
}

/// UserPromptSubmit: append a turn marker (with the user's prompt text, used
/// as grounding for ids the user supplied). Rows after the newest marker are
/// "this turn".
pub fn mark_turn_start(request: &HookRequest) {
    if disabled() {
        return;
    }
    if let Some(state) = state_dir() {
        let _ = mark_turn_start_in(&state, request, now_secs(), now_nanos());
    }
}

pub fn mark_turn_start_in(
    state: &Path,
    request: &HookRequest,
    now: u64,
    nonce: u128,
) -> Option<()> {
    if !matches!(
        request.event_type.as_str(),
        "UserPromptSubmit" | "user-prompt-submit"
    ) {
        return None;
    }
    let object = request.payload.as_object()?;
    let session = session_id(&request.payload)?;
    let prompt = first_string(object, &["prompt", "user_prompt", "userPrompt"])?;
    // Host-injected notices are not a genuine user turn.
    if [
        "<task-notification",
        "<system-reminder",
        "[Request interrupted",
    ]
    .iter()
    .any(|prefix| prompt.starts_with(*prefix))
    {
        return None;
    }
    let row = json!({
        "marker": "turn",
        "t": now,
        "id": nonce.to_string(),
        "prompt": truncate_chars(&prompt, PROMPT_LIMIT),
    });
    append_capped(
        &ledger_path(state, &session),
        &row.to_string(),
        LEDGER_CAP_BYTES,
    )
}

// ---------------------------------------------------------------------------
// Ledger reading
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct Row {
    tool: String,
    command: Option<String>,
    exit: Option<i64>,
    failed: bool,
    edit: bool,
    path: Option<String>,
    tail: String,
    ids: Vec<String>,
    success_seen: bool,
    failure_seen: bool,
}

#[derive(Clone, Debug)]
enum Entry {
    Turn { id: String, prompt: String },
    Row(Row),
}

fn parse_entry(line: &str) -> Option<Entry> {
    let value: Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    if object.get("marker").and_then(Value::as_str) == Some("turn") {
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                object
                    .get("t")
                    .and_then(Value::as_u64)
                    .map(|seconds| seconds.to_string())
            })?;
        let prompt = object
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        return Some(Entry::Turn { id, prompt });
    }
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    let flag = |key: &str| object.get(key).and_then(Value::as_bool).unwrap_or(false);
    Some(Entry::Row(Row {
        tool: text("tool")?,
        command: text("command"),
        exit: object.get("exit").and_then(Value::as_i64),
        failed: flag("failed"),
        edit: flag("edit"),
        path: text("path"),
        tail: text("tail").unwrap_or_default(),
        ids: object
            .get("ids")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        success_seen: flag("success_seen"),
        failure_seen: flag("failure_seen"),
    }))
}

fn read_ledger(path: &Path) -> Option<Vec<Entry>> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    Some(text.lines().filter_map(parse_entry).collect())
}

struct TurnView<'a> {
    id: Option<String>,
    prompt: String,
    rows: Vec<&'a Row>,
}

/// Rows since the newest turn marker. With no marker (not wired, or trimmed
/// away) every retained row counts, which only ever widens the evidence.
fn split_turn(entries: &[Entry]) -> TurnView<'_> {
    let marker = entries
        .iter()
        .rposition(|entry| matches!(entry, Entry::Turn { .. }));
    let (id, prompt, start) = match marker.map(|index| (index, &entries[index])) {
        Some((index, Entry::Turn { id, prompt })) => (Some(id.clone()), prompt.clone(), index + 1),
        _ => (None, String::new(), 0),
    };
    let rows = entries[start..]
        .iter()
        .filter_map(|entry| match entry {
            Entry::Row(row) => Some(row),
            Entry::Turn { .. } => None,
        })
        .collect();
    TurnView { id, prompt, rows }
}

// ---------------------------------------------------------------------------
// Claim parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Green,
    Installed,
    Live,
    Done,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Claim {
    class: Class,
    word: String,
}

const HEDGE_WORDS: &[&str] = &[
    "will",
    "ll",
    "next",
    "plan",
    "plans",
    "planned",
    "planning",
    "once",
    "until",
    "unless",
    "should",
    "would",
    "hypothesis",
    "hypotheses",
    "unverified",
    "untested",
    "unconfirmed",
    "todo",
];

const HEDGE_PHRASES: &[&str] = &[
    "not verified",
    "not tested",
    "not confirmed",
    "not run",
    "not done",
    "not yet",
    "not complete",
    "not checked",
    "not been verified",
    "not been tested",
    "have not verified",
    "haven t verified",
    "did not verify",
    "didn t verify",
    "could not verify",
    "couldn t verify",
    "unable to verify",
    "can t verify",
    "cannot verify",
    "without verifying",
];

const PREDICATE_PREV: &[&str] = &[
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "s",
    "i",
    "we",
    "it",
    "they",
    "he",
    "she",
    "ve",
    "d",
    "re",
    "m",
    "has",
    "have",
    "had",
    "already",
    "now",
    "successfully",
    "fully",
    "freshly",
    "newly",
    "also",
    "just",
    "then",
    "finally",
    "all",
    "everything",
    "and",
    "but",
    "so",
    "looks",
    "looked",
    "seems",
    "remains",
    "still",
    "got",
];

const PREDICATE_NEXT: &[&str] = &[
    "and",
    "but",
    "on",
    "at",
    "in",
    "to",
    "from",
    "via",
    "into",
    "as",
    "with",
    "by",
    "for",
    "now",
    "again",
    "across",
    "everywhere",
    "locally",
    "successfully",
    "correctly",
    "properly",
    "here",
    "there",
];

const LIVE_PREV: &[&str] = &[
    "is", "are", "was", "were", "went", "goes", "gone", "now", "s", "already", "be", "been", "go",
    "going", "got", "finally", "still",
];

const GREEN_NEXT: &[&str] = &[
    "ci", "build", "builds", "tests", "test", "suite", "run", "runs", "checks", "gate", "workflow",
    "pipeline", "status", "light",
];

const TEST_CONTEXT: &[&str] = &[
    "test", "tests", "ci", "build", "builds", "check", "checks", "suite", "suites", "gate",
    "clippy", "lint", "workflow", "pipeline", "nextest", "pytest", "cargo", "run", "runs", "job",
    "jobs", "spec", "specs",
];

const FIXED_ADJECTIVE_NEXT: &[&str] = &[
    "width", "point", "size", "position", "height", "length", "rate", "price", "set", "interval",
    "delay", "cost", "ip", "number",
];

const DONE_EXCLUDED_PREV: &[&str] = &[
    "of", "to", "be", "get", "getting", "when", "once", "until", "if", "what", "how", "well", "got",
];

const WORKING_BLOCKED_NEXT: &[&str] = &[
    "on",
    "with",
    "tree",
    "directory",
    "dir",
    "copy",
    "set",
    "group",
    "memory",
    "session",
    "state",
    "file",
    "files",
    "from",
    "through",
    "toward",
    "towards",
    "together",
    "hard",
];

fn in_list(list: &[&str], item: Option<&str>) -> bool {
    item.map_or(false, |value| list.contains(&value))
}

fn classify_at(tokens: &[String], index: usize) -> Option<Class> {
    let word = tokens[index].as_str();
    let prev = index
        .checked_sub(1)
        .map(|position| tokens[position].as_str());
    let next = tokens.get(index + 1).map(String::as_str);
    let last = index + 1 == tokens.len();
    // A participle used as a statement ("is installed", "Fixed the bug"), not
    // an adjective inside a noun phrase ("the installed build").
    let predicative =
        index == 0 || last || in_list(PREDICATE_PREV, prev) || in_list(PREDICATE_NEXT, next);
    let test_context = tokens
        .iter()
        .any(|token| TEST_CONTEXT.contains(&token.as_str()));
    let (class, matched) = match word {
        "green" => (Class::Green, predicative || in_list(GREEN_NEXT, next)),
        "passing" => (
            Class::Green,
            test_context
                && (predicative
                    || in_list(
                        &["tests", "test", "suite", "ci", "checks", "gate", "build"],
                        prev,
                    )),
        ),
        "passes" | "passed" => (
            Class::Green,
            test_context
                && !in_list(
                    &[
                        "to", "can", "may", "must", "could", "should", "would", "let", "make",
                    ],
                    prev,
                )
                && !in_list(
                    &[
                        "to", "through", "in", "into", "as", "by", "over", "along", "on", "away",
                    ],
                    next,
                ),
        ),
        "pass" => (
            Class::Green,
            test_context
                && in_list(
                    &[
                        "tests",
                        "test",
                        "suite",
                        "ci",
                        "checks",
                        "check",
                        "build",
                        "gate",
                        "they",
                        "it",
                        "all",
                        "everything",
                        "now",
                        "still",
                        "clippy",
                        "lint",
                        "specs",
                    ],
                    prev,
                ),
        ),
        "installed" => (Class::Installed, predicative),
        "live" => (
            Class::Live,
            last || in_list(LIVE_PREV, prev)
                || in_list(&["now", "on", "at", "in", "and", "again"], next),
        ),
        "deployed" | "published" => (Class::Live, predicative),
        "fixed" => (
            Class::Done,
            predicative && !in_list(FIXED_ADJECTIVE_NEXT, next),
        ),
        "done" => (
            Class::Done,
            predicative
                && !in_list(DONE_EXCLUDED_PREV, prev)
                && !in_list(&["criteria", "definition"], next),
        ),
        // "Complete the steps" is an imperative; only the participles may open
        // a sentence as a claim.
        "complete" => (Class::Done, predicative && (index != 0 || last)),
        "completed" | "implemented" => (Class::Done, predicative),
        "works" => (
            Class::Done,
            !tokens[index.saturating_sub(3)..index].iter().any(|token| {
                matches!(
                    token.as_str(),
                    "how" | "what" | "why" | "whether" | "see" | "understand"
                )
            }),
        ),
        "working" => (
            Class::Done,
            !in_list(WORKING_BLOCKED_NEXT, next)
                && (in_list(
                    &[
                        "is",
                        "are",
                        "was",
                        "s",
                        "now",
                        "be",
                        "been",
                        "all",
                        "everything",
                        "fully",
                        "also",
                        "properly",
                        "correctly",
                        "it",
                    ],
                    prev,
                ) || in_list(
                    &[
                        "correctly",
                        "properly",
                        "now",
                        "fine",
                        "again",
                        "as",
                        "end",
                        "well",
                        "ok",
                        "okay",
                        "perfectly",
                    ],
                    next,
                )),
        ),
        _ => return None,
    };
    if matched {
        Some(class)
    } else {
        None
    }
}

fn negated(tokens: &[String], index: usize) -> bool {
    tokens[index.saturating_sub(2)..index].iter().any(|token| {
        matches!(
            token.as_str(),
            "not" | "no" | "never" | "t" | "cannot" | "without"
        )
    })
}

fn claims_in_tokens(tokens: &[String]) -> Vec<Claim> {
    let mut claims = Vec::new();
    for index in 0..tokens.len() {
        if let Some(class) = classify_at(tokens, index) {
            if !negated(tokens, index) {
                claims.push(Claim {
                    class,
                    word: tokens[index].clone(),
                });
            }
        }
    }
    claims
}

/// A sentence that says it is unverified, planned, hypothetical or negated is
/// not a completion claim.
fn is_hedged(tokens: &[String]) -> bool {
    if tokens
        .iter()
        .any(|token| HEDGE_WORDS.contains(&token.as_str()))
    {
        return true;
    }
    let joined = format!(" {} ", tokens.join(" "));
    HEDGE_PHRASES
        .iter()
        .any(|phrase| joined.contains(&format!(" {phrase} ")))
}

/// "Fixed the parser. Not verified." - the hedge sits in the next sentence.
fn starts_with_hedge(tokens: &[String]) -> bool {
    let head = |count: usize| {
        tokens
            .iter()
            .take(count)
            .map(String::as_str)
            .collect::<Vec<&str>>()
            .join(" ")
    };
    matches!(
        head(1).as_str(),
        "unverified" | "untested" | "hypothesis" | "unconfirmed"
    ) || matches!(
        head(2).as_str(),
        "not verified" | "not tested" | "not run" | "not yet" | "not confirmed" | "not checked"
    )
}

fn split_sentences(line: &str) -> Vec<String> {
    let characters: Vec<char> = line.chars().collect();
    let mut sentences: Vec<String> = Vec::new();
    let mut current = String::new();
    for (index, character) in characters.iter().enumerate() {
        current.push(*character);
        let terminal = matches!(*character, '.' | '!' | '?');
        let boundary = characters
            .get(index + 1)
            .map_or(true, |following| following.is_whitespace());
        if terminal && boundary {
            sentences.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        sentences.push(current);
    }
    sentences
}

fn remove_inline_code(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut inside = false;
    for character in line.chars() {
        if character == '`' {
            inside = !inside;
            out.push(' ');
        } else if !inside {
            out.push(character);
        }
    }
    out
}

/// Claim words in the assistant's own statements: fenced code, block quotes,
/// double-quoted text, inline code, questions and hedged sentences are skipped.
fn claims_in(message: &str) -> Vec<Claim> {
    let unfenced = strip_fenced_blocks(message);
    let unquoted = unfenced
        .lines()
        .filter(|line| !line.trim_start().starts_with('>'))
        .collect::<Vec<&str>>()
        .join("\n");
    let (scan_text, _) = split_quotes(&unquoted);
    let mut claims: Vec<Claim> = Vec::new();
    for line in scan_text.lines() {
        let line = remove_inline_code(line);
        let sentences = split_sentences(&line);
        let token_lists: Vec<Vec<String>> = sentences
            .iter()
            .map(|sentence| word_list(sentence))
            .collect();
        for (index, sentence) in sentences.iter().enumerate() {
            let tokens = &token_lists[index];
            if tokens.is_empty() || sentence.trim_end().ends_with('?') || is_hedged(tokens) {
                continue;
            }
            if token_lists
                .get(index + 1)
                .map_or(false, |following| starts_with_hedge(following))
            {
                continue;
            }
            for claim in claims_in_tokens(tokens) {
                if !claims.contains(&claim) {
                    claims.push(claim);
                }
            }
        }
    }
    claims
}

// ---------------------------------------------------------------------------
// Evidence matching
// ---------------------------------------------------------------------------

const NON_RUN: &[&str] = &[
    "cat", "ls", "ll", "grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "head", "tail", "find",
    "fd", "echo", "printf", "less", "more", "wc", "cd", "pwd", "export", "set", "unset", "source",
    "test", "[", "[[", "true", "false", "type", "which", "stat", "file", "diff", "cmp", "sort",
    "uniq", "tr", "cut", "tee", "mkdir", "rm", "rmdir", "cp", "mv", "ln", "touch", "chmod",
    "chown", "open", "git", "date", "sleep", "read", "wait", "basename", "dirname", "realpath",
    "readlink", "jq", "yq", "column", "nl", "du", "df", "ps", "pgrep", "kill", "printenv", "id",
    "whoami", "hostname", "uname", "say", "tput", "clear", "history", "rustfmt", "prettier",
    "gofmt", "black", "isort",
];

const WRAPPERS: &[&str] = &[
    "time",
    "sudo",
    "env",
    "nohup",
    "exec",
    "command",
    "nice",
    "caffeinate",
];

const GREEN_WORDS: &[&str] = &[
    "test", "tests", "nextest", "gate", "check", "checks", "clippy", "pytest", "vitest", "jest",
    "mocha", "tsc", "lint", "unittest", "ctest", "verify",
];

const INSTALLED_WORDS: &[&str] = &[
    "install",
    "reinstall",
    "installed",
    "installer",
    "version",
    "doctor",
    "shasum",
    "sha256sum",
    "codesign",
    "plutil",
    "mdls",
    "spctl",
    "pkgutil",
    "readlink",
    "which",
];

const READ_ONLY_FIRST: &[&str] = &[
    "echo", "printf", "git", "grep", "egrep", "fgrep", "rg", "sed", "awk",
];

const LIVE_WORDS: &[&str] = &[
    "curl",
    "wget",
    "wrangler",
    "deploy",
    "health",
    "healthcheck",
    "smoke",
    "httpie",
];

struct Segment {
    first: String,
    words: Vec<String>,
}

impl Segment {
    fn has(&self, word: &str) -> bool {
        self.words
            .iter()
            .any(|candidate| candidate.as_str() == word)
    }

    fn has_any(&self, words: &[&str]) -> bool {
        words.iter().any(|word| self.has(word))
    }
}

fn is_env_assignment(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|character: char| character.is_ascii_digit())
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        }
        None => false,
    }
}

/// Split a shell command on `&&`, `||`, `;`, `|` and newlines. Each segment
/// keeps its first real program (after env assignments and wrappers) and its
/// words.
fn segments(command: &str) -> Vec<Segment> {
    let normalized = command
        .replace("&&", "\n")
        .replace("||", "\n")
        .replace(';', "\n")
        .replace('|', "\n");
    let mut out: Vec<Segment> = Vec::new();
    for raw in normalized.lines() {
        let mut tokens: Vec<&str> = raw.split_whitespace().collect();
        loop {
            let skip = match tokens.first() {
                Some(token) => is_env_assignment(token) || WRAPPERS.contains(token),
                None => false,
            };
            if !skip {
                break;
            }
            tokens.remove(0);
        }
        if tokens.is_empty() {
            continue;
        }
        let head = tokens[0];
        let first = head
            .rsplit(|character: char| character == '/' || character == '\\')
            .next()
            .unwrap_or(head)
            .to_ascii_lowercase();
        out.push(Segment {
            first,
            words: word_list(raw),
        });
    }
    out
}

/// Did this command execute something (as opposed to only reading, listing or
/// shuffling files)?
fn runs_code(command: &str) -> bool {
    segments(command)
        .iter()
        .any(|segment| !NON_RUN.contains(&segment.first.as_str()))
}

fn green_command(command: &str, row: &Row) -> bool {
    for segment in segments(command) {
        if NON_RUN.contains(&segment.first.as_str()) {
            continue;
        }
        if segment.first == "gh" {
            let ci_view = (segment.has("run") && (segment.has("watch") || segment.has("view")))
                || (segment.has("pr") && segment.has("checks"));
            if ci_view {
                if row.success_seen && !row.failure_seen {
                    return true;
                }
                continue;
            }
        }
        if segment.has_any(GREEN_WORDS) && !row.failure_seen {
            return true;
        }
    }
    false
}

fn installed_command(command: &str) -> bool {
    segments(command).iter().any(|segment| {
        !READ_ONLY_FIRST.contains(&segment.first.as_str())
            && (segment.has_any(INSTALLED_WORDS) || (segment.has("setup") && segment.has("status")))
    })
}

fn live_command(command: &str) -> bool {
    segments(command).iter().any(|segment| {
        !READ_ONLY_FIRST.contains(&segment.first.as_str())
            && (segment.has_any(LIVE_WORDS)
                || (segment.first == "gh" && (segment.has("release") || segment.has("api"))))
    })
}

fn non_evidence_tool(tool: &str) -> bool {
    matches!(
        tool.to_ascii_lowercase().as_str(),
        "agent"
            | "task"
            | "taskcreate"
            | "taskupdate"
            | "tasklist"
            | "taskget"
            | "taskoutput"
            | "taskstop"
            | "todowrite"
            | "sendmessage"
            | "askuserquestion"
            | "exitplanmode"
            | "enterplanmode"
            | "skill"
            | "toolsearch"
    )
}

/// Tools that look at the real target (a page, a screen, a simulator).
fn observation_tool(tool: &str) -> bool {
    let lowered = tool.to_ascii_lowercase();
    [
        "navigate",
        "browser",
        "chrome",
        "playwright",
        "screenshot",
        "computer",
        "webfetch",
        "web_fetch",
        "simulator",
    ]
    .iter()
    .any(|needle| lowered.contains(*needle))
}

fn row_counts(class: Class, row: &Row, edited: bool) -> bool {
    if row.failed || row.edit || non_evidence_tool(&row.tool) {
        return false;
    }
    let command = row.command.as_deref();
    match class {
        Class::Green => command.map_or(false, |text| green_command(text, row)),
        Class::Installed => command.map_or(false, installed_command),
        Class::Live => command.map_or(false, live_command) || observation_tool(&row.tool),
        Class::Done => {
            if !edited {
                // Nothing was changed this turn: any successful tool result
                // (a command, a read, a fetch) is something to cite.
                return true;
            }
            observation_tool(&row.tool)
                || command.map_or(false, |text| runs_code(text) && !row.failure_seen)
        }
    }
}

/// A successful, matching row after the last successful edit of this turn.
fn class_satisfied(class: Class, rows: &[&Row]) -> bool {
    let last_edit = rows.iter().rposition(|row| row.edit && !row.failed);
    let window = match last_edit {
        Some(index) => &rows[index + 1..],
        None => rows,
    };
    window
        .iter()
        .any(|row| row_counts(class, row, last_edit.is_some()))
}

// ---------------------------------------------------------------------------
// Grounding
// ---------------------------------------------------------------------------

struct Haystack {
    text: String,
    ids: Vec<String>,
}

impl Haystack {
    fn build(rows: &[&Row], prompt: &str, message: &str) -> Self {
        let mut text = String::new();
        let mut ids: Vec<String> = Vec::new();
        for row in rows {
            if let Some(command) = &row.command {
                text.push_str(command);
                text.push('\n');
            }
            text.push_str(&row.tail);
            text.push('\n');
            if let Some(path) = &row.path {
                text.push_str(path);
                text.push('\n');
            }
            ids.extend(row.ids.iter().cloned());
        }
        text.push_str(prompt);
        for quoted in quoted_text(message) {
            text.push('\n');
            text.push_str(&quoted);
        }
        Self {
            text: text.to_lowercase().replace('\\', "/"),
            ids: ids
                .into_iter()
                .map(|id| id.to_lowercase().replace('\\', "/"))
                .collect(),
        }
    }

    fn has_text(&self, needle: &str) -> bool {
        let lowered = needle.to_lowercase();
        self.text.contains(&lowered) || self.ids.iter().any(|id| *id == lowered)
    }

    fn has_sha(&self, sha: &str) -> bool {
        let lowered = sha.to_ascii_lowercase();
        self.text.contains(&lowered)
            || self.ids.iter().any(|id| {
                id.len() >= 7
                    && (id.starts_with(lowered.as_str()) || lowered.starts_with(id.as_str()))
            })
    }

    fn has_issue(&self, issue: &str) -> bool {
        let digits = issue.trim_start_matches('#');
        self.text.contains(issue)
            || contains_number_token(&self.text, digits)
            || self.ids.iter().any(|id| id == issue)
    }

    fn has_path(&self, path: &str) -> bool {
        let normalized = path.to_lowercase().replace('\\', "/");
        if self.text.contains(&normalized) || self.ids.iter().any(|id| id.contains(&normalized)) {
            return true;
        }
        let name = normalized
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("");
        name.len() >= 3 && (self.text.contains(name) || self.ids.iter().any(|id| id.contains(name)))
    }
}

/// Identifiers cited in the message that appear nowhere in this turn's
/// ledger, the user's prompt, or the message's own quoted text.
fn ungrounded_items(message: &str, haystack: &Haystack) -> Vec<String> {
    let cleaned = strip_uuids(message);
    let mut out: Vec<String> = Vec::new();
    for sha in sha_tokens(&cleaned, 200) {
        if !haystack.has_sha(&sha) {
            push_unique(&mut out, sha, 200);
        }
    }
    for run in run_ids(&cleaned) {
        if !haystack.has_text(&run) {
            push_unique(&mut out, format!("run {run}"), 200);
        }
    }
    for issue in issue_refs(&cleaned, 200) {
        if !haystack.has_issue(&issue) {
            push_unique(&mut out, issue, 200);
        }
    }
    for path in backticked_paths(message) {
        if !haystack.has_path(&path) {
            push_unique(&mut out, format!("`{path}`"), 200);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

struct Verdict {
    turn_id: Option<String>,
    unsatisfied: Vec<Claim>,
    ungrounded: Vec<String>,
}

fn evaluate(message: &str, entries: &[Entry]) -> Option<Verdict> {
    if message.trim().is_empty() {
        return None;
    }
    let view = split_turn(entries);
    let mut unsatisfied: Vec<Claim> = Vec::new();
    for claim in claims_in(message) {
        if !class_satisfied(claim.class, &view.rows) {
            unsatisfied.push(claim);
        }
    }
    let haystack = Haystack::build(&view.rows, &view.prompt, message);
    let all = ungrounded_items(message, &haystack);
    let ungrounded = if all.len() >= UNGROUNDED_BLOCK_THRESHOLD {
        all
    } else {
        Vec::new()
    };
    if unsatisfied.is_empty() && ungrounded.is_empty() {
        return None;
    }
    Some(Verdict {
        turn_id: view.id,
        unsatisfied,
        ungrounded,
    })
}

fn listed(items: &[String]) -> String {
    let shown: Vec<&str> = items
        .iter()
        .take(REPORTED_LIST_LIMIT)
        .map(String::as_str)
        .collect();
    let mut text = shown.join(", ");
    if items.len() > REPORTED_LIST_LIMIT {
        text.push_str(&format!(" (+{} more)", items.len() - REPORTED_LIST_LIMIT));
    }
    text
}

fn reason_text(verdict: &Verdict) -> String {
    const TAIL: &str = "Show output from the real target this turn, or say 'not verified'. Wrong surface is not a pass; green CI is not a verdict.";
    let mut text = String::new();
    match verdict.unsatisfied.first() {
        Some(first) => {
            text.push_str(&format!("You said '{}'. {TAIL}", first.word));
            if verdict.unsatisfied.len() > 1 {
                let others: Vec<String> = verdict
                    .unsatisfied
                    .iter()
                    .skip(1)
                    .map(|claim| format!("'{}'", claim.word))
                    .collect();
                text.push_str(&format!(
                    " Also claimed without evidence: {}.",
                    listed(&others)
                ));
            }
            if !verdict.ungrounded.is_empty() {
                text.push_str(&format!(
                    " Not found in this turn's output: {}.",
                    listed(&verdict.ungrounded)
                ));
            }
        }
        None => {
            text.push_str(&format!(
                "The message cites identifiers that appear in no output from this turn: {}. {TAIL}",
                listed(&verdict.ungrounded)
            ));
        }
    }
    text
}

fn log_shadow(state: &Path, session: &str, verdict: &Verdict, reason: &str, now: u64) {
    let claims: Vec<&str> = verdict
        .unsatisfied
        .iter()
        .map(|claim| claim.word.as_str())
        .collect();
    let row = json!({
        "t": now,
        "session": session,
        "turn": verdict.turn_id,
        "would_block": true,
        "claims": claims,
        "ungrounded": verdict.ungrounded,
        "reason": reason,
    });
    let _ = append_capped(
        &evidence_dir(state).join(SHADOW_FILE),
        &row.to_string(),
        LEDGER_CAP_BYTES,
    );
}

/// Stop: `Some(denied)` when the final message claims something the ledger
/// does not back (host turns it into a block with the reason), else `None`.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    if disabled() {
        return None;
    }
    let state = state_dir()?;
    let mode = mode_from(std::env::var(MODE_ENV).ok().as_deref());
    stop_check_in(&state, request, mode, now_secs())
}

pub fn stop_check_in(
    state: &Path,
    request: &HookRequest,
    mode: Mode,
    now: u64,
) -> Option<HookResponse> {
    if mode == Mode::Off || !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let object = request.payload.as_object()?;
    // A stop that follows a block carries stop_hook_active: never block twice.
    if first_bool(object, &["stop_hook_active", "stopHookActive"]) == Some(true) {
        return None;
    }
    let message = first_string(object, &LAST_MESSAGE_KEYS)?;
    let session = session_id(&request.payload)?;
    let entries = read_ledger(&ledger_path(state, &session))?;
    let verdict = evaluate(&message, &entries)?;
    if let Some(turn) = verdict.turn_id.as_deref() {
        let blocked = fs::read_to_string(blocked_path(state, &session)).unwrap_or_default();
        if blocked.trim() == turn {
            return None;
        }
    }
    let reason = reason_text(&verdict);
    match mode {
        Mode::Shadow => {
            log_shadow(state, &session, &verdict, &reason, now);
            None
        }
        Mode::Enforce => {
            if let Some(turn) = verdict.turn_id.as_deref() {
                let _ = write_atomic(&blocked_path(state, &session), turn.as_bytes());
            }
            Some(HookResponse::denied(
                request.event_type.clone(),
                BLOCK_CODE,
                reason,
                "strong",
            ))
        }
        Mode::Off => None,
    }
}

/// The line for the end of a turn that this check blocked once and that still
/// stands unresolved: call it on the `Stop` that carries `stop_hook_active`
/// (the host allowed the stop after our block) and append the result to the
/// reply. `None` when this check did not block this turn or the claim is now
/// backed.
pub fn unresolved_note(request: &HookRequest) -> Option<String> {
    if disabled() {
        return None;
    }
    if mode_from(std::env::var(MODE_ENV).ok().as_deref()) == Mode::Off {
        return None;
    }
    let state = state_dir()?;
    unresolved_note_in(&state, request)
}

pub fn unresolved_note_in(state: &Path, request: &HookRequest) -> Option<String> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let object = request.payload.as_object()?;
    if first_bool(object, &["stop_hook_active", "stopHookActive"]) != Some(true) {
        return None;
    }
    let message = first_string(object, &LAST_MESSAGE_KEYS)?;
    let session = session_id(&request.payload)?;
    let entries = read_ledger(&ledger_path(state, &session))?;
    let verdict = evaluate(&message, &entries)?;
    let turn = verdict.turn_id.as_deref()?;
    let blocked = fs::read_to_string(blocked_path(state, &session)).ok()?;
    if blocked.trim() != turn {
        return None;
    }
    Some(format!("UNRESOLVED: {}", reason_text(&verdict)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("legion-hook-evidence-{}-{nonce}", process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create scratch directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(event: &str, payload: Value) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.into(),
            event_type: event.into(),
            payload,
        }
    }

    fn bash(command: &str, stdout: &str) -> HookRequest {
        request(
            "PostToolUse",
            json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_response": {"stdout": stdout, "stderr": "", "interrupted": false},
            }),
        )
    }

    fn bash_failure(command: &str, error: &str) -> HookRequest {
        request(
            "PostToolUseFailure",
            json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "error": error,
            }),
        )
    }

    fn edit(path: &str) -> HookRequest {
        request(
            "PostToolUse",
            json!({
                "session_id": "s1",
                "tool_name": "Edit",
                "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"},
                "tool_response": {"filePath": path},
            }),
        )
    }

    fn prompt(text: &str) -> HookRequest {
        request(
            "UserPromptSubmit",
            json!({"session_id": "s1", "prompt": text}),
        )
    }

    fn stop(message: &str, active: bool) -> HookRequest {
        request(
            "Stop",
            json!({
                "session_id": "s1",
                "last_assistant_message": message,
                "stop_hook_active": active,
            }),
        )
    }

    fn observe(state: &Path, requests: &[HookRequest]) {
        for item in requests {
            observe_post_tool_in(state, item, 100).expect("row recorded");
        }
    }

    fn start_turn(state: &Path, text: &str, nonce: u128) {
        mark_turn_start_in(state, &prompt(text), 100, nonce).expect("turn marker recorded");
    }

    fn check(state: &Path, message: &str) -> Option<HookResponse> {
        stop_check_in(state, &stop(message, false), Mode::Enforce, 200)
    }

    /// The verdict without the once-per-turn marker, for tests that ask more
    /// than once in a single turn.
    fn verdict(state: &Path, message: &str) -> Option<Verdict> {
        let entries = read_ledger(&ledger_path(state, "s1")).expect("ledger exists");
        evaluate(message, &entries)
    }

    fn claim_words(message: &str) -> Vec<String> {
        claims_in(message)
            .into_iter()
            .map(|claim| claim.word)
            .collect()
    }

    #[test]
    fn claim_with_no_evidence_blocks() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        let response = check(scratch.path(), "Fixed the parser bug.").expect("blocks");
        assert!(!response.allowed);
        assert_eq!(response.event_type, "Stop");
        assert_eq!(response.code.as_deref(), Some(BLOCK_CODE));
        assert!(
            response
                .reason
                .starts_with("You said 'fixed'. Show output from the real target"),
            "reason: {}",
            response.reason
        );
        assert!(response.reason.contains("green CI is not a verdict"));
    }

    #[test]
    fn missing_ledger_fails_open() {
        let scratch = Scratch::new();
        assert!(check(scratch.path(), "Fixed the parser bug.").is_none());
    }

    #[test]
    fn not_verified_is_allowed() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        assert!(check(scratch.path(), "Fixed the parser, not verified.").is_none());
        assert!(check(scratch.path(), "Fixed the parser. Not verified.").is_none());
        assert!(check(scratch.path(), "The fix is done, unverified.").is_none());
    }

    #[test]
    fn green_with_matching_test_after_last_edit_is_allowed() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix it", 1);
        observe(
            scratch.path(),
            &[
                edit("src/a.rs"),
                bash("cargo test -p x", "test result: ok. 3 passed; 0 failed"),
            ],
        );
        assert!(check(scratch.path(), "All tests pass.").is_none());
    }

    #[test]
    fn green_with_test_before_last_edit_blocks() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix it", 1);
        observe(
            scratch.path(),
            &[
                bash("cargo test -p x", "test result: ok. 3 passed; 0 failed"),
                edit("src/a.rs"),
            ],
        );
        let response = check(scratch.path(), "Tests are green.").expect("blocks");
        assert!(response.reason.starts_with("You said 'green'."));
    }

    #[test]
    fn failed_test_run_is_not_evidence() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix it", 1);
        observe(
            scratch.path(),
            &[
                edit("src/a.rs"),
                bash_failure("cargo test", "Exit code 101\nerror: test failed"),
            ],
        );
        assert!(check(scratch.path(), "Tests pass.").is_some());

        let other = Scratch::new();
        start_turn(other.path(), "fix it", 1);
        observe(
            other.path(),
            &[
                edit("src/a.rs"),
                bash(
                    "cargo test 2>&1 | tail -3",
                    "test result: FAILED. 3 passed; 1 failed",
                ),
            ],
        );
        assert!(check(other.path(), "Tests pass.").is_some());
    }

    #[test]
    fn stop_hook_active_is_allowed() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        let response = stop_check_in(
            scratch.path(),
            &stop("Fixed the parser bug.", true),
            Mode::Enforce,
            200,
        );
        assert!(response.is_none());
    }

    #[test]
    fn working_on_does_not_trigger() {
        assert!(claim_words("Still working on the parser.").is_empty());
        assert!(claim_words("I am working on it now.").is_empty());
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        assert!(check(scratch.path(), "Still working on the parser.").is_none());
    }

    #[test]
    fn claim_parser_separates_statements_from_nouns_and_hedges() {
        assert!(claim_words("The installed build is at /Applications/X.").is_empty());
        assert_eq!(claim_words("It is installed."), vec!["installed"]);
        assert!(claim_words("Is it done?").is_empty());
        assert!(claim_words("Not done.").is_empty());
        assert!(claim_words("It isn't fixed.").is_empty());
        assert!(claim_words("I will fix this next.").is_empty());
        assert!(claim_words("Fixed width columns are used.").is_empty());
        assert!(claim_words("Live data is shown here.").is_empty());
        assert_eq!(claim_words("The site is live."), vec!["live"]);
        assert!(claim_words("```\nfixed\n```").is_empty());
        assert!(claim_words("> it is done").is_empty());
        assert!(claim_words("You said \"it is done\" earlier.").is_empty());
        assert!(claim_words("Run `cargo test` and check the output.").is_empty());
        assert_eq!(claim_words("Tests are green."), vec!["green"]);
        assert!(claim_words("Add a green button.").is_empty());
        assert!(claim_words("That is how it works.").is_empty());
        assert_eq!(claim_words("Implemented the check."), vec!["implemented"]);
    }

    #[test]
    fn grounding_below_threshold_is_ignored() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "land it", 1);
        assert!(check(scratch.path(), "Landed abc1234 and fed5678c.").is_none());
    }

    #[test]
    fn grounding_at_threshold_blocks_and_lists_items() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "land it", 1);
        let response = check(
            scratch.path(),
            "Landed abc1234 and fed5678c, see `docs/zzz/readme.md`.",
        )
        .expect("blocks");
        assert!(response.reason.contains("abc1234"));
        assert!(response.reason.contains("fed5678c"));
        assert!(response.reason.contains("`docs/zzz/readme.md`"));
        assert!(response
            .reason
            .contains("appear in no output from this turn"));
    }

    #[test]
    fn grounding_accepts_ids_from_output_commands_and_the_prompt() {
        let from_output = Scratch::new();
        start_turn(from_output.path(), "land it", 1);
        observe(
            from_output.path(),
            &[
                bash("git log --oneline -3", "abc1234 one\nfed5678c two\n"),
                bash("ls docs/zzz", "readme.md\n"),
            ],
        );
        assert!(check(
            from_output.path(),
            "Landed abc1234 and fed5678c, see `docs/zzz/readme.md`."
        )
        .is_none());

        let from_prompt = Scratch::new();
        start_turn(
            from_prompt.path(),
            "compare abc1234 with fed5678c in docs/zzz/readme.md",
            1,
        );
        assert!(check(
            from_prompt.path(),
            "Landed abc1234 and fed5678c, see `docs/zzz/readme.md`."
        )
        .is_none());
    }

    #[test]
    fn grounding_uses_ids_beyond_the_tail() {
        let mut long_output = String::new();
        for index in 0..40 {
            long_output.push_str(&format!("{index:07x}a commit number {index}\n"));
        }
        long_output.push_str("done listing\n");
        let row = ledger_row(&bash("git log --oneline", &long_output), 1).expect("row");
        let ids: Vec<&str> = row["ids"]
            .as_array()
            .expect("ids array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(ids.contains(&"0000000a"));
        assert!(row["tail"].as_str().expect("tail").chars().count() <= TAIL_LIMIT);
    }

    #[test]
    fn identifier_extraction_handles_runs_issues_uuids_and_paths() {
        let message = "Run 12345678901 and #4321 at https://github.com/o/r/actions/runs/998877665544 \
                       id 123e4567-e89b-12d3-a456-426614174000 `src/main.rs:12` `cargo test` `std::fs` `a/b`";
        assert_eq!(run_ids(message), vec!["12345678901", "998877665544"]);
        assert_eq!(issue_refs(message, 10), vec!["#4321"]);
        assert!(sha_tokens(&strip_uuids(message), 10).is_empty());
        assert_eq!(backticked_paths(message), vec!["src/main.rs"]);
        assert_eq!(issue_refs("&#39; abc#12 (#7)", 10), vec!["#7"]);
    }

    #[test]
    fn block_is_once_per_turn_and_resets_on_a_new_prompt() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        assert!(check(scratch.path(), "Fixed the parser bug.").is_some());
        assert!(check(scratch.path(), "Fixed the parser bug.").is_none());
        start_turn(scratch.path(), "and the lexer", 2);
        assert!(check(scratch.path(), "Fixed the lexer bug.").is_some());
    }

    #[test]
    fn unresolved_note_follows_a_block_that_still_stands() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        // No block yet: nothing to report.
        assert!(unresolved_note_in(scratch.path(), &stop("Fixed the parser bug.", true)).is_none());
        assert!(check(scratch.path(), "Fixed the parser bug.").is_some());
        // The host re-enters Stop with stop_hook_active; the stop is allowed.
        assert!(stop_check_in(
            scratch.path(),
            &stop("Fixed the parser bug.", true),
            Mode::Enforce,
            300
        )
        .is_none());
        let note = unresolved_note_in(scratch.path(), &stop("Fixed the parser bug.", true))
            .expect("unresolved");
        assert!(note.starts_with("UNRESOLVED: You said 'fixed'."), "{note}");
        // Resolved by a successful run after the block: no note.
        observe(scratch.path(), &[bash("cargo build", "Finished dev")]);
        assert!(unresolved_note_in(scratch.path(), &stop("Fixed the parser bug.", true)).is_none());
        // Not a re-entered stop: no note.
        assert!(
            unresolved_note_in(scratch.path(), &stop("Fixed the parser bug.", false)).is_none()
        );
    }

    #[test]
    fn rows_before_the_turn_marker_do_not_count() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "first", 1);
        observe(
            scratch.path(),
            &[bash("cargo test", "test result: ok. 1 passed; 0 failed")],
        );
        start_turn(scratch.path(), "second", 2);
        assert!(check(scratch.path(), "Tests pass.").is_some());
    }

    #[test]
    fn shadow_mode_logs_and_allows() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix the parser", 1);
        let response = stop_check_in(
            scratch.path(),
            &stop("Fixed the parser bug.", false),
            Mode::Shadow,
            200,
        );
        assert!(response.is_none());
        let log = fs::read_to_string(evidence_dir(scratch.path()).join(SHADOW_FILE))
            .expect("shadow log written");
        assert!(log.contains("\"would_block\":true"));
        assert!(log.contains("fixed"));
    }

    #[test]
    fn kill_switch_and_mode_parsing() {
        assert!(killed("a, Evidence ,b"));
        assert!(killed("evidence"));
        assert!(!killed("other,evidences"));
        assert!(!killed(""));
        assert_eq!(mode_from(None), DEFAULT_MODE);
        assert_eq!(mode_from(Some("shadow")), Mode::Shadow);
        assert_eq!(mode_from(Some(" Enforce ")), Mode::Enforce);
        assert_eq!(mode_from(Some("off")), Mode::Off);
        assert_eq!(mode_from(Some("nonsense")), DEFAULT_MODE);
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix", 1);
        assert!(stop_check_in(scratch.path(), &stop("Fixed it.", false), Mode::Off, 1).is_none());
    }

    #[test]
    fn exit_codes_are_read_from_the_shapes_the_hosts_send() {
        let failure = ledger_row(&bash_failure("false", "Exit code 2\nboom"), 1).expect("row");
        assert_eq!(failure["exit"], json!(2));
        assert_eq!(failure["failed"], json!(true));

        let explicit = ledger_row(
            &request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "Bash",
                    "tool_input": {"command": "x"},
                    "tool_response": {"stdout": "", "stderr": "", "exit_code": 1},
                }),
            ),
            1,
        )
        .expect("row");
        assert_eq!(explicit["exit"], json!(1));
        assert_eq!(explicit["failed"], json!(true));

        let codex = ledger_row(
            &request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "shell",
                    "tool_input": {"command": ["bash", "-lc", "ls"]},
                    "tool_response": "Exit code: 0\nWall time: 1 seconds\nOutput:\nok",
                }),
            ),
            1,
        )
        .expect("row");
        assert_eq!(codex["exit"], json!(0));
        assert_eq!(codex["failed"], json!(false));
        assert_eq!(codex["command"], json!("bash -lc ls"));

        let unknown = ledger_row(&bash("ls", "a"), 1).expect("row");
        assert_eq!(unknown["exit"], Value::Null);
        assert_eq!(unknown["failed"], json!(false));
        assert_eq!(unknown["edit"], json!(false));

        let interrupted = ledger_row(
            &request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "Bash",
                    "tool_input": {"command": "sleep 99"},
                    "tool_response": {"stdout": "", "stderr": "", "interrupted": true},
                }),
            ),
            1,
        )
        .expect("row");
        assert_eq!(interrupted["failed"], json!(true));
    }

    #[test]
    fn rows_record_edits_paths_truncated_commands_and_tails() {
        let row = ledger_row(&edit("/repo/src/a.rs"), 7).expect("row");
        assert_eq!(row["edit"], json!(true));
        assert_eq!(row["path"], json!("/repo/src/a.rs"));
        assert_eq!(row["t"], json!(7));

        let patch = ledger_row(
            &request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "apply_patch",
                    "tool_input": {"command": ["apply_patch", "*** Begin Patch\n*** Update File: src/b.rs\n@@\n-a\n+b\n*** End Patch"]},
                    "tool_response": "Exit code: 0\nOutput:\nSuccess",
                }),
            ),
            1,
        )
        .expect("row");
        assert_eq!(patch["edit"], json!(true));
        assert_eq!(patch["path"], json!("src/b.rs"));

        let long_command = "x".repeat(900);
        let long_output = format!("{}END", "y".repeat(900));
        let row = ledger_row(&bash(&long_command, &long_output), 1).expect("row");
        assert_eq!(
            row["command"].as_str().expect("command").chars().count(),
            COMMAND_LIMIT
        );
        let tail = row["tail"].as_str().expect("tail");
        assert!(tail.ends_with("END"));
        assert_eq!(tail.chars().count(), TAIL_LIMIT);

        let with_error = ledger_row(
            &request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "Bash",
                    "tool_input": {"command": "x"},
                    "tool_response": {"stdout": "out", "stderr": "warn", "interrupted": false},
                }),
            ),
            1,
        )
        .expect("row");
        assert_eq!(with_error["tail"], json!("out\n[stderr] warn"));
    }

    #[test]
    fn observe_ignores_other_events_and_missing_sessions() {
        let scratch = Scratch::new();
        assert!(observe_post_tool_in(scratch.path(), &stop("x", false), 1).is_none());
        let no_session = request(
            "PostToolUse",
            json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        );
        assert!(observe_post_tool_in(scratch.path(), &no_session, 1).is_none());
        let injected = request(
            "UserPromptSubmit",
            json!({"session_id": "s1", "prompt": "<task-notification>done</task-notification>"}),
        );
        assert!(mark_turn_start_in(scratch.path(), &injected, 1, 1).is_none());
    }

    #[test]
    fn done_without_an_edit_accepts_any_successful_result() {
        let bare = Scratch::new();
        start_turn(bare.path(), "is the hook installed?", 1);
        assert!(check(bare.path(), "Yes, it is implemented.").is_some());

        let read = Scratch::new();
        start_turn(read.path(), "is the hook installed?", 1);
        observe(
            read.path(),
            &[request(
                "PostToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/repo/src/main.rs"},
                    "tool_response": {"type": "text", "file": {"content": "fn main() {}"}},
                }),
            )],
        );
        assert!(check(read.path(), "Yes, it is implemented.").is_none());

        let grep = Scratch::new();
        start_turn(grep.path(), "is the hook installed?", 1);
        observe(
            grep.path(),
            &[bash("grep -n fn src/main.rs", "3:fn main() {}")],
        );
        assert!(check(grep.path(), "Yes, it is implemented.").is_none());
    }

    #[test]
    fn worker_summaries_are_not_evidence() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix it", 1);
        let agent = request(
            "PostToolUse",
            json!({
                "session_id": "s1",
                "tool_name": "Agent",
                "tool_input": {"prompt": "fix"},
                "tool_response": {"content": [{"type": "text", "text": "Done, all tests pass."}]},
            }),
        );
        observe(scratch.path(), &[edit("src/a.rs"), agent]);
        assert!(check(scratch.path(), "All tests pass.").is_some());
    }

    #[test]
    fn installed_and_live_need_their_own_evidence() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "ship it", 1);
        observe(
            scratch.path(),
            &[
                edit("src/a.rs"),
                bash("cargo test", "test result: ok. 1 passed; 0 failed"),
            ],
        );
        assert!(verdict(scratch.path(), "It is installed.").is_some());
        observe(scratch.path(), &[bash("legion --version", "legion 1.2.3")]);
        assert!(verdict(scratch.path(), "It is installed.").is_none());

        let live = Scratch::new();
        start_turn(live.path(), "ship it", 1);
        observe(live.path(), &[edit("src/a.rs")]);
        assert!(verdict(live.path(), "The site is live.").is_some());
        observe(
            live.path(),
            &[bash("curl -sI https://example.test", "HTTP/2 200")],
        );
        assert!(verdict(live.path(), "The site is live.").is_none());
    }

    #[test]
    fn gh_run_view_counts_only_when_it_shows_success() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "check ci", 1);
        observe(
            scratch.path(),
            &[bash("gh run view 1", "X main CI - 1\nconclusion failure")],
        );
        assert!(verdict(scratch.path(), "CI is green.").is_some());
        observe(
            scratch.path(),
            &[bash(
                "gh run watch 1 --exit-status",
                "completed with 'success'",
            )],
        );
        assert!(verdict(scratch.path(), "CI is green.").is_none());
    }

    #[test]
    fn viewing_files_named_test_is_not_a_test_run() {
        let scratch = Scratch::new();
        start_turn(scratch.path(), "fix it", 1);
        observe(
            scratch.path(),
            &[
                edit("src/a.rs"),
                bash("cat tests/foo.rs && ls tests", "fn t() {}"),
            ],
        );
        assert!(check(scratch.path(), "Tests pass.").is_some());
    }

    #[test]
    fn segments_skip_env_assignments_and_wrappers() {
        let parsed = segments("FOO=1 time cargo test -p x 2>&1 | tail -5; cd /x && ls");
        let firsts: Vec<&str> = parsed
            .iter()
            .map(|segment| segment.first.as_str())
            .collect();
        assert_eq!(firsts, vec!["cargo", "tail", "cd", "ls"]);
        assert!(runs_code("cd /x && cargo build"));
        assert!(!runs_code("cd /x && ls -la | grep foo"));
        assert!(!runs_code("git status"));
    }

    #[test]
    fn ledger_cap_drops_oldest_lines_and_keeps_the_turn_marker() {
        let scratch = Scratch::new();
        let path = scratch.path().join("ledger.jsonl");
        let cap = 2000;
        append_capped(
            &path,
            r#"{"marker":"turn","t":1,"id":"1","prompt":"p"}"#,
            cap,
        )
        .expect("append marker");
        for index in 0..200 {
            let line = format!(r#"{{"t":{index},"tool":"Bash","command":"echo {index}"}}"#);
            append_capped(&path, &line, cap).expect("append row");
            assert!(fs::metadata(&path).expect("metadata").len() <= cap);
        }
        let text = fs::read_to_string(&path).expect("read ledger");
        assert!(text.contains(r#""marker":"turn""#), "marker kept");
        assert!(text.contains(r#""command":"echo 199""#), "newest kept");
        assert!(!text.contains(r#""command":"echo 0""#), "oldest dropped");
        assert!(text
            .lines()
            .all(|line| serde_json::from_str::<Value>(line).is_ok()));
    }

    #[test]
    fn ledger_cap_keeps_the_newest_line_even_when_it_alone_exceeds_the_cap() {
        let scratch = Scratch::new();
        let path = scratch.path().join("ledger.jsonl");
        append_capped(&path, r#"{"t":1,"tool":"a"}"#, 100).expect("append");
        let big = format!(r#"{{"t":2,"tool":"{}"}}"#, "b".repeat(300));
        append_capped(&path, &big, 100).expect("append big");
        let text = fs::read_to_string(&path).expect("read ledger");
        assert_eq!(text.trim_end(), big);
    }
}
