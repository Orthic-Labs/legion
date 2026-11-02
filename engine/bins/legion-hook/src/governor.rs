//! Guard checks `sleep`, `poll`, `cron` and `agents` (fix-plan M4, progress
//! governor). All four fail open: unreadable state or transcripts, a missing
//! session id, or a counter that looks wrong never deny. Each has a kill
//! switch: `LEGION_HOOK_OFF` is a comma list of check ids.
//!
//! * `sleep`: a foreground Bash command whose `sleep` durations add up to more
//!   than 30 s is denied. A loop with a visible count multiplies; any other
//!   loop that sleeps counts as unbounded. Quoted text and heredoc bodies are
//!   data. `bash -c '...'`, `ssh host "..."` and `win "..."` arguments are
//!   analysed too. Work behind a trailing `&` is not foreground and does not
//!   count. Not seen: `sleep` built by `eval` or variables, `time.sleep()` in
//!   `python -c`, `timeout N sleep M`.
//! * `poll`: the fourth `gh run view` / `gh run list` on the same key within an
//!   hour of one session is denied. The key is the run id for `view`, the
//!   argument text for `list`. `--log` reads are not polls.
//! * `cron`: `CronCreate`, `ScheduleWakeup`, `RemoteTrigger` and scheduled-task
//!   creation are denied unless the latest genuine user turn asks for one.
//! * `agents`: an `Agent` launch is denied while six or more subagents of the
//!   session are still running (`LEGION_MAX_AGENTS` overrides the six).

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value};

use crate::protocol::{HookRequest, HookResponse};

pub const CODE_SLEEP: &str = "ARC_SLEEP_WAIT";
pub const CODE_POLL: &str = "ARC_POLL_LIMIT";
pub const CODE_CRON: &str = "ARC_SELF_SCHEDULE";
pub const CODE_AGENTS: &str = "ARC_AGENT_CAP";

const MSG_SLEEP: &str = "Use one background wait (gh run watch <id> --exit-status, or the gate's own wait); no sleep polling.";
const MSG_POLL: &str = "Status checks on this run are capped at three. Use one background wait (gh run watch <id> --exit-status, or the gate's own wait), not repeated gh run view or gh run list.";
const MSG_CRON: &str = "The user has not asked for a schedule, wake, loop or watchdog. Do the work now, or state the blocker once and stop; no self-made crons or wakes.";

const SLEEP_LIMIT_SECS: f64 = 30.0;
/// The fourth call inside the window is denied.
const POLL_LIMIT: usize = 3;
const POLL_WINDOW_SECS: u64 = 60 * 60;
const MAX_POLL_KEYS: usize = 48;
const DEFAULT_AGENT_CAP: usize = 6;
/// A launch or stop marker older than this no longer counts.
const AGENT_STALE: Duration = Duration::from_secs(2 * 60 * 60);
const MAX_SHELL_DEPTH: u8 = 3;
const MAX_TRANSCRIPT_BYTES: u64 = 2 * 1024 * 1024;
const WIDE_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn kill_switch_on(id: &str) -> bool {
    std::env::var("LEGION_HOOK_OFF")
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(id))
        })
        .unwrap_or(false)
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
}

fn tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))
        .and_then(Value::as_object)
}

fn sanitize(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(96)
        .collect()
}

fn session_id(payload: &Map<String, Value>) -> Option<String> {
    first_string(payload, &["session_id", "sessionId", "conversation_id"])
        .map(|id| sanitize(&id))
        .filter(|id| !id.is_empty())
}

fn env_nonempty(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

/// `$LEGION_STATE_DIR`, else `~/.legion`.
fn state_root() -> Option<PathBuf> {
    if let Some(dir) = env_nonempty("LEGION_STATE_DIR") {
        return Some(PathBuf::from(dir));
    }
    let home = env_nonempty("HOME").or_else(|| env_nonempty("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".legion"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        UNIQUE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Write a temp file beside the target, then rename it over the target.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = parent.join(format!(".{name}.{}.tmp", unique_suffix()));
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        error
    })
}

fn denial(event: &str, code: &'static str, message: impl Into<String>) -> HookResponse {
    HookResponse::denied(event.to_owned(), code, message, "strong")
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// PreToolUse entry point. `None` means no opinion (allow); a denied response
/// blocks. The `agents` check writes a launch marker, so call this after other
/// denials and rewrites have been decided.
pub fn check_pre_tool_use(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = first_string(payload, &["tool_name", "toolName"])?;
    let event = request.event_type.as_str();
    if matches!(tool.as_str(), "Bash" | "exec_command") {
        let input = tool_input(payload)?;
        let command = shell_command(input)?;
        let background = input.get("run_in_background").and_then(Value::as_bool) == Some(true);
        if !background && !kill_switch_on("sleep") && sleep_exceeds_limit(&command) {
            return Some(denial(event, CODE_SLEEP, MSG_SLEEP));
        }
        if !kill_switch_on("poll") {
            return poll_check(event, payload, &command);
        }
        return None;
    }
    if is_cron_tool(&tool) {
        if kill_switch_on("cron") {
            return None;
        }
        return cron_check(event, payload);
    }
    if matches!(tool.as_str(), "Agent" | "Task") {
        if kill_switch_on("agents") {
            return None;
        }
        return agents_check(event, payload);
    }
    None
}

/// Record that a subagent ended. The lead calls this for `SubagentStop`
/// events; it never blocks and never fails.
pub fn observe_subagent_stop(request: &HookRequest) {
    if !matches!(
        request.event_type.as_str(),
        "SubagentStop" | "subagent-stop"
    ) || kill_switch_on("agents")
    {
        return;
    }
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    let Some(session) = session_id(payload) else {
        return;
    };
    let Some(root) = state_root() else {
        return;
    };
    let id = first_string(payload, &["agent_id", "agentId"])
        .map(|id| sanitize(&id))
        .filter(|id| !id.is_empty())
        .unwrap_or_else(unique_suffix);
    agents_stop(&root, &session, &id);
}

fn shell_command(input: &Map<String, Value>) -> Option<String> {
    match input.get("command").or_else(|| input.get("cmd"))? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(shell_quote)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

fn shell_quote(arg: &str) -> String {
    let special = arg.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | ';' | '&' | '|' | '$' | '`' | '(' | ')' | '<' | '>' | '\\' | '#'
            )
    });
    if special {
        format!("'{}'", arg.replace('\'', "'\\''"))
    } else {
        arg.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Shell scanning (sleep and poll)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Tok {
    Word(String),
    /// `;`, newline, `&&`, `||`, `|`
    Semi,
    /// A single `&`: the command before it runs in the background.
    Amp,
    Open,
    Close,
}

fn flush(tokens: &mut Vec<Tok>, word: &mut String, in_word: &mut bool) {
    if *in_word {
        tokens.push(Tok::Word(std::mem::take(word)));
        *in_word = false;
    }
}

/// Index just past the `)` matching the `(` at `open` (or the end of input).
/// Quotes are skipped.
fn consume_parens(chars: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            quote @ ('\'' | '"') => {
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && quote == '"' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

/// Parse `<<[-]DELIM` starting just after the `<<`. Returns the delimiter,
/// whether leading tabs are stripped, and the index after the delimiter word.
fn parse_heredoc_operator(chars: &[char], start: usize) -> (String, bool, usize) {
    let mut i = start;
    let strip_tabs = chars.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
        i += 1;
    }
    let mut delimiter = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') {
            break;
        }
        if !matches!(c, '\'' | '"' | '\\') {
            delimiter.push(c);
        }
        i += 1;
    }
    (delimiter, strip_tabs, i)
}

/// Index after the heredoc body that starts at `from`.
fn skip_heredoc(chars: &[char], from: usize, delimiter: &str, strip_tabs: bool) -> usize {
    let mut i = from;
    while i < chars.len() {
        let line_end = chars[i..]
            .iter()
            .position(|&c| c == '\n')
            .map(|offset| i + offset)
            .unwrap_or(chars.len());
        let line: String = chars[i..line_end].iter().collect();
        let line = line.trim_end_matches('\r');
        let candidate = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        i = (line_end + 1).min(chars.len());
        if candidate == delimiter {
            return i;
        }
    }
    chars.len()
}

/// Quote-aware split of a shell command into words and separators. Quotes are
/// removed; `$(...)`, backticks and `((...))` stay inside their word as raw
/// text. Heredoc bodies and comments are dropped.
fn tokenize(src: &str) -> Vec<Tok> {
    let chars: Vec<char> = src.chars().collect();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => {
                flush(&mut tokens, &mut word, &mut in_word);
                i += 1;
            }
            '\n' => {
                flush(&mut tokens, &mut word, &mut in_word);
                tokens.push(Tok::Semi);
                i += 1;
                for (delimiter, strip_tabs) in std::mem::take(&mut heredocs) {
                    i = skip_heredoc(&chars, i, &delimiter, strip_tabs);
                }
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ';' => {
                flush(&mut tokens, &mut word, &mut in_word);
                tokens.push(Tok::Semi);
                i += 1;
            }
            '&' => {
                let redirect = (in_word && word.ends_with(|ch: char| ch == '>' || ch == '<'))
                    || chars.get(i + 1) == Some(&'>');
                if redirect {
                    // `2>&1`, `>&2`, `&>file`
                    word.push('&');
                    in_word = true;
                    i += 1;
                } else if chars.get(i + 1) == Some(&'&') {
                    flush(&mut tokens, &mut word, &mut in_word);
                    tokens.push(Tok::Semi);
                    i += 2;
                } else {
                    flush(&mut tokens, &mut word, &mut in_word);
                    tokens.push(Tok::Amp);
                    i += 1;
                }
            }
            '|' => {
                flush(&mut tokens, &mut word, &mut in_word);
                tokens.push(Tok::Semi);
                i += if chars.get(i + 1) == Some(&'|') { 2 } else { 1 };
            }
            '(' => {
                if chars.get(i + 1) == Some(&'(') {
                    let end = consume_parens(&chars, i);
                    word.extend(chars[i..end].iter());
                    in_word = true;
                    i = end;
                } else {
                    flush(&mut tokens, &mut word, &mut in_word);
                    tokens.push(Tok::Open);
                    i += 1;
                }
            }
            ')' => {
                flush(&mut tokens, &mut word, &mut in_word);
                tokens.push(Tok::Close);
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'(') => {
                let end = consume_parens(&chars, i + 1);
                word.extend(chars[i..end].iter());
                in_word = true;
                i = end;
            }
            '`' => {
                let mut end = i + 1;
                while end < chars.len() && chars[end] != '`' {
                    end += 1;
                }
                let stop = (end + 1).min(chars.len());
                word.extend(chars[i..stop].iter());
                in_word = true;
                i = stop;
            }
            '\'' => {
                let mut end = i + 1;
                while end < chars.len() && chars[end] != '\'' {
                    end += 1;
                }
                word.extend(chars[i + 1..end].iter());
                in_word = true;
                i = end + 1;
            }
            '"' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\'
                        && j + 1 < chars.len()
                        && matches!(chars[j + 1], '"' | '\\' | '$' | '`')
                    {
                        word.push(chars[j + 1]);
                        j += 2;
                    } else {
                        word.push(chars[j]);
                        j += 1;
                    }
                }
                in_word = true;
                i = j + 1;
            }
            '\\' => {
                if let Some(&next) = chars.get(i + 1) {
                    if next != '\n' {
                        word.push(next);
                        in_word = true;
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '<' if chars.get(i + 1) == Some(&'<')
                && chars.get(i + 2) != Some(&'<')
                && (i == 0 || chars[i - 1] != '<') =>
            {
                flush(&mut tokens, &mut word, &mut in_word);
                let (delimiter, strip_tabs, next) = parse_heredoc_operator(&chars, i + 2);
                if !delimiter.is_empty() {
                    heredocs.push((delimiter, strip_tabs));
                }
                i = next;
            }
            _ => {
                word.push(c);
                in_word = true;
                i += 1;
            }
        }
    }
    flush(&mut tokens, &mut word, &mut in_word);
    tokens
}

fn basename(word: &str) -> &str {
    word.rsplit(|c: char| c == '/' || c == '\\')
        .next()
        .unwrap_or(word)
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Index of the first word that is the command itself, after assignments,
/// shell keywords that precede a command, and wrapper commands.
fn command_start(words: &[String]) -> usize {
    let mut i = 0usize;
    while i < words.len() {
        let word = words[i].as_str();
        if is_assignment(word)
            || matches!(
                word,
                "do" | "then" | "else" | "elif" | "if" | "{" | "}" | "!"
            )
        {
            i += 1;
            continue;
        }
        if matches!(
            word,
            "time" | "nohup" | "exec" | "command" | "builtin" | "sudo" | "env" | "nice"
        ) {
            i += 1;
            while i < words.len() && words[i].starts_with('-') {
                i += 1;
            }
            continue;
        }
        break;
    }
    i
}

/// Bodies of every `$(...)` and backtick substitution inside a word.
fn substitution_bodies(word: &str) -> Vec<String> {
    let chars: Vec<char> = word.chars().collect();
    let mut bodies: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        if chars[i] == '$' && chars[i + 1] == '(' {
            let end = consume_parens(&chars, i + 1);
            let inner_end = if end > i + 2 && chars[end - 1] == ')' {
                end - 1
            } else {
                end
            };
            bodies.push(chars[i + 2..inner_end].iter().collect());
            i = end;
        } else if chars[i] == '`' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '`' {
                j += 1;
            }
            bodies.push(chars[i + 1..j].iter().collect());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    bodies
}

// ---------------------------------------------------------------------------
// sleep
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mult {
    Count(f64),
    Unbounded,
}

/// Foreground sleeping found so far. `slept` records that some `sleep` ran,
/// even one of unknown length, so an unbounded loop around it counts.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Total {
    secs: f64,
    slept: bool,
    unbounded: bool,
}

impl Total {
    fn add(&mut self, other: Total) {
        self.secs += other.secs;
        self.slept |= other.slept;
        self.unbounded |= other.unbounded;
    }

    fn scaled(self, mult: Mult) -> Total {
        match mult {
            Mult::Count(count) => Total {
                secs: self.secs * count,
                ..self
            },
            Mult::Unbounded => Total {
                unbounded: self.unbounded || self.slept,
                ..self
            },
        }
    }

    fn exceeds(&self, limit_secs: f64) -> bool {
        self.unbounded || self.secs > limit_secs
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum FrameKind {
    Root,
    Group,
    Loop,
}

struct Frame {
    kind: FrameKind,
    mult: Mult,
    total: Total,
}

struct Frames(Vec<Frame>);

impl Frames {
    fn new() -> Self {
        Self(vec![Frame {
            kind: FrameKind::Root,
            mult: Mult::Count(1.0),
            total: Total::default(),
        }])
    }

    fn push(&mut self, kind: FrameKind, mult: Mult) {
        self.0.push(Frame {
            kind,
            mult,
            total: Total::default(),
        });
    }

    fn top_kind(&self) -> FrameKind {
        self.0
            .last()
            .map(|frame| frame.kind)
            .unwrap_or(FrameKind::Root)
    }

    fn add(&mut self, total: Total) {
        if let Some(top) = self.0.last_mut() {
            top.total.add(total);
        }
    }

    /// Close the top frame. A backgrounded frame is dropped; any other adds
    /// its total, scaled by its loop count, to its parent.
    fn pop(&mut self, background: bool) {
        if self.0.len() <= 1 {
            return;
        }
        if let Some(frame) = self.0.pop() {
            if !background {
                self.add(frame.total.scaled(frame.mult));
            }
        }
    }

    fn finish(mut self) -> Total {
        while self.0.len() > 1 {
            self.pop(false);
        }
        self.0.first().map(|frame| frame.total).unwrap_or_default()
    }
}

const SHELL_WRAPPERS: [&str; 10] = [
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "eval",
    "ssh",
    "win",
    "pwsh",
    "powershell",
];

/// Seconds of one `sleep` argument list. GNU `sleep` sums its arguments and
/// accepts `s`, `m`, `h`, `d` suffixes; `infinity` never ends.
fn parse_duration(arg: &str) -> Option<f64> {
    let lowered = arg.trim().to_ascii_lowercase();
    let (number, factor) = match lowered.chars().last()? {
        's' => (&lowered[..lowered.len() - 1], 1.0),
        'm' => (&lowered[..lowered.len() - 1], 60.0),
        'h' => (&lowered[..lowered.len() - 1], 3600.0),
        'd' => (&lowered[..lowered.len() - 1], 86400.0),
        _ => (&lowered[..], 1.0),
    };
    number
        .parse::<f64>()
        .ok()
        .filter(|value| !value.is_nan() && *value >= 0.0)
        .map(|value| value * factor)
}

fn sleep_total(args: &[String]) -> Total {
    let mut total = Total {
        slept: true,
        ..Total::default()
    };
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        match parse_duration(arg) {
            Some(value) if value.is_infinite() => total.unbounded = true,
            Some(value) => total.secs += value,
            None => {}
        }
    }
    total
}

/// PowerShell `Start-Sleep [-Seconds] N | -Milliseconds N`.
fn start_sleep_total(args: &[String]) -> Total {
    let mut total = Total {
        slept: true,
        ..Total::default()
    };
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].to_ascii_lowercase();
        let next = args.get(i + 1).and_then(|value| value.parse::<f64>().ok());
        match arg.as_str() {
            "-seconds" | "-s" => {
                total.secs += next.unwrap_or(0.0);
                i += 2;
            }
            "-milliseconds" | "-ms" | "-m" => {
                total.secs += next.unwrap_or(0.0) / 1000.0;
                i += 2;
            }
            other => {
                total.secs += other.parse::<f64>().unwrap_or(0.0);
                i += 1;
            }
        }
    }
    total
}

/// Items produced by a `for` word list entry, when they can be counted.
fn brace_count(item: &str) -> Option<f64> {
    let inner = item.strip_prefix('{')?.strip_suffix('}')?;
    if inner.contains("..") {
        let numbers: Option<Vec<f64>> = inner
            .split("..")
            .map(|part| part.parse::<f64>().ok())
            .collect();
        let (first, last, step) = match numbers?.as_slice() {
            [first, last] => (*first, *last, 1.0),
            [first, last, step] if *step != 0.0 => (*first, *last, step.abs()),
            _ => return None,
        };
        return Some((((last - first).abs() / step).floor() + 1.0).max(0.0));
    }
    if inner.contains(',') && !inner.contains('{') {
        return Some(inner.split(',').count() as f64);
    }
    None
}

fn seq_count(body: &str) -> Option<f64> {
    let mut parts = body.split_whitespace();
    if parts.next()? != "seq" {
        return None;
    }
    let numbers: Vec<f64> = parts.filter_map(|part| part.parse::<f64>().ok()).collect();
    let count = match numbers.as_slice() {
        [last] => *last,
        [first, last] => last - first + 1.0,
        [first, step, last] if *step != 0.0 => (last - first) / step + 1.0,
        _ => return None,
    };
    Some(count.floor().max(0.0))
}

fn literal_item_count(item: &str) -> Option<f64> {
    if let Some(count) = brace_count(item) {
        return Some(count);
    }
    if let Some(body) = item
        .strip_prefix("$(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return seq_count(body);
    }
    if item
        .chars()
        .any(|c| matches!(c, '$' | '`' | '*' | '?' | '[' | '{' | '~'))
    {
        return None;
    }
    Some(1.0)
}

/// Iteration count of `for VAR in WORDS`. Anything not visible (`$@`, globs,
/// command output, C-style loops) is unbounded.
fn for_multiplier(words: &[String]) -> Mult {
    let Some(position) = words.iter().position(|word| word.as_str() == "in") else {
        return Mult::Unbounded;
    };
    let mut count = 0.0;
    for item in &words[position + 1..] {
        match literal_item_count(item) {
            Some(items) => count += items,
            None => return Mult::Unbounded,
        }
    }
    Mult::Count(count)
}

fn run_command(frames: &mut Frames, words: &mut Vec<String>, background: bool, depth: u8) {
    if words.is_empty() {
        return;
    }
    let command = std::mem::take(words);
    let start = command_start(&command);
    let head = command.get(start).map(String::as_str).unwrap_or("");
    match head {
        "for" | "select" => {
            frames.push(FrameKind::Loop, for_multiplier(&command[start + 1..]));
            return;
        }
        "while" | "until" => {
            frames.push(FrameKind::Loop, Mult::Unbounded);
            let mut condition = command[start + 1..].to_vec();
            run_command(frames, &mut condition, background, depth);
            return;
        }
        "done" => {
            if frames.top_kind() == FrameKind::Loop {
                frames.pop(background);
            }
            return;
        }
        "fi" | "esac" => return,
        _ => {}
    }
    let name = basename(head).to_ascii_lowercase();
    let wrapper = SHELL_WRAPPERS.contains(&name.as_str());
    if !wrapper && !background {
        for word in &command {
            for body in substitution_bodies(word) {
                frames.add(analyze(&body, depth + 1));
            }
        }
    }
    let rest = &command[start.min(command.len())..];
    if rest.is_empty() {
        return;
    }
    let args = &rest[1..];
    let total = match name.as_str() {
        "sleep" => Some(sleep_total(args)),
        "start-sleep" => Some(start_sleep_total(args)),
        _ if wrapper => {
            let mut inner = Total::default();
            for arg in args {
                if arg.chars().any(char::is_whitespace) {
                    inner.add(analyze(arg, depth + 1));
                }
            }
            Some(inner)
        }
        _ => None,
    };
    if !background {
        if let Some(total) = total {
            frames.add(total);
        }
    }
}

/// Foreground sleeping in `src`.
fn analyze(src: &str, depth: u8) -> Total {
    if depth > MAX_SHELL_DEPTH {
        return Total::default();
    }
    let tokens = tokenize(src);
    let mut frames = Frames::new();
    let mut words: Vec<String> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Tok::Word(word) => words.push(word.clone()),
            Tok::Semi => run_command(&mut frames, &mut words, false, depth),
            Tok::Amp => run_command(&mut frames, &mut words, true, depth),
            Tok::Open => {
                run_command(&mut frames, &mut words, false, depth);
                frames.push(FrameKind::Group, Mult::Count(1.0));
            }
            Tok::Close => {
                run_command(&mut frames, &mut words, false, depth);
                if frames.top_kind() == FrameKind::Group {
                    let background = matches!(tokens.get(index + 1), Some(Tok::Amp));
                    frames.pop(background);
                }
            }
        }
    }
    run_command(&mut frames, &mut words, false, depth);
    frames.finish()
}

fn sleep_exceeds_limit(command: &str) -> bool {
    analyze(command, 0).exceeds(SLEEP_LIMIT_SECS)
}

// ---------------------------------------------------------------------------
// poll
// ---------------------------------------------------------------------------

/// A run or job id: a long all-digit word, or the number after `/runs/`.
fn run_id(arg: &str) -> Option<String> {
    if arg.len() >= 5 && arg.chars().all(|c| c.is_ascii_digit()) {
        return Some(arg.to_owned());
    }
    let (_, after) = arg.split_once("/runs/")?;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

/// Poll key of one simple command, when it is `gh run view` or `gh run list`.
fn poll_key(words: &[String]) -> Option<String> {
    let rest = &words[command_start(words).min(words.len())..];
    if rest.len() < 3 || basename(&rest[0]) != "gh" {
        return None;
    }
    let mut i = 1usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "-R" | "--repo" => i += 2,
            flag if flag.starts_with('-') => i += 1,
            _ => break,
        }
    }
    if rest.get(i).map(String::as_str) != Some("run") {
        return None;
    }
    let sub = rest.get(i + 1)?.as_str();
    let args = &rest[i + 2..];
    match sub {
        "view" => {
            if args.iter().any(|arg| arg.starts_with("--log")) {
                return None;
            }
            let id = args.iter().find_map(|arg| run_id(arg)).unwrap_or_default();
            Some(format!("view:{id}"))
        }
        "list" => Some(format!("list:{}", args.join(" "))),
        _ => None,
    }
}

fn gh_run_poll_keys(command: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut words: Vec<String> = Vec::new();
    for token in tokenize(command) {
        match token {
            Tok::Word(word) => words.push(word),
            _ => {
                keys.extend(poll_key(&words));
                words.clear();
            }
        }
    }
    keys.extend(poll_key(&words));
    keys
}

/// Record one call and return how many calls of this key fall inside the
/// window, this one included. `None` on any state error (fail open).
fn record_poll(root: &Path, session: &str, key: &str, now: u64) -> Option<usize> {
    let path = root.join("poll").join(format!("{session}.json"));
    let mut doc: Map<String, Value> = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    let cutoff = now.saturating_sub(POLL_WINDOW_SECS);
    for value in doc.values_mut() {
        if let Value::Array(items) = value {
            items.retain(|item| item.as_u64().is_some_and(|stamp| stamp >= cutoff));
        }
    }
    doc.retain(|_, value| value.as_array().is_some_and(|items| !items.is_empty()));
    if doc.len() >= MAX_POLL_KEYS && !doc.contains_key(key) {
        doc.clear();
    }
    let entry = doc
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    let items = entry.as_array_mut()?;
    items.push(Value::from(now));
    let count = items.len();
    let text = serde_json::to_string(&Value::Object(doc)).ok()?;
    write_atomic(&path, text.as_bytes()).ok()?;
    Some(count)
}

fn poll_check(event: &str, payload: &Map<String, Value>, command: &str) -> Option<HookResponse> {
    let keys = gh_run_poll_keys(command);
    if keys.is_empty() {
        return None;
    }
    let session = session_id(payload)?;
    let root = state_root()?;
    let now = unix_now();
    for key in keys {
        let count = record_poll(&root, &session, &key, now)?;
        if count > POLL_LIMIT {
            return Some(denial(event, CODE_POLL, MSG_POLL));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------

fn is_cron_tool(tool: &str) -> bool {
    matches!(tool, "CronCreate" | "ScheduleWakeup" | "RemoteTrigger")
        || tool.ends_with("__create_scheduled_task")
}

const SCHEDULE_WORDS: [&str; 24] = [
    "schedule",
    "scheduled",
    "schedules",
    "scheduling",
    "scheduler",
    "wake",
    "wakes",
    "wakeup",
    "wakeups",
    "loop",
    "loops",
    "looping",
    "watchdog",
    "watchdogs",
    "cron",
    "crons",
    "crontab",
    "cronjob",
    "daily",
    "hourly",
    "nightly",
    "weekly",
    "recurring",
    "remind",
];

const EVERY_UNITS: [&str; 14] = [
    "second", "seconds", "sec", "secs", "minute", "minutes", "min", "mins", "hour", "hours", "day",
    "days", "morning", "night",
];

/// Does a user turn ask for a schedule, wake, loop, watchdog or cron, or say
/// "every N ..." / "daily"?
fn asks_for_schedule(text: &str) -> bool {
    let lowered = text.to_lowercase();
    let tokens: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    for (index, token) in tokens.iter().enumerate() {
        if SCHEDULE_WORDS.contains(token) || *token == "reminder" || *token == "reminders" {
            return true;
        }
        if *token == "every" {
            if let Some(next) = tokens.get(index + 1) {
                let numeric = next.chars().next().is_some_and(|c| c.is_ascii_digit());
                if numeric || EVERY_UNITS.contains(next) || matches!(*next, "week" | "weeks") {
                    return true;
                }
            }
        }
    }
    false
}

/// Text that never came from the user typing a turn.
const NON_HUMAN_PREFIXES: [&str; 11] = [
    "[Pulse Chat",
    "<task-notification",
    "<scheduled-task",
    "<cross-session-message",
    "<local-command",
    "<artifact-content-authored-by-others/>",
    "Another Claude session sent a message",
    "Stop hook feedback",
    "This session is being continued",
    "[Request interrupted",
    "Caveat:",
];

fn strip_system_reminders(text: &str) -> String {
    const OPEN: &str = "<system-reminder>";
    const CLOSE: &str = "</system-reminder>";
    let mut out = String::new();
    let mut rest = text;
    loop {
        let Some(start) = rest.find(OPEN) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        match after.find(CLOSE) {
            Some(end) => rest = &after[end + CLOSE.len()..],
            None => break,
        }
    }
    out
}

/// The text of a genuine user turn: a `user` record with text content that is
/// not a tool result, not meta, not a relay, task notification or compaction
/// summary. System reminders are removed from the text.
fn genuine_user_text(record: &Value) -> Option<String> {
    if record.get("type").and_then(Value::as_str) != Some("user") {
        return None;
    }
    if record.get("isMeta").and_then(Value::as_bool) == Some(true)
        || record.get("isSidechain").and_then(Value::as_bool) == Some(true)
    {
        return None;
    }
    if let Some(kind) = record.pointer("/origin/kind").and_then(Value::as_str) {
        if kind != "human" {
            return None;
        }
    }
    if record.get("promptSource").and_then(Value::as_str) == Some("system")
        || matches!(
            record.get("turnOrigin").and_then(Value::as_str),
            Some("scheduled" | "peer" | "system" | "task-notification")
        )
    {
        return None;
    }
    let raw = crate::roles::user_message_text(record.pointer("/message/content"));
    let text = strip_system_reminders(&raw);
    let text = text.trim();
    if text.is_empty()
        || NON_HUMAN_PREFIXES
            .iter()
            .any(|prefix| text.starts_with(prefix))
    {
        return None;
    }
    Some(text.to_owned())
}

struct UserScan {
    latest: Option<String>,
    /// At least one `user` record parsed, so the transcript format is known.
    saw_user: bool,
}

/// Walk the transcript from the end for the latest genuine user turn.
fn scan_user_turns(transcript: &str) -> UserScan {
    let mut saw_user = false;
    for line in transcript.lines().rev() {
        if !(line.contains("\"type\":\"user\"") || line.contains("\"type\": \"user\"")) {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if record.get("type").and_then(Value::as_str) != Some("user") {
            continue;
        }
        saw_user = true;
        if let Some(text) = genuine_user_text(&record) {
            return UserScan {
                latest: Some(text),
                saw_user,
            };
        }
    }
    UserScan {
        latest: None,
        saw_user,
    }
}

/// Deny unless the latest genuine user turn asks for a schedule. Unknown
/// (unreadable transcript, no recognisable user records, window too small)
/// allows.
fn cron_check(event: &str, payload: &Map<String, Value>) -> Option<HookResponse> {
    let path = first_string(payload, &["transcript_path", "transcriptPath"])?;
    let mut scan = UserScan {
        latest: None,
        saw_user: false,
    };
    let mut complete = false;
    for window in [MAX_TRANSCRIPT_BYTES, WIDE_TRANSCRIPT_BYTES] {
        let (text, truncated) = crate::roles::read_transcript_tail(&path, window)?;
        scan = scan_user_turns(&text);
        complete = !truncated;
        if scan.latest.is_some() || complete {
            break;
        }
    }
    match scan.latest {
        Some(text) if asks_for_schedule(&text) => None,
        Some(_) => Some(denial(event, CODE_CRON, MSG_CRON)),
        // Only machine-origin user records in a fully read transcript: nobody asked.
        None if scan.saw_user && complete => Some(denial(event, CODE_CRON, MSG_CRON)),
        None => None,
    }
}

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

fn agent_cap() -> usize {
    std::env::var("LEGION_MAX_AGENTS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|cap| *cap >= 1)
        .unwrap_or(DEFAULT_AGENT_CAP)
}

fn agents_dir(root: &Path, session: &str) -> PathBuf {
    root.join("agents").join(session)
}

/// Fresh launch markers and stop markers of one session.
struct Census {
    launches: usize,
    stops: Vec<(PathBuf, SystemTime)>,
}

/// Count markers newer than `AGENT_STALE`; older ones are deleted.
fn take_census(dir: &Path, now: SystemTime) -> Option<Census> {
    let mut launches = 0usize;
    let mut stops = Vec::new();
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_launch = name.starts_with("L-");
        let is_stop = name.starts_with("S-");
        if !is_launch && !is_stop {
            continue;
        }
        let path = entry.path();
        let Some(modified) = entry.metadata().ok().and_then(|meta| meta.modified().ok()) else {
            continue;
        };
        if now.duration_since(modified).unwrap_or_default() > AGENT_STALE {
            let _ = fs::remove_file(&path);
            continue;
        }
        if is_launch {
            launches += 1;
        } else {
            stops.push((path, modified));
        }
    }
    Some(Census { launches, stops })
}

#[derive(Debug, PartialEq, Eq)]
enum LaunchOutcome {
    Allowed,
    /// State unreadable or inconsistent: allowed.
    FailedOpen,
    OverCap {
        others: usize,
    },
}

/// Register a launch, then count. The marker is written first so parallel
/// launches see each other. `others` is the number of other agents running.
fn agents_launch(
    root: &Path,
    session: &str,
    launch_id: &str,
    cap: usize,
    now: SystemTime,
) -> LaunchOutcome {
    let dir = agents_dir(root, session);
    let marker = dir.join(format!("L-{launch_id}"));
    if write_atomic(&marker, b"1\n").is_err() {
        return LaunchOutcome::FailedOpen;
    }
    let Some(census) = take_census(&dir, now) else {
        return LaunchOutcome::FailedOpen;
    };
    let stops = census.stops.len();
    if stops >= census.launches {
        // This launch is counted, so stops must be fewer than launches. More
        // stops than launches means agents we never saw launch (workflow
        // agents, a restart): fail open and drop the surplus stop markers.
        let surplus = stops + 1 - census.launches;
        let mut stale = census.stops;
        stale.sort_by_key(|(_, modified)| *modified);
        for (path, _) in stale.into_iter().take(surplus) {
            let _ = fs::remove_file(path);
        }
        return LaunchOutcome::FailedOpen;
    }
    let others = census.launches - stops - 1;
    if others >= cap {
        let _ = fs::remove_file(&marker);
        return LaunchOutcome::OverCap { others };
    }
    LaunchOutcome::Allowed
}

fn agents_stop(root: &Path, session: &str, agent_id: &str) {
    let marker = agents_dir(root, session).join(format!("S-{agent_id}"));
    let _ = write_atomic(&marker, b"1\n");
}

fn agents_check(event: &str, payload: &Map<String, Value>) -> Option<HookResponse> {
    let session = session_id(payload)?;
    let root = state_root()?;
    let launch_id = first_string(payload, &["tool_use_id", "toolUseId"])
        .map(|id| sanitize(&id))
        .filter(|id| !id.is_empty())
        .unwrap_or_else(unique_suffix);
    let cap = agent_cap();
    match agents_launch(&root, &session, &launch_id, cap, SystemTime::now()) {
        LaunchOutcome::OverCap { others } => Some(denial(
            event,
            CODE_AGENTS,
            format!(
                "{others} subagents launched in this session are still running (cap {cap}). Wait for one to finish before launching another."
            ),
        )),
        LaunchOutcome::Allowed | LaunchOutcome::FailedOpen => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-governor-{tag}-{}", unique_suffix()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn request(payload: Value) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload,
        }
    }

    // sleep -------------------------------------------------------------

    #[test]
    fn short_or_background_or_quoted_sleeps_pass() {
        for command in [
            "sleep 5",
            "sleep 30",
            "echo hi",
            "sleep 0.5 && echo ok",
            "sleep $N",
            "for i in 1 2 3; do sleep 5; done",
            "for i in 1 2 3 4 5 6; do sleep 5; done",
            "for i in $(seq 1 10); do sleep 2; done",
            "echo \"sleep 600\"",
            "git commit -m 'no sleep 100 here'",
            "cat <<'EOF'\nsleep 600\nEOF\necho done",
            "(sleep 600; echo hi) &",
            "nohup sleep 600 &",
            "sleep 600 &",
            "while true; do echo x; done",
            "gh run watch 123456789 --exit-status",
            "sleep 20 # sleep 600",
        ] {
            assert!(!sleep_exceeds_limit(command), "should pass: {command}");
        }
    }

    #[test]
    fn long_sleeps_and_unbounded_sleep_loops_are_caught() {
        for command in [
            "sleep 31",
            "sleep 20; sleep 20",
            "sleep 20 && sleep 20",
            "sleep 20 20",
            "sleep 1m",
            "sleep 100 2>&1",
            "echo a; sleep infinity",
            "if true; then sleep 40; fi",
            "x=$(sleep 100)",
            "for i in $(seq 1 100); do sleep 1; done",
            "for i in {1..10}; do sleep 5; done",
            "for a in 1 2; do for b in 1 2 3; do sleep 6; done; done",
            "for f in *.log; do sleep 1; done",
            "while true; do sleep 5; done",
            "while [ $i -lt 3 ]; do sleep 1; i=$((i+1)); done",
            "until gh run view 123456789 | grep -q completed; do sleep 10; done",
            "ssh mac \"sleep 100\"",
            "bash -c 'sleep 45'",
            "win \"Start-Sleep 60\"",
            "Start-Sleep -Seconds 40",
            "/bin/sleep 90",
            "FOO=1 sleep 60",
            "time sleep 60",
            "echo start\nsleep 45\necho end",
        ] {
            assert!(sleep_exceeds_limit(command), "should deny: {command}");
        }
    }

    #[test]
    fn sleep_arguments_parse_like_gnu_sleep() {
        assert_eq!(parse_duration("5"), Some(5.0));
        assert_eq!(parse_duration("0.5"), Some(0.5));
        assert_eq!(parse_duration("2m"), Some(120.0));
        assert_eq!(parse_duration("1h"), Some(3600.0));
        assert_eq!(parse_duration("10s"), Some(10.0));
        assert_eq!(parse_duration("$N"), None);
        assert_eq!(parse_duration(""), None);
        assert!(parse_duration("infinity").is_some_and(f64::is_infinite));
    }

    #[test]
    fn loop_counts_come_from_visible_lists() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(for_multiplier(&words("i in 1 2 3")), Mult::Count(3.0));
        assert_eq!(for_multiplier(&words("i in {1..10}")), Mult::Count(10.0));
        assert_eq!(for_multiplier(&words("i in {a,b,c}")), Mult::Count(3.0));
        assert_eq!(
            for_multiplier(&["i".to_owned(), "in".to_owned(), "$(seq 5)".to_owned()]),
            Mult::Count(5.0)
        );
        assert_eq!(for_multiplier(&words("f in *.txt")), Mult::Unbounded);
        assert_eq!(for_multiplier(&words("i")), Mult::Unbounded);
        assert_eq!(seq_count("seq 1 100"), Some(100.0));
        assert_eq!(seq_count("seq 2 2 10"), Some(5.0));
        assert_eq!(seq_count("ls"), None);
    }

    #[test]
    fn bash_tool_denies_foreground_sleep_only() {
        let denied = request(json!({
            "tool_name": "Bash",
            "session_id": "s1",
            "tool_input": {"command": "sleep 100"}
        }));
        let response = check_pre_tool_use(&denied).expect("denial");
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some(CODE_SLEEP));
        assert_eq!(response.reason, MSG_SLEEP);

        let background = request(json!({
            "tool_name": "Bash",
            "session_id": "s1",
            "tool_input": {"command": "sleep 100", "run_in_background": true}
        }));
        assert!(check_pre_tool_use(&background).is_none());

        let array = request(json!({
            "tool_name": "Bash",
            "tool_input": {"command": ["bash", "-lc", "sleep 100"]}
        }));
        assert!(check_pre_tool_use(&array).is_some());

        let ordinary = request(json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"}
        }));
        assert!(check_pre_tool_use(&ordinary).is_none());
    }

    // poll --------------------------------------------------------------

    #[test]
    fn poll_keys_name_the_run_and_skip_log_reads() {
        assert_eq!(
            gh_run_poll_keys("gh run view 12345678901 --json status"),
            vec!["view:12345678901".to_owned()]
        );
        assert_eq!(
            gh_run_poll_keys(
                "gh -R org/repo run view https://github.com/org/repo/actions/runs/998877665/job/1"
            ),
            vec!["view:998877665".to_owned()]
        );
        assert_eq!(
            gh_run_poll_keys("gh run list --limit 5 --json status | jq ."),
            vec!["list:--limit 5 --json status".to_owned()]
        );
        assert!(gh_run_poll_keys("gh run view 12345678901 --log-failed").is_empty());
        assert!(gh_run_poll_keys("gh run watch 12345678901 --exit-status").is_empty());
        assert!(gh_run_poll_keys("echo gh run view 12345678901").is_empty());
        assert_eq!(
            gh_run_poll_keys("gh run view 111111; gh run view 222222").len(),
            2
        );
    }

    #[test]
    fn fourth_call_in_the_window_is_the_first_denied() {
        let root = temp_root("poll");
        let counts: Vec<usize> = (0..5)
            .map(|offset| record_poll(&root, "s1", "view:1", 1000 + offset).expect("count"))
            .collect();
        assert_eq!(counts, vec![1, 2, 3, 4, 5]);
        // Another run and another session count separately.
        assert_eq!(record_poll(&root, "s1", "view:2", 1010), Some(1));
        assert_eq!(record_poll(&root, "s2", "view:1", 1010), Some(1));
        // An hour later the old calls have aged out.
        assert_eq!(
            record_poll(&root, "s1", "view:1", 1004 + POLL_WINDOW_SECS + 1),
            Some(1)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn poll_state_that_is_unreadable_is_replaced_not_fatal() {
        let root = temp_root("poll-bad");
        fs::create_dir_all(root.join("poll")).expect("dir");
        fs::write(root.join("poll").join("s1.json"), "not json").expect("write");
        assert_eq!(record_poll(&root, "s1", "view:1", 1000), Some(1));
        let _ = fs::remove_dir_all(&root);
    }

    // cron --------------------------------------------------------------

    #[test]
    fn schedule_requests_are_recognised() {
        for text in [
            "wake me in 10 minutes",
            "check it every 5 minutes",
            "run it every hour",
            "every 30s please",
            "daily check of the disk",
            "/loop 5m /babysit",
            "set up a watchdog",
            "add a cron for that",
            "schedule the run",
            "remind me tomorrow",
            "every week",
        ] {
            assert!(asks_for_schedule(text), "should match: {text}");
        }
        for text in [
            "fix the build",
            "I am awake now",
            "check every file in src",
            "please schedulable",
            "what is the weather",
        ] {
            assert!(!asks_for_schedule(text), "should not match: {text}");
        }
    }

    #[test]
    fn genuine_user_turns_exclude_machine_records() {
        let human = r#"{"type":"user","origin":{"kind":"human"},"message":{"role":"user","content":"fix the build"}}"#;
        let human_list = r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<system-reminder>wake schedule cron</system-reminder>"},{"type":"text","text":"just fix it"}]}}"#;
        let tool_result = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"wake me"}]}}"#;
        let meta = r#"{"type":"user","isMeta":true,"message":{"role":"user","content":"wake me every 5 minutes"}}"#;
        let pulse = r#"{"type":"user","message":{"role":"user","content":"[Pulse Chat from rkn] wake me daily"}}"#;
        let notification = r#"{"type":"user","origin":{"kind":"task-notification"},"message":{"role":"user","content":"daily check"}}"#;
        let peer = r#"{"type":"user","origin":{"kind":"peer"},"message":{"role":"user","content":"every 5 minutes"}}"#;
        let reminder_only = r#"{"type":"user","message":{"role":"user","content":"<system-reminder>every 5 minutes</system-reminder>"}}"#;
        let assistant =
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"wake"}]}}"#;

        let genuine =
            |line: &str| genuine_user_text(&serde_json::from_str::<Value>(line).expect("json"));
        assert_eq!(genuine(human).as_deref(), Some("fix the build"));
        assert_eq!(genuine(human_list).as_deref(), Some("just fix it"));
        for line in [
            tool_result,
            meta,
            pulse,
            notification,
            peer,
            reminder_only,
            assistant,
        ] {
            assert_eq!(genuine(line), None, "{line}");
        }
    }

    #[test]
    fn latest_genuine_turn_decides() {
        let ask =
            r#"{"type":"user","message":{"role":"user","content":"wake me every 5 minutes"}}"#;
        let tool = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"ok"}]}}"#;
        let work = r#"{"type":"user","message":{"role":"user","content":"now fix the build"}}"#;
        let scan = scan_user_turns(&format!("{ask}\n{tool}\n{tool}"));
        assert_eq!(scan.latest.as_deref(), Some("wake me every 5 minutes"));
        let scan = scan_user_turns(&format!("{ask}\n{tool}\n{work}\n{tool}"));
        assert_eq!(scan.latest.as_deref(), Some("now fix the build"));
        assert!(!asks_for_schedule(scan.latest.as_deref().unwrap_or("")));
        let scan = scan_user_turns(tool);
        assert!(scan.latest.is_none() && scan.saw_user);
        let scan = scan_user_turns("{\"type\":\"assistant\"}");
        assert!(scan.latest.is_none() && !scan.saw_user);
    }

    #[test]
    fn cron_tool_names_are_matched() {
        for tool in [
            "CronCreate",
            "ScheduleWakeup",
            "RemoteTrigger",
            "mcp__scheduled-tasks__create_scheduled_task",
        ] {
            assert!(is_cron_tool(tool), "{tool}");
        }
        for tool in [
            "CronList",
            "Bash",
            "mcp__scheduled-tasks__list_scheduled_tasks",
        ] {
            assert!(!is_cron_tool(tool), "{tool}");
        }
    }

    #[test]
    fn cron_check_reads_the_transcript() {
        let root = temp_root("cron");
        let path = root.join("transcript.jsonl");
        let payload = |p: &Path| {
            json!({"transcript_path": p.to_string_lossy()})
                .as_object()
                .cloned()
                .expect("object")
        };
        let ask =
            r#"{"type":"user","message":{"role":"user","content":"wake me in five minutes"}}"#;
        let work = r#"{"type":"user","message":{"role":"user","content":"fix the build"}}"#;

        fs::write(&path, format!("{ask}\n")).expect("write");
        assert!(cron_check("PreToolUse", &payload(&path)).is_none());

        fs::write(&path, format!("{ask}\n{work}\n")).expect("write");
        let response = cron_check("PreToolUse", &payload(&path)).expect("denial");
        assert_eq!(response.code.as_deref(), Some(CODE_CRON));

        // Only machine-origin user records: nobody asked.
        let meta = r#"{"type":"user","isMeta":true,"message":{"role":"user","content":"wake"}}"#;
        fs::write(&path, format!("{meta}\n")).expect("write");
        assert!(cron_check("PreToolUse", &payload(&path)).is_some());

        // Unreadable or unrecognised transcripts allow.
        assert!(cron_check("PreToolUse", &payload(&root.join("missing.jsonl"))).is_none());
        fs::write(&path, "not a transcript\n").expect("write");
        assert!(cron_check("PreToolUse", &payload(&path)).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    // agents ------------------------------------------------------------

    #[test]
    fn seventh_launch_is_the_first_denied() {
        let root = temp_root("agents");
        let now = SystemTime::now();
        for n in 0..6 {
            assert_eq!(
                agents_launch(&root, "s1", &format!("t{n}"), 6, now),
                LaunchOutcome::Allowed,
                "launch {n}"
            );
        }
        assert_eq!(
            agents_launch(&root, "s1", "t6", 6, now),
            LaunchOutcome::OverCap { others: 6 }
        );
        // The denied launch left no marker: finishing one agent frees a slot.
        agents_stop(&root, "s1", "a0");
        assert_eq!(
            agents_launch(&root, "s1", "t7", 6, now),
            LaunchOutcome::Allowed
        );
        // Another session is counted separately.
        assert_eq!(
            agents_launch(&root, "s2", "t0", 6, now),
            LaunchOutcome::Allowed
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cap_can_be_raised() {
        let root = temp_root("agents-cap");
        let now = SystemTime::now();
        for n in 0..8 {
            assert_eq!(
                agents_launch(&root, "s1", &format!("t{n}"), 9, now),
                LaunchOutcome::Allowed
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn extra_stops_fail_open_and_heal() {
        let root = temp_root("agents-heal");
        let now = SystemTime::now();
        for n in 0..3 {
            agents_stop(&root, "s1", &format!("w{n}"));
        }
        assert_eq!(
            agents_launch(&root, "s1", "t0", 6, now),
            LaunchOutcome::FailedOpen
        );
        // After healing, this launch counts as running and the next one pairs normally.
        let census = take_census(&agents_dir(&root, "s1"), now).expect("census");
        assert_eq!(census.launches, 1);
        assert_eq!(census.stops.len(), 0);
        assert_eq!(
            agents_launch(&root, "s1", "t1", 6, now),
            LaunchOutcome::Allowed
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_markers_stop_counting() {
        let root = temp_root("agents-stale");
        let now = SystemTime::now();
        for n in 0..6 {
            assert_eq!(
                agents_launch(&root, "s1", &format!("t{n}"), 6, now),
                LaunchOutcome::Allowed
            );
        }
        // Age every marker past the stale limit.
        let old = now - AGENT_STALE - Duration::from_secs(60);
        for entry in fs::read_dir(agents_dir(&root, "s1"))
            .expect("dir")
            .flatten()
        {
            fs::OpenOptions::new()
                .write(true)
                .open(entry.path())
                .and_then(|file| file.set_modified(old))
                .expect("age marker");
        }
        assert_eq!(
            agents_launch(&root, "s1", "t-new", 6, SystemTime::now()),
            LaunchOutcome::Allowed
        );
        let census = take_census(&agents_dir(&root, "s1"), SystemTime::now()).expect("census");
        assert_eq!(census.launches, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn subagent_stop_is_only_observed_on_the_stop_event() {
        // No state is touched for other events or a missing session id.
        observe_subagent_stop(&HookRequest {
            event_type: "SubagentStop".to_owned(),
            ..request(json!({"agent_id": "a1"}))
        });
        observe_subagent_stop(&request(json!({"session_id": "s1", "agent_id": "a1"})));
    }
}
