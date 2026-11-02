//! Failure extraction for `legion daily`: Claude Code and Codex transcripts and
//! the Legion evidence ledger. Ported from the failure-review `extract.py` and
//! `markers.py`. A failure is a corrected agent turn, a hook denial, a red
//! build, CI run or install, or an `UNRESOLVED:` line. Read-only: nothing here
//! writes to a transcript or the ledger it reads.
use super::{
    buckets::{self, Class},
    clock, text,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

pub const QUOTE_CHARS: usize = 240;
pub const CONTEXT_CHARS: usize = 260;
/// How much of a corrected turn the keyword map reads.
const CLASSIFY_CHARS: usize = 1000;
/// Longer "user" turns are pasted logs, not corrections.
const MAX_USER_CHARS: usize = 6000;
/// A confirmation prompt is a question to Adrian, not a denial.
const CONFIRMATION_CODE: &str = "ARC_USER_CONFIRMATION_REQUIRED";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Correction,
    HookDenial,
    RedBuild,
    Unresolved,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Correction => "correction",
            Kind::HookDenial => "hook denial",
            Kind::RedBuild => "red build",
            Kind::Unresolved => "unresolved",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub id: String,
    pub host: String,
    pub kind: Kind,
    pub epoch: i64,
    pub session: String,
    pub project: String,
    pub quote: String,
    pub context: String,
    pub bucket: &'static str,
    pub cause: String,
    pub catch_all: bool,
}

impl Failure {
    pub fn fingerprint(&self) -> String {
        format!("{}/{}", self.bucket, self.cause)
    }
}

/// The scan window, in epoch seconds.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub since: i64,
    pub until: i64,
}

/// Stable 16-hex id for an event: the same event hashes the same on every run,
/// so overlapping scan windows never count it twice.
pub fn event_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hex::encode(hasher.finalize());
    digest[..16].to_owned()
}

/// Sort by time and drop repeated ids (a build can appear in a transcript and
/// in the evidence ledger).
pub fn finish(mut failures: Vec<Failure>) -> Vec<Failure> {
    failures.sort_by(|left, right| {
        left.epoch
            .cmp(&right.epoch)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut seen: HashSet<String> = HashSet::new();
    failures.retain(|failure| seen.insert(failure.id.clone()));
    failures
}

// ---------------------------------------------------------------------------
// Build commands
// ---------------------------------------------------------------------------

fn is_assignment(token: &str) -> bool {
    token.contains('=')
        && !token.starts_with('-')
        && !token.starts_with('/')
        && !token.contains('"')
}

fn program_name(token: &str) -> &str {
    let base = token.rsplit(['/', '\\']).next().unwrap_or(token);
    base.strip_suffix(".exe").unwrap_or(base)
}

/// What kind of build, CI run or install a shell command is, judged from the
/// program each command segment starts with (so `grep cargo` is not a build).
pub fn build_kind(command: &str) -> Option<&'static str> {
    for segment in command.split(['\n', ';', '|', '&']) {
        let mut tokens = segment
            .split_whitespace()
            .filter(|token| !is_assignment(token))
            .skip_while(|token| matches!(*token, "env" | "time" | "command" | "nohup" | "exec"));
        let Some(first) = tokens.next() else {
            continue;
        };
        let program = program_name(first).to_ascii_lowercase();
        let sub = tokens.next().unwrap_or("").to_ascii_lowercase();
        let kind = match program.as_str() {
            "cargo" => Some("cargo"),
            "rustright" | "rightkit-gate" | "rightkit-host-gate" | "right-release" => Some("gate"),
            "gh" if sub == "run" || sub == "workflow" => Some("ci"),
            "pnpm" | "npm" | "yarn" | "npx" => match sub.as_str() {
                "install" | "i" | "ci" | "add" => Some("install"),
                "build" | "test" | "run" | "exec" | "dlx" => Some("build"),
                _ => None,
            },
            "swift" if sub == "build" || sub == "test" => Some("build"),
            "cmake" | "ninja" | "xcodebuild" | "gradle" | "gradlew" | "make" => Some("build"),
            _ => None,
        };
        if kind.is_some() {
            return kind;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Line reading
// ---------------------------------------------------------------------------

fn for_each_line(path: &Path, mut handle: impl FnMut(&str)) -> std::io::Result<()> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buffer);
        handle(line.trim_end());
    }
    Ok(())
}

/// The top-level `"timestamp":"..."` of a transcript line, read without a full
/// JSON parse so lines outside the window are skipped cheaply.
fn line_epoch(line: &str) -> Option<i64> {
    const KEY: &str = "\"timestamp\":\"";
    let start = line.find(KEY)? + KEY.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    clock::parse_rfc3339(&rest[..end])
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn flatten_result(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Clip long text first, mask token-like words, then clip to the final size, so
/// a multi-megabyte tool result is never walked word by word for redaction.
fn safe_quote(raw: &str, max: usize) -> String {
    text::clip(&text::redact(&text::clip(raw, max * 4)), max)
}

fn denial_code(result: &str) -> Option<String> {
    if let Some(name) = text::hook_block_name(result) {
        return Some(format!("hook:{name}"));
    }
    let mentions_hook =
        result.to_ascii_lowercase().contains("hook") || result.trim_start().starts_with("ARC_");
    if !mentions_hook {
        return None;
    }
    text::arc_codes(result)
        .into_iter()
        .find(|code| code.as_str() != CONFIRMATION_CODE)
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

struct Scanner<'a> {
    host: &'a str,
    session: String,
    project: String,
    last_agent: String,
    commands: HashMap<String, String>,
    seen: HashSet<String>,
    out: &'a mut Vec<Failure>,
}

impl<'a> Scanner<'a> {
    fn new(host: &'a str, session: String, project: String, out: &'a mut Vec<Failure>) -> Self {
        Scanner {
            host,
            session,
            project,
            last_agent: String::new(),
            commands: HashMap::new(),
            seen: HashSet::new(),
            out,
        }
    }

    fn push(
        &mut self,
        kind: Kind,
        epoch: i64,
        id: String,
        quote: String,
        context: String,
        class: Class,
    ) {
        if !self.seen.insert(id.clone()) {
            return;
        }
        self.out.push(Failure {
            id,
            host: self.host.to_owned(),
            kind,
            epoch,
            session: self.session.clone(),
            project: self.project.clone(),
            quote,
            context,
            bucket: class.bucket,
            cause: class.cause,
            catch_all: class.catch_all,
        });
    }

    /// An agent turn: remember it as the context for the next correction and
    /// collect its `UNRESOLVED:` lines.
    fn agent_text(&mut self, body: &str, epoch: i64) {
        if body.trim().is_empty() {
            return;
        }
        self.last_agent = text::clip(body, CONTEXT_CHARS);
        for line in text::unresolved_lines(body) {
            let quote = safe_quote(&line, QUOTE_CHARS);
            let class = buckets::classify_unresolved(&quote);
            let head = text::clip(&line, 80);
            let id = event_id(&[
                self.session.as_str(),
                "unresolved",
                epoch.to_string().as_str(),
                head.as_str(),
            ]);
            let context = self.last_agent.clone();
            self.push(Kind::Unresolved, epoch, id, quote, context, class);
        }
    }

    /// A genuine user turn that matches the correction markers, linked to the
    /// agent turn before it.
    fn user_text(&mut self, body: &str, epoch: i64) {
        let trimmed = body.trim();
        if trimmed.is_empty()
            || text::is_injected(trimmed)
            || trimmed.chars().count() > MAX_USER_CHARS
            || text::correction_marker(trimmed).is_none()
        {
            return;
        }
        let wide = safe_quote(trimmed, CLASSIFY_CHARS);
        let class = buckets::classify_correction(&wide, &self.last_agent);
        let quote = text::clip(&wide, QUOTE_CHARS);
        let head = text::clip(trimmed, 60);
        let id = event_id(&[
            self.session.as_str(),
            "correction",
            epoch.to_string().as_str(),
            head.as_str(),
        ]);
        let context = self.last_agent.clone();
        self.push(Kind::Correction, epoch, id, quote, context, class);
    }

    fn denial(&mut self, epoch: i64, tool_id: &str, code: &str, message: &str, command: &str) {
        let class = buckets::classify_denial(code);
        let quote = safe_quote(message, QUOTE_CHARS);
        let context = safe_quote(command, CONTEXT_CHARS);
        let id = event_id(&[self.session.as_str(), "denial", tool_id, code]);
        self.push(Kind::HookDenial, epoch, id, quote, context, class);
    }

    fn red_build(&mut self, epoch: i64, kind: &str, command: &str, tail: &str) {
        let class = buckets::classify_build(kind);
        let quote = safe_quote(command, QUOTE_CHARS);
        let context = safe_quote(tail, CONTEXT_CHARS);
        let key = text::clip(command, 80);
        let id = event_id(&[
            self.session.as_str(),
            "build",
            key.as_str(),
            (epoch / 120).to_string().as_str(),
        ]);
        self.push(Kind::RedBuild, epoch, id, quote, context, class);
    }

    // ----- Claude Code -----

    fn claude_line(&mut self, value: &Value, epoch: i64) {
        match value.get("type").and_then(Value::as_str) {
            Some("assistant") => self.claude_assistant(value, epoch),
            Some("user") => self.claude_user(value, epoch),
            Some("attachment") => self.claude_attachment(value, epoch),
            _ => {}
        }
    }

    fn claude_assistant(&mut self, value: &Value, epoch: i64) {
        let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
            return;
        };
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    let body = block.get("text").and_then(Value::as_str).unwrap_or("");
                    self.agent_text(body, epoch);
                }
                Some("tool_use") => {
                    if block.get("name").and_then(Value::as_str) == Some("Bash") {
                        let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                        let command = block
                            .pointer("/input/command")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if !id.is_empty() {
                            self.commands.insert(id.to_owned(), command.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn claude_user(&mut self, value: &Value, epoch: i64) {
        if value.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            return;
        }
        let origin_kind = value
            .get("origin")
            .and_then(|origin| origin.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("human");
        let is_meta = value
            .get("isMeta")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let human = origin_kind == "human" && !is_meta;
        match value.pointer("/message/content") {
            Some(Value::String(body)) => {
                if human {
                    self.user_text(body, epoch);
                }
            }
            Some(Value::Array(blocks)) => {
                for block in blocks {
                    match block.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            if human {
                                let body = block.get("text").and_then(Value::as_str).unwrap_or("");
                                self.user_text(body, epoch);
                            }
                        }
                        Some("tool_result") => self.claude_tool_result(block, epoch),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn claude_tool_result(&mut self, block: &Value, epoch: i64) {
        let is_error = block
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !is_error {
            return;
        }
        let tool_id = block
            .get("tool_use_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let result = flatten_result(block.get("content"));
        let command = self.commands.get(&tool_id).cloned().unwrap_or_default();
        if let Some(code) = denial_code(&result) {
            self.denial(epoch, &tool_id, &code, &result, &command);
            return;
        }
        if let Some(kind) = build_kind(&command) {
            self.red_build(epoch, kind, &command, &result);
        }
    }

    fn claude_attachment(&mut self, value: &Value, epoch: i64) {
        let Some(attachment) = value.get("attachment") else {
            return;
        };
        let tool_id = attachment
            .get("toolUseID")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match attachment.get("type").and_then(Value::as_str) {
            Some("hook_blocking_error") => {
                let message = attachment
                    .pointer("/blockingError/blockingError")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let code = text::arc_codes(message)
                    .into_iter()
                    .find(|code| code.as_str() != CONFIRMATION_CODE);
                if let Some(code) = code {
                    self.denial(epoch, &tool_id, &code, message, "");
                }
            }
            Some("hook_success") => {
                let stdout = attachment
                    .get("stdout")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let Ok(parsed) = serde_json::from_str::<Value>(stdout) else {
                    return;
                };
                if parsed.get("allowed").and_then(Value::as_bool) != Some(false) {
                    return;
                }
                let code = parsed.get("code").and_then(Value::as_str).unwrap_or("");
                if !code.starts_with("ARC_") || code == CONFIRMATION_CODE {
                    return;
                }
                let reason = parsed.get("reason").and_then(Value::as_str).unwrap_or(code);
                self.denial(epoch, &tool_id, code, reason, "");
            }
            _ => {}
        }
    }

    // ----- Codex -----

    fn codex_line(&mut self, value: &Value, epoch: i64) {
        if value.get("type").and_then(Value::as_str) != Some("response_item") {
            return;
        }
        let Some(payload) = value.get("payload") else {
            return;
        };
        match payload.get("type").and_then(Value::as_str) {
            Some("message") => {
                let role = payload.get("role").and_then(Value::as_str).unwrap_or("");
                let body = payload
                    .get("content")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.get("text").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                if role == "user" {
                    let head: String = body.chars().take(200).collect();
                    if !head.contains("[Pulse Chat") {
                        self.user_text(&body, epoch);
                    }
                } else if role == "assistant" {
                    self.agent_text(&body, epoch);
                }
            }
            Some("function_call") | Some("custom_tool_call") => {
                let call_id = payload.get("call_id").and_then(Value::as_str).unwrap_or("");
                let command =
                    codex_command(payload.get("arguments").or_else(|| payload.get("input")));
                if !call_id.is_empty() {
                    self.commands.insert(call_id.to_owned(), command);
                }
            }
            Some("function_call_output") | Some("custom_tool_call_output") => {
                let call_id = payload
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let output = payload.get("output").and_then(Value::as_str).unwrap_or("");
                let command = self.commands.get(&call_id).cloned().unwrap_or_default();
                self.codex_output(epoch, &call_id, output, &command);
            }
            _ => {}
        }
    }

    fn codex_output(&mut self, epoch: i64, call_id: &str, output: &str, command: &str) {
        let head: String = output.chars().take(600).collect();
        if let Some(name) = text::hook_block_name(&head) {
            self.denial(epoch, call_id, &format!("hook:{name}"), &head, command);
            return;
        }
        let lower = head.to_ascii_lowercase();
        let denied =
            lower.contains("hook") || lower.contains("denied") || lower.contains("blocked");
        if denied {
            let code = text::arc_codes(&head)
                .into_iter()
                .find(|code| code.as_str() != CONFIRMATION_CODE);
            if let Some(code) = code {
                self.denial(epoch, call_id, &code, &head, command);
                return;
            }
        }
        if let Some(exit) = codex_exit_code(output) {
            if exit != 0 {
                if let Some(kind) = build_kind(command) {
                    self.red_build(epoch, kind, command, output);
                }
            }
        }
    }

    // ----- Evidence ledger -----

    fn evidence_row(&mut self, row: &Value) {
        if row.get("marker").is_some() {
            return;
        }
        let Some(epoch) = row.get("t").and_then(Value::as_i64) else {
            return;
        };
        let command = row.get("command").and_then(Value::as_str).unwrap_or("");
        let exit = row.get("exit").and_then(Value::as_i64);
        let failed = row.get("failed").and_then(Value::as_bool).unwrap_or(false);
        let red = match exit {
            Some(code) => code != 0,
            None => failed,
        };
        if !red {
            return;
        }
        let Some(kind) = build_kind(command) else {
            return;
        };
        let tail = row.get("tail").and_then(Value::as_str).unwrap_or("");
        self.red_build(epoch, kind, command, tail);
    }
}

fn codex_command(arguments: Option<&Value>) -> String {
    let raw = match arguments {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => return String::new(),
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        return raw;
    };
    match parsed.get("cmd").or_else(|| parsed.get("command")) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        Some(Value::String(text)) => text.clone(),
        _ => raw,
    }
}

/// Exit code from a Codex tool output: `metadata.exit_code` in JSON output, or
/// an `Exit code: N` line in text output.
fn codex_exit_code(output: &str) -> Option<i64> {
    if let Ok(parsed) = serde_json::from_str::<Value>(output) {
        if let Some(code) = parsed
            .pointer("/metadata/exit_code")
            .and_then(Value::as_i64)
        {
            return Some(code);
        }
    }
    let marker = "Exit code: ";
    let start = output.find(marker)? + marker.len();
    let digits: String = output[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    digits.parse::<i64>().ok()
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

fn in_window(epoch: i64, window: &Window) -> bool {
    epoch >= window.since && epoch <= window.until
}

pub fn scan_claude(path: &Path, host: &str, window: &Window, out: &mut Vec<Failure>) {
    let project = path
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut scanner = Scanner::new(host, file_stem(path), project, out);
    let _ = for_each_line(path, |line| {
        let Some(epoch) = line_epoch(line) else {
            return;
        };
        if !in_window(epoch, window) {
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            scanner.claude_line(&value, epoch);
        }
    });
}

pub fn scan_codex(path: &Path, host: &str, window: &Window, out: &mut Vec<Failure>) {
    let mut scanner = Scanner::new(host, file_stem(path), "codex".to_owned(), out);
    let _ = for_each_line(path, |line| {
        let Some(epoch) = line_epoch(line) else {
            return;
        };
        if !in_window(epoch, window) {
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            scanner.codex_line(&value, epoch);
        }
    });
}

pub fn scan_evidence(path: &Path, host: &str, window: &Window, out: &mut Vec<Failure>) {
    let mut scanner = Scanner::new(host, file_stem(path), "evidence".to_owned(), out);
    let _ = for_each_line(path, |line| {
        if !line.starts_with('{') {
            return;
        }
        let Ok(row) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let Some(epoch) = row.get("t").and_then(Value::as_i64) else {
            return;
        };
        if in_window(epoch, window) {
            scanner.evidence_row(&row);
        }
    });
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Transcript and ledger files that may hold lines in the window.
#[derive(Debug, Default)]
pub struct SourceFiles {
    pub claude: Vec<PathBuf>,
    pub codex: Vec<PathBuf>,
    pub evidence: Vec<PathBuf>,
}

fn modified_epoch(path: &Path) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(elapsed.as_secs() as i64)
}

fn is_fresh_jsonl(path: &Path, since: i64) -> bool {
    path.extension()
        .is_some_and(|extension| extension == "jsonl")
        && modified_epoch(path).is_some_and(|modified| modified >= since)
}

fn child_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// `dir/*.jsonl`
fn jsonl_in(dir: &Path, since: i64, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_fresh_jsonl(path, since))
        .collect();
    files.sort();
    out.extend(files);
}

/// `dir/*/*.jsonl`
fn jsonl_in_subdirs(dir: &Path, since: i64, out: &mut Vec<PathBuf>) {
    for child in child_dirs(dir) {
        jsonl_in(&child, since, out);
    }
}

/// Every `*.jsonl` below `dir`, down to `depth` directory levels.
fn jsonl_recursive(dir: &Path, since: i64, depth: usize, out: &mut Vec<PathBuf>) {
    jsonl_in(dir, since, out);
    if depth == 0 {
        return;
    }
    for child in child_dirs(dir) {
        jsonl_recursive(&child, since, depth - 1, out);
    }
}

/// This machine's transcripts: `~/.claude/projects/*/*.jsonl`,
/// `~/ClaudeProfiles/*/.claude/projects/*/*.jsonl`, `~/.codex/sessions/**` and
/// the evidence ledger under the state directory.
pub fn local_sources(home: &Path, state: &Path, since: i64) -> SourceFiles {
    let mut files = SourceFiles::default();
    jsonl_in_subdirs(
        &home.join(".claude").join("projects"),
        since,
        &mut files.claude,
    );
    for profile in child_dirs(&home.join("ClaudeProfiles")) {
        jsonl_in_subdirs(
            &profile.join(".claude").join("projects"),
            since,
            &mut files.claude,
        );
    }
    jsonl_recursive(
        &home.join(".codex").join("sessions"),
        since,
        6,
        &mut files.codex,
    );
    jsonl_in(&state.join("evidence"), since, &mut files.evidence);
    files
        .evidence
        .retain(|path| path.file_name().is_none_or(|name| name != "shadow.jsonl"));
    files
}

/// Files copied from the Dell into `root` (`claude/`, `profiles/`, `codex/`,
/// `evidence/`; see `remote.rs`).
pub fn copied_sources(root: &Path) -> SourceFiles {
    let mut files = SourceFiles::default();
    jsonl_in_subdirs(&root.join("claude"), 0, &mut files.claude);
    jsonl_in_subdirs(&root.join("profiles"), 0, &mut files.claude);
    jsonl_recursive(&root.join("codex"), 0, 6, &mut files.codex);
    jsonl_in(&root.join("evidence"), 0, &mut files.evidence);
    files
        .evidence
        .retain(|path| path.file_name().is_none_or(|name| name != "shadow.jsonl"));
    files
}

/// Scan every source file of one host and return its failures.
pub fn scan_host(host: &str, files: &SourceFiles, window: &Window) -> Vec<Failure> {
    let mut out: Vec<Failure> = Vec::new();
    for path in &files.claude {
        scan_claude(path, host, window, &mut out);
    }
    for path in &files.codex {
        scan_codex(path, host, window, &mut out);
    }
    for path in &files.evidence {
        scan_evidence(path, host, window, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn window() -> Window {
        Window {
            since: 0,
            until: i64::MAX,
        }
    }

    fn scan_lines(lines: &[Value]) -> Vec<Failure> {
        let mut out = Vec::new();
        {
            let mut scanner = Scanner::new("mac", "sess-1".to_owned(), "proj".to_owned(), &mut out);
            for line in lines {
                let epoch = line
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .and_then(clock::parse_rfc3339)
                    .unwrap_or(0);
                if in_window(epoch, &window()) {
                    scanner.claude_line(line, epoch);
                }
            }
        }
        out
    }

    #[test]
    fn classifies_build_commands_by_program() {
        assert_eq!(build_kind("cargo test -p x"), Some("cargo"));
        assert_eq!(build_kind("cd /x && FOO=1 cargo build"), Some("cargo"));
        assert_eq!(build_kind("rightkit-gate --to compile"), Some("gate"));
        assert_eq!(build_kind("gh run view 12"), Some("ci"));
        assert_eq!(build_kind("pnpm install"), Some("install"));
        assert_eq!(build_kind("pnpm exec vitest"), Some("build"));
        assert_eq!(build_kind("/usr/local/bin/cmake --build ."), Some("build"));
        assert_eq!(build_kind("grep -rn cargo src"), None);
        assert_eq!(build_kind("gh issue list"), None);
        assert_eq!(build_kind("echo cargo"), None);
        assert_eq!(build_kind(""), None);
    }

    #[test]
    fn corrected_agent_turn_links_the_turn_before_it() {
        let failures = scan_lines(&[
            json!({"type":"assistant","timestamp":"2026-11-02T10:00:00.000Z",
                   "message":{"content":[{"type":"text","text":"I pushed the release to production."}]}}),
            json!({"type":"user","timestamp":"2026-11-02T10:01:00.000Z",
                   "message":{"content":"who authorized you to push that? I said stop."}}),
        ]);
        assert_eq!(failures.len(), 1);
        let failure = &failures[0];
        assert_eq!(failure.kind, Kind::Correction);
        assert_eq!(failure.bucket, "B1");
        assert!(failure.context.contains("pushed the release"));
        assert_eq!(failure.fingerprint(), format!("B1/{}", failure.cause));
    }

    #[test]
    fn host_injected_and_peer_turns_are_not_corrections() {
        let failures = scan_lines(&[
            json!({"type":"user","timestamp":"2026-11-02T10:00:00.000Z",
                   "message":{"content":"<task-notification>stop wrong again</task-notification>"}}),
            json!({"type":"user","timestamp":"2026-11-02T10:00:01.000Z","origin":{"kind":"peer"},
                   "message":{"content":"stop, that is wrong"}}),
            json!({"type":"user","timestamp":"2026-11-02T10:00:02.000Z","isMeta":true,
                   "message":{"content":"stop, that is wrong"}}),
            json!({"type":"user","timestamp":"2026-11-02T10:00:03.000Z",
                   "message":{"content":"looks good, ship it"}}),
        ]);
        assert!(failures.is_empty());
    }

    #[test]
    fn hook_denials_are_found_once_across_result_and_attachment() {
        let failures = scan_lines(&[
            json!({"type":"assistant","timestamp":"2026-11-02T10:00:00.000Z",
                   "message":{"content":[{"type":"tool_use","id":"t1","name":"Bash",
                                          "input":{"command":"cargo check"}}]}}),
            json!({"type":"attachment","timestamp":"2026-11-02T10:00:01.000Z",
                   "attachment":{"type":"hook_success","toolUseID":"t1",
                   "stdout":"{\"allowed\":false,\"code\":\"ARC_SELF_SCHEDULE\",\"reason\":\"no cron\"}"}}),
            json!({"type":"user","timestamp":"2026-11-02T10:00:02.000Z",
                   "message":{"content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,
                   "content":"PreToolUse:Bash hook error: ARC_SELF_SCHEDULE: no cron"}]}}),
        ]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, Kind::HookDenial);
        assert_eq!(failures[0].fingerprint(), "B10/hook-arc-self-schedule");
    }

    #[test]
    fn confirmation_prompts_are_not_denials() {
        let failures = scan_lines(&[
            json!({"type":"attachment","timestamp":"2026-11-02T10:00:01.000Z",
            "attachment":{"type":"hook_success","toolUseID":"t9",
            "stdout":"{\"allowed\":false,\"code\":\"ARC_USER_CONFIRMATION_REQUIRED\"}"}}),
        ]);
        assert!(failures.is_empty());
    }

    #[test]
    fn red_builds_need_an_error_result_and_a_build_command() {
        let failures = scan_lines(&[
            json!({"type":"assistant","timestamp":"2026-11-02T10:00:00.000Z",
                   "message":{"content":[
                       {"type":"tool_use","id":"b1","name":"Bash","input":{"command":"cargo test"}},
                       {"type":"tool_use","id":"b2","name":"Bash","input":{"command":"grep -r cargo ."}}]}}),
            json!({"type":"user","timestamp":"2026-11-02T10:00:05.000Z",
                   "message":{"content":[
                       {"type":"tool_result","tool_use_id":"b1","is_error":true,"content":"Exit code 101\nerror[E0432]"},
                       {"type":"tool_result","tool_use_id":"b2","is_error":true,"content":"Exit code 1"}]}}),
        ]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, Kind::RedBuild);
        assert_eq!(failures[0].fingerprint(), "B3/cargo-red");
        assert!(failures[0].catch_all);
    }

    #[test]
    fn unresolved_lines_become_failures() {
        let failures = scan_lines(&[
            json!({"type":"assistant","timestamp":"2026-11-02T10:00:00.000Z",
            "message":{"content":[{"type":"text","text":"Done.\nUNRESOLVED: no read-back of the installed build"}]}}),
        ]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, Kind::Unresolved);
        assert!(failures[0].quote.contains("no read-back"));
    }

    #[test]
    fn evidence_rows_report_failed_builds_only() {
        let mut out = Vec::new();
        {
            let mut scanner =
                Scanner::new("mac", "sess-2".to_owned(), "evidence".to_owned(), &mut out);
            scanner.evidence_row(&json!({"t": 1_793_628_394, "tool": "Bash", "command": "cargo test", "exit": 101, "tail": "boom"}));
            scanner.evidence_row(
                &json!({"t": 1_793_628_400, "tool": "Bash", "command": "cargo test", "exit": 0}),
            );
            scanner.evidence_row(
                &json!({"t": 1_793_628_410, "tool": "Bash", "command": "ls", "exit": 1}),
            );
            scanner.evidence_row(&json!({"marker": "turn", "t": 1_793_628_420, "prompt": "p"}));
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fingerprint(), "B3/cargo-red");
    }

    #[test]
    fn event_ids_are_stable_and_finish_drops_repeats() {
        assert_eq!(event_id(&["a", "b"]), event_id(&["a", "b"]));
        assert_ne!(event_id(&["a", "b"]), event_id(&["ab", ""]));
        assert_eq!(event_id(&["a"]).len(), 16);
        let make = |epoch: i64| Failure {
            id: "same".to_owned(),
            host: "mac".to_owned(),
            kind: Kind::Correction,
            epoch,
            session: "s".to_owned(),
            project: "p".to_owned(),
            quote: String::new(),
            context: String::new(),
            bucket: "B5",
            cause: "x".to_owned(),
            catch_all: false,
        };
        assert_eq!(finish(vec![make(2), make(1)]).len(), 1);
    }

    #[test]
    fn codex_exit_codes_come_from_json_or_text() {
        assert_eq!(
            codex_exit_code(r#"{"output":"x","metadata":{"exit_code":2}}"#),
            Some(2)
        );
        assert_eq!(codex_exit_code("Exit code: 1\nWall time: 1s"), Some(1));
        assert_eq!(codex_exit_code("fine"), None);
        assert_eq!(
            codex_command(Some(&json!(r#"{"cmd":["cargo","test"]}"#))),
            "cargo test"
        );
    }
}
