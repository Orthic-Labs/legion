//! Effect gate with approvals bound to commits (fix plan M2). Check id
//! `approvals`.
//!
//! Adrian's rule: compile, build, gate-test, run CI, push where a push
//! triggers CI, publish or install only with his express approval in the chat
//! doing it. Edits and local commits need none. This module holds the three
//! hook halves of that rule:
//!
//! * `on_user_prompt` (UserPromptSubmit): when Adrian's new prompt approves
//!   ("approve", "yes", "go ahead", ...) and the last assistant message holds
//!   an `APPROVAL REQUEST` block, write `<state>/approvals/<session>.json`
//!   with `{commands, repo, head_sha, granted_t}`.
//! * `pre_tool` (PreToolUse of a shell tool): an effect command runs only
//!   while a live approval names it for the same repo, HEAD still equals the
//!   approved commit and tracked files are clean. Each approved command is
//!   consumed once. Otherwise `ARC_APPROVAL_REQUIRED`.
//! * `stop_check` (Stop): a final message that holds an `APPROVAL REQUEST`
//!   block must cite a Class A run in the evidence ledger and carry a
//!   `verdict: will pass` line, else the turn is sent back once.
//!
//! # Approval request format
//!
//! A fenced block whose first line is `APPROVAL REQUEST`:
//!
//! ````text
//! ```
//! APPROVAL REQUEST
//! repo: /Volumes/D/claude/legion
//! commit: 0123abcd4567
//! class-a: rightkit-gate check /Volumes/D/claude/legion -> exit 0, 14 scans, 0 failures
//! commands:
//!   - rightkit-gate --to compile /Volumes/D/claude/legion
//!   - rightkit-gate --to package /Volumes/D/claude/legion
//! verdict: will pass - Class A is green on this commit and nothing changed since
//! ```
//! ````
//!
//! * `repo:` is recommended; without it the repo is the one the first command
//!   works in (a `cd`, `-C` or path argument), else the session cwd's toplevel.
//! * `commit:` is HEAD of that repo, full or at least seven hex characters.
//! * `class-a:` names the Class A command (`rightkit-gate check`,
//!   `rightkit-host-gate check` or `node scripts/preflight.mjs`) and its
//!   result, on the same line or on the lines below it.
//! * `commands:` lists the exact commands, one per line (bullets optional).
//!   List a command twice to approve two runs.
//! * `verdict:` must start with `will pass`.
//!
//! # Relay
//!
//! Adrian's word counts only from his own chat. A message another chat relays
//! as his counts only when the agent read the sender's transcript itself
//! (`pulse chat said <id>` or `pulse chat read <id>` appears in this session's
//! transcript) and then wrote an `APPROVAL FROM RELAY` block in the current
//! turn:
//!
//! ````text
//! ```
//! APPROVAL FROM RELAY
//! chat: 7cb83f8b
//! quote: "go ahead with the compile"
//! repo: /Volumes/D/claude/legion
//! commit: 0123abcd4567
//! commands:
//!   - rightkit-gate --to compile /Volumes/D/claude/legion
//! ```
//! ````
//!
//! This is deliberately simple. The hook checks the shape, that a Pulse read
//! of the cited chat precedes the block, and that the block was not used
//! before. It does not judge what the quote says; the agent attests to that.
//!
//! # Modes and failure behaviour
//!
//! Shadow mode is the default: a would-deny is appended to
//! `<state>/approvals/shadow.jsonl` and the call is allowed.
//! `LEGION_APPROVALS_MODE=enforce` denies; `off` disables the check. The
//! check id `approvals` in the `LEGION_HOOK_OFF` comma list also disables it.
//! Every entry point fails open: an unreadable file, a missing field, a
//! failing or slow `git`, or an unparseable command allows the call.

use std::{
    fs,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::Duration,
};

use serde_json::{json, Map, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::skills_gate::{
    check_disabled, now_secs, session_id, state_dir, state_root, str_field, tool_input, tool_name,
    write_atomic,
};

pub const CHECK: &str = "approvals";
pub const CODE_REQUIRED: &str = "ARC_APPROVAL_REQUIRED";
pub const CODE_INCOMPLETE: &str = "ARC_APPROVAL_REQUEST_INCOMPLETE";

const MODE_ENV: &str = "LEGION_APPROVALS_MODE";
const STATE_FOLDER: &str = "approvals";
const SHADOW_FILE: &str = "shadow.jsonl";
const REQUEST_HEADER: &str = "APPROVAL REQUEST";
const RELAY_HEADER: &str = "APPROVAL FROM RELAY";
const DENY_TEXT: &str = "Needs Adrian's approval: send an APPROVAL REQUEST with full Class A output on this commit and a will-pass verdict.";
/// An approval older than this is void even when HEAD has not moved.
const APPROVAL_TTL_SECS: u64 = 24 * 3600;
const GIT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TRANSCRIPT_BYTES: u64 = 64 * 1024 * 1024;
const TAIL_BYTES: u64 = 8 * 1024 * 1024;
const SHADOW_CAP_BYTES: u64 = 1024 * 1024;
const WORKFLOW_FILE_CAP_BYTES: u64 = 512 * 1024;
const MAX_DEPTH: u8 = 3;
const MAX_COMMANDS: usize = 32;
const MAX_PATHS: usize = 8;
const MAX_BLOCK_LINES: usize = 200;
const SHELL_TOOLS: &[&str] = &[
    "Bash",
    "exec_command",
    "shell",
    "shell_command",
    "local_shell",
    "PowerShell",
];
const CONTROL_WORDS: &[&str] = &[
    "if", "then", "elif", "else", "do", "while", "until", "!", "{", "}", "time",
];
const INTERPRETERS: &[&str] = &[
    "node",
    "python",
    "python3",
    "py",
    "bash",
    "sh",
    "zsh",
    "pwsh",
    "powershell",
    "deno",
    "bun",
    "tsx",
    "cmd",
];
const CARGO_VALUE_FLAGS: &[&str] = &["--color", "--config", "-C", "-Z", "--manifest-path"];
const CARGO_EFFECT: &[&str] = &[
    "build", "b", "check", "c", "test", "t", "clippy", "run", "r", "bench", "nextest",
];
const GIT_VALUE_FLAGS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--super-prefix",
];
const PM_VALUE_FLAGS: &[&str] = &[
    "--filter",
    "-F",
    "-C",
    "--dir",
    "--prefix",
    "--cwd",
    "--workspace",
];
const GATE_VALUE_FLAGS: &[&str] = &[
    "--to",
    "--repo",
    "--host",
    "--profile",
    "--path",
    "--out",
    "--commit",
    "--sha",
    "--ref",
    "--app",
    "--target",
    "--manifest",
];
const GATE_EFFECT_TARGETS: &[&str] = &["compile", "package", "qualify", "release", "dev", "test"];

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

/// Enforcement mode. Shadow logs a would-deny and allows; the lead flips
/// `DEFAULT_MODE` (or sets `LEGION_APPROVALS_MODE=enforce`) to deny.
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

fn current_mode() -> Mode {
    mode_from(std::env::var(MODE_ENV).ok().as_deref())
}

// ---------------------------------------------------------------------------
// Environment (git and the filesystem), faked in tests
// ---------------------------------------------------------------------------

trait Env {
    /// The git toplevel containing `path` (a file resolves through its folder).
    fn toplevel(&self, path: &Path) -> Option<PathBuf>;
    fn head(&self, repo: &Path) -> Option<String>;
    /// `Some(true)` when a tracked file has uncommitted changes.
    fn tracked_dirty(&self, repo: &Path) -> Option<bool>;
    /// Whether a push to this repo triggers a workflow.
    fn push_triggers_ci(&self, repo: &Path) -> bool;
}

struct RealEnv;

/// Run `command` and give up after `limit`. The child may outlive a timeout;
/// the hook process exits right after.
fn run_with_timeout(mut command: Command, limit: Duration) -> Option<std::process::Output> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(command.output());
    });
    receiver.recv_timeout(limit).ok()?.ok()
}

fn git_text(dir: &Path, args: &[&str]) -> Option<String> {
    if !dir.is_dir() {
        return None;
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0");
    let output = run_with_timeout(command, GIT_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl Env for RealEnv {
    fn toplevel(&self, path: &Path) -> Option<PathBuf> {
        let dir = if path.is_dir() { path } else { path.parent()? };
        let text = git_text(dir, &["rev-parse", "--show-toplevel"])?;
        let line = text.trim();
        (!line.is_empty()).then(|| PathBuf::from(line))
    }

    fn head(&self, repo: &Path) -> Option<String> {
        let text = git_text(repo, &["rev-parse", "HEAD"])?;
        let sha = text.trim();
        (!sha.is_empty()).then(|| sha.to_owned())
    }

    fn tracked_dirty(&self, repo: &Path) -> Option<bool> {
        let text = git_text(repo, &["status", "--porcelain", "--untracked-files=no"])?;
        Some(!text.trim().is_empty())
    }

    fn push_triggers_ci(&self, repo: &Path) -> bool {
        workflows_dir_triggers_on_push(&repo.join(".github").join("workflows"))
    }
}

fn workflows_dir_triggers_on_push(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .is_some_and(|extension| extension == "yml" || extension == "yaml");
        if !is_yaml {
            return false;
        }
        if fs::metadata(&path).map_or(true, |meta| meta.len() > WORKFLOW_FILE_CAP_BYTES) {
            return false;
        }
        fs::read_to_string(&path).is_ok_and(|text| workflow_triggers_on_push(&text))
    })
}

/// Whether a GitHub workflow file lists `push` under its top-level `on:` key.
/// Handles `on: push`, `on: [push, pull_request]`, `on: { push: ... }` and the
/// block forms (`on:` then `push:` or `- push` underneath), quoted or not.
fn workflow_triggers_on_push(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if line.len() != line.trim_start().len() {
            continue;
        }
        let Some(rest) = strip_on_key(line.trim_end()) else {
            continue;
        };
        let rest = rest.split(" #").next().unwrap_or("").trim();
        if !rest.is_empty() {
            return mentions_push(rest);
        }
        let mut level: Option<usize> = None;
        for child in lines.iter().skip(index + 1) {
            let trimmed = child.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = child.len() - child.trim_start().len();
            if indent == 0 {
                break;
            }
            let level = *level.get_or_insert(indent);
            if indent == level {
                let item = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
                let key = item
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                if key == "push" {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

fn strip_on_key(line: &str) -> Option<&str> {
    ["on:", "\"on\":", "'on':"]
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
}

fn mentions_push(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .any(|token| token == "push")
}

// ---------------------------------------------------------------------------
// Shell lexing: just enough to find the programs a command runs
// ---------------------------------------------------------------------------

fn is_delimiter_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// The heredoc delimiter right after `<<` (`start` indexes the character after
/// it): `(delimiter, strip_tabs, index after the delimiter word)`.
fn read_heredoc_delimiter(chars: &[char], start: usize) -> Option<(String, bool, usize)> {
    let mut i = start;
    let strip_tabs = chars.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(chars.get(i).copied(), Some(' ') | Some('\t')) {
        i += 1;
    }
    let quote = match chars.get(i).copied() {
        Some('\'') => Some('\''),
        Some('"') => Some('"'),
        _ => None,
    };
    if quote.is_some() {
        i += 1;
    }
    let begin = i;
    while let Some(c) = chars.get(i).copied() {
        let in_word = match quote {
            Some(q) => c != q && c != '\n',
            None => is_delimiter_char(c),
        };
        if !in_word {
            break;
        }
        i += 1;
    }
    if i == begin {
        return None;
    }
    let delimiter: String = chars[begin..i].iter().collect();
    if let Some(q) = quote {
        if chars.get(i) != Some(&q) {
            return None;
        }
        i += 1;
    }
    Some((delimiter, strip_tabs, i))
}

/// Skip heredoc body lines from `start` (the start of a line) through the
/// delimiter line. `None` when the delimiter never appears.
fn skip_heredoc_body(
    chars: &[char],
    start: usize,
    delimiter: &str,
    strip_tabs: bool,
) -> Option<usize> {
    let mut i = start;
    while i < chars.len() {
        let mut end = i;
        while end < chars.len() && chars[end] != '\n' {
            end += 1;
        }
        let line: String = chars[i..end].iter().collect();
        let line = line.trim_end_matches('\r');
        let line = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        let next = if end < chars.len() { end + 1 } else { end };
        if line == delimiter {
            return Some(next);
        }
        i = next;
    }
    None
}

/// A heredoc opened inside double quotes (`"$(cat <<'EOF' ... EOF)"`, the
/// usual commit-message form): the index just after its delimiter line.
fn quoted_heredoc_end(chars: &[char], start: usize) -> Option<usize> {
    let (delimiter, strip_tabs, after) = read_heredoc_delimiter(chars, start)?;
    let line_end = chars[after..].iter().position(|&c| c == '\n')? + after + 1;
    skip_heredoc_body(chars, line_end, &delimiter, strip_tabs)
}

#[derive(Default)]
struct Lexer {
    commands: Vec<Vec<String>>,
    words: Vec<String>,
    current: String,
    in_word: bool,
}

impl Lexer {
    fn push_char(&mut self, c: char) {
        self.in_word = true;
        self.current.push(c);
    }

    fn end_word(&mut self) {
        if self.in_word {
            self.words.push(std::mem::take(&mut self.current));
            self.in_word = false;
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        if !self.words.is_empty() {
            self.commands.push(std::mem::take(&mut self.words));
        }
    }
}

/// Split shell text into simple commands, each a list of unquoted words.
/// `;` `|` `&` `(` `)` backticks and newlines end a command. Quotes group
/// words, heredoc bodies and comments are skipped, so `cargo test` inside a
/// quoted string, a heredoc or a comment is never mistaken for a command.
fn split_simple_commands(command: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = command.chars().collect();
    let mut lexer = Lexer::default();
    let mut pending: Vec<(String, bool)> = Vec::new();
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
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        lexer.current.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if chars[i] == '<' && chars.get(i + 1) == Some(&'<') {
                        if let Some(resume) = quoted_heredoc_end(&chars, i + 2) {
                            lexer.current.push(' ');
                            i = resume;
                            continue;
                        }
                    }
                    lexer.current.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '\\' => {
                match chars.get(i + 1).copied() {
                    Some('\n') | None => {}
                    Some(next) => lexer.push_char(next),
                }
                i += 2;
            }
            ' ' | '\t' | '\r' => {
                lexer.end_word();
                i += 1;
            }
            '\n' => {
                lexer.end_command();
                i += 1;
                for (delimiter, strip_tabs) in std::mem::take(&mut pending) {
                    match skip_heredoc_body(&chars, i, &delimiter, strip_tabs) {
                        Some(next) => i = next,
                        None => {
                            i = chars.len();
                            break;
                        }
                    }
                }
            }
            ';' | '|' | '(' | ')' | '`' => {
                lexer.end_command();
                i += 1;
            }
            '&' => {
                let attached =
                    (i > 0 && matches!(chars[i - 1], '>' | '<')) || chars.get(i + 1) == Some(&'>');
                if attached {
                    lexer.push_char('&');
                } else {
                    lexer.end_command();
                }
                i += 1;
            }
            '#' if !lexer.in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) == Some(&'<') => {
                for _ in 0..3 {
                    lexer.push_char('<');
                }
                i += 3;
            }
            '<' if chars.get(i + 1) == Some(&'<') => match read_heredoc_delimiter(&chars, i + 2) {
                Some((delimiter, strip_tabs, next)) => {
                    lexer.end_word();
                    pending.push((delimiter, strip_tabs));
                    i = next;
                }
                None => {
                    lexer.push_char('<');
                    i += 1;
                }
            },
            other => {
                lexer.push_char(other);
                i += 1;
            }
        }
    }
    lexer.end_command();
    lexer.commands
}

// ---------------------------------------------------------------------------
// Words: wrappers, redirects, programs
// ---------------------------------------------------------------------------

fn is_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit())
        }
        None => false,
    }
}

fn is_redirect(word: &str) -> bool {
    let trimmed = word.trim_start_matches(|c: char| c.is_ascii_digit());
    trimmed.starts_with('>') || trimmed.starts_with('<') || word.starts_with("&>")
}

fn strip_redirects(words: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if is_redirect(word) {
            let operator = word.trim_start_matches(|c: char| c.is_ascii_digit());
            let bare = operator.chars().all(|c| matches!(c, '>' | '<' | '&' | '|'));
            i += if bare { 2 } else { 1 };
            continue;
        }
        out.push(words[i].clone());
        i += 1;
    }
    out
}

/// The program a word names: its basename without a `.exe` suffix.
fn program_name(word: &str) -> &str {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    match base.len().checked_sub(4) {
        Some(cut) if base.is_char_boundary(cut) && base[cut..].eq_ignore_ascii_case(".exe") => {
            &base[..cut]
        }
        _ => base,
    }
}

/// Index after any run of option words from `start`; each option in
/// `value_flags` also takes the following word.
fn skip_options(words: &[String], start: usize, value_flags: &[&str]) -> usize {
    let mut i = start;
    while let Some(word) = words.get(i) {
        let word = word.as_str();
        if word == "--" || !word.starts_with('-') || word.len() < 2 {
            break;
        }
        i += if value_flags.contains(&word) { 2 } else { 1 };
    }
    i
}

fn skip_env(words: &[String], start: usize) -> usize {
    let mut i = start;
    while let Some(word) = words.get(i) {
        let word = word.as_str();
        if is_assignment(word) {
            i += 1;
        } else if matches!(word, "-u" | "-C" | "-S") {
            i += 2;
        } else if word.starts_with('-') && word.len() > 1 && word != "--" {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Drop redirects, leading `VAR=x` assignments, shell keywords and wrapper
/// programs (`env`, `sudo`, `nice`, `timeout`, `xargs`, ...), leaving the
/// command that actually runs.
fn clean_words(raw: &[String]) -> Vec<String> {
    let words = strip_redirects(raw);
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        let lower = word.to_ascii_lowercase();
        if is_assignment(word) || CONTROL_WORDS.contains(&lower.as_str()) {
            i += 1;
            continue;
        }
        let program = program_name(word).to_ascii_lowercase();
        let next = match program.as_str() {
            "env" => Some(skip_env(&words, i + 1)),
            "sudo" | "doas" => Some(skip_options(
                &words,
                i + 1,
                &[
                    "-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D", "-R", "-T",
                ],
            )),
            "nice" => Some(skip_options(&words, i + 1, &["-n"])),
            "timeout" => Some(skip_options(&words, i + 1, &["-k", "-s"]) + 1),
            "xargs" => Some(skip_options(
                &words,
                i + 1,
                &["-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "-J"],
            )),
            "nohup" | "command" | "exec" | "builtin" | "setsid" | "caffeinate" => {
                Some(skip_options(&words, i + 1, &[]))
            }
            _ => None,
        };
        match next {
            Some(next) => i = next,
            None => break,
        }
    }
    words[i.min(words.len())..].to_vec()
}

/// Positional (non-option) words in `rest`, in order.
fn positionals<'a>(rest: &[&'a str], value_flags: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let word = rest[i];
        if word == "--" {
            i += 1;
            continue;
        }
        if word.starts_with('-') && word.len() > 1 {
            i += if value_flags.contains(&word) { 2 } else { 1 };
            continue;
        }
        out.push(word);
        i += 1;
    }
    out
}

fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('~')
        || path.starts_with('\\')
        || path.as_bytes().get(1) == Some(&b':')
}

fn looks_like_path(word: &str) -> bool {
    is_absolute(word)
        || word.starts_with("./")
        || word.starts_with("../")
        || word == "."
        || word == ".."
}

fn path_words(words: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |value: &str| {
        if !value.is_empty() && out.len() < MAX_PATHS && !out.iter().any(|path| path == value) {
            out.push(value.to_owned());
        }
    };
    for (index, word) in words.iter().enumerate() {
        if matches!(word.as_str(), "-C" | "--path" | "--manifest-path") {
            if let Some(next) = words.get(index + 1) {
                add(next);
            }
            continue;
        }
        let value = word
            .split_once('=')
            .filter(|(flag, _)| flag.starts_with('-'))
            .map_or(word.as_str(), |(_, value)| value);
        if looks_like_path(value) {
            add(value);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Effect classes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Build,
    Ci,
    Publish,
    Install,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Build => "compile/build/test",
            Kind::Ci => "CI",
            Kind::Publish => "publish",
            Kind::Install => "install",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    None,
    ClassA,
    Effect(Kind),
    /// `git push`: an effect only where the repo has workflows that trigger
    /// on push.
    Push,
}

/// One effect found in a command.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hit {
    kind: Kind,
    /// The command with wrappers removed and whitespace collapsed; approvals
    /// match against this form.
    text: String,
    /// Directory set by an earlier `cd` in the same command.
    dir: Option<String>,
    /// Path-like words and `-C` values: where the command works.
    paths: Vec<String>,
    push: bool,
}

#[derive(Clone, Debug, Default)]
struct Scan {
    hits: Vec<Hit>,
    class_a: bool,
}

/// `npx x ...`, `pnpm exec x ...`, `pnpm dlx x ...`: the command `x ...`.
fn unwrap_runner(words: &[String]) -> Vec<String> {
    let Some(first) = words.first() else {
        return Vec::new();
    };
    let program = program_name(first).to_ascii_lowercase();
    let from = match program.as_str() {
        "npx" | "pnpx" | "bunx" => Some(1),
        "pnpm" | "npm" | "yarn" | "bun" => {
            let mut index = 1;
            let mut found = None;
            while index < words.len() {
                let word = words[index].as_str();
                if word == "--" {
                    index += 1;
                    continue;
                }
                if word.starts_with('-') && word.len() > 1 {
                    index += if PM_VALUE_FLAGS.contains(&word) { 2 } else { 1 };
                    continue;
                }
                found = Some(index);
                break;
            }
            match found {
                Some(i) if matches!(words[i].as_str(), "exec" | "dlx" | "x") => Some(i + 1),
                _ => None,
            }
        }
        _ => None,
    };
    let Some(mut index) = from else {
        return words.to_vec();
    };
    while index < words.len() {
        let word = words[index].as_str();
        if word == "--" {
            index += 1;
            break;
        }
        if word.starts_with('-') && word.len() > 1 {
            index += if matches!(word, "-p" | "--package" | "-c" | "--call") {
                2
            } else {
                1
            };
            continue;
        }
        break;
    }
    words
        .get(index..)
        .map(|rest| rest.to_vec())
        .unwrap_or_default()
}

fn is_gate_token(token: &str) -> bool {
    let base = program_name(token).to_ascii_lowercase();
    ["rightkit-gate", "rightkit-host-gate"]
        .iter()
        .any(|name| base == *name || base.starts_with(&format!("{name}.")))
}

/// `rightkit-gate` and `rightkit-host-gate` runs: `check` is Class A (never
/// gated), `--to compile|package|qualify|release|dev|test` is an effect.
/// `None` when the command is not a gate invocation.
fn classify_gate(words: &[String]) -> Option<Class> {
    let first = words.first()?;
    let index = if is_gate_token(first) {
        0
    } else if INTERPRETERS.contains(&program_name(first).to_ascii_lowercase().as_str()) {
        words.iter().take(3).position(|word| is_gate_token(word))?
    } else {
        return None;
    };
    let args: Vec<&str> = words[index + 1..].iter().map(String::as_str).collect();
    if positionals(&args, GATE_VALUE_FLAGS).first().copied() == Some("check") {
        return Some(Class::ClassA);
    }
    let mut target = None;
    for (position, arg) in args.iter().copied().enumerate() {
        if arg == "--to" {
            target = args.get(position + 1).copied();
            break;
        }
        if let Some(value) = arg.strip_prefix("--to=") {
            target = Some(value);
            break;
        }
    }
    match target {
        Some(value) if GATE_EFFECT_TARGETS.contains(&value) => {
            if value == "dev" && args.iter().any(|arg| arg.contains("install")) {
                Some(Class::Effect(Kind::Install))
            } else {
                Some(Class::Effect(Kind::Build))
            }
        }
        _ => Some(Class::None),
    }
}

/// `node scripts/preflight.mjs` (Class A).
fn is_preflight(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    INTERPRETERS.contains(&program_name(first).to_ascii_lowercase().as_str())
        && words
            .iter()
            .skip(1)
            .take(3)
            .any(|word| word.replace('\\', "/").ends_with("preflight.mjs"))
}

fn classify_cargo(rest: &[&str]) -> Class {
    let sub = positionals(rest, CARGO_VALUE_FLAGS)
        .into_iter()
        .find(|word| !word.starts_with('+'));
    match sub {
        Some(sub) if CARGO_EFFECT.contains(&sub) => Class::Effect(Kind::Build),
        Some("install") => Class::Effect(Kind::Install),
        Some("publish") => Class::Effect(Kind::Publish),
        _ => Class::None,
    }
}

fn is_build_or_test_script(name: &str) -> bool {
    matches!(name, "build" | "test" | "t")
        || name.starts_with("build:")
        || name.starts_with("test:")
}

fn classify_node_pm(rest: &[&str]) -> Class {
    let pos = positionals(rest, PM_VALUE_FLAGS);
    let Some(sub) = pos.first().copied() else {
        return Class::None;
    };
    if sub == "publish" {
        return Class::Effect(Kind::Publish);
    }
    if sub == "tauri" && pos.get(1).copied() == Some("build") {
        return Class::Effect(Kind::Build);
    }
    let script = match sub {
        "run" | "run-script" => pos.get(1).copied(),
        other => Some(other),
    };
    match script {
        Some(script) if is_build_or_test_script(script) => Class::Effect(Kind::Build),
        _ => Class::None,
    }
}

fn classify_gh(rest: &[&str]) -> Class {
    let pos = positionals(rest, &["-R", "--repo", "--hostname"]);
    match (pos.first().copied(), pos.get(1).copied()) {
        (Some("workflow"), Some("run")) | (Some("run"), Some("rerun")) => Class::Effect(Kind::Ci),
        (Some("release"), Some("create")) | (Some("release"), Some("upload")) => {
            Class::Effect(Kind::Publish)
        }
        _ => Class::None,
    }
}

fn classify_git(rest: &[&str]) -> Class {
    let pos = positionals(rest, GIT_VALUE_FLAGS);
    if pos.first().copied() != Some("push") {
        return Class::None;
    }
    if rest.iter().any(|word| matches!(*word, "--dry-run" | "-n")) {
        return Class::None;
    }
    Class::Push
}

fn is_install_script(path: &str) -> bool {
    let name = program_name(path).to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((stem, extension)) => {
            stem.starts_with("install")
                && matches!(extension, "sh" | "ps1" | "command" | "bat" | "cmd" | "py")
        }
        None => false,
    }
}

fn classify_install_script(words: &[String], program: &str) -> Class {
    let candidate = if INTERPRETERS.contains(&program) {
        words
            .iter()
            .skip(1)
            .find(|word| !word.starts_with('-'))
            .map(String::as_str)
    } else {
        words.first().map(String::as_str)
    };
    match candidate {
        Some(candidate) if is_install_script(candidate) => Class::Effect(Kind::Install),
        _ => Class::None,
    }
}

fn classify(all: &[String]) -> Class {
    let words = unwrap_runner(all);
    let Some(first) = words.first() else {
        return Class::None;
    };
    let program = program_name(first).to_ascii_lowercase();
    if let Some(class) = classify_gate(&words) {
        return class;
    }
    if is_preflight(&words) {
        return Class::ClassA;
    }
    let rest: Vec<&str> = words[1..].iter().map(String::as_str).collect();
    match program.as_str() {
        "rustright" => {
            if rest.first().copied() == Some("cargo") {
                classify_cargo(&rest[1..])
            } else {
                Class::None
            }
        }
        "cargo" => classify_cargo(&rest),
        "swift" => {
            let pos = positionals(&rest, &[]);
            if matches!(
                pos.first().copied(),
                Some("build") | Some("test") | Some("run")
            ) {
                Class::Effect(Kind::Build)
            } else {
                Class::None
            }
        }
        "xcodebuild" => {
            let read_only = rest.iter().any(|word| {
                matches!(
                    *word,
                    "-list"
                        | "-showBuildSettings"
                        | "-showsdks"
                        | "-showdestinations"
                        | "-version"
                        | "-help"
                        | "-usage"
                )
            });
            if read_only {
                Class::None
            } else {
                Class::Effect(Kind::Build)
            }
        }
        "tsc" => {
            let quiet = rest.iter().any(|word| {
                word.eq_ignore_ascii_case("--noEmit")
                    || matches!(
                        *word,
                        "-v" | "--version" | "-h" | "--help" | "--init" | "--showConfig"
                    )
            });
            if quiet {
                Class::None
            } else {
                Class::Effect(Kind::Build)
            }
        }
        "pnpm" | "npm" | "yarn" | "bun" => classify_node_pm(&rest),
        "gh" => classify_gh(&rest),
        "git" => classify_git(&rest),
        "wrangler" => {
            let pos = positionals(&rest, &[]);
            if pos
                .iter()
                .copied()
                .take(2)
                .any(|word| matches!(word, "deploy" | "publish"))
            {
                Class::Effect(Kind::Publish)
            } else {
                Class::None
            }
        }
        "right-release" => {
            if positionals(&rest, &[]).first().copied() == Some("publish") {
                Class::Effect(Kind::Publish)
            } else {
                Class::None
            }
        }
        "brew" | "winget" | "choco" | "scoop" | "apt" | "apt-get" => {
            let pos = positionals(&rest, &[]);
            let installs = match program.as_str() {
                "brew" => matches!(pos.first().copied(), Some("install") | Some("reinstall")),
                _ => pos.first().copied() == Some("install"),
            };
            if installs {
                Class::Effect(Kind::Install)
            } else {
                Class::None
            }
        }
        "msiexec" => Class::Effect(Kind::Install),
        "installer" => {
            if rest.iter().any(|word| word.eq_ignore_ascii_case("-pkg")) {
                Class::Effect(Kind::Install)
            } else {
                Class::None
            }
        }
        "legion" => {
            let pos = positionals(&rest, &[]);
            if pos.first().copied() == Some("setup")
                && matches!(pos.get(1).copied(), Some("repair") | Some("install"))
            {
                Class::Effect(Kind::Install)
            } else {
                Class::None
            }
        }
        _ => classify_install_script(&words, &program),
    }
}

fn is_command_flag(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    matches!(lower.as_str(), "-c" | "/c" | "-command")
        || (lower.len() >= 2
            && lower.starts_with('-')
            && !lower.starts_with("--")
            && lower.ends_with('c')
            && lower[1..].chars().all(|c| c.is_ascii_alphabetic()))
}

fn shell_flag_index(words: &[String], program: &str) -> Option<usize> {
    for (offset, word) in words.iter().enumerate().skip(1) {
        if is_command_flag(word) {
            return Some(offset);
        }
        let slash_flag = program == "cmd" && word.starts_with('/');
        if !word.starts_with('-') && !word.starts_with('+') && !slash_flag {
            return None;
        }
    }
    None
}

fn ssh_remote_command(words: &[String]) -> Option<String> {
    const VALUE_FLAGS: &[&str] = &[
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w",
    ];
    let mut i = 1;
    while let Some(word) = words.get(i) {
        if word.starts_with('-') && word.len() > 1 {
            i += if VALUE_FLAGS.contains(&word.as_str()) {
                2
            } else {
                1
            };
        } else {
            break;
        }
    }
    let rest = words.get(i + 1..)?;
    (!rest.is_empty()).then(|| rest.join(" "))
}

/// The command a shell, `eval`, `ssh` or `win` is asked to run, if any.
fn inner_command(words: &[String], program: &str) -> Option<String> {
    match program {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish" => {
            let flag = shell_flag_index(words, program)?;
            words.get(flag + 1).cloned()
        }
        "pwsh" | "powershell" | "cmd" => {
            let flag = shell_flag_index(words, program)?;
            let rest = words.get(flag + 1..)?;
            (!rest.is_empty()).then(|| rest.join(" "))
        }
        "eval" => (words.len() > 1).then(|| words[1..].join(" ")),
        "ssh" => ssh_remote_command(words),
        "win" => (words.len() > 1).then(|| words[1..].join(" ")),
        _ => None,
    }
}

fn next_dir(previous: Option<&str>, target: &str) -> String {
    match previous {
        Some(previous) if !is_absolute(target) => format!("{previous}/{target}"),
        _ => target.to_owned(),
    }
}

fn make_hit(kind: Kind, push: bool, words: &[String], dir: Option<String>) -> Hit {
    let words = unwrap_runner(words);
    Hit {
        kind,
        text: normalise(&words.join(" ")),
        dir,
        paths: path_words(&words),
        push,
    }
}

/// Every effect in `command`, and whether it runs Class A. Follows `cd`,
/// `bash -c '...'`, `ssh host '...'` and `win '...'` up to `MAX_DEPTH`.
fn scan_command(command: &str, depth: u8) -> Scan {
    let mut scan = Scan::default();
    let mut dir: Option<String> = None;
    for raw in split_simple_commands(command) {
        let words = clean_words(&raw);
        let Some(first) = words.first() else {
            continue;
        };
        let program = program_name(first).to_ascii_lowercase();
        if matches!(program.as_str(), "cd" | "pushd") {
            if let Some(target) = words.get(1).filter(|word| !word.starts_with('-')) {
                dir = Some(next_dir(dir.as_deref(), target));
            }
            continue;
        }
        if depth < MAX_DEPTH {
            if let Some(inner) = inner_command(&words, &program) {
                let sub = scan_command(&inner, depth + 1);
                scan.class_a |= sub.class_a;
                for mut hit in sub.hits {
                    if hit.dir.is_none() {
                        hit.dir = dir.clone();
                    }
                    scan.hits.push(hit);
                }
                continue;
            }
        }
        match classify(&words) {
            Class::None => {}
            Class::ClassA => scan.class_a = true,
            Class::Effect(kind) => scan.hits.push(make_hit(kind, false, &words, dir.clone())),
            Class::Push => scan
                .hits
                .push(make_hit(Kind::Ci, true, &words, dir.clone())),
        }
    }
    scan
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn expand_home(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_owned()
}

fn normalize_path(path: &str) -> String {
    let unified = path.replace('\\', "/");
    let root = if unified.starts_with('/') { "/" } else { "" };
    let mut parts: Vec<&str> = Vec::new();
    for component in unified.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("{root}{}", parts.join("/"))
}

fn resolve_path(base: &str, path: &str) -> String {
    let expanded = expand_home(path);
    if is_absolute(&expanded) {
        normalize_path(&expanded)
    } else {
        normalize_path(&format!("{base}/{expanded}"))
    }
}

fn resolve_dir(cwd: &str, dir: Option<&str>) -> String {
    match dir {
        None => cwd.to_owned(),
        Some(dir) if dir.contains('$') || dir.contains('`') || dir == "-" => cwd.to_owned(),
        Some(dir) => resolve_path(cwd, dir),
    }
}

fn same_path(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim_end_matches('/'), b.trim_end_matches('/'));
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn candidate_in_repo(env: &dyn Env, candidate: &str, repo: &str) -> bool {
    match env.toplevel(Path::new(candidate)) {
        Some(top) => same_path(&top.to_string_lossy(), repo),
        None => {
            let repo = repo.trim_end_matches('/');
            candidate == repo || candidate.starts_with(&format!("{repo}/"))
        }
    }
}

/// Does `hit` run in `repo`? Its working directory, or any path it names,
/// must resolve to that repository.
fn hit_in_repo(hit: &Hit, cwd: &str, repo: &str, env: &dyn Env) -> bool {
    let base = resolve_dir(cwd, hit.dir.as_deref());
    let mut candidates = vec![base.clone()];
    candidates.extend(hit.paths.iter().map(|path| resolve_path(&base, path)));
    candidates
        .iter()
        .any(|candidate| candidate_in_repo(env, candidate, repo))
}

fn repo_of(env: &dyn Env, path: &str) -> String {
    env.toplevel(Path::new(path))
        .map(|top| top.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned())
}

/// Drop `git push` hits whose repo has no workflow that triggers on push.
fn resolve_pushes(hits: Vec<Hit>, cwd: &str, env: &dyn Env) -> Vec<Hit> {
    hits.into_iter()
        .filter(|hit| {
            if !hit.push {
                return true;
            }
            let base = resolve_dir(cwd, hit.dir.as_deref());
            let start = hit
                .paths
                .first()
                .map(|path| resolve_path(&base, path))
                .unwrap_or_else(|| base.clone());
            match env.toplevel(Path::new(&start)) {
                Some(top) => env.push_triggers_ci(&top),
                None => false,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Request and relay blocks
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Block {
    repo: Option<String>,
    commit: Option<String>,
    class_a: Option<String>,
    verdict: Option<String>,
    chat: Option<String>,
    quote: Option<String>,
    commands: Vec<String>,
    raw: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Section {
    None,
    Commands,
    ClassA,
}

fn is_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

fn is_bare_fence(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 3 && (trimmed.chars().all(|c| c == '`') || trimmed.chars().all(|c| c == '~'))
}

fn header_matches(line: &str, header: &str) -> bool {
    line.trim()
        .trim_end_matches(':')
        .trim()
        .eq_ignore_ascii_case(header)
}

fn is_sha(token: &str) -> bool {
    (7..=64).contains(&token.len()) && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn block_key(line: &str) -> Option<(&'static str, &str)> {
    let (left, right) = line.split_once(':')?;
    let key = left.trim().to_ascii_lowercase().replace([' ', '_'], "-");
    let name = match key.as_str() {
        "repo" => "repo",
        "commit" => "commit",
        "class-a" => "class-a",
        "verdict" => "verdict",
        "commands" | "command" => "commands",
        "chat" => "chat",
        "quote" => "quote",
        _ => return None,
    };
    Some((name, right))
}

fn strip_bullet(line: &str) -> (bool, &str) {
    for marker in ["- ", "* ", "\u{2022} "] {
        if let Some(rest) = line.strip_prefix(marker) {
            return (true, rest.trim());
        }
    }
    let digits = line.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 {
        let rest = &line[digits..];
        if let Some(rest) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return (true, rest.trim());
        }
    }
    (false, line)
}

fn push_command(block: &mut Block, text: &str) {
    let text = text
        .trim()
        .trim_start_matches("$ ")
        .trim()
        .trim_matches('`')
        .trim();
    if !text.is_empty() && block.commands.len() < MAX_COMMANDS {
        block.commands.push(text.to_owned());
    }
}

fn parse_block_body(lines: &[&str], raw: String) -> Block {
    let mut block = Block {
        raw,
        ..Block::default()
    };
    let mut section = Section::None;
    for line in lines.iter().take(MAX_BLOCK_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (bullet, item) = strip_bullet(trimmed);
        if !bullet {
            if let Some((key, value)) = block_key(trimmed) {
                let value = value.trim();
                section = Section::None;
                match key {
                    "repo" => block.repo = non_empty(value.trim_matches('`')),
                    "commit" => {
                        block.commit = value
                            .split_whitespace()
                            .next()
                            .map(|token| token.trim_matches('`').to_owned())
                            .filter(|token| is_sha(token));
                    }
                    "class-a" => {
                        block.class_a = non_empty(value);
                        section = Section::ClassA;
                    }
                    "verdict" => block.verdict = non_empty(value),
                    "chat" => {
                        block.chat = value.split_whitespace().next().and_then(non_empty);
                    }
                    "quote" => block.quote = non_empty(value),
                    "commands" => {
                        section = Section::Commands;
                        if !value.is_empty() {
                            push_command(&mut block, value);
                        }
                    }
                    _ => {}
                }
                continue;
            }
        }
        match section {
            Section::Commands => push_command(&mut block, item),
            Section::ClassA => {
                let text = block.class_a.get_or_insert_with(String::new);
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(trimmed);
            }
            Section::None => {}
        }
    }
    block
}

/// Every fenced block in `text` whose first line is `header`.
fn find_blocks(text: &str, header: &str) -> Vec<Block> {
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_fence(lines[i]) {
            i += 1;
            continue;
        }
        let mut close = lines.len();
        for (j, line) in lines.iter().enumerate().skip(i + 1) {
            if is_bare_fence(line) {
                close = j;
                break;
            }
        }
        let body = &lines[i + 1..close];
        if let Some(first) = body.iter().position(|line| !line.trim().is_empty()) {
            if header_matches(body[first], header) {
                blocks.push(parse_block_body(&body[first + 1..], body.join("\n")));
            }
        }
        i = close + 1;
    }
    blocks
}

fn fnv64(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn short(sha: &str) -> String {
    sha.chars().take(8).collect()
}

fn sha_matches(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim().to_ascii_lowercase(), b.trim().to_ascii_lowercase());
    a.len().min(b.len()) >= 7 && (a.starts_with(&b) || b.starts_with(&a))
}

fn cites_class_a(text: &str) -> bool {
    let lowered = normalise(&text.to_ascii_lowercase());
    lowered.contains("rightkit-gate check")
        || lowered.contains("rightkit-host-gate check")
        || lowered.contains("preflight.mjs")
}

fn verdict_is_will_pass(verdict: &str) -> bool {
    verdict.trim().to_ascii_lowercase().starts_with("will pass")
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum Ev {
    /// A user-role text message; `genuine` is false for relays and host notices.
    User {
        text: String,
        genuine: bool,
    },
    ToolResult,
    AssistantText(String),
    ShellCall(String),
}

/// Prompts that are not Adrian typing: Pulse relays and host notices.
fn is_genuine_prompt(prompt: &str) -> bool {
    let trimmed = prompt.trim_start();
    ![
        "[Pulse Chat",
        "<task-notification",
        "<system-reminder",
        "<command-name",
        "<local-command",
        "[Request interrupted",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn command_of(input: &Map<String, Value>) -> Option<String> {
    for key in ["command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => return Some(text.clone()),
            Some(Value::Array(items)) => {
                let parts: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                if !parts.is_empty() {
                    return Some(
                        parts
                            .iter()
                            .map(|part| {
                                if part.contains(char::is_whitespace) || part.contains('\'') {
                                    format!("'{}'", part.replace('\'', "'\\''"))
                                } else {
                                    (*part).to_owned()
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
            }
            _ => {}
        }
    }
    None
}

fn shell_call_command(item: &Value) -> Option<String> {
    let name = item.get("name").and_then(Value::as_str)?;
    if !SHELL_TOOLS.contains(&name) {
        return None;
    }
    command_of(item.get("input")?.as_object()?)
}

fn claude_events(value: &Value, kind: &str) -> Vec<Ev> {
    if value.get("isSidechain").and_then(Value::as_bool) == Some(true) {
        return Vec::new();
    }
    let meta = value.get("isMeta").and_then(Value::as_bool) == Some(true)
        || value.get("isCompactSummary").and_then(Value::as_bool) == Some(true);
    let Some(content) = value
        .get("message")
        .and_then(|message| message.get("content"))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match content {
        Value::String(text) => {
            if kind == "assistant" {
                out.push(Ev::AssistantText(text.clone()));
            } else {
                out.push(Ev::User {
                    genuine: !meta && is_genuine_prompt(text),
                    text: text.clone(),
                });
            }
        }
        Value::Array(items) => {
            let mut user_text = String::new();
            let mut saw_result = false;
            for item in items {
                match item.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
                        if kind == "assistant" {
                            out.push(Ev::AssistantText(text.to_owned()));
                        } else {
                            if !user_text.is_empty() {
                                user_text.push('\n');
                            }
                            user_text.push_str(text);
                        }
                    }
                    Some("tool_use") => {
                        if let Some(command) = shell_call_command(item) {
                            out.push(Ev::ShellCall(command));
                        }
                    }
                    Some("tool_result") => saw_result = true,
                    _ => {}
                }
            }
            if kind == "user" {
                if saw_result {
                    out.push(Ev::ToolResult);
                } else if !user_text.is_empty() {
                    out.push(Ev::User {
                        genuine: !meta && is_genuine_prompt(&user_text),
                        text: user_text,
                    });
                }
            }
        }
        _ => {}
    }
    out
}

/// Codex rollout lines (shape UNVERIFIED until a live run): messages and
/// shell function calls.
fn codex_events(value: &Value) -> Vec<Ev> {
    let Some(payload) = value.get("payload") else {
        return Vec::new();
    };
    match payload.get("type").and_then(Value::as_str) {
        Some("message") => {
            let role = payload.get("role").and_then(Value::as_str).unwrap_or("");
            let text = payload
                .get("content")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            match role {
                "assistant" => vec![Ev::AssistantText(text)],
                "user" => vec![Ev::User {
                    genuine: is_genuine_prompt(&text),
                    text,
                }],
                _ => Vec::new(),
            }
        }
        Some("function_call") | Some("local_shell_call") => {
            let arguments = payload
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|text| serde_json::from_str::<Value>(text).ok());
            let command = arguments
                .as_ref()
                .and_then(Value::as_object)
                .and_then(command_of);
            command.map(Ev::ShellCall).into_iter().collect()
        }
        _ => Vec::new(),
    }
}

fn events_of_line(line: &str) -> Vec<Ev> {
    let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
        return Vec::new();
    };
    match value.get("type").and_then(Value::as_str).unwrap_or("") {
        kind @ ("user" | "assistant") => claude_events(&value, kind),
        "response_item" => codex_events(&value),
        _ => Vec::new(),
    }
}

/// Events of a transcript file. A file over `max_bytes` is read from its tail
/// when `tail_ok`, else not at all.
fn read_events(path: &Path, max_bytes: u64, tail_ok: bool) -> Option<Vec<Ev>> {
    let mut file = fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = if len > max_bytes {
        if !tail_ok {
            return None;
        }
        len - max_bytes
    } else {
        0
    };
    if start > 0 {
        file.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    Some(lines.flat_map(events_of_line).collect())
}

/// The assistant text of the turn before `prompt`: every assistant text since
/// the previous genuine user prompt. The just-submitted prompt itself, if the
/// host already wrote it, is skipped.
fn last_assistant_text(events: &[Ev], prompt: &str) -> String {
    let current = prompt.trim();
    let mut parts: Vec<&str> = Vec::new();
    let mut skipped_current = false;
    for event in events.iter().rev() {
        match event {
            Ev::AssistantText(text) => parts.push(text),
            Ev::User {
                text,
                genuine: true,
            } => {
                if parts.is_empty() && !skipped_current && text.trim() == current {
                    skipped_current = true;
                    continue;
                }
                break;
            }
            _ => {}
        }
    }
    parts.reverse();
    parts.join("\n\n")
}

// ---------------------------------------------------------------------------
// Approval record
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Approval {
    /// Effect commands still approved, one entry per permitted run.
    commands: Vec<String>,
    repo: String,
    head_sha: String,
    granted_t: u64,
    consumed: Vec<String>,
    relay_keys: Vec<String>,
    source: String,
}

impl Approval {
    fn parse(bytes: &[u8]) -> Option<Approval> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let object = value.as_object()?;
        let strings = |key: &str| -> Vec<String> {
            object
                .get(key)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(Approval {
            commands: strings("commands"),
            repo: object.get("repo").and_then(Value::as_str)?.to_owned(),
            head_sha: object
                .get("head_sha")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            granted_t: object.get("granted_t").and_then(Value::as_u64).unwrap_or(0),
            consumed: strings("consumed"),
            relay_keys: strings("relay_keys"),
            source: object
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        })
    }

    fn render(&self) -> Vec<u8> {
        json!({
            "commands": self.commands,
            "repo": self.repo,
            "head_sha": self.head_sha,
            "granted_t": self.granted_t,
            "consumed": self.consumed,
            "relay_keys": self.relay_keys,
            "source": self.source,
        })
        .to_string()
        .into_bytes()
    }
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

fn approval_file(dir: &Path, session: &str) -> PathBuf {
    dir.join(format!("{}.json", safe_name(session)))
}

fn read_approval(path: &Path) -> Option<Approval> {
    Approval::parse(&fs::read(path).ok()?)
}

/// True when the approval file exists but cannot be read or parsed. That is
/// an unreadable state, not "no approval", so the gate fails open.
fn approval_unreadable(path: &Path) -> bool {
    match fs::read(path) {
        Ok(bytes) => Approval::parse(&bytes).is_none(),
        Err(error) => error.kind() != ErrorKind::NotFound,
    }
}

fn payload_cwd(payload: &Map<String, Value>) -> String {
    str_field(payload, &["cwd", "workdir"])
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        })
        .unwrap_or_default()
}

/// The repo a block's commands work in when it names none: the directory or
/// path of the first command that has one, else the session cwd's repo.
fn repo_from_hits(hits: &[Hit], cwd: &str, env: &dyn Env) -> String {
    for hit in hits {
        if hit.dir.is_none() && hit.paths.is_empty() {
            continue;
        }
        let base = resolve_dir(cwd, hit.dir.as_deref());
        let start = hit
            .paths
            .first()
            .map(|path| resolve_path(&base, path))
            .unwrap_or_else(|| base.clone());
        return repo_of(env, &start);
    }
    repo_of(env, cwd)
}

/// An approval from a parsed block. `None` when the block lists no command
/// the gate controls (nothing to approve).
fn build_approval(
    block: &Block,
    cwd: &str,
    env: &dyn Env,
    now: u64,
    source: &str,
) -> Option<Approval> {
    let hits: Vec<Hit> = block
        .commands
        .iter()
        .flat_map(|line| scan_command(line, 0).hits)
        .take(MAX_COMMANDS)
        .collect();
    if hits.is_empty() {
        return None;
    }
    let repo = match block.repo.as_deref() {
        Some(repo) => repo_of(env, repo),
        None => repo_from_hits(&hits, cwd, env),
    };
    let commands: Vec<String> = hits.into_iter().map(|hit| hit.text).collect();
    let head = if repo.is_empty() {
        None
    } else {
        env.head(Path::new(&repo))
    };
    // A stale or unverifiable commit binds the approval to what was asked for,
    // so a moved HEAD denies with a clear reason instead of silently passing.
    let head_sha = match (head, block.commit.as_deref()) {
        (Some(head), Some(commit)) if sha_matches(&head, commit) => head,
        (_, Some(commit)) => commit.to_owned(),
        (Some(head), None) => head,
        (None, None) => String::new(),
    };
    Some(Approval {
        commands,
        repo,
        head_sha,
        granted_t: now,
        consumed: Vec::new(),
        relay_keys: Vec::new(),
        source: source.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Decision (pure apart from the injected environment)
// ---------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq)]
enum Decision {
    Allow {
        remaining: Vec<String>,
        used: Vec<String>,
    },
    Deny(String),
}

/// `command` is covered by `approved` when it equals it or extends it with
/// further arguments (word-boundary prefix).
fn covers(approved: &str, command: &str) -> bool {
    !approved.is_empty()
        && (command == approved
            || command
                .strip_prefix(approved)
                .is_some_and(|rest| rest.starts_with(' ')))
}

fn decide(
    hits: &[Hit],
    approval: Option<&Approval>,
    cwd: &str,
    env: &dyn Env,
    now: u64,
) -> Decision {
    let first = hits.first().map_or("", |hit| hit.text.as_str());
    let Some(approval) = approval else {
        return Decision::Deny(format!(
            "no approval is on record in this chat for `{first}`."
        ));
    };
    if approval.granted_t > 0 && now.saturating_sub(approval.granted_t) > APPROVAL_TTL_SECS {
        return Decision::Deny("the approval is more than 24 hours old.".to_owned());
    }
    let mut pool = approval.commands.clone();
    let mut used = Vec::new();
    for hit in hits {
        match pool.iter().position(|approved| covers(approved, &hit.text)) {
            Some(index) => used.push(pool.remove(index)),
            None => {
                return Decision::Deny(format!(
                    "`{}` is not among the approved commands (each approved command runs once).",
                    hit.text
                ))
            }
        }
    }
    if !approval.repo.is_empty() {
        for hit in hits {
            if !hit_in_repo(hit, cwd, &approval.repo, env) {
                return Decision::Deny(format!(
                    "`{}` does not run in the approved repo {}.",
                    hit.text, approval.repo
                ));
            }
        }
        if !approval.head_sha.is_empty() {
            let repo = Path::new(&approval.repo);
            if let Some(head) = env.head(repo) {
                if !sha_matches(&head, &approval.head_sha) {
                    return Decision::Deny(format!(
                        "HEAD is {} but the approval is for {}; any new commit voids it.",
                        short(&head),
                        short(&approval.head_sha)
                    ));
                }
            }
            if env.tracked_dirty(repo) == Some(true) {
                return Decision::Deny(
                    "tracked files have uncommitted edits since the approval; any edit voids it."
                        .to_owned(),
                );
            }
        }
    }
    Decision::Allow {
        remaining: pool,
        used,
    }
}

// ---------------------------------------------------------------------------
// Shadow log
// ---------------------------------------------------------------------------

fn log_shadow(dir: &Path, row: Value) {
    let path = dir.join(SHADOW_FILE);
    let line = row.to_string();
    let _ = (|| -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let len = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        if len > SHADOW_CAP_BYTES {
            let mut bytes = fs::read(&path)?;
            let half = bytes.len() / 2;
            let cut = bytes[half..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| half + offset + 1);
            bytes.drain(..cut);
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(b'\n');
            return write_atomic(&path, &bytes);
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")
    })();
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

// ---------------------------------------------------------------------------
// UserPromptSubmit: record an approval
// ---------------------------------------------------------------------------

const APPROVE_WORDS: &[&str] = &[
    "approve",
    "approved",
    "yes",
    "yep",
    "yeah",
    "go",
    "proceed",
    "ok",
    "okay",
    "confirmed",
];
const FILLER_WORDS: &[&str] = &[
    "please",
    "thanks",
    "thank",
    "you",
    "ahead",
    "and",
    "run",
    "it",
    "them",
    "that",
    "do",
    "sure",
    "for",
    "the",
    "request",
    "all",
    "now",
    "everything",
    "this",
];
const NEGATIVE_WORDS: &[&str] = &[
    "not",
    "no",
    "don't",
    "dont",
    "don\u{2019}t",
    "never",
    "wait",
    "hold",
    "stop",
    "cancel",
    "but",
    "except",
    "without",
    "instead",
    "only",
    "first",
    "unless",
    "until",
    "after",
    "before",
    "if",
];

/// Whether a prompt is a plain approval: "approve", "yes", "go ahead", or a
/// button label that starts with "approve". Anything hedged or conditional is
/// not, so Adrian's qualified answers never record an approval.
fn is_approval_reply(prompt: &str) -> bool {
    let trimmed = prompt.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 120 || trimmed.contains('?') {
        return false;
    }
    let lowered = trimmed.to_lowercase();
    let tokens: Vec<&str> = lowered
        .split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '\u{2019}'))
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() || tokens.len() > 12 {
        return false;
    }
    if tokens.iter().any(|token| NEGATIVE_WORDS.contains(token)) {
        return false;
    }
    if matches!(tokens[0], "approve" | "approved") {
        return true;
    }
    tokens.iter().any(|token| APPROVE_WORDS.contains(token))
        && tokens
            .iter()
            .all(|token| APPROVE_WORDS.contains(token) || FILLER_WORDS.contains(token))
}

fn note(request: &HookRequest, text: impl Into<String>) -> HookResponse {
    HookResponse::allowed(request.event_type.clone(), "approval note").with_additional_context(text)
}

fn is_user_prompt_event(event_type: &str) -> bool {
    matches!(event_type, "UserPromptSubmit" | "user-prompt-submit")
}

/// UserPromptSubmit: when Adrian's prompt approves and the last assistant
/// message holds an `APPROVAL REQUEST` block, record the approval. Returns a
/// context note only when something was recorded or the request was unusable.
pub fn on_user_prompt(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK)
        || !is_user_prompt_event(&request.event_type)
        || current_mode() == Mode::Off
    {
        return None;
    }
    let dir = state_dir(STATE_FOLDER)?;
    on_user_prompt_in(request, &dir, &RealEnv, now_secs())
}

fn on_user_prompt_in(
    request: &HookRequest,
    dir: &Path,
    env: &dyn Env,
    now: u64,
) -> Option<HookResponse> {
    let payload = request.payload.as_object()?;
    let prompt = str_field(payload, &["prompt", "user_prompt", "userPrompt"])?;
    if !is_genuine_prompt(&prompt) || !is_approval_reply(&prompt) {
        return None;
    }
    let session = session_id(payload)?;
    let transcript = str_field(payload, &["transcript_path", "transcriptPath"])?;
    let events = read_events(Path::new(&transcript), TAIL_BYTES, true)?;
    let message = last_assistant_text(&events, &prompt);
    let block = find_blocks(&message, REQUEST_HEADER).pop()?;
    let cwd = payload_cwd(payload);
    let Some(mut approval) = build_approval(&block, &cwd, env, now, "adrian") else {
        return Some(note(
            request,
            "Approval not recorded: the APPROVAL REQUEST block lists no compile, build, test, CI, publish or install command. List the exact commands under `commands:`.",
        ));
    };
    let path = approval_file(dir, &session);
    if let Some(previous) = read_approval(&path) {
        approval.relay_keys = previous.relay_keys;
    }
    write_atomic(&path, &approval.render()).ok()?;
    Some(note(
        request,
        format!(
            "Approval recorded from Adrian: {} command(s) in {} on commit {}. Each runs once while HEAD stays at that commit and tracked files stay clean; any edit or new commit voids it.",
            approval.commands.len(),
            approval.repo,
            short(&approval.head_sha)
        ),
    ))
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

fn is_pulse_read(command: &str, chat: &str) -> bool {
    let lowered = normalise(&command.to_ascii_lowercase());
    (lowered.contains("pulse chat said") || lowered.contains("pulse chat read"))
        && lowered.contains(chat)
}

/// An approval from an `APPROVAL FROM RELAY` block in the current turn, valid
/// only when a `pulse chat said|read` of the cited chat precedes it in the
/// transcript, it carries a quote and it has not been used before.
fn relay_from_events(
    events: &[Ev],
    previous: Option<&Approval>,
    cwd: &str,
    env: &dyn Env,
    now: u64,
) -> Option<Approval> {
    // The turn starts at the last message Adrian typed or another chat relayed;
    // host notices and injected reminders do not start a turn.
    let turn_start = events
        .iter()
        .rposition(|event| {
            matches!(event, Ev::User { text, genuine }
                if *genuine || text.trim_start().starts_with("[Pulse Chat"))
        })
        .map_or(0, |index| index + 1);
    let mut found = None;
    for index in (turn_start..events.len()).rev() {
        if let Ev::AssistantText(text) = &events[index] {
            if let Some(block) = find_blocks(text, RELAY_HEADER).pop() {
                found = Some((index, block));
                break;
            }
        }
    }
    let (position, block) = found?;
    let chat = block
        .chat
        .as_deref()?
        .trim_matches(|c: char| c == '#' || c == '`' || c.is_whitespace())
        .to_ascii_lowercase();
    if chat.len() < 6 {
        return None;
    }
    let read_before = events[..position]
        .iter()
        .any(|event| matches!(event, Ev::ShellCall(command) if is_pulse_read(command, &chat)));
    if !read_before
        || block
            .quote
            .as_deref()
            .map_or(true, |quote| quote.trim().is_empty())
    {
        return None;
    }
    let key = format!("{position}:{:016x}", fnv64(&block.raw));
    if previous.is_some_and(|approval| approval.relay_keys.iter().any(|used| *used == key)) {
        return None;
    }
    let mut approval = build_approval(&block, cwd, env, now, "relay")?;
    approval.relay_keys = previous
        .map(|approval| approval.relay_keys.clone())
        .unwrap_or_default();
    approval.relay_keys.push(key);
    Some(approval)
}

fn relay_approval(
    payload: &Map<String, Value>,
    previous: Option<&Approval>,
    cwd: &str,
    env: &dyn Env,
    now: u64,
) -> Option<Approval> {
    let transcript = str_field(payload, &["transcript_path", "transcriptPath"])?;
    let events = read_events(Path::new(&transcript), MAX_TRANSCRIPT_BYTES, false)?;
    relay_from_events(&events, previous, cwd, env, now)
}

// ---------------------------------------------------------------------------
// PreToolUse
// ---------------------------------------------------------------------------

/// The shell command of a tool call, `None` for any other tool.
fn shell_command(payload: &Map<String, Value>) -> Option<String> {
    let tool = tool_name(payload)?;
    if !SHELL_TOOLS.contains(&tool.as_str()) {
        return None;
    }
    command_of(tool_input(payload)?)
}

/// PreToolUse of a shell tool: an effect command needs a live approval.
/// `Some(denied)` in enforce mode when it has none, else `None`.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() || check_disabled(CHECK) {
        return None;
    }
    let mode = current_mode();
    if mode == Mode::Off {
        return None;
    }
    let payload = request.payload.as_object()?;
    let command = shell_command(payload)?;
    let dir = state_dir(STATE_FOLDER)?;
    pre_tool_in(request, &command, &dir, mode, &RealEnv, now_secs())
}

fn pre_tool_in(
    request: &HookRequest,
    command: &str,
    dir: &Path,
    mode: Mode,
    env: &dyn Env,
    now: u64,
) -> Option<HookResponse> {
    let payload = request.payload.as_object()?;
    let session = session_id(payload)?;
    let scan = scan_command(command, 0);
    if scan.hits.is_empty() {
        return None;
    }
    let cwd = payload_cwd(payload);
    let hits = resolve_pushes(scan.hits, &cwd, env);
    if hits.is_empty() {
        return None;
    }
    let path = approval_file(dir, &session);
    let approval = read_approval(&path);
    if approval.is_none() && approval_unreadable(&path) {
        return None;
    }
    let mut outcome = decide(&hits, approval.as_ref(), &cwd, env, now);
    let mut base = approval.clone();
    if matches!(outcome, Decision::Deny(_)) {
        if let Some(relay) = relay_approval(payload, approval.as_ref(), &cwd, env, now) {
            let relayed = decide(&hits, Some(&relay), &cwd, env, now);
            if matches!(relayed, Decision::Allow { .. }) {
                outcome = relayed;
                base = Some(relay);
            }
        }
    }
    match outcome {
        Decision::Allow { remaining, used } => {
            if let Some(mut record) = base {
                record.commands = remaining;
                record.consumed.extend(used);
                let _ = write_atomic(&path, &record.render());
            }
            None
        }
        Decision::Deny(detail) => {
            let label = hits[0].kind.label();
            let reason = format!("{DENY_TEXT} (effect: {label}; {detail})");
            match mode {
                Mode::Enforce => Some(HookResponse::denied(
                    request.event_type.clone(),
                    CODE_REQUIRED,
                    reason,
                    "strong",
                )),
                Mode::Shadow => {
                    log_shadow(
                        dir,
                        json!({
                            "t": now,
                            "session": session,
                            "event": "PreToolUse",
                            "would_deny": true,
                            "class": label,
                            "command": truncate(command, 300),
                            "reason": detail,
                        }),
                    );
                    None
                }
                Mode::Off => None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

const LAST_MESSAGE_KEYS: [&str; 3] = [
    "last_assistant_message",
    "lastAssistantMessage",
    "lastAssistantText",
];

fn is_scratch_path(path: &str) -> bool {
    let lowered = path.replace('\\', "/").to_ascii_lowercase();
    [
        "/volumes/d/scratch",
        "d:/scratch",
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
    ]
    .iter()
    .any(|prefix| lowered.starts_with(prefix))
}

/// Whether the evidence ledger shows a successful Class A run after the last
/// edit (edits to scratch paths and, when `repo` is known, to other repos do
/// not count). Pure over the ledger text.
fn class_a_after_last_edit(ledger: &str, repo: Option<&str>) -> bool {
    let mut last_edit: Option<usize> = None;
    let mut last_class_a: Option<usize> = None;
    for (index, line) in ledger.lines().enumerate() {
        let Ok(Value::Object(row)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if row.contains_key("marker") {
            continue;
        }
        if row.get("edit").and_then(Value::as_bool) == Some(true) {
            let path = row.get("path").and_then(Value::as_str);
            let counts = match (path, repo) {
                (Some(path), _) if is_scratch_path(path) => false,
                (Some(path), Some(repo)) => path.starts_with(repo),
                _ => true,
            };
            if counts {
                last_edit = Some(index);
            }
            continue;
        }
        let failed = row.get("failed").and_then(Value::as_bool).unwrap_or(false);
        let exit_ok = row
            .get("exit")
            .and_then(Value::as_i64)
            .map_or(true, |code| code == 0);
        if failed || !exit_ok {
            continue;
        }
        let Some(command) = row.get("command").and_then(Value::as_str) else {
            continue;
        };
        if scan_command(command, 0).class_a {
            last_class_a = Some(index);
        }
    }
    match (last_class_a, last_edit) {
        (Some(class_a), Some(edit)) => class_a > edit,
        (Some(_), None) => true,
        _ => false,
    }
}

fn ledger_path(root: &Path, session: &str) -> PathBuf {
    root.join("evidence")
        .join(format!("{}.jsonl", safe_name(session)))
}

/// `None` when the ledger cannot be read (the caller does not flag).
fn ledger_class_a(root: &Path, session: &str, repo: Option<&str>) -> Option<bool> {
    let text = fs::read_to_string(ledger_path(root, session)).ok()?;
    Some(class_a_after_last_edit(&text, repo))
}

/// What a request block is missing. `class_a_in_ledger` is `None` when the
/// ledger could not be read; `head` is `None` when git could not answer.
fn request_problems(
    block: &Block,
    class_a_in_ledger: Option<bool>,
    head: Option<&str>,
) -> Vec<String> {
    let mut problems = Vec::new();
    if block.commands.is_empty() {
        problems.push("commands: the exact commands to approve, one per line".to_owned());
    }
    match (block.commit.as_deref(), head) {
        (None, _) => problems.push("commit: the commit these commands run on (HEAD)".to_owned()),
        (Some(commit), Some(head)) if !sha_matches(commit, head) => problems.push(format!(
            "commit: {commit} is not HEAD ({}); commit first, rerun Class A and cite HEAD",
            short(head)
        )),
        _ => {}
    }
    match block.class_a.as_deref() {
        Some(text) if cites_class_a(text) => {
            if class_a_in_ledger == Some(false) {
                problems.push(
                    "class-a: no successful Class A run (rightkit-gate check, rightkit-host-gate check or node scripts/preflight.mjs) appears in this chat's evidence ledger after your last edit; run it now"
                        .to_owned(),
                );
            }
        }
        _ => problems.push(
            "class-a: the Class A command (rightkit-gate check, rightkit-host-gate check or node scripts/preflight.mjs), its commit, scan count and pass or fail per scan"
                .to_owned(),
        ),
    }
    if !block.verdict.as_deref().is_some_and(verdict_is_will_pass) {
        problems.push(
            "verdict: will pass, with the evidence behind it (if you are not sure it will pass, go back, check everything, fix it and rerun Class A first)"
                .to_owned(),
        );
    }
    problems
}

fn request_reminder(problems: &[String]) -> String {
    format!(
        "Your APPROVAL REQUEST is incomplete. Missing:\n- {}\nSend it again as a fenced block:\nAPPROVAL REQUEST\nrepo: <absolute repo path>\ncommit: <HEAD sha>\nclass-a: <Class A command> -> exit 0, <n> scans, <failures named or none>\ncommands:\n  - <exact command>\nverdict: will pass - <evidence>",
        problems.join("\n- ")
    )
}

fn last_message(payload: &Map<String, Value>) -> Option<String> {
    str_field(payload, &LAST_MESSAGE_KEYS).or_else(|| {
        let transcript = str_field(payload, &["transcript_path", "transcriptPath"])?;
        let events = read_events(Path::new(&transcript), TAIL_BYTES, true)?;
        Some(last_assistant_text(&events, ""))
    })
}

fn stop_hook_active(payload: &Map<String, Value>) -> bool {
    ["stop_hook_active", "stopHookActive"]
        .iter()
        .any(|key| payload.get(*key).and_then(Value::as_bool) == Some(true))
}

/// Stop: a final message that holds an `APPROVAL REQUEST` block must cite a
/// Class A run from the evidence ledger and carry a `verdict: will pass` line.
/// Blocks once (never while `stop_hook_active`); shadow mode only logs.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK) {
        return None;
    }
    let mode = current_mode();
    if mode == Mode::Off {
        return None;
    }
    let dir = state_dir(STATE_FOLDER)?;
    let root = state_root()?;
    stop_check_in(&dir, &root, request, mode, &RealEnv, now_secs())
}

fn stop_check_in(
    dir: &Path,
    root: &Path,
    request: &HookRequest,
    mode: Mode,
    env: &dyn Env,
    now: u64,
) -> Option<HookResponse> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let payload = request.payload.as_object()?;
    if stop_hook_active(payload) {
        return None;
    }
    let message = last_message(payload)?;
    let block = find_blocks(&message, REQUEST_HEADER).pop()?;
    let session = session_id(payload)?;
    let cwd = payload_cwd(payload);
    let repo = match block.repo.as_deref() {
        Some(repo) => repo_of(env, repo),
        None => repo_of(env, &cwd),
    };
    let repo_known = (!repo.is_empty()).then_some(repo.as_str());
    let head = repo_known.and_then(|repo| env.head(Path::new(repo)));
    let class_a = ledger_class_a(root, &session, repo_known);
    let problems = request_problems(&block, class_a, head.as_deref());
    if problems.is_empty() {
        return None;
    }
    let marker = dir.join(format!("{}.blocked", safe_name(&session)));
    let digest = format!("{:016x}", fnv64(&message));
    if fs::read_to_string(&marker).is_ok_and(|seen| seen.trim() == digest) {
        return None;
    }
    match mode {
        Mode::Shadow => {
            log_shadow(
                dir,
                json!({
                    "t": now,
                    "session": session,
                    "event": "Stop",
                    "would_block": true,
                    "problems": problems,
                }),
            );
            None
        }
        Mode::Enforce => {
            let _ = write_atomic(&marker, digest.as_bytes());
            Some(HookResponse::denied(
                request.event_type.clone(),
                CODE_INCOMPLETE,
                request_reminder(&problems),
                "strong",
            ))
        }
        Mode::Off => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills_gate::kill_switch_names;
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-approvals-{tag}-{}-{}",
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

    #[derive(Default)]
    struct FakeEnv {
        tops: Vec<String>,
        heads: HashMap<String, String>,
        dirty: Vec<String>,
        ci: Vec<String>,
    }

    impl FakeEnv {
        fn with_repo(repo: &str, head: &str) -> Self {
            let mut env = FakeEnv::default();
            env.tops.push(repo.to_owned());
            env.heads.insert(repo.to_owned(), head.to_owned());
            env
        }
    }

    impl Env for FakeEnv {
        fn toplevel(&self, path: &Path) -> Option<PathBuf> {
            let text = path.to_string_lossy().into_owned();
            self.tops
                .iter()
                .filter(|top| text == **top || text.starts_with(&format!("{top}/")))
                .max_by_key(|top| top.len())
                .map(PathBuf::from)
        }

        fn head(&self, repo: &Path) -> Option<String> {
            self.heads
                .get(&repo.to_string_lossy().into_owned())
                .cloned()
        }

        fn tracked_dirty(&self, repo: &Path) -> Option<bool> {
            Some(self.dirty.iter().any(|dirty| Path::new(dirty) == repo))
        }

        fn push_triggers_ci(&self, repo: &Path) -> bool {
            self.ci.iter().any(|ci| Path::new(ci) == repo)
        }
    }

    const REPO: &str = "/Volumes/D/claude/legion";
    const HEAD: &str = "abc1234def5678abc1234def5678abc1234def56";

    fn request(event: &str, payload: Value) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: event.to_owned(),
            payload,
        }
    }

    fn bash(command: &str) -> HookRequest {
        request(
            "PreToolUse",
            json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "cwd": REPO,
                "tool_input": {"command": command},
            }),
        )
    }

    fn hit_texts(command: &str) -> Vec<String> {
        scan_command(command, 0)
            .hits
            .into_iter()
            .map(|hit| hit.text)
            .collect()
    }

    fn approval(commands: &[&str]) -> Approval {
        Approval {
            commands: commands.iter().map(|c| (*c).to_owned()).collect(),
            repo: REPO.to_owned(),
            head_sha: HEAD.to_owned(),
            granted_t: 1000,
            ..Approval::default()
        }
    }

    fn assistant_line(text: &str) -> String {
        json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}}).to_string()
    }

    fn user_line(text: &str) -> String {
        json!({"type": "user", "message": {"role": "user", "content": text}}).to_string()
    }

    const REQUEST_TEXT: &str = "Ready for approval.\n\n```\nAPPROVAL REQUEST\nrepo: /Volumes/D/claude/legion\ncommit: abc1234def5678\nclass-a: rightkit-gate check /Volumes/D/claude/legion -> exit 0, 14 scans, 0 failures\ncommands:\n  - rightkit-gate --to compile /Volumes/D/claude/legion\n  - cargo test -p legion-hook\nverdict: will pass - Class A is green on this commit\n```\n";

    // --- lexing and classification ---------------------------------------

    #[test]
    fn kill_switch_id_is_approvals() {
        assert!(kill_switch_names(Some("locks, approvals"), CHECK));
        assert!(!kill_switch_names(Some("approvals-x"), CHECK));
    }

    #[test]
    fn mode_defaults_to_shadow() {
        assert_eq!(mode_from(None), Mode::Shadow);
        assert_eq!(mode_from(Some("enforce")), Mode::Enforce);
        assert_eq!(mode_from(Some(" OFF ")), Mode::Off);
        assert_eq!(mode_from(Some("nonsense")), Mode::Shadow);
    }

    #[test]
    fn cargo_compile_commands_are_effects() {
        for command in [
            "cargo build",
            "cargo check -p legion-hook",
            "cargo test --workspace",
            "cargo clippy --all-targets",
            "cargo run -- --help",
            "cargo +nightly test",
            "RUST_LOG=debug cargo test",
            "rustright cargo test -p x",
            "time cargo check",
            "cargo t",
        ] {
            assert_eq!(hit_texts(command).len(), 1, "{command}");
        }
        for command in [
            "cargo fmt",
            "cargo metadata",
            "cargo +nightly fmt",
            "cargo tree",
        ] {
            assert!(hit_texts(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn hit_text_drops_wrappers_and_collapses_space() {
        assert_eq!(
            hit_texts("RUST_LOG=x   nice -n 5  cargo   test  -p  a"),
            vec!["cargo test -p a"]
        );
        assert_eq!(hit_texts("pnpm exec tsc -p ."), vec!["tsc -p ."]);
    }

    #[test]
    fn gate_check_is_class_a_and_never_an_effect() {
        for command in [
            "rightkit-gate check /Volumes/D/claude/legion",
            "rightkit-host-gate check .",
            "node scripts/preflight.mjs",
            "node ./scripts/preflight.mjs --quick",
            "node /x/rightkit-gate check /r",
        ] {
            let scan = scan_command(command, 0);
            assert!(scan.hits.is_empty(), "{command}");
            assert!(scan.class_a, "{command}");
        }
    }

    #[test]
    fn gate_targets_are_effects() {
        for target in ["compile", "package", "qualify", "release", "dev", "test"] {
            let command = format!("rightkit-gate --to {target} /r");
            assert_eq!(hit_texts(&command).len(), 1, "{command}");
        }
        assert_eq!(
            scan_command("rightkit-gate --to=compile /r", 0).hits.len(),
            1
        );
        assert!(hit_texts("rightkit-gate --to nowhere /r").is_empty());
        assert!(hit_texts("rightkit-gate status").is_empty());
        let dev = scan_command("rightkit-gate --to dev --install /r", 0).hits;
        assert_eq!(dev[0].kind, Kind::Install);
    }

    #[test]
    fn other_build_tools_follow_the_brief() {
        for command in [
            "xcodebuild -scheme App build",
            "swift build",
            "swift test",
            "tsc -p tsconfig.json",
            "pnpm build",
            "pnpm run test",
            "pnpm --filter app build",
            "pnpm -r build:web",
            "npx tsc",
        ] {
            assert_eq!(hit_texts(command).len(), 1, "{command}");
        }
        for command in [
            "xcodebuild -list",
            "xcodebuild -showBuildSettings",
            "tsc --noEmit",
            "tsc --version",
            "pnpm install",
            "pnpm add left-pad",
            "swift package resolve",
        ] {
            assert!(hit_texts(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn ci_publish_and_install_commands_are_effects() {
        let cases = [
            ("gh workflow run ci.yml", Kind::Ci),
            ("gh run rerun 123 --failed", Kind::Ci),
            ("gh release create v1 --notes x", Kind::Publish),
            ("gh release upload v1 a.zip", Kind::Publish),
            ("npm publish", Kind::Publish),
            ("pnpm publish --no-git-checks", Kind::Publish),
            ("cargo publish", Kind::Publish),
            ("wrangler deploy", Kind::Publish),
            ("npx wrangler pages deploy dist", Kind::Publish),
            ("right-release publish app", Kind::Publish),
            ("brew install jq", Kind::Install),
            ("legion setup repair", Kind::Install),
            ("cargo install --path .", Kind::Install),
            ("./install.sh", Kind::Install),
            ("bash scripts/install-legion.sh", Kind::Install),
            ("sudo installer -pkg App.pkg -target /", Kind::Install),
        ];
        for (command, kind) in cases {
            let hits = scan_command(command, 0).hits;
            assert_eq!(hits.len(), 1, "{command}");
            assert_eq!(hits[0].kind, kind, "{command}");
        }
        for command in [
            "gh pr view 5",
            "gh run watch 1",
            "gh release view v1",
            "wrangler whoami",
            "brew list",
            "install -m 755 a b",
            "legion setup status",
        ] {
            assert!(hit_texts(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn git_push_is_flagged_and_other_git_is_not() {
        let hits = scan_command("git push origin main", 0).hits;
        assert_eq!(hits.len(), 1);
        assert!(hits[0].push);
        assert!(scan_command("git -C /r push", 0).hits[0]
            .paths
            .contains(&"/r".to_owned()));
        assert!(hit_texts("git push --dry-run").is_empty());
        assert!(hit_texts("git commit -m 'cargo test'").is_empty());
        assert!(hit_texts("git status").is_empty());
    }

    #[test]
    fn commands_inside_text_are_not_effects() {
        assert!(hit_texts("echo cargo test").is_empty());
        assert!(hit_texts("grep -rn \"cargo build\" docs").is_empty());
        assert!(hit_texts("cat file # cargo test").is_empty());
        assert!(hit_texts("git commit -m \"run cargo test first\"").is_empty());
        let heredoc = "cat > /tmp/x <<'EOF'\ncargo test\nEOF\necho done";
        assert!(hit_texts(heredoc).is_empty());
        let commit = "git commit -m \"$(cat <<'EOF'\nfix: cargo test passes\nEOF\n)\"";
        assert!(hit_texts(commit).is_empty());
        assert!(hit_texts("cat <<< 'cargo test'").is_empty());
    }

    #[test]
    fn compound_and_nested_commands_are_scanned_in_full() {
        assert_eq!(hit_texts("cd /r && cargo build && cargo test").len(), 2);
        assert_eq!(hit_texts("echo hi; cargo check | tee out").len(), 1);
        assert_eq!(
            hit_texts("bash -c 'cargo test -p a'"),
            vec!["cargo test -p a"]
        );
        assert_eq!(
            hit_texts("sh -lc \"cd /r && cargo build\""),
            vec!["cargo build"]
        );
        assert_eq!(
            hit_texts("ssh mac \"cargo build -p x\""),
            vec!["cargo build -p x"]
        );
        assert_eq!(hit_texts("win \"cargo test\""), vec!["cargo test"]);
        assert_eq!(
            hit_texts("ssh -p 22 -i key mac cargo check"),
            vec!["cargo check"]
        );
        assert_eq!(hit_texts("echo $(cargo test)"), vec!["cargo test"]);
        assert_eq!(
            hit_texts("if cargo test; then echo ok; fi"),
            vec!["cargo test"]
        );
        assert_eq!(hit_texts("cargo test > out.txt 2>&1"), vec!["cargo test"]);
        assert_eq!(hit_texts("echo a && cargo test &"), vec!["cargo test"]);
        assert_eq!(hit_texts("xargs -n1 cargo test"), vec!["cargo test"]);
    }

    #[test]
    fn cd_sets_the_directory_of_later_hits() {
        let hits = scan_command("cd /Volumes/D/claude/legion && cargo test", 0).hits;
        assert_eq!(hits[0].dir.as_deref(), Some("/Volumes/D/claude/legion"));
        let inner = scan_command("bash -c 'cargo test'", 0).hits;
        assert_eq!(inner[0].dir, None);
        let relative = scan_command("cd a && cd b && cargo test", 0).hits;
        assert_eq!(relative[0].dir.as_deref(), Some("a/b"));
    }

    #[test]
    fn workflow_push_triggers_are_detected() {
        assert!(workflow_triggers_on_push(
            "name: CI\non: push\njobs:\n  a:\n"
        ));
        assert!(workflow_triggers_on_push("on: [push, pull_request]\n"));
        assert!(workflow_triggers_on_push(
            "name: x\non:\n  push:\n    branches: [main]\n  pull_request:\njobs: {}\n"
        ));
        assert!(workflow_triggers_on_push(
            "on:\n  - push\n  - workflow_dispatch\n"
        ));
        assert!(workflow_triggers_on_push("\"on\":\n  push: {}\n"));
        assert!(workflow_triggers_on_push(
            "on: { push: { branches: [main] } }\n"
        ));
        assert!(!workflow_triggers_on_push("on: workflow_dispatch\n"));
        assert!(!workflow_triggers_on_push(
            "on:\n  workflow_dispatch:\n  pull_request:\n    branches: [push]\n"
        ));
        assert!(!workflow_triggers_on_push(
            "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  a:\n    on: push\n"
        ));
        assert!(!workflow_triggers_on_push("name: nothing\n"));
    }

    #[test]
    fn push_needs_a_workflow_that_triggers_on_push() {
        let mut env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("git push", 0).hits;
        assert!(resolve_pushes(hits.clone(), REPO, &env).is_empty());
        env.ci.push(REPO.to_owned());
        assert_eq!(resolve_pushes(hits, REPO, &env).len(), 1);
        let gh = scan_command("gh workflow run ci.yml", 0).hits;
        assert_eq!(resolve_pushes(gh, "/elsewhere", &env).len(), 1);
    }

    // --- decision ---------------------------------------------------------

    #[test]
    fn covers_is_a_word_boundary_prefix() {
        assert!(covers("cargo test", "cargo test"));
        assert!(covers("cargo test", "cargo test -p x"));
        assert!(!covers("cargo test", "cargo testify"));
        assert!(!covers("cargo test -p x", "cargo test"));
        assert!(!covers("", "cargo test"));
    }

    #[test]
    fn no_approval_denies() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("cargo test", 0).hits;
        let decision = decide(&hits, None, REPO, &env, 2000);
        assert!(matches!(decision, Decision::Deny(reason) if reason.contains("no approval")));
    }

    #[test]
    fn approved_command_is_allowed_once() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("cargo test -p legion-hook", 0).hits;
        let record = approval(&["cargo test"]);
        let first = decide(&hits, Some(&record), REPO, &env, 2000);
        let Decision::Allow { remaining, used } = first else {
            panic!("expected allow");
        };
        assert!(remaining.is_empty());
        assert_eq!(used, vec!["cargo test"]);
        let spent = Approval {
            commands: remaining,
            ..record
        };
        let second = decide(&hits, Some(&spent), REPO, &env, 2000);
        assert!(matches!(second, Decision::Deny(_)));
    }

    #[test]
    fn run_counts_are_honoured() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let record = approval(&[
            "rightkit-gate --to compile /Volumes/D/claude/legion",
            "rightkit-gate --to package /Volumes/D/claude/legion",
        ]);
        let both = scan_command(
            "rightkit-gate --to compile /Volumes/D/claude/legion && rightkit-gate --to package /Volumes/D/claude/legion",
            0,
        )
        .hits;
        assert!(matches!(
            decide(&both, Some(&record), "/Volumes/D/claude", &env, 2000),
            Decision::Allow { .. }
        ));
        let twice = scan_command("cargo test && cargo test", 0).hits;
        let one = approval(&["cargo test"]);
        assert!(matches!(
            decide(&twice, Some(&one), REPO, &env, 2000),
            Decision::Deny(_)
        ));
        let two = approval(&["cargo test", "cargo test"]);
        assert!(matches!(
            decide(&twice, Some(&two), REPO, &env, 2000),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn unlisted_command_denies() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("cargo build", 0).hits;
        let record = approval(&["cargo test"]);
        assert!(matches!(
            decide(&hits, Some(&record), REPO, &env, 2000),
            Decision::Deny(reason) if reason.contains("not among the approved")
        ));
    }

    #[test]
    fn moved_head_and_dirty_tree_void_the_approval() {
        let mut env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("cargo test", 0).hits;
        let record = approval(&["cargo test"]);
        env.heads
            .insert(REPO.to_owned(), "ffffffffffffffffffff".to_owned());
        assert!(matches!(
            decide(&hits, Some(&record), REPO, &env, 2000),
            Decision::Deny(reason) if reason.contains("HEAD is")
        ));
        let mut dirty = FakeEnv::with_repo(REPO, HEAD);
        dirty.dirty.push(REPO.to_owned());
        assert!(matches!(
            decide(&hits, Some(&record), REPO, &dirty, 2000),
            Decision::Deny(reason) if reason.contains("uncommitted")
        ));
    }

    #[test]
    fn approval_is_bound_to_its_repo_and_nested_repos_are_separate() {
        let mut env = FakeEnv::with_repo(REPO, HEAD);
        env.tops.push("/Volumes/D/claude".to_owned());
        let record = approval(&["cargo test"]);
        let hits = scan_command("cargo test", 0).hits;
        assert!(matches!(
            decide(
                &hits,
                Some(&record),
                "/Volumes/D/claude/legion/engine",
                &env,
                2000
            ),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            decide(&hits, Some(&record), "/Volumes/D/claude", &env, 2000),
            Decision::Deny(reason) if reason.contains("approved repo")
        ));
        let by_path = scan_command("rightkit-gate --to compile /Volumes/D/claude/legion", 0).hits;
        let gate = approval(&["rightkit-gate --to compile"]);
        assert!(matches!(
            decide(&by_path, Some(&gate), "/Volumes/D/claude", &env, 2000),
            Decision::Allow { .. }
        ));
        let by_cd = scan_command("cd /Volumes/D/claude/legion && cargo test", 0).hits;
        assert!(matches!(
            decide(&by_cd, Some(&record), "/Volumes/D/claude", &env, 2000),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn old_approvals_expire() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let hits = scan_command("cargo test", 0).hits;
        let record = approval(&["cargo test"]);
        let late = 1000 + APPROVAL_TTL_SECS + 1;
        assert!(matches!(
            decide(&hits, Some(&record), REPO, &env, late),
            Decision::Deny(reason) if reason.contains("24 hours")
        ));
    }

    #[test]
    fn unknown_repo_or_head_fails_open() {
        let env = FakeEnv::default();
        let hits = scan_command("cargo test", 0).hits;
        let mut record = approval(&["cargo test"]);
        record.repo = String::new();
        assert!(matches!(
            decide(&hits, Some(&record), "/anywhere", &env, 2000),
            Decision::Allow { .. }
        ));
        let mut no_git = approval(&["cargo test"]);
        no_git.repo = "/anywhere".to_owned();
        assert!(matches!(
            decide(&hits, Some(&no_git), "/anywhere", &env, 2000),
            Decision::Allow { .. }
        ));
    }

    // --- blocks -----------------------------------------------------------

    #[test]
    fn request_block_parses() {
        let blocks = find_blocks(REQUEST_TEXT, REQUEST_HEADER);
        assert_eq!(blocks.len(), 1);
        let block = &blocks[0];
        assert_eq!(block.repo.as_deref(), Some(REPO));
        assert_eq!(block.commit.as_deref(), Some("abc1234def5678"));
        assert!(block.class_a.as_deref().unwrap_or("").contains("14 scans"));
        assert_eq!(
            block.commands,
            vec![
                "rightkit-gate --to compile /Volumes/D/claude/legion",
                "cargo test -p legion-hook"
            ]
        );
        assert!(verdict_is_will_pass(block.verdict.as_deref().unwrap_or("")));
        assert!(request_problems(block, Some(true), Some(HEAD)).is_empty());
    }

    #[test]
    fn unfenced_or_other_blocks_are_not_requests() {
        assert!(find_blocks(
            "APPROVAL REQUEST\ncommands:\n- cargo test\n",
            REQUEST_HEADER
        )
        .is_empty());
        assert!(find_blocks("```\nsome code\n```\n", REQUEST_HEADER).is_empty());
        assert!(find_blocks(
            "```\nAPPROVAL FROM RELAY\nchat: abcdef\n```",
            REQUEST_HEADER
        )
        .is_empty());
        let last =
            format!("{REQUEST_TEXT}\nLater:\n```\nAPPROVAL REQUEST\ncommands: cargo check\n```\n");
        let blocks = find_blocks(&last, REQUEST_HEADER);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].commands, vec!["cargo check"]);
    }

    #[test]
    fn class_a_may_follow_on_the_next_lines() {
        let text = "```text\nAPPROVAL REQUEST\ncommit: abc1234def\nclass-a:\n  rightkit-gate check /r\n  14 scans, 0 failures\ncommands:\n1. cargo test\n2. `cargo check`\nverdict: will pass.\n```";
        let block = find_blocks(text, REQUEST_HEADER).remove(0);
        assert!(cites_class_a(block.class_a.as_deref().unwrap_or("")));
        assert_eq!(block.commands, vec!["cargo test", "cargo check"]);
    }

    #[test]
    fn incomplete_requests_name_what_is_missing() {
        let text = "```\nAPPROVAL REQUEST\ncommands:\n  - cargo test\n```";
        let block = find_blocks(text, REQUEST_HEADER).remove(0);
        let problems = request_problems(&block, Some(true), Some(HEAD));
        assert!(problems.iter().any(|p| p.starts_with("commit:")));
        assert!(problems.iter().any(|p| p.starts_with("class-a:")));
        assert!(problems.iter().any(|p| p.starts_with("verdict:")));
        assert!(!problems.iter().any(|p| p.starts_with("commands:")));
    }

    #[test]
    fn verdict_must_say_will_pass() {
        for bad in ["probably", "will not pass", "95% likely", "should pass"] {
            assert!(!verdict_is_will_pass(bad), "{bad}");
        }
        assert!(verdict_is_will_pass("Will pass - Class A green"));
    }

    #[test]
    fn stale_commit_and_missing_ledger_run_are_problems() {
        let block = find_blocks(REQUEST_TEXT, REQUEST_HEADER).remove(0);
        let stale = request_problems(&block, Some(true), Some("1111111222222"));
        assert!(stale.iter().any(|p| p.contains("is not HEAD")));
        let no_run = request_problems(&block, Some(false), Some(HEAD));
        assert!(no_run.iter().any(|p| p.contains("evidence ledger")));
        assert!(request_problems(&block, None, None).is_empty());
    }

    // --- approval replies --------------------------------------------------

    #[test]
    fn plain_approvals_are_recognised() {
        for reply in [
            "approve",
            "Approved.",
            "yes",
            "Yes, go ahead",
            "go",
            "go ahead and run them",
            "ok",
            "yes please",
            "Approve compile and package",
        ] {
            assert!(is_approval_reply(reply), "{reply}");
        }
    }

    #[test]
    fn hedged_or_other_replies_are_not_approvals() {
        for reply in [
            "",
            "no",
            "don't go",
            "yes but only the compile",
            "wait",
            "go ahead?",
            "run it again",
            "what does it build",
            "approve everything except the push",
            "first fix the lint then go",
            "ship it to production tonight and tell the dell chat about it afterwards please",
        ] {
            assert!(!is_approval_reply(reply), "{reply}");
        }
    }

    // --- transcript and grant ----------------------------------------------

    #[test]
    fn last_assistant_text_stops_at_the_previous_prompt() {
        let events = vec![
            Ev::User {
                text: "old request".into(),
                genuine: true,
            },
            Ev::AssistantText("old block".into()),
            Ev::User {
                text: "build it".into(),
                genuine: true,
            },
            Ev::AssistantText("working".into()),
            Ev::ShellCall("cargo check".into()),
            Ev::ToolResult,
            Ev::AssistantText("the request".into()),
            Ev::User {
                text: "approve".into(),
                genuine: true,
            },
        ];
        assert_eq!(
            last_assistant_text(&events, "approve"),
            "working\n\nthe request"
        );
        assert_eq!(
            last_assistant_text(&events[..7], "approve"),
            "working\n\nthe request"
        );
    }

    #[test]
    fn claude_transcript_lines_become_events() {
        let tool_use = json!({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "running"},
            {"type": "tool_use", "name": "Bash", "input": {"command": "pulse chat said abcdef12"}},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "/x"}},
        ]}})
        .to_string();
        assert_eq!(
            events_of_line(&tool_use),
            vec![
                Ev::AssistantText("running".into()),
                Ev::ShellCall("pulse chat said abcdef12".into())
            ]
        );
        let result = json!({"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]}})
            .to_string();
        assert_eq!(events_of_line(&result), vec![Ev::ToolResult]);
        assert_eq!(
            events_of_line(&user_line("[Pulse Chat from x] go")),
            vec![Ev::User {
                text: "[Pulse Chat from x] go".into(),
                genuine: false
            }]
        );
        let meta =
            json!({"type": "user", "isMeta": true, "message": {"content": "note"}}).to_string();
        assert_eq!(
            events_of_line(&meta),
            vec![Ev::User {
                text: "note".into(),
                genuine: false
            }]
        );
        let sidechain =
            json!({"type": "assistant", "isSidechain": true, "message": {"content": "x"}})
                .to_string();
        assert!(events_of_line(&sidechain).is_empty());
        assert!(events_of_line("not json").is_empty());
    }

    #[test]
    fn approval_is_recorded_from_the_request_and_the_reply() {
        let scratch = TestDir::new("grant");
        let transcript = scratch.path().join("t.jsonl");
        fs::write(
            &transcript,
            format!(
                "{}\n{}\n{}\n",
                user_line("run the gate"),
                assistant_line(REQUEST_TEXT),
                user_line("approve")
            ),
        )
        .expect("write transcript");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let dir = scratch.path().join("approvals");
        let prompt = request(
            "UserPromptSubmit",
            json!({
                "session_id": "s1",
                "prompt": "approve",
                "cwd": "/Volumes/D/claude",
                "transcript_path": transcript.to_string_lossy(),
            }),
        );
        let response = on_user_prompt_in(&prompt, &dir, &env, 5000).expect("note");
        assert!(response
            .additional_context
            .as_deref()
            .unwrap_or("")
            .contains("Approval recorded"));
        let record = read_approval(&approval_file(&dir, "s1")).expect("record");
        assert_eq!(record.repo, REPO);
        assert_eq!(record.head_sha, HEAD);
        assert_eq!(record.granted_t, 5000);
        assert_eq!(
            record.commands,
            vec![
                "rightkit-gate --to compile /Volumes/D/claude/legion",
                "cargo test -p legion-hook"
            ]
        );
    }

    #[test]
    fn replies_that_do_not_approve_or_have_no_request_record_nothing() {
        let scratch = TestDir::new("nogrant");
        let transcript = scratch.path().join("t.jsonl");
        fs::write(
            &transcript,
            format!("{}\n{}\n", user_line("hi"), assistant_line("no block here")),
        )
        .expect("write transcript");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let dir = scratch.path().join("approvals");
        let make = |text: &str| {
            request(
                "UserPromptSubmit",
                json!({
                    "session_id": "s1",
                    "prompt": text,
                    "transcript_path": transcript.to_string_lossy(),
                }),
            )
        };
        assert!(on_user_prompt_in(&make("approve"), &dir, &env, 1).is_none());
        assert!(on_user_prompt_in(&make("yes but not the push"), &dir, &env, 1).is_none());
        assert!(on_user_prompt_in(&make("[Pulse Chat x] approve"), &dir, &env, 1).is_none());
        assert!(!approval_file(&dir, "s1").exists());
    }

    #[test]
    fn stale_request_commit_is_recorded_so_the_denial_is_specific() {
        let env = FakeEnv::with_repo(REPO, "9999999999999999");
        let block = find_blocks(REQUEST_TEXT, REQUEST_HEADER).remove(0);
        let record = build_approval(&block, REPO, &env, 5, "adrian").expect("approval");
        assert_eq!(record.head_sha, "abc1234def5678");
        let hits = scan_command("cargo test", 0).hits;
        assert!(matches!(
            decide(&hits, Some(&record), REPO, &env, 6),
            Decision::Deny(reason) if reason.contains("HEAD is")
        ));
    }

    // --- relay --------------------------------------------------------------

    fn relay_text(chat: &str) -> String {
        format!(
            "```\nAPPROVAL FROM RELAY\nchat: {chat}\nquote: \"go ahead with the compile\"\nrepo: {REPO}\ncommit: abc1234def5678\ncommands:\n  - cargo test\n```"
        )
    }

    #[test]
    fn relay_needs_a_pulse_read_before_the_block() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let events = vec![
            Ev::User {
                text: "[Pulse Chat from x] adrian said go".into(),
                genuine: false,
            },
            Ev::ShellCall("pulse chat said 7cb83f8b".into()),
            Ev::AssistantText(relay_text("7cb83f8b")),
        ];
        let relay = relay_from_events(&events, None, REPO, &env, 9).expect("relay");
        assert_eq!(relay.source, "relay");
        assert_eq!(relay.commands, vec!["cargo test"]);
        assert_eq!(relay.relay_keys.len(), 1);

        let no_read = vec![
            Ev::User {
                text: "[Pulse Chat from x] go".into(),
                genuine: false,
            },
            Ev::AssistantText(relay_text("7cb83f8b")),
        ];
        assert!(relay_from_events(&no_read, None, REPO, &env, 9).is_none());

        let wrong_chat = vec![
            Ev::ShellCall("pulse chat read 11111111".into()),
            Ev::AssistantText(relay_text("7cb83f8b")),
        ];
        assert!(relay_from_events(&wrong_chat, None, REPO, &env, 9).is_none());

        let read_after = vec![
            Ev::AssistantText(relay_text("7cb83f8b")),
            Ev::ShellCall("pulse chat said 7cb83f8b".into()),
        ];
        assert!(relay_from_events(&read_after, None, REPO, &env, 9).is_none());
    }

    #[test]
    fn relay_block_works_once_and_only_in_the_current_turn() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let events = vec![
            Ev::ShellCall("pulse chat said 7cb83f8b".into()),
            Ev::AssistantText(relay_text("7cb83f8b")),
        ];
        let first = relay_from_events(&events, None, REPO, &env, 9).expect("relay");
        assert!(relay_from_events(&events, Some(&first), REPO, &env, 9).is_none());
        let later_turn = vec![
            Ev::ShellCall("pulse chat said 7cb83f8b".into()),
            Ev::AssistantText(relay_text("7cb83f8b")),
            Ev::User {
                text: "next".into(),
                genuine: true,
            },
            Ev::AssistantText("nothing".into()),
        ];
        assert!(relay_from_events(&later_turn, None, REPO, &env, 9).is_none());
    }

    #[test]
    fn relay_without_a_quote_is_refused() {
        let env = FakeEnv::with_repo(REPO, HEAD);
        let text = "```\nAPPROVAL FROM RELAY\nchat: 7cb83f8b\ncommit: abc1234def5678\ncommands:\n  - cargo test\n```";
        let events = vec![
            Ev::ShellCall("pulse chat said 7cb83f8b".into()),
            Ev::AssistantText(text.into()),
        ];
        assert!(relay_from_events(&events, None, REPO, &env, 9).is_none());
    }

    // --- pre_tool end to end -------------------------------------------------

    #[test]
    fn enforce_denies_an_unapproved_effect_with_the_required_text() {
        let scratch = TestDir::new("enforce");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let response = pre_tool_in(
            &bash("cargo test"),
            "cargo test",
            scratch.path(),
            Mode::Enforce,
            &env,
            10,
        )
        .expect("denied");
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some(CODE_REQUIRED));
        assert!(response.reason.starts_with(DENY_TEXT));
    }

    #[test]
    fn shadow_logs_and_allows() {
        let scratch = TestDir::new("shadow");
        let env = FakeEnv::with_repo(REPO, HEAD);
        assert!(pre_tool_in(
            &bash("cargo test"),
            "cargo test",
            scratch.path(),
            Mode::Shadow,
            &env,
            10
        )
        .is_none());
        let log = fs::read_to_string(scratch.path().join(SHADOW_FILE)).expect("shadow log");
        assert!(log.contains("\"would_deny\":true"));
        assert!(log.contains("cargo test"));
    }

    #[test]
    fn approved_command_runs_once_then_is_denied() {
        let scratch = TestDir::new("once");
        let env = FakeEnv::with_repo(REPO, HEAD);
        write_atomic(
            &approval_file(scratch.path(), "s1"),
            &approval(&["cargo test"]).render(),
        )
        .expect("write approval");
        let run = || {
            pre_tool_in(
                &bash("cargo test -p x"),
                "cargo test -p x",
                scratch.path(),
                Mode::Enforce,
                &env,
                2000,
            )
        };
        assert!(run().is_none());
        let record = read_approval(&approval_file(scratch.path(), "s1")).expect("record");
        assert!(record.commands.is_empty());
        assert_eq!(record.consumed, vec!["cargo test"]);
        assert!(run().expect("second run denied").code.as_deref() == Some(CODE_REQUIRED));
    }

    #[test]
    fn class_a_and_plain_commands_are_never_gated() {
        let scratch = TestDir::new("free");
        let env = FakeEnv::with_repo(REPO, HEAD);
        for command in [
            "rightkit-gate check /Volumes/D/claude/legion",
            "node scripts/preflight.mjs",
            "git status",
            "git commit -m 'cargo test'",
            "ls && echo cargo build",
            "gh issue list",
        ] {
            let outcome = pre_tool_in(
                &bash(command),
                command,
                scratch.path(),
                Mode::Enforce,
                &env,
                10,
            );
            assert!(outcome.is_none(), "{command}");
        }
        let edit = request(
            "PreToolUse",
            json!({"session_id": "s1", "tool_name": "Edit", "tool_input": {"file_path": "/x"}}),
        );
        assert!(shell_command(edit.payload.as_object().expect("object")).is_none());
    }

    #[test]
    fn missing_session_or_unreadable_state_allows() {
        let scratch = TestDir::new("open");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let no_session = request(
            "PreToolUse",
            json!({"tool_name": "Bash", "tool_input": {"command": "cargo test"}}),
        );
        assert!(pre_tool_in(
            &no_session,
            "cargo test",
            scratch.path(),
            Mode::Enforce,
            &env,
            10
        )
        .is_none());
        let missing = pre_tool_in(
            &bash("cargo test"),
            "cargo test",
            scratch.path(),
            Mode::Enforce,
            &env,
            10,
        );
        assert_eq!(
            missing.expect("no file is no approval").code.as_deref(),
            Some(CODE_REQUIRED)
        );
        fs::write(approval_file(scratch.path(), "s1"), b"not json").expect("write junk");
        assert!(pre_tool_in(
            &bash("cargo test"),
            "cargo test",
            scratch.path(),
            Mode::Enforce,
            &env,
            10
        )
        .is_none());
    }

    #[test]
    fn relay_approval_lets_the_command_run_and_is_recorded() {
        let scratch = TestDir::new("relaypre");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let transcript = scratch.path().join("t.jsonl");
        let call = json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "pulse chat said 7cb83f8b"}}
        ]}})
        .to_string();
        fs::write(
            &transcript,
            format!(
                "{}\n{}\n{}\n",
                user_line("[Pulse Chat from heardright] adrian approved"),
                call,
                assistant_line(&relay_text("7cb83f8b"))
            ),
        )
        .expect("write transcript");
        let call = request(
            "PreToolUse",
            json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "cwd": REPO,
                "transcript_path": transcript.to_string_lossy(),
                "tool_input": {"command": "cargo test"},
            }),
        );
        let dir = scratch.path().join("approvals");
        assert!(pre_tool_in(&call, "cargo test", &dir, Mode::Enforce, &env, 2000).is_none());
        let record = read_approval(&approval_file(&dir, "s1")).expect("record");
        assert_eq!(record.source, "relay");
        assert_eq!(record.consumed, vec!["cargo test"]);
        let again = pre_tool_in(&call, "cargo test", &dir, Mode::Enforce, &env, 2001);
        assert_eq!(
            again.expect("replay denied").code.as_deref(),
            Some(CODE_REQUIRED)
        );
    }

    // --- Stop -----------------------------------------------------------------

    fn stop(message: &str, active: bool) -> HookRequest {
        request(
            "Stop",
            json!({
                "session_id": "s1",
                "cwd": REPO,
                "last_assistant_message": message,
                "stop_hook_active": active,
            }),
        )
    }

    fn write_ledger(root: &Path, lines: &[Value]) {
        let path = ledger_path(root, "s1");
        fs::create_dir_all(path.parent().expect("parent")).expect("create ledger dir");
        let text: Vec<String> = lines.iter().map(Value::to_string).collect();
        fs::write(path, text.join("\n")).expect("write ledger");
    }

    #[test]
    fn class_a_must_follow_the_last_edit() {
        let edit = json!({"tool": "Edit", "edit": true, "path": "/Volumes/D/claude/legion/a.rs", "failed": false});
        let run = json!({"tool": "Bash", "command": "rightkit-gate check /Volumes/D/claude/legion", "exit": 0, "failed": false, "edit": false});
        let red = json!({"tool": "Bash", "command": "rightkit-gate check /r", "exit": 1, "failed": true, "edit": false});
        let scratch_edit =
            json!({"tool": "Write", "edit": true, "path": "/Volumes/D/scratch/notes.md"});
        let other_repo =
            json!({"tool": "Edit", "edit": true, "path": "/Volumes/D/claude/heardright/x.rs"});
        let text = |rows: &[&Value]| {
            rows.iter()
                .map(|row| row.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(class_a_after_last_edit(&text(&[&edit, &run]), Some(REPO)));
        assert!(!class_a_after_last_edit(&text(&[&run, &edit]), Some(REPO)));
        assert!(!class_a_after_last_edit(&text(&[&edit, &red]), Some(REPO)));
        assert!(class_a_after_last_edit(
            &text(&[&edit, &run, &scratch_edit]),
            Some(REPO)
        ));
        assert!(class_a_after_last_edit(
            &text(&[&edit, &run, &other_repo]),
            Some(REPO)
        ));
        assert!(class_a_after_last_edit(&text(&[&run]), None));
        assert!(!class_a_after_last_edit("", None));
        let marker = json!({"marker": "turn", "id": "1", "prompt": "x"});
        assert!(class_a_after_last_edit(
            &text(&[&edit, &marker, &run]),
            Some(REPO)
        ));
    }

    #[test]
    fn complete_request_with_a_ledger_run_passes_the_stop_check() {
        let scratch = TestDir::new("stopok");
        let env = FakeEnv::with_repo(REPO, HEAD);
        write_ledger(
            scratch.path(),
            &[
                json!({"tool": "Edit", "edit": true, "path": "/Volumes/D/claude/legion/a.rs"}),
                json!({"tool": "Bash", "command": "rightkit-gate check /Volumes/D/claude/legion", "exit": 0, "failed": false}),
            ],
        );
        let dir = scratch.path().join("approvals");
        let outcome = stop_check_in(
            &dir,
            scratch.path(),
            &stop(REQUEST_TEXT, false),
            Mode::Enforce,
            &env,
            10,
        );
        assert!(outcome.is_none());
    }

    #[test]
    fn request_without_a_ledger_run_is_blocked_once() {
        let scratch = TestDir::new("stopblock");
        let env = FakeEnv::with_repo(REPO, HEAD);
        write_ledger(
            scratch.path(),
            &[json!({"tool": "Edit", "edit": true, "path": "/Volumes/D/claude/legion/a.rs"})],
        );
        let dir = scratch.path().join("approvals");
        let blocked = stop_check_in(
            &dir,
            scratch.path(),
            &stop(REQUEST_TEXT, false),
            Mode::Enforce,
            &env,
            10,
        )
        .expect("blocked");
        assert!(!blocked.allowed);
        assert_eq!(blocked.code.as_deref(), Some(CODE_INCOMPLETE));
        assert!(blocked.reason.contains("evidence ledger"));
        assert!(stop_check_in(
            &dir,
            scratch.path(),
            &stop(REQUEST_TEXT, false),
            Mode::Enforce,
            &env,
            11
        )
        .is_none());
        assert!(stop_check_in(
            &dir,
            scratch.path(),
            &stop(REQUEST_TEXT, true),
            Mode::Enforce,
            &env,
            12
        )
        .is_none());
    }

    #[test]
    fn missing_verdict_blocks_and_shadow_only_logs() {
        let scratch = TestDir::new("stopverdict");
        let env = FakeEnv::with_repo(REPO, HEAD);
        write_ledger(
            scratch.path(),
            &[
                json!({"tool": "Bash", "command": "rightkit-gate check /r", "exit": 0, "failed": false}),
            ],
        );
        let message = REQUEST_TEXT.replace("verdict: will pass", "verdict: probably fine");
        let dir = scratch.path().join("approvals");
        let shadow = stop_check_in(
            &dir,
            scratch.path(),
            &stop(&message, false),
            Mode::Shadow,
            &env,
            10,
        );
        assert!(shadow.is_none());
        let log = fs::read_to_string(dir.join(SHADOW_FILE)).expect("shadow log");
        assert!(log.contains("would_block"));
        assert!(log.contains("verdict:"));
        let blocked = stop_check_in(
            &dir,
            scratch.path(),
            &stop(&message, false),
            Mode::Enforce,
            &env,
            11,
        )
        .expect("blocked");
        assert!(blocked.reason.contains("verdict: will pass"));
    }

    #[test]
    fn messages_without_a_request_block_are_ignored_by_stop() {
        let scratch = TestDir::new("stopnone");
        let env = FakeEnv::with_repo(REPO, HEAD);
        let dir = scratch.path().join("approvals");
        let message = "Done. Nothing to approve.";
        assert!(stop_check_in(
            &dir,
            scratch.path(),
            &stop(message, false),
            Mode::Enforce,
            &env,
            10
        )
        .is_none());
        let other = request("PreToolUse", json!({"session_id": "s1"}));
        assert!(stop_check_in(&dir, scratch.path(), &other, Mode::Enforce, &env, 10).is_none());
    }
}
