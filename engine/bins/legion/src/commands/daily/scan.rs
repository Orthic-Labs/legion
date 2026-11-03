//! Failures from Claude Code and Codex transcripts (read-only): a corrected agent turn, a hook
//! denial, a red build, CI run or install, an `UNRESOLVED:` line. Ported from the failure-review
//! `extract.py` and `markers.py`, with correction phrases instead of bare words. Codex
//! transcripts yield corrections and `UNRESOLVED:` lines only; their tool results are not read.
use super::{buckets, time};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

/// One failure: its fingerprint (`<bucket>/<cause>`), when, and one line of evidence.
pub struct Failure {
    pub fp: String,
    pub epoch: i64,
    pub text: String,
}

/// A user turn is a correction only when it holds one of these phrases or opens with an
/// opener. Profanity and a bare "no" or "stop" are not corrections.
#[rustfmt::skip]
const PHRASES: &[&str] = &[
    "i told you", "i said", "i asked you", "i already", "how many times", "not what i",
    "you were supposed", "supposed to", "instead of", "who told you", "without asking",
    "without my", "i never asked", "i never said", "i didn't ask", "you didn't", "you did not",
    "you ignored", "you forgot", "you lied", "you claimed", "that's wrong", "you're wrong",
    "this is wrong", "still not", "still wrong", "still broken", "why did you", "why are you",
    "why would you", "why didn't you", "why haven't you", "stop doing", "don't do that",
    "keep doing", "keep making", "again?", "wasting", "not true", "that's false",
];
#[rustfmt::skip]
const OPENERS: &[&str] = &["no,", "no.", "no!", "nope", "wrong", "that's not", "not what"];
/// Text the host injects as a "user" turn.
#[rustfmt::skip]
const INJECTED: &[&str] = &[
    "<command-", "<local-command", "<task-notification", "<system-reminder", "caveat:",
    "[system notification", "<side-sessions-event", "<ci-monitor-event", "[request interrupted",
    "<user-prompt-submit-hook", "this session is being continued", "[pulse chat",
    "<environment_context", "<user_instructions", "# agents.md", "<turn_aborted",
    "<subagent_notification",
];
#[rustfmt::skip]
const TOOLS: &[&str] = &[
    "cargo", "rustright", "rightkit-gate", "pnpm", "npm", "yarn", "npx", "cmake", "ninja",
    "xcodebuild", "gradle", "gradlew", "make",
];
#[rustfmt::skip]
const SECRETS: &[&str] = &["ghp_", "gho_", "github_pat_", "sk-", "xox", "AKIA", "eyJ"];
const CONFIRMATION: &str = "ARC_USER_CONFIRMATION_REQUIRED";

pub fn clip(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(max) {
        Some((end, _)) => format!("{}...", &flat[..end]),
        None => flat,
    }
}

/// A JSON string, or "" when the value is not one.
fn txt(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

/// Clip, masking token-like words first so a secret never reaches an issue.
pub fn safe(text: &str, max: usize) -> String {
    let key = |w: &str| w.len() > 12 && SECRETS.iter().any(|prefix| w.starts_with(prefix));
    let blob = |w: &str| w.len() >= 28 && !w.contains('/') && w.bytes().any(|b| b.is_ascii_digit());
    let words = text.split_whitespace().take(max);
    let words: Vec<&str> = words
        .map(|w| if key(w) || blob(w) { "[redacted]" } else { w })
        .collect();
    clip(&words.join(" "), max)
}

pub fn is_correction(text: &str) -> bool {
    let lower = text.trim().to_lowercase().replace('\u{2019}', "'");
    OPENERS.iter().any(|opener| lower.starts_with(opener))
        || PHRASES.iter().any(|phrase| buckets::has(&lower, phrase))
}

/// The build tool a shell command starts with, per segment (`grep cargo` is not a build).
pub fn build_tool(command: &str) -> Option<String> {
    command.split(['\n', ';', '|', '&']).find_map(|segment| {
        let mut words = segment.split_whitespace().filter(|w| !w.contains('='));
        let program = words.find(|w| !matches!(*w, "env" | "time" | "nohup"))?;
        let program = program.rsplit(['/', '\\']).next()?.trim_end_matches(".exe");
        let ci = program == "gh" && matches!(words.next(), Some("run" | "workflow"));
        (TOOLS.contains(&program) || ci).then(|| program.to_lowercase())
    })
}

/// `hook:<name>` for `[HOOK:<name>:block]`, else the first `ARC_*` code of a hook message
/// (a confirmation prompt is a question, not a denial).
pub fn denial_code(text: &str) -> Option<String> {
    let hook = text
        .split("[HOOK:")
        .nth(1)
        .and_then(|rest| rest.split_once(":block]"));
    if let Some((name, _)) = hook.filter(|(name, _)| !name.contains([' ', ']', '\n'])) {
        return Some(format!("hook:{name}"));
    }
    if !(text.to_lowercase().contains("hook") || text.trim_start().starts_with("ARC_")) {
        return None;
    }
    let end = |c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let mut codes = text
        .match_indices("ARC_")
        .filter_map(|(at, _)| text[at..].split(end).next());
    codes
        .find(|code| code.len() > 4 && *code != CONFIRMATION)
        .map(str::to_owned)
}

#[derive(Default)]
struct Scan<'a> {
    host: &'a str,
    session: String,
    agent: String,
    commands: HashMap<String, String>,
    out: Vec<Failure>,
}

impl Scan<'_> {
    /// One failure; `evidence` is its kind, what was said or run, and what it answers.
    fn add(&mut self, epoch: i64, bucket: &str, cause: &str, evidence: [&str; 3]) {
        let [kind, quote, context] = evidence;
        let after = if context.is_empty() {
            String::new()
        } else {
            format!(" after \"{}\"", safe(context, 120))
        };
        let (when, quote) = (time::stamp(epoch), safe(quote, 240));
        let text = format!(
            "{when} {} {kind} {} \"{quote}\"{after}",
            self.host, self.session
        );
        self.out.push(Failure {
            fp: format!("{bucket}/{cause}"),
            epoch,
            text,
        });
    }

    fn agent(&mut self, text: &str, epoch: i64) {
        if text.trim().is_empty() {
            return;
        }
        self.agent = clip(text, 260);
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("UNRESOLVED:"))
        {
            let (bucket, cause) = buckets::classify(line).unwrap_or(("B11", "unresolved"));
            self.add(epoch, bucket, cause, ["unresolved", line, ""]);
        }
    }

    fn user(&mut self, text: &str, epoch: i64) {
        let head = text.trim_start().to_lowercase();
        let injected =
            head.is_empty() || head.len() > 3000 || INJECTED.iter().any(|p| head.starts_with(p));
        if injected || !is_correction(text) {
            return;
        }
        let class = buckets::classify(text).or_else(|| buckets::classify(&self.agent));
        let (bucket, cause) = class.unwrap_or(("B11", "unclassified"));
        let context = self.agent.clone();
        self.add(epoch, bucket, cause, ["correction", text, &context]);
    }

    fn denial(&mut self, epoch: i64, id: &str, text: &str) -> bool {
        let Some(code) = denial_code(text) else {
            return false;
        };
        let slug = code.to_lowercase().replace(['_', ':'], "-");
        let bucket = buckets::classify(&slug.replace('-', " ")).map_or("B10", |class| class.0);
        let command = self.commands.get(id).cloned().unwrap_or_default();
        self.add(epoch, bucket, &slug, ["hook denial", text, &command]);
        true
    }

    /// Only a failed tool result can be a denial or a red build.
    fn result(&mut self, epoch: i64, id: &str, text: &str, failed: bool) {
        if !failed || self.denial(epoch, id, text) {
            return;
        }
        let command = self.commands.get(id).cloned().unwrap_or_default();
        if let Some(tool) = build_tool(&command) {
            let start = text.char_indices().rev().nth(199).map_or(0, |(at, _)| at);
            let tail = &text[start..];
            self.add(
                epoch,
                "B3",
                &format!("red-{tool}"),
                ["red build", &command, tail],
            );
        }
    }

    fn claude(&mut self, line: &Value, epoch: i64) {
        let (kind, content) = (txt(&line["type"]), &line["message"]["content"]);
        // Stop hooks also carry peer messages; only a coded denial counts.
        let blocked = txt(&line["attachment"]["blockingError"]["blockingError"]);
        if blocked.starts_with("ARC_") || blocked.contains("[HOOK:") {
            self.denial(epoch, txt(&line["attachment"]["toolUseID"]), blocked);
        }
        let human = kind == "user" && line["isMeta"] != true && line["isSidechain"] != true;
        let human = human && ["", "human"].contains(&txt(&line["origin"]["kind"]));
        // A bare string is a single text block.
        let blocks = content
            .as_array()
            .map_or(std::slice::from_ref(content), Vec::as_slice);
        for item in blocks {
            let id = format!("{}{}", txt(&item["id"]), txt(&item["tool_use_id"]));
            match txt(&item["type"]) {
                "tool_use" if item["name"] == "Bash" => {
                    self.commands
                        .insert(id, txt(&item["input"]["command"]).to_owned());
                }
                "tool_result" => {
                    let text = match &item["content"] {
                        Value::Array(parts) => parts
                            .iter()
                            .map(|part| txt(&part["text"]))
                            .collect::<String>(),
                        other => txt(other).to_owned(),
                    };
                    self.result(epoch, &id, &text, item["is_error"] == true);
                }
                _ => {
                    let text = txt(item).to_owned() + txt(&item["text"]);
                    match (text.is_empty(), kind) {
                        (true, _) => {}
                        (false, "assistant") => self.agent(&text, epoch),
                        (false, _) if human => self.user(&text, epoch),
                        (false, _) => {}
                    }
                }
            }
        }
    }

    fn codex(&mut self, line: &Value, epoch: i64) {
        let payload = &line["payload"];
        if line["type"] != "response_item" || payload["type"] != "message" {
            return;
        }
        let parts = payload["content"].as_array().into_iter().flatten();
        let text: Vec<&str> = parts.map(|part| txt(&part["text"])).collect();
        let text = text.join(" ");
        match txt(&payload["role"]) {
            "user" if !text.contains("[Pulse Chat") => self.user(&text, epoch),
            "assistant" => self.agent(&text, epoch),
            _ => {}
        }
    }
}

/// The timestamp of a transcript line, read without parsing the whole line.
fn epoch_of(line: &str) -> Option<i64> {
    let rest = line.split("\"timestamp\":\"").nth(1)?;
    time::parse(rest.split('"').next()?)
}

fn scan_file(path: &Path, host: &str, codex: bool, window: (i64, i64)) -> Vec<Failure> {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let session: String = stem.chars().take(8).collect();
    let mut scan = Scan {
        host,
        session,
        ..Scan::default()
    };
    let Ok(file) = fs::File::open(path) else {
        return scan.out;
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let epoch = epoch_of(&line).filter(|at| (window.0..=window.1).contains(at));
        let Some(epoch) = epoch else { continue };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if codex {
            scan.codex(&value, epoch)
        } else {
            scan.claude(&value, epoch)
        }
    }
    scan.out
}

/// `*.jsonl` files modified since `since`, down to `depth` directory levels.
pub fn files(dir: &Path, depth: usize, since: i64, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() && depth > 1 {
            files(&entry.path(), depth - 1, since, out);
        } else if entry.path().extension().is_some_and(|ext| ext == "jsonl")
            && time::modified(&meta) >= since
        {
            out.push(entry.path());
        }
    }
}

/// Scan one host's transcripts: `files` is Claude Code's, then Codex's.
pub fn scan(host: &str, files: &[Vec<PathBuf>; 2], window: (i64, i64)) -> Vec<Failure> {
    let mut found = Vec::new();
    for (index, paths) in files.iter().enumerate() {
        for path in paths {
            found.extend(scan_file(path, host, index == 1, window));
        }
    }
    found
}
