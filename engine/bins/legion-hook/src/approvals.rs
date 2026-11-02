//! Effect gate with approvals bound to commits. Compile, build, test, CI, publish and install run
//! only under an approval Adrian gave in this chat for the exact commands, repo and commit.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, git, ledger, mode, now_secs, off, session_id, state_dir};
use crate::state::{str_field, tool_input, write_atomic, Mode, Payload};
use crate::transcript::{has_tool_command, human, last_assistant_text};

/// Effect classes and their commands. A command is its program and non-option arguments, with
/// `--to X` as `to:X`, `rustright cargo` as `cargo`, the host gate as the gate, and paths dropped.
static EFFECTS: [(&str, &str); 4] = [
    ("compile", "cargo build|cargo check|cargo test|cargo clippy|cargo run|rightkit-gate to:compile|rightkit-gate to:package|rightkit-gate to:qualify|rightkit-gate to:release|rightkit-gate to:test|xcodebuild build|swift build|pnpm build|pnpm test|pnpm run build|pnpm run test"),
    ("ci", "gh workflow run|gh run rerun"),
    ("publish", "gh release create|gh release upload|npm publish|pnpm publish|cargo publish|wrangler deploy|wrangler publish"),
    ("install", "legion setup repair|brew install|rightkit-gate to:dev"),
];
const TTL_SECS: u64 = 24 * 3600;
/// An effect command: its class, its normalized text, and the paths that say which repo it runs in.
type Hit = (&'static str, String, Vec<String>);
/// Effect commands with the repo each runs in.
type Resolved = Vec<(String, Option<String>)>;
type Decision = Result<Vec<String>, String>;

fn key(words: &[String]) -> String {
    let text = words
        .join(" ")
        .replace("--to ", "to:")
        .replace("--to=", "to:");
    let (mut parts, mut args) = (Vec::new(), text.split(' '));
    while let Some(word) = args.next() {
        if matches!(word, "-R" | "--repo" | "-C" | "-c" | "--filter" | "-F") {
            args.next();
        } else if parts.is_empty() || !word.starts_with(['-', '+', '/', '~']) {
            parts.push(word);
        }
    }
    let program = parts.first().map_or("", |first| crate::program_name(first));
    let program = program.replace("rightkit-host-gate", "rightkit-gate");
    let cargo = program == "rustright" && parts.get(1) == Some(&"cargo");
    let rest = parts.get(if cargo { 2.. } else { 1.. }).unwrap_or_default();
    let mut out = vec![if cargo { "cargo" } else { program.as_str() }];
    out.extend_from_slice(rest);
    out.join(" ")
}

/// Is `key` the approved command `entry`, with or without further arguments?
fn covers(entry: &str, key: &str) -> bool {
    key == entry || key.starts_with(&format!("{entry} "))
}

fn class_of(key: &str) -> Option<&'static str> {
    let class = EFFECTS
        .iter()
        .find(|(_, entries)| entries.split('|').any(|entry| covers(entry, key)));
    class
        .map(|(class, _)| *class)
        .or(key.starts_with("git push").then_some("ci"))
}

/// The effect commands in a shell command. `cd` moves where later commands run; absolute path
/// arguments (also `-C dir`) name the repo before the directory does.
fn hits(command: &str, cwd: &str, depth: u8) -> Vec<Hit> {
    let (mut found, mut dir) = (Vec::new(), cwd.to_owned());
    for segment in crate::command_segments(command) {
        let stripped = crate::strip_command_prefixes(&segment);
        let inner = crate::unwrap_shell_command(stripped);
        if depth < 2 && inner != stripped {
            found.extend(hits(inner, &dir, depth + 1));
            continue;
        }
        let words = crate::shell_words(stripped);
        if words.first().map(String::as_str) == Some("cd") {
            let next = words.get(1).map(|to| Path::new(&dir).join(to));
            dir = next.map_or(dir, |next| next.to_string_lossy().into_owned());
            continue;
        }
        let text = key(&words);
        let mut paths: Vec<String> = words
            .iter()
            .filter(|w| w.starts_with('/'))
            .cloned()
            .collect();
        paths.push(dir.clone());
        if let Some(class) = class_of(&text) {
            found.push((class, text, paths));
        }
    }
    found
}

/// The git toplevel of the first of these paths that is in a repo.
fn repo_of(paths: &[String]) -> Option<String> {
    paths.iter().find_map(|path| {
        let path = Path::new(path);
        let dir = if path.is_dir() { path } else { path.parent()? };
        Some(
            git(dir, &["rev-parse", "--show-toplevel"])?
                .trim()
                .to_owned(),
        )
    })
}

/// Whether a push to this repo starts a workflow (`on: push`).
fn push_starts_ci(repo: &str) -> bool {
    let files = fs::read_dir(Path::new(repo).join(".github/workflows"));
    let texts = files
        .into_iter()
        .flatten()
        .flatten()
        .map(|file| fs::read_to_string(file.path()));
    let on = |line: &str| {
        ["push:", "- push"].contains(&line.trim())
            || (line.starts_with("on:") && line.contains("push"))
    };
    texts.flatten().any(|text| text.lines().any(on))
}

/// The text of every fenced block in `text` whose first line is `header`, without that line.
fn blocks(text: &str, header: &str) -> Vec<String> {
    let (mut found, mut lines) = (Vec::new(), text.lines());
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```") {
            let body: Vec<&str> = lines
                .by_ref()
                .take_while(|line| !line.trim_start().starts_with("```"))
                .collect();
            if body
                .first()
                .is_some_and(|first| first.trim().eq_ignore_ascii_case(header))
            {
                found.push(body[1..].join("\n"));
            }
        }
    }
    found
}

/// The value of a `name: value` line of a block (empty when absent).
fn field(block: &str, name: &str) -> String {
    let prefix = format!("{name}:");
    let line = block
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()));
    line.map_or(String::new(), |value| {
        value.trim().trim_matches('`').to_owned()
    })
}

/// The commands of a block: the text after `commands:` on its line, and the bullet lines below it.
fn commands(block: &str) -> Vec<&str> {
    let (mut found, mut listing) = (Vec::new(), false);
    for line in block.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("commands:") {
            (listing, found) = (true, vec![rest]);
        } else if listing && line.starts_with(['-', '*']) {
            found.push(line[1..].trim());
        } else if !line.is_empty() {
            listing = false;
        }
    }
    let cleaned = found.into_iter().map(clean);
    cleaned.filter(|command| !command.is_empty()).collect()
}

/// A command as written in a block: without code ticks or a `$ ` prompt.
fn clean(command: &str) -> &str {
    command.trim().trim_matches('`').trim_start_matches("$ ")
}

/// Two commit ids (7+ hex chars) where one is a prefix of the other.
fn same_commit(a: &str, b: &str) -> bool {
    a.len().min(b.len()) >= 7 && (a.starts_with(b) || b.starts_with(a))
}

/// An approval from a request block: the commands it covers, the repo and the commit.
fn approval_from(block: &str, cwd: &str, now: u64) -> Option<Value> {
    let mut found: Vec<Hit> = Vec::new();
    for command in commands(block) {
        found.extend(hits(command, cwd, 0));
    }
    let repo = field(block, "repo");
    let repo = repo_of(&if repo.is_empty() {
        found.first()?.2.clone()
    } else {
        vec![repo]
    })?;
    let head = git(Path::new(&repo), &["rev-parse", "HEAD"]).map(|head| head.trim().to_owned());
    let commit = field(block, "commit");
    let sha = match head {
        Some(head) if commit.is_empty() || same_commit(&head, &commit) => head,
        _ => commit,
    };
    let keys: Vec<&String> = found.iter().map(|hit| &hit.1).collect();
    (!keys.is_empty())
        .then(|| json!({"commands": keys, "repo": repo, "head_sha": sha, "granted_t": now}))
}

/// Does the prompt approve (approve, approved, yes, go, go ahead) without doubts or questions?
fn is_approval(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    let tokens = lower.split(|c: char| !(c.is_alphanumeric() || c == '\''));
    let words: Vec<&str> = tokens.filter(|word| !word.is_empty()).collect();
    let doubts = "no not don't dont stop wait hold but however instead";
    let doubtful = words
        .iter()
        .any(|word| doubts.split(' ').any(|doubt| doubt == *word));
    let opens = matches!(
        words.first(),
        Some(&("approve" | "approved" | "yes" | "go"))
    );
    opens && words.len() <= 12 && !lower.contains('?') && !doubtful
}

fn approval_file(payload: &Payload) -> Option<PathBuf> {
    Some(state_dir("approvals")?.join(format!("{}.json", session_id(payload)?)))
}

/// Shadow mode logs a refusal and allows; enforce mode returns the denial.
fn refuse(request: &HookRequest, near: &Path, code: &str, reason: String) -> Option<HookResponse> {
    if mode("LEGION_APPROVALS_MODE") == Mode::Shadow {
        let row = json!({"t": now_secs(), "code": code, "reason": reason});
        append_line(&near.with_file_name("shadow.jsonl"), &row.to_string());
        return None;
    }
    Some(HookResponse::denied(
        request.event_type.clone(),
        code,
        reason,
        "strong",
    ))
}

/// UserPromptSubmit: Adrian's approving reply to a turn that ended in an `APPROVAL REQUEST` block
/// records the approval.
pub fn on_user_prompt(request: &HookRequest) -> Option<HookResponse> {
    if off("approvals") || mode("LEGION_APPROVALS_MODE") == Mode::Off {
        return None;
    }
    let payload = request.payload.as_object()?;
    let prompt = str_field(payload, &["prompt", "user_prompt", "userPrompt"])?;
    if !human(&prompt) || !is_approval(&prompt) {
        return None;
    }
    let last = last_assistant_text(&str_field(payload, &["transcript_path"])?)?;
    let block = blocks(&last, "APPROVAL REQUEST").pop()?;
    let cwd = str_field(payload, &["cwd", "workdir"]).unwrap_or_default();
    let note = |text: &str| {
        HookResponse::allowed(request.event_type.clone(), "approval note")
            .with_additional_context(text)
    };
    let Some(approval) = approval_from(&block, &cwd, now_secs()) else {
        return Some(note("Approval not recorded: the request lists no compile, build, test, CI, publish or install command."));
    };
    write_atomic(&approval_file(payload)?, approval.to_string().as_bytes())?;
    Some(note(&format!("Approval recorded for {} on commit {}. Each command runs once; any edit or new commit voids it.", approval["repo"], approval["head_sha"])))
}

/// What blocks `hits` under this approval, or the approved commands left after they run.
/// `facts` are HEAD of the approved repo, whether its tracked files are dirty, and the time.
fn decide(hits: &Resolved, approval: &Value, facts: (Option<&str>, bool, u64)) -> Decision {
    let (head, dirty, now) = facts;
    if now.saturating_sub(approval["granted_t"].as_u64().unwrap_or(0)) > TTL_SECS {
        return Err("the approval is more than 24 hours old".to_owned());
    }
    let mut pool: Vec<String> =
        serde_json::from_value(approval["commands"].clone()).unwrap_or_default();
    let want = approval["repo"].as_str();
    for (key, repo) in hits {
        let Some(index) = pool.iter().position(|approved| covers(approved, key)) else {
            return Err(format!("`{key}` is not among the approved commands"));
        };
        pool.remove(index);
        if repo.as_deref().is_some_and(|repo| Some(repo) != want) {
            return Err(format!("`{key}` does not run in the approved repo"));
        }
    }
    let sha = approval["head_sha"].as_str().unwrap_or("");
    if head.is_some_and(|head| !sha.is_empty() && !same_commit(head, sha)) {
        return Err("HEAD moved since the approval; any new commit voids it".to_owned());
    }
    if dirty {
        return Err("tracked files have uncommitted edits since the approval".to_owned());
    }
    Ok(pool)
}

/// An approval from an `APPROVAL FROM RELAY` block the agent wrote after reading the sender's chat
/// (`pulse chat said` or `pulse chat read` in the transcript); each block is used once.
fn relay_approval(payload: &Payload, cwd: &str, used: Option<&Value>) -> Option<Value> {
    let path = str_field(payload, &["transcript_path"])?;
    let read = ["pulse chat said", "pulse chat read"]
        .iter()
        .any(|needle| has_tool_command(&path, needle));
    let last = last_assistant_text(&path).filter(|_| read)?;
    if used.is_some_and(|approval| approval["relay"] == last.as_str()) {
        return None;
    }
    let block = blocks(&last, "APPROVAL FROM RELAY").pop()?;
    let mut approval = approval_from(&block, cwd, now_secs())?;
    approval["relay"] = json!(last);
    Some(approval)
}

/// PreToolUse of a shell tool: an effect command needs a live approval for it, its repo and HEAD.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if off("approvals") || mode("LEGION_APPROVALS_MODE") == Mode::Off || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let command = crate::command_text(tool_input(payload)?)?;
    let cwd = str_field(payload, &["cwd", "workdir"]).unwrap_or_default();
    let mut resolved: Resolved = Vec::new();
    for (_, key, paths) in hits(&command, &cwd, 0) {
        let repo = repo_of(&paths);
        if !key.starts_with("git push") || repo.as_deref().is_some_and(push_starts_ci) {
            resolved.push((key, repo));
        }
    }
    if resolved.is_empty() {
        return None;
    }
    let file = approval_file(payload)?;
    let text = fs::read_to_string(&file).unwrap_or_default();
    let mut base: Option<Value> = serde_json::from_str(&text).ok();
    if base.is_none() && !text.is_empty() {
        return None;
    }
    let now = now_secs();
    let attempt = |approval: &Value| {
        let repo = Path::new(approval["repo"].as_str().unwrap_or(""));
        let head = git(repo, &["rev-parse", "HEAD"]);
        let status = git(repo, &["status", "--porcelain", "--untracked-files=no"]);
        let dirty = status.is_some_and(|out| !out.trim().is_empty());
        let facts = (head.as_deref().map(str::trim), dirty, now);
        decide(&resolved, approval, facts)
    };
    let none: Decision = Err("no approval is on record in this chat".to_owned());
    let mut outcome = base.as_ref().map_or(none, attempt);
    if outcome.is_err() {
        let relay = relay_approval(payload, &cwd, base.as_ref());
        if let Some(Ok(left)) = relay.as_ref().map(attempt) {
            (outcome, base) = (Ok(left), relay);
        }
    }
    let detail = match outcome {
        Ok(left) => {
            let mut approval = base?;
            approval["commands"] = json!(left);
            write_atomic(&file, approval.to_string().as_bytes());
            return None;
        }
        Err(detail) => detail,
    };
    let reason = format!("Needs Adrian's approval: send an APPROVAL REQUEST (repo, commit, class-a, commands, verdict: will pass) and wait for his reply. ({detail})");
    refuse(request, &file, "ARC_APPROVAL_REQUIRED", reason)
}

/// Is there a successful Class A run in the ledger after the last edit (scratch edits excluded)?
fn class_a_after_edit(rows: &[Value]) -> bool {
    let tmp = |row: &Value| {
        row["path"]
            .as_str()
            .is_some_and(|path| path.contains("/scratch/") || path.starts_with("/tmp/"))
    };
    let edit = rows
        .iter()
        .rposition(|row| row["edit"] == true && !tmp(row));
    let passed = |row: &Value| {
        let command = row["command"].as_str().unwrap_or("");
        row["failed"] != true
            && (command.contains("gate check") || command.contains("preflight.mjs"))
    };
    rows[edit.map_or(0, |index| index + 1)..].iter().any(passed)
}

/// Stop: a final message with an `APPROVAL REQUEST` block needs every field, a Class A run after the
/// last edit and `verdict: will pass`. Sent back once; shadow mode only logs.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    let stop = matches!(request.event_type.as_str(), "Stop" | "stop");
    if off("approvals") || mode("LEGION_APPROVALS_MODE") == Mode::Off || !stop {
        return None;
    }
    let payload = request.payload.as_object()?;
    let message = str_field(payload, &["last_assistant_message", "lastAssistantText"])?;
    let block = blocks(&message, "APPROVAL REQUEST").pop()?;
    let verdict = field(&block, "verdict").to_lowercase();
    let will_pass = verdict.starts_with("will pass");
    let class_a = class_a_after_edit(&ledger(&session_id(payload)?));
    let problems = [
        (field(&block, "repo").is_empty(), "repo:"),
        (field(&block, "commit").is_empty(), "commit:"),
        (field(&block, "class-a").is_empty(), "class-a:"),
        (commands(&block).is_empty(), "commands:"),
        (
            !will_pass,
            "verdict: will pass (or check everything and fix it first)",
        ),
        (!class_a, "a successful Class A run after your last edit"),
    ];
    let missing: Vec<_> = problems.iter().filter(|(bad, _)| *bad).collect();
    let texts: Vec<&str> = missing.iter().map(|problem| problem.1).collect();
    let marker = approval_file(payload)?.with_extension("blocked");
    let seen = fs::read_to_string(&marker).is_ok_and(|text| text == message);
    if missing.is_empty() || seen || payload.get("stop_hook_active") == Some(&Value::Bool(true)) {
        return None;
    }
    write_atomic(&marker, message.as_bytes());
    let reason = format!("Your APPROVAL REQUEST is incomplete: {}", texts.join("; "));
    refuse(request, &marker, "ARC_APPROVAL_REQUEST_INCOMPLETE", reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "Ready.\n```\nAPPROVAL REQUEST\nrepo: /r/legion\ncommit: 0123abcd4567\nclass-a: rightkit-gate check /r/legion -> exit 0, 14 scans\ncommands:\n  - rightkit-gate --to compile /r/legion\n  - `cargo test -p legion-hook`\nverdict: will pass - Class A green\n```\n";

    fn effects(text: &str) -> Vec<(&'static str, String)> {
        hits(text, "/r/legion", 0)
            .into_iter()
            .map(|(class, key, _)| (class, key))
            .collect()
    }

    #[test]
    fn effect_commands_are_classified_and_class_a_is_never_gated() {
        assert_eq!(
            effects("rustright cargo test -p x"),
            [("compile", "cargo test x".to_owned())]
        );
        assert_eq!(
            effects("cd /r && rightkit-host-gate --to package /r/legion"),
            [("compile", "rightkit-gate to:package".to_owned())]
        );
        assert_eq!(
            effects("rightkit-gate --to=dev"),
            [("install", "rightkit-gate to:dev".to_owned())]
        );
        assert_eq!(
            effects("bash -c 'gh -R o/r workflow run ci.yml'"),
            [("ci", "gh workflow run ci.yml".to_owned())]
        );
        assert_eq!(
            effects("git -C /r push origin main"),
            [("ci", "git push origin main".to_owned())]
        );
        assert_eq!(effects("gh release create v1 && wrangler deploy").len(), 2);
        for free in [
            "rightkit-gate check /r",
            "rightkit-host-gate check",
            "node scripts/preflight.mjs",
            "cargo fmt",
            "git status",
        ] {
            assert!(effects(free).is_empty(), "{free}");
        }
    }

    #[test]
    fn a_request_block_is_parsed() {
        let block = blocks(REQUEST, "APPROVAL REQUEST").pop().unwrap();
        assert_eq!(
            (
                field(&block, "repo").as_str(),
                field(&block, "commit").as_str()
            ),
            ("/r/legion", "0123abcd4567")
        );
        assert_eq!(
            commands(&block),
            [
                "rightkit-gate --to compile /r/legion",
                "cargo test -p legion-hook"
            ]
        );
        assert!(
            field(&block, "verdict").starts_with("will pass")
                && field(&block, "class-a").contains("14 scans")
        );
        assert!(blocks(REQUEST, "APPROVAL FROM RELAY").is_empty());
    }

    #[test]
    fn only_a_plain_yes_approves() {
        for yes in ["yes", "Approved.", "go ahead", "yes, go"] {
            assert!(is_approval(yes), "{yes}");
        }
        for no in [
            "no",
            "yes but wait",
            "go ahead and also fix the docs first, then run everything again later",
            "should I go?",
            "fix it",
        ] {
            assert!(!is_approval(no), "{no}");
        }
    }

    fn approval() -> Value {
        json!({"commands": ["cargo test", "rightkit-gate to:package"], "repo": "/r", "head_sha": "0123abcd4567", "granted_t": 100})
    }

    fn run(keys: &[&str], head: &str, dirty: bool, now: u64) -> Decision {
        let hits: Resolved = keys
            .iter()
            .map(|key| (key.to_string(), Some("/r".to_owned())))
            .collect();
        decide(&hits, &approval(), (Some(head), dirty, now))
    }

    #[test]
    fn an_approval_covers_its_commands_once_for_its_commit() {
        assert_eq!(
            run(&["cargo test x"], "0123abcd4567ff", false, 200),
            Ok(vec!["rightkit-gate to:package".to_owned()])
        );
        assert!(run(&["cargo build"], "0123abcd4567", false, 200).is_err());
        assert!(run(&["cargo test"], "ffffffffffff", false, 200).is_err());
        assert!(run(&["cargo test"], "0123abcd4567", true, 200).is_err());
        assert!(run(&["cargo test"], "0123abcd4567", false, 100 + TTL_SECS + 1).is_err());
        assert!(run(&["cargo test", "cargo test"], "0123abcd4567", false, 200).is_err());
    }

    #[test]
    fn a_request_needs_class_a_after_the_last_edit() {
        let edit = json!({"tool": "Edit", "edit": true, "path": "/r/a.rs"});
        let check = json!({"tool": "Bash", "command": "rightkit-gate check /r", "failed": false});
        assert!(class_a_after_edit(&[edit.clone(), check.clone()]));
        assert!(!class_a_after_edit(&[check, edit]));
    }
}
