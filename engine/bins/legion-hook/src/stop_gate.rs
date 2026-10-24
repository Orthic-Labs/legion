//! Stop gate: a turn that changed the repository may not end on a claim of
//! completion unless the turn's own tool output carries objective evidence
//! that postdates the last change.
//!
//! Evidence is read from the transcript's tool results, never from the
//! assistant's wording. Exactly three kinds count:
//!
//! * a green line of the repository gate (`right-release check`,
//!   `rightkit-gate check`, or, until `rightkit-gate check` ships,
//!   `node scripts/preflight.mjs`) that the gate command itself printed, for
//!   the current HEAD;
//! * a CI run URL together with the current HEAD and a success marker, in a
//!   tool result (for example `gh run view`);
//! * a host receipt block: a JSON object with an id, a verification command
//!   and exit code 0.
//!
//! A turn that made no repository change is never held (conversation, review,
//! read-only questions), and a message that says plainly that completion is
//! not verified is not a claim of completion. The gate fails open when it
//! cannot read the transcript format, and re-opens a turn at most
//! `MAX_STOP_REOPENINGS` times.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::{Map, Value};

use crate::{
    first_string, process::bounded_output, protocol::HookRequest, protocol::HookResponse,
    repository_root_from_payload, revision_for_workspace, session_marker, vcs_gate, EDIT_TOOLS,
    MAX_STOP_REOPENINGS, MAX_TRANSCRIPT_BYTES,
};

pub(crate) const MISSING_CODE: &str = "ARC_COMPLETION_EVIDENCE_MISSING";

const SHELL_TOOLS: [&str; 4] = ["Bash", "PowerShell", "shell", "shell_command"];

/// Git subcommands that move HEAD or rewrite the tree, so evidence gathered
/// before them says nothing about what exists now. `add`, `push`, `fetch`,
/// `status` and `log` change neither.
const CHANGING_SUBCOMMANDS: [&str; 14] = [
    "commit",
    "merge",
    "rebase",
    "am",
    "apply",
    "cherry-pick",
    "revert",
    "reset",
    "pull",
    "restore",
    "checkout",
    "switch",
    "stash",
    "clean",
];

/// Phrases that mean the author is not claiming completion.
const NOT_A_CLAIM: [&str; 24] = [
    "not done",
    "not complete",
    "not finished",
    "incomplete",
    "not verified",
    "unverified",
    "cannot verify",
    "can't verify",
    "could not verify",
    "couldn't verify",
    "did not run",
    "didn't run",
    "not run",
    "haven't run",
    "have not run",
    "blocked",
    "unable to",
    "not able to",
    "partial",
    "work in progress",
    "wip",
    "still failing",
    "not fixed",
    "no evidence",
];

/// Words that claim the work is finished.
const CLAIM_WORDS: [&str; 17] = [
    "done",
    "complete",
    "completed",
    "finished",
    "fixed",
    "implemented",
    "shipped",
    "delivered",
    "ready",
    "resolved",
    "merged",
    "pushed",
    "committed",
    "passing",
    "passes",
    "passed",
    "works",
];

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Evidence {
    Gate,
    Ci,
    Receipt,
}

#[derive(Debug)]
pub(crate) struct Turn {
    /// The transcript shows the turn editing files or moving HEAD.
    pub changed: bool,
    /// Objective evidence that follows the last change, if any.
    pub evidence: Option<Evidence>,
}

pub(crate) fn claims_completion(message: &str) -> bool {
    let lowered = message.to_lowercase();
    if NOT_A_CLAIM.iter().any(|phrase| lowered.contains(phrase)) {
        return false;
    }
    lowered
        .split(|character: char| !character.is_alphanumeric())
        .any(|word| CLAIM_WORDS.contains(&word))
}

// ---------------------------------------------------------------------------
// Transcript analysis
// ---------------------------------------------------------------------------

enum Event {
    Change,
    Result {
        command: Option<String>,
        is_error: bool,
        text: String,
    },
}

/// Analyse the current turn of a Claude-shaped transcript. `None` when the
/// text is not a transcript this gate understands.
pub(crate) fn analyze_turn(transcript: &str, head: Option<&str>) -> Option<Turn> {
    let lines: Vec<Value> = transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line.get("isSidechain").and_then(Value::as_bool) != Some(true))
        .filter(|line| {
            matches!(
                line.get("type").and_then(Value::as_str),
                Some("assistant" | "user")
            ) && line.get("message").is_some_and(Value::is_object)
        })
        .collect();
    if lines.is_empty() {
        return None;
    }
    let turn_start = lines
        .iter()
        .rposition(is_user_prompt)
        .map_or(0, |index| index + 1);

    let mut commands: std::collections::HashMap<String, String> = Default::default();
    let mut events = Vec::new();
    for line in &lines[turn_start..] {
        let Some(blocks) = line["message"]["content"].as_array() else {
            continue;
        };
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("tool_use") => {
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    let input = block.get("input").and_then(Value::as_object);
                    let command = input
                        .and_then(|input| input.get("command"))
                        .and_then(Value::as_str);
                    if let (Some(id), Some(command)) =
                        (block.get("id").and_then(Value::as_str), command)
                    {
                        commands.insert(id.to_owned(), command.to_owned());
                    }
                    let edits = EDIT_TOOLS.contains(&name);
                    let moves_head = SHELL_TOOLS.contains(&name)
                        && command.is_some_and(command_changes_repository);
                    if edits || moves_head {
                        events.push(Event::Change);
                    }
                }
                Some("tool_result") => {
                    let id = block.get("tool_use_id").and_then(Value::as_str);
                    events.push(Event::Result {
                        command: id.and_then(|id| commands.get(id).cloned()),
                        is_error: block.get("is_error").and_then(Value::as_bool) == Some(true),
                        text: result_text(block.get("content")),
                    });
                }
                _ => {}
            }
        }
    }

    let last_change = events
        .iter()
        .rposition(|event| matches!(event, Event::Change));
    let after = match last_change {
        Some(index) => &events[index + 1..],
        None => &events[..],
    };
    let evidence = after.iter().find_map(|event| match event {
        Event::Result {
            command,
            is_error: false,
            text,
        } => evidence_in(command.as_deref(), text, head),
        _ => None,
    });
    Some(Turn {
        changed: last_change.is_some(),
        evidence,
    })
}

/// A real prompt from the person: a user line that is not a tool result and
/// not host-injected.
fn is_user_prompt(line: &Value) -> bool {
    if line.get("type").and_then(Value::as_str) != Some("user")
        || line.get("isMeta").and_then(Value::as_bool) == Some(true)
    {
        return false;
    }
    match &line["message"]["content"] {
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(blocks) => {
            !blocks
                .iter()
                .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
                && blocks
                    .iter()
                    .any(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        }
        _ => false,
    }
}

fn result_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn command_changes_repository(command: &str) -> bool {
    vcs_gate::git_subcommands(command)
        .iter()
        .any(|subcommand| CHANGING_SUBCOMMANDS.contains(&subcommand.as_str()))
}

fn evidence_in(command: Option<&str>, text: &str, head: Option<&str>) -> Option<Evidence> {
    if command.is_some_and(is_gate_command) && gate_line_is_green(text, head) {
        return Some(Evidence::Gate);
    }
    if has_receipt_block(text) {
        return Some(Evidence::Receipt);
    }
    if ci_run_on_head(text, head) {
        return Some(Evidence::Ci);
    }
    None
}

// -- gate ------------------------------------------------------------------

const GATE_PROGRAMS: [&str; 2] = ["right-release", "rightkit-gate"];
const RUNNERS: [&str; 7] = ["pnpm", "npx", "npm", "yarn", "node", "corepack", "bunx"];

/// The gate that exists on RightKit main today: `scripts/preflight.mjs` (stem
/// `preflight`) prints the same `preflight: <sha> passed <n> rules` line but
/// takes no `check` subcommand. Transitional: `rightkit-gate check` replaces it
/// when `@rightkit/release` 0.6.5 ships, and the three spellings stay
/// recognised until then.
const TRANSITIONAL_GATE_SCRIPT: &str = "scripts/preflight.mjs";

fn stem(word: &str) -> String {
    let name = crate::program_name(word).to_ascii_lowercase();
    for extension in [".mjs", ".cjs", ".js"] {
        if let Some(stripped) = name.strip_suffix(extension) {
            return stripped.to_owned();
        }
    }
    name
}

/// `scripts/preflight.mjs`, run from any directory or checkout.
fn is_transitional_gate_script(word: &str) -> bool {
    let normalized = word.replace('\\', "/").to_ascii_lowercase();
    normalized == TRANSITIONAL_GATE_SCRIPT
        || normalized.ends_with(&format!("/{TRANSITIONAL_GATE_SCRIPT}"))
}

/// Does this command line run the repository gate's `check`?
pub(crate) fn is_gate_command(command: &str) -> bool {
    vcs_gate::command_words(command).iter().any(|words| {
        let Some(first) = words.first() else {
            return false;
        };
        if is_transitional_gate_script(first)
            || (RUNNERS.contains(&stem(first).as_str())
                && words
                    .iter()
                    .skip(1)
                    .any(|word| is_transitional_gate_script(word)))
        {
            return true;
        }
        let first = stem(first);
        let program_at = if GATE_PROGRAMS.contains(&first.as_str()) {
            Some(0)
        } else if RUNNERS.contains(&first.as_str()) {
            words
                .iter()
                .position(|word| GATE_PROGRAMS.contains(&stem(word).as_str()))
        } else {
            None
        };
        program_at.is_some_and(|index| {
            words[index + 1..]
                .iter()
                .find(|word| !word.starts_with('-'))
                .is_some_and(|word| word == "check")
        })
    })
}

/// A line like `check: 66c9ddd4d704 passed 12 rules in 6.2s`, naming a commit
/// that is the current HEAD (or any commit when HEAD is unknown).
fn gate_line_is_green(text: &str, head: Option<&str>) -> bool {
    text.lines().any(|line| {
        let lowered = line.trim().to_ascii_lowercase();
        let Some((label, rest)) = lowered.split_once(':') else {
            return false;
        };
        if !["check", "preflight", "rightkit-gate", "right-release"]
            .iter()
            .any(|name| label.trim() == *name || label.trim().starts_with(&format!("{name} ")))
        {
            return false;
        }
        let words: Vec<&str> = rest.split_whitespace().collect();
        let [sha, "passed", count, rules, ..] = words.as_slice() else {
            return false;
        };
        (7..=64).contains(&sha.len())
            && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
            && count.bytes().all(|byte| byte.is_ascii_digit())
            && rules.starts_with("rule")
            && head.is_none_or(|head| head.starts_with(sha))
    })
}

// -- CI --------------------------------------------------------------------

fn ci_run_on_head(text: &str, head: Option<&str>) -> bool {
    let Some(head) = head else {
        return false;
    };
    let lowered = text.to_lowercase();
    let has_run_url = lowered
        .match_indices("/actions/runs/")
        .any(|(index, marker)| {
            lowered[index + marker.len()..]
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_digit())
        });
    if !has_run_url {
        return false;
    }
    let cites_head = lowered
        .split(|character: char| !character.is_ascii_hexdigit())
        .any(|token| token.len() >= 7 && head.starts_with(token));
    let green = lowered.contains("success") || lowered.contains('✓');
    let red = [
        "failure",
        "cancelled",
        "timed_out",
        "startup_failure",
        "in_progress",
        "queued",
        "✗",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));
    cites_head && green && !red
}

// -- host receipt ----------------------------------------------------------

const MAX_RECEIPT_SCAN: usize = 64;

fn has_receipt_block(text: &str) -> bool {
    text.match_indices('{')
        .take(MAX_RECEIPT_SCAN)
        .any(|(index, _)| {
            matches!(
                serde_json::Deserializer::from_str(&text[index..])
                    .into_iter::<Value>()
                    .next(),
                Some(Ok(Value::Object(ref object))) if is_receipt(object)
            )
        })
}

/// `{"id": ..., "command": "cargo test ...", "exitCode": 0}` and its
/// snake_case twin: a terminal receipt of a verifying command.
fn is_receipt(object: &Map<String, Value>) -> bool {
    let has_id = ["id", "requestId", "request_id"].iter().any(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    });
    let exit_zero = ["exitCode", "exit_code"]
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_i64) == Some(0));
    let verifying = object
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_lowercase)
        .is_some_and(|command| {
            ["check", "test", "build", "clippy", "nextest"]
                .iter()
                .any(|verb| command.contains(verb))
        });
    has_id && exit_zero && verifying
}

// ---------------------------------------------------------------------------
// Turn baseline (git status at prompt time)
// ---------------------------------------------------------------------------

fn snapshot(root: &Path) -> Option<String> {
    let git = |arguments: &[&str]| {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(root)
            .args(arguments)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C");
        bounded_output(command, Duration::from_secs(4)).ok()
    };
    let status = git(&["status", "--porcelain=v1", "-z", "--untracked-files=normal"])?;
    if status.code != Some(0) {
        return None;
    }
    let head = revision_for_workspace(root).unwrap_or_else(|| "none".into());
    let digest =
        legion_contracts::canonical_digest(&String::from_utf8_lossy(&status.stdout).into_owned())
            .ok()?;
    Some(format!("{head}\n{digest}\n"))
}

/// UserPromptSubmit: remember HEAD and the working-tree state the turn
/// started from, so Stop can tell a conversational turn from one that changed
/// files through a shell. Observation only; failure changes nothing.
pub(crate) fn record_turn_baseline(request: &HookRequest) {
    let Some(object) = request.payload.as_object() else {
        return;
    };
    let (Some(root), Some(path)) = (
        repository_root_from_payload(object),
        session_marker(&request.payload, "turn-baseline"),
    ) else {
        return;
    };
    if let Some(snapshot) = snapshot(&root) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, snapshot);
    }
}

fn baseline_differs(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let (Some(root), Some(path)) = (
        repository_root_from_payload(object),
        session_marker(payload, "turn-baseline"),
    ) else {
        return false;
    };
    let Ok(before) = fs::read_to_string(path) else {
        return false;
    };
    snapshot(&root).is_some_and(|now| now != before)
}

// ---------------------------------------------------------------------------
// The Stop decision
// ---------------------------------------------------------------------------

fn read_transcript_tail(path: &str) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let truncated = length > MAX_TRANSCRIPT_BYTES;
    if truncated {
        io::Seek::seek(
            &mut file,
            io::SeekFrom::Start(length - MAX_TRANSCRIPT_BYTES),
        )
        .ok()?;
    }
    let mut bytes = Vec::new();
    Read::take(file, MAX_TRANSCRIPT_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // A cut window starts mid-line; drop that partial line.
    Some(if truncated {
        text.split_once('\n')
            .map_or_else(String::new, |(_, rest)| rest.to_owned())
    } else {
        text
    })
}

fn read_count(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// `Some(denial)` when this Stop must be held for missing evidence.
pub(crate) fn completion_evidence_response(request: &HookRequest) -> Option<HookResponse> {
    let object = request.payload.as_object()?;
    let message = first_string(object, &["last_assistant_message", "lastAssistantText"])?;
    let counter: Option<PathBuf> = session_marker(&request.payload, "evidence-denials");
    let clear = |counter: &Option<PathBuf>| {
        if let Some(path) = counter {
            let _ = fs::remove_file(path);
        }
    };

    let path = first_string(object, &["transcript_path", "transcriptPath"])?;
    let head = repository_root_from_payload(object).and_then(|root| revision_for_workspace(&root));
    let Some(turn) = read_transcript_tail(&path)
        .and_then(|transcript| analyze_turn(&transcript, head.as_deref()))
    else {
        // A transcript this gate cannot read proves nothing either way.
        return None;
    };
    let changed = turn.changed || baseline_differs(&request.payload);
    if !changed || !claims_completion(&message) || turn.evidence.is_some() {
        clear(&counter);
        return None;
    }

    let used = counter.as_deref().map_or(0, read_count);
    let still_active = object.get("stop_hook_active").and_then(Value::as_bool) == Some(true);
    if used >= MAX_STOP_REOPENINGS || (counter.is_none() && still_active) {
        clear(&counter);
        return None;
    }
    if let Some(path) = &counter {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, format!("{}\n", used + 1));
    }
    Some(HookResponse::denied(
        request.event_type.clone(),
        MISSING_CODE,
        "Legion: this turn changed the repository and the final message claims it is done, but no objective evidence follows the last change. Run the repository gate (`right-release check` or `rightkit-gate check`) and cite its green line, or cite a CI run URL on the exact head with its success, or a host receipt block; or say plainly that completion is not verified.",
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HEAD: &str = "66c9ddd4d704934d8408f38ef0ab9a09e4817661";

    fn assistant(blocks: Value) -> String {
        json!({"type":"assistant","message":{"role":"assistant","content":blocks}}).to_string()
    }

    fn user_prompt(text: &str) -> String {
        json!({"type":"user","message":{"role":"user","content":text}}).to_string()
    }

    fn tool_use(id: &str, name: &str, input: Value) -> String {
        assistant(json!([{"type":"tool_use","id":id,"name":name,"input":input}]))
    }

    fn tool_result(id: &str, text: &str, is_error: bool) -> String {
        json!({"type":"user","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":id,"content":text,"is_error":is_error}]}})
        .to_string()
    }

    fn transcript(lines: &[String]) -> String {
        lines.join("\n")
    }

    fn edit(id: &str) -> String {
        tool_use(
            id,
            "Edit",
            json!({"file_path":"src/lib.rs","old_string":"a","new_string":"b"}),
        )
    }

    #[test]
    fn a_turn_with_no_edit_or_head_move_is_not_a_change() {
        let text = transcript(&[
            user_prompt("what does this do"),
            tool_use("t1", "Read", json!({"file_path":"a"})),
            tool_result("t1", "contents", false),
            tool_use(
                "t2",
                "Bash",
                json!({"command":"git status && git log --oneline"}),
            ),
            tool_result("t2", "clean", false),
        ]);
        let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
        assert!(!turn.changed);
    }

    #[test]
    fn edits_and_head_moving_git_commands_are_changes() {
        for lines in [
            vec![edit("t1")],
            vec![tool_use(
                "t1",
                "Write",
                json!({"file_path":"a","content":"b"}),
            )],
            vec![tool_use(
                "t1",
                "Bash",
                json!({"command":"git commit -am x"}),
            )],
            vec![tool_use(
                "t1",
                "Bash",
                json!({"command":"cd r && git rebase main"}),
            )],
            vec![tool_use(
                "t1",
                "Bash",
                json!({"command":"bash -c 'git merge topic'"}),
            )],
        ] {
            let mut all = vec![user_prompt("do it")];
            all.extend(lines);
            let turn = analyze_turn(&transcript(&all), Some(HEAD)).expect("understood");
            assert!(turn.changed, "{all:?}");
        }
    }

    #[test]
    fn only_the_current_turn_counts() {
        let text = transcript(&[
            user_prompt("fix it"),
            edit("t1"),
            tool_result("t1", "ok", false),
            user_prompt("thanks, what was the cause?"),
            assistant(json!([{"type":"text","text":"A typo."}])),
        ]);
        let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
        assert!(!turn.changed);
    }

    #[test]
    fn a_green_gate_line_after_the_last_change_is_evidence() {
        let text = transcript(&[
            user_prompt("fix it"),
            edit("t1"),
            tool_result("t1", "ok", false),
            tool_use(
                "t2",
                "Bash",
                json!({"command":"pnpm exec right-release check"}),
            ),
            tool_result("t2", "check: 66c9ddd4d704 passed 12 rules in 6.2s", false),
        ]);
        let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
        assert!(turn.changed);
        assert_eq!(turn.evidence, Some(Evidence::Gate));
    }

    #[test]
    fn gate_evidence_that_predates_the_last_edit_does_not_count() {
        let text = transcript(&[
            user_prompt("fix it"),
            tool_use("t1", "Bash", json!({"command":"right-release check"})),
            tool_result("t1", "check: 66c9ddd4d704 passed 12 rules in 6.2s", false),
            edit("t2"),
            tool_result("t2", "ok", false),
        ]);
        let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
        assert_eq!(turn.evidence, None);
    }

    #[test]
    fn gate_evidence_is_refused_when_red_errored_for_another_commit_or_not_the_gate() {
        let red = "FAIL eol-policy (G04): x\ncheck: 1 problem(s) in 66c9ddd4d704 (12 rules, 6.2s).";
        let green = "check: 66c9ddd4d704 passed 12 rules in 6.2s";
        let other = "check: 0123456789ab passed 12 rules in 6.2s";
        for (command, output, is_error) in [
            ("right-release check", red, false),
            ("right-release check", green, true),
            ("right-release check", other, false),
            // The line printed by something that is not the gate.
            (
                "echo 'check: 66c9ddd4d704 passed 12 rules in 6.2s'",
                green,
                false,
            ),
            ("cat notes.txt", green, false),
            ("right-release doctor", green, false),
        ] {
            let text = transcript(&[
                user_prompt("fix it"),
                edit("t1"),
                tool_result("t1", "ok", false),
                tool_use("t2", "Bash", json!({"command": command})),
                tool_result("t2", output, is_error),
            ]);
            let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
            assert_eq!(turn.evidence, None, "{command} / {output} / {is_error}");
        }
    }

    #[test]
    fn every_spelling_of_the_gate_command_is_recognised() {
        for command in [
            "right-release check",
            "rightkit-gate check",
            "pnpm exec right-release check",
            "pnpm exec rightkit-gate check --commit HEAD",
            "npx rightkit-gate check",
            "node node_modules/@rightkit/release/bin/rightkit-gate.mjs check",
            "cd app && pnpm right-release check",
            "bash -c 'right-release check'",
            // Transitional: the only gate on RightKit main takes no subcommand.
            "node scripts/preflight.mjs",
            "node ./scripts/preflight.mjs --worktree",
            "node /work/rightkit/scripts/preflight.mjs --repo ../app --commit HEAD",
            "node 'scripts\\preflight.mjs'",
            "pnpm exec node scripts/preflight.mjs",
            "cd rightkit && node scripts/preflight.mjs",
            "./scripts/preflight.mjs",
            "bash -c 'node scripts/preflight.mjs'",
        ] {
            assert!(is_gate_command(command), "{command}");
        }
        for command in [
            "right-release doctor",
            "right-release build",
            "echo right-release check",
            "pnpm test",
            "grep check right-release.config.mjs",
            "cat scripts/preflight.mjs",
            "echo node scripts/preflight.mjs",
            "node scripts/preflight.test.mjs",
            "node scripts/check-syntax.mjs",
            "node tools/preflight.mjs",
            "node preflight.mjs",
        ] {
            assert!(!is_gate_command(command), "{command}");
        }
    }

    #[test]
    fn a_green_preflight_script_line_is_evidence_for_the_current_head() {
        for command in [
            "node scripts/preflight.mjs",
            "pnpm exec node scripts/preflight.mjs --worktree",
        ] {
            let text = transcript(&[
                user_prompt("fix it"),
                edit("t1"),
                tool_result("t1", "ok", false),
                tool_use("t2", "Bash", json!({"command": command})),
                tool_result(
                    "t2",
                    "preflight: 66c9ddd4d704 passed 7 rules in 1.4s",
                    false,
                ),
            ]);
            let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
            assert_eq!(turn.evidence, Some(Evidence::Gate), "{command}");
        }
        // The same line for another commit, or from a command that is not the
        // script, still counts for nothing.
        for (command, output) in [
            (
                "node scripts/preflight.mjs",
                "preflight: 0123456789ab passed 7 rules in 1.4s",
            ),
            (
                "node scripts/preflight.mjs",
                "preflight: 66c9ddd4d704 1 problem(s) in 7 rules",
            ),
            (
                "cat scripts/preflight.mjs",
                "preflight: 66c9ddd4d704 passed 7 rules in 1.4s",
            ),
        ] {
            let text = transcript(&[
                user_prompt("fix it"),
                edit("t1"),
                tool_result("t1", "ok", false),
                tool_use("t2", "Bash", json!({"command": command})),
                tool_result("t2", output, false),
            ]);
            let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
            assert_eq!(turn.evidence, None, "{command} / {output}");
        }
    }

    #[test]
    fn a_ci_run_on_the_exact_head_is_evidence_only_when_it_succeeded() {
        let ok = format!(
            "{{\"conclusion\":\"success\",\"headSha\":\"{HEAD}\",\"url\":\"https://github.com/o/r/actions/runs/123456\"}}"
        );
        let failed = ok.replace("success", "failure");
        let other_head = ok.replace(HEAD, "0123456789abcdef0123456789abcdef01234567");
        let no_url = format!("{{\"conclusion\":\"success\",\"headSha\":\"{HEAD}\"}}");
        for (output, expected) in [
            (ok.as_str(), Some(Evidence::Ci)),
            (failed.as_str(), None),
            (other_head.as_str(), None),
            (no_url.as_str(), None),
        ] {
            let text = transcript(&[
                user_prompt("ship it"),
                edit("t1"),
                tool_result("t1", "ok", false),
                tool_use(
                    "t2",
                    "Bash",
                    json!({"command":"gh run view 123456 --json conclusion,headSha,url"}),
                ),
                tool_result("t2", output, false),
            ]);
            let turn = analyze_turn(&text, Some(HEAD)).expect("understood");
            assert_eq!(turn.evidence, expected, "{output}");
        }
        // With no HEAD to compare, a CI URL proves nothing.
        let text = transcript(&[
            user_prompt("ship it"),
            edit("t1"),
            tool_use("t2", "Bash", json!({"command":"gh run view 1"})),
            tool_result("t2", &ok, false),
        ]);
        assert_eq!(analyze_turn(&text, None).unwrap().evidence, None);
    }

    #[test]
    fn a_terminal_host_receipt_with_exit_zero_is_evidence() {
        let receipt = r#"{"id":"req-42","command":"cargo test -p legion-hook","workspace":"/w","exitCode":0,"queueMs":1}"#;
        let wrapped = format!("receipt for req-42\n{{\"receipt\": {receipt}}}");
        let failed = receipt.replace("\"exitCode\":0", "\"exitCode\":101");
        let not_verifying = receipt.replace("cargo test -p legion-hook", "cargo fmt");
        let no_id = receipt.replace("\"id\":\"req-42\",", "");
        for (output, expected) in [
            (receipt.to_owned(), Some(Evidence::Receipt)),
            (wrapped, Some(Evidence::Receipt)),
            (failed, None),
            (not_verifying, None),
            (no_id, None),
            ("exitCode: 0 and all is well".to_owned(), None),
        ] {
            let text = transcript(&[
                user_prompt("test it"),
                edit("t1"),
                tool_result("t1", "ok", false),
                tool_use("t2", "Bash", json!({"command":"rustright status req-42"})),
                tool_result("t2", &output, false),
            ]);
            assert_eq!(
                analyze_turn(&text, Some(HEAD)).unwrap().evidence,
                expected,
                "{output}"
            );
        }
    }

    #[test]
    fn the_word_passed_in_a_tool_result_is_not_evidence() {
        let text = transcript(&[
            user_prompt("fix it"),
            edit("t1"),
            tool_result("t1", "ok", false),
            tool_use("t2", "Bash", json!({"command":"cargo test"})),
            tool_result("t2", "test result: ok. 12 passed; 0 failed", false),
        ]);
        assert_eq!(analyze_turn(&text, Some(HEAD)).unwrap().evidence, None);
    }

    #[test]
    fn an_unreadable_transcript_is_not_understood() {
        assert!(analyze_turn("", Some(HEAD)).is_none());
        assert!(analyze_turn("not json\nat all", Some(HEAD)).is_none());
        assert!(analyze_turn(
            &json!({"type":"response_item","payload":{"type":"function_call"}}).to_string(),
            Some(HEAD)
        )
        .is_none());
    }

    #[test]
    fn subagent_lines_are_not_the_main_turn() {
        let sidechain = json!({"type":"assistant","isSidechain":true,"message":{"role":"assistant",
            "content":[{"type":"tool_use","id":"s1","name":"Edit","input":{}}]}})
        .to_string();
        let text = transcript(&[user_prompt("look around"), sidechain]);
        assert!(!analyze_turn(&text, Some(HEAD)).unwrap().changed);
    }

    #[test]
    fn completion_claims_need_a_claim_word_and_no_honest_marker() {
        for message in [
            "Done.",
            "All fixed and pushed.",
            "The change is complete; 12 tests passed.",
            "Shipped. It works.",
        ] {
            assert!(claims_completion(message), "{message}");
        }
        for message in [
            "I recommend this approach.",
            "Shall I continue?",
            "Not done: the gate was not run, so completion is not verified.",
            "Partial: two of three files changed; unverified.",
            "Blocked on the CI queue.",
            "Here is the plan.",
        ] {
            assert!(!claims_completion(message), "{message}");
        }
    }
}
