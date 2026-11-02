//! Progress governor: sleep waits, run polling, self-made schedules, the subagent cap and new chats.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{append_line, now_secs, off, session_id, state_dir, str_field};
use crate::state::{tool_input, tool_name, write_atomic, Payload};
use crate::transcript::genuine_user_turns;

const MSG_SLEEP: &str = "Use one background wait (gh run watch <id> --exit-status, or the gate's own wait); no sleep polling.";
const MSG_POLL: &str = "Status checks on this run are capped at three. Use one background wait (gh run watch <id> --exit-status), not repeated gh run view or gh run list.";
const MSG_CRON: &str = "Adrian has not asked for a schedule, wake, loop or watchdog. Do the work now, or state the blocker once and stop.";
const MSG_CHAT: &str = "Starting a new chat needs Adrian's express approval (workspace rules); use the existing chat or ask him.";
/// Words that make a `claude` or `codex` command a one-shot or an introspection, not a chat.
const NOT_A_CHAT: [&str; 7] = ["-p", "--print", "exec", "--version", "-v", "--help", "-h"];
/// Subcommands that manage the CLI rather than open a chat.
const TOOLS: [&str; 14] = [
    "plugin",
    "mcp",
    "config",
    "update",
    "doctor",
    "install",
    "auth",
    "setup-token",
    "login",
    "logout",
    "apply",
    "completion",
    "features",
    "sandbox",
];

/// True when a command line starts `claude` or `codex` as an interactive chat.
fn starts_chat(command: &str, depth: u8) -> bool {
    crate::command_segments(command).iter().any(|segment| {
        let stripped = crate::strip_command_prefixes(segment);
        let inner = crate::unwrap_shell_command(stripped);
        if depth < 2 && inner != stripped {
            return starts_chat(inner, depth + 1);
        }
        let words = crate::shell_words(stripped);
        let program = words.first().map(|word| crate::program_name(word));
        let tool = words
            .get(1)
            .is_some_and(|word| TOOLS.contains(&word.as_str()));
        matches!(program, Some("claude" | "codex"))
            && !tool
            && !words.iter().any(|word| NOT_A_CHAT.contains(&word.as_str()))
    })
}

/// Seconds of one `sleep` argument (`30`, `2m`, `1h`); unknown text counts as 0.
fn seconds(arg: &str) -> f64 {
    let (digits, unit) = match arg.chars().last() {
        Some(c @ ('s' | 'm' | 'h' | 'd')) => (&arg[..arg.len() - 1], c),
        _ => (arg, 's'),
    };
    let factor = match unit {
        'm' => 60.0,
        'h' => 3600.0,
        'd' => 86400.0,
        _ => 1.0,
    };
    digits.parse::<f64>().unwrap_or(0.0) * factor
}

/// Foreground `sleep` seconds in a command; any sleep inside a `while` or `until` loop is unbounded.
fn sleep_secs(command: &str, depth: u8) -> f64 {
    let (mut total, mut looping, mut slept) = (0.0, false, false);
    for segment in crate::command_segments(command) {
        let stripped = crate::strip_command_prefixes(&segment);
        let inner = crate::unwrap_shell_command(stripped);
        if depth < 2 && inner != stripped {
            let nested = sleep_secs(inner, depth + 1);
            (slept, total) = (slept || nested > 0.0, total + nested);
            continue;
        }
        let words = crate::shell_words(stripped);
        let control = |word: &&String| matches!(word.as_str(), "do" | "then" | "else" | "{" | "!");
        let skip = words.iter().take_while(control).count();
        match words.get(skip).map(|word| crate::program_name(word)) {
            Some("while" | "until") => looping = true,
            Some("sleep") => {
                slept = true;
                total += words[skip + 1..]
                    .iter()
                    .map(|arg| seconds(arg))
                    .sum::<f64>();
            }
            _ => {}
        }
    }
    if looping && slept {
        f64::INFINITY
    } else {
        total
    }
}

/// Keys of the `gh run view|list` calls in a command (`--log` reads are not polls).
fn poll_keys(command: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for segment in crate::command_segments(command) {
        let words = crate::shell_words(crate::strip_command_prefixes(&segment));
        let Some(("run", rest)) = crate::program_subcommand(&words, "gh", &["-R", "--repo"]) else {
            continue;
        };
        let args: Vec<&str> = rest.iter().skip(1).map(String::as_str).collect();
        let id = args
            .iter()
            .find(|arg| arg.chars().all(|c| c.is_ascii_digit()));
        match rest.first().map(String::as_str) {
            _ if args.iter().any(|arg| arg.starts_with("--log")) => {}
            Some("view") => keys.push(format!("view:{}", id.unwrap_or(&""))),
            Some("list") => keys.push(format!("list:{}", args.join(" "))),
            _ => {}
        }
    }
    keys
}

/// Record this command's polls; true when one key has been polled three times in the last hour.
fn polled_too_often(command: &str, session: &str) -> bool {
    let Some(dir) = state_dir("poll") else {
        return false;
    };
    let path = dir.join(format!("{session}.log"));
    let (now, log) = (now_secs(), fs::read_to_string(&path).unwrap_or_default());
    let mut over = false;
    for key in poll_keys(command) {
        let recent = |line: &&str| {
            let (stamp, seen) = line.split_once(' ').unwrap_or(("0", ""));
            seen == key
                && stamp
                    .parse::<u64>()
                    .is_ok_and(|t| now.saturating_sub(t) <= 3600)
        };
        over |= log.lines().filter(recent).count() >= 3;
        append_line(&path, &format!("{now} {key}"));
    }
    over
}

fn asks_for_schedule(text: &str) -> bool {
    let words = ["schedul", "wake", "loop", "cron", "watchdog", "daily"];
    let lower = text.to_lowercase();
    let mut tokens = lower.split(|c: char| !c.is_alphanumeric());
    tokens.any(|token| token == "every" || words.iter().any(|word| token.starts_with(word)))
}

/// Count launch (`L-`) and stop (`S-`) markers under 2 h old; older markers are removed.
fn census(dir: &Path) -> (usize, usize) {
    let (mut launches, mut stops) = (0, 0);
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let modified = entry.metadata().and_then(|meta| meta.modified());
        let age = modified.ok().and_then(|time| time.elapsed().ok());
        if age.is_some_and(|age| age.as_secs() > 2 * 3600) {
            let _ = fs::remove_file(entry.path());
        } else if entry.file_name().to_string_lossy().starts_with("L-") {
            launches += 1;
        } else if entry.file_name().to_string_lossy().starts_with("S-") {
            stops += 1;
        }
    }
    (launches, stops)
}

/// Mark a launch, then count the others still running; `Some(count)` when that reaches the cap.
fn launch(dir: &Path, id: &str, cap: usize) -> Option<usize> {
    let marker = dir.join(format!("L-{id}"));
    write_atomic(&marker, b"1")?;
    let (launches, stops) = census(dir);
    let others = launches.saturating_sub(stops + 1);
    if others >= cap {
        let _ = fs::remove_file(marker);
        return Some(others);
    }
    None
}

fn verdict(payload: &Payload, tool: &str, session: &str) -> Option<(&'static str, String)> {
    let input = tool_input(payload);
    if let Some(command) = input.and_then(crate::command_text) {
        let background = input.and_then(|input| input.get("run_in_background"));
        let background = background == Some(&Value::Bool(true));
        let background = background || command.trim_end().ends_with(" &");
        if !off("sleep") && !background && sleep_secs(&command, 0) > 30.0 {
            return Some(("ARC_SLEEP_WAIT", MSG_SLEEP.to_owned()));
        }
        if !off("new-chat") && starts_chat(&command, 0) {
            return Some(("ARC_NO_NEW_CHAT", MSG_CHAT.to_owned()));
        }
        let polled = !off("poll") && polled_too_often(&command, session);
        return polled.then(|| ("ARC_POLL_LIMIT", MSG_POLL.to_owned()));
    }
    let scheduler = matches!(tool, "CronCreate" | "ScheduleWakeup" | "RemoteTrigger");
    if (scheduler || tool.ends_with("__create_scheduled_task")) && !off("cron") {
        let path = str_field(payload, &["transcript_path"])?;
        let latest = genuine_user_turns(&path).pop()?;
        return (!asks_for_schedule(&latest)).then(|| ("ARC_SELF_SCHEDULE", MSG_CRON.to_owned()));
    }
    if matches!(tool, "Agent" | "Task") && !off("agents") {
        let id = str_field(payload, &["tool_use_id", "toolUseId"]);
        let id = id.unwrap_or_else(|| now_secs().to_string());
        let cap = std::env::var("LEGION_MAX_AGENTS").unwrap_or_default();
        let cap: usize = cap.trim().parse().ok().filter(|cap| *cap >= 1).unwrap_or(6);
        let others = launch(&state_dir("agents")?.join(session), &id, cap)?;
        let message = format!(
            "{others} subagents are still running (cap {cap}). Wait for one to finish first."
        );
        return Some(("ARC_AGENT_CAP", message));
    }
    None
}

/// PreToolUse: deny long sleeps, a fourth run poll, a self-made schedule or the seventh agent.
pub fn check_pre_tool_use(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let (code, message) = verdict(payload, &tool_name(payload)?, &session_id(payload)?)?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        code,
        message,
        "strong",
    ))
}

/// A `SubagentStop`, or a failed `Agent`/`Task` launch, frees one agent slot.
pub fn observe_subagent_stop(request: &HookRequest) {
    let event = request.event_type.as_str();
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    let tool = tool_name(payload).unwrap_or_default();
    let failed = matches!(event, "PostToolUseFailure" | "post-effect-failure");
    let ended = matches!(event, "SubagentStop" | "subagent-stop");
    if !(ended || (failed && matches!(tool.as_str(), "Agent" | "Task"))) || off("agents") {
        return;
    }
    let (Some(session), Some(dir)) = (session_id(payload), state_dir("agents")) else {
        return;
    };
    let id = str_field(payload, &["agent_id", "agentId", "tool_use_id"]);
    let id = id.unwrap_or_else(|| now_secs().to_string());
    let _ = write_atomic(&dir.join(session).join(format!("S-{id}")), b"1");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::temp_dir;

    #[test]
    fn sleeps_over_thirty_seconds_are_caught() {
        assert!(sleep_secs("sleep 60", 0) > 30.0);
        assert!(sleep_secs("sleep 5; sleep 20 && sleep 10", 0) > 30.0);
        assert!(sleep_secs("bash -c 'sleep 45'", 0) > 30.0);
        assert!(sleep_secs("sleep 2m", 0) > 30.0);
        assert!(sleep_secs("while true; do sleep 5; done", 0).is_infinite());
        assert_eq!(
            sleep_secs("for i in 1 2 3; do curl x && break; sleep 2; done", 0),
            2.0
        );
        assert!(sleep_secs("sleep 20", 0) <= 30.0);
        assert_eq!(sleep_secs("echo sleep 100", 0), 0.0);
    }

    #[test]
    fn run_polls_have_a_key_per_run() {
        assert_eq!(
            poll_keys("gh run view 1234567 --json status"),
            vec!["view:1234567"]
        );
        assert_eq!(poll_keys("gh run list -L 5 && true"), vec!["list:-L 5"]);
        assert!(poll_keys("gh run view 1234567 --log").is_empty());
        assert!(poll_keys("gh pr view 1234567").is_empty());
    }

    #[test]
    fn only_a_user_who_asked_may_schedule() {
        assert!(asks_for_schedule("run it every morning"));
        assert!(asks_for_schedule("set up a Watchdog"));
        assert!(!asks_for_schedule("fix the build, everything is red"));
    }

    #[test]
    fn only_an_interactive_claude_or_codex_is_a_new_chat() {
        for chat in [
            "claude",
            "codex --model x",
            "env A=1 /usr/bin/claude",
            "bash -c 'claude'",
        ] {
            assert!(starts_chat(chat, 0), "{chat}");
        }
        for fine in [
            "claude -p 'hi'",
            "claude plugin update legion",
            "codex mcp list",
            "codex login",
            "codex exec fix",
            "claude --version",
            "echo claude",
            "grep codex x",
        ] {
            assert!(!starts_chat(fine, 0), "{fine}");
        }
    }

    #[test]
    fn the_terminal_tools_are_held_to_the_same_rule() {
        for (tool, command, denied) in [
            ("mcp__terminal__run_in_terminal", "claude", true),
            ("mcp__terminal__open_terminal_tab", "codex --model x", true),
            ("mcp__terminal__run_in_terminal", "claude -p hi", false),
        ] {
            let payload = serde_json::json!({ "tool_input": { "command": command } });
            let payload = payload.as_object().unwrap();
            let got = verdict(payload, tool, "s").map(|(code, _)| code);
            assert_eq!(got == Some("ARC_NO_NEW_CHAT"), denied, "{tool} {command}");
        }
    }

    #[test]
    fn the_agent_cap_counts_launches_minus_stops() {
        let dir = temp_dir("agents");
        for id in ["a", "b", "c"] {
            assert_eq!(launch(&dir, id, 3), None);
        }
        assert_eq!(launch(&dir, "d", 3), Some(3));
        write_atomic(&dir.join("S-a"), b"1").unwrap();
        assert_eq!(launch(&dir, "e", 3), None);
    }
}
