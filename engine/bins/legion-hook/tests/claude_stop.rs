use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(payload: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion-hook"))
        .env_remove("LEGION_M1_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn claude_stop_prose_cannot_start_or_repeat_a_continuation_chain() {
    for text in [
        "I recommend this approach.",
        "Shall I continue?",
        "Done. One caveat: remaining work waits for the running CI job.",
    ] {
        for active in [false, true] {
            for text_field in ["last_assistant_message", "lastAssistantText"] {
                let mut payload = json!({"hook_event_name":"Stop", "stop_hook_active":active});
                payload[text_field] = json!(text);
                let result = invoke(&payload);
                assert_eq!(result["allowed"], true, "{result}");
                assert_ne!(result["decision"], "block");
            }
        }
    }
}

#[test]
fn claude_stop_keeps_explicit_verification_enforcement() {
    let result = invoke(&json!({"hook_event_name":"Stop", "stop_hook_active":true,
        "last_assistant_message":"Done.", "verificationRequirement":"oracle"}));
    assert_eq!(result["allowed"], false);
    assert_eq!(result["code"], "ARC_VERIFICATION_REQUIRED");
}

#[test]
fn claude_pre_tool_use_is_never_gated_by_legion() {
    for (tool, input) in [
        ("mcp__docs__query", json!({})),
        ("mcp__files__write_file", json!({})),
        ("Bash", json!({"command": "git push --force"})),
        ("Write", json!({"file_path": "/tmp/x"})),
    ] {
        let result = invoke(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input
        }));
        assert_eq!(result["allowed"], true, "{result}");
        assert!(result["hookSpecificOutput"].is_null(), "{result}");
    }
}

fn invoke_in(state: &std::path::Path, payload: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion-hook"))
        .env_remove("LEGION_M1_CONFIG")
        .env("LEGION_STATE_ROOT", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn claude_stop_reminds_once_when_edits_have_no_evidence_and_never_blocks() {
    let state = std::env::temp_dir().join(format!("legion-hook-stop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let session = "stop-evidence-session";
    let stop = |text: &str| {
        json!({"hook_event_name":"Stop", "session_id":session,
        "last_assistant_message":text})
    };
    // No edits observed: no reminder.
    let quiet = invoke_in(&state, &stop("Done."));
    assert!(quiet["systemMessage"].is_null(), "{quiet}");
    invoke_in(
        &state,
        &json!({"hook_event_name":"PostToolUse", "session_id":session,
        "tool_name":"Edit", "tool_input":{}}),
    );
    // Evidence present: no reminder.
    let cited = invoke_in(&state, &stop("Changed src/lib.rs:10, 3 tests passed."));
    assert!(cited["systemMessage"].is_null(), "{cited}");
    let reminded = invoke_in(&state, &stop("Done."));
    assert_eq!(reminded["allowed"], true);
    assert_ne!(reminded["decision"], "block");
    assert_eq!(
        reminded["systemMessage"],
        "Legion: changes were made but the final message cites no evidence."
    );
    let again = invoke_in(&state, &stop("Done."));
    assert!(again["systemMessage"].is_null(), "{again}");
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn claude_stop_blocks_once_for_a_named_skill_that_was_never_called() {
    let root = std::env::temp_dir().join(format!("legion-hook-skill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let skill = root.join("home/.claude/plugins/cache/market/legion/1/skills/zzdemo");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "---\nname: zzdemo\n---\n").unwrap();
    let send = |payload: &Value| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_legion-hook"))
            .env_remove("LEGION_M1_CONFIG")
            .env_remove("LEGION_STATE_DIR")
            .env_remove("LEGION_HOOK_OFF")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env("HOME", root.join("home"))
            .env("LEGION_STATE_ROOT", root.join("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = payload.to_string();
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let event = |session: &str, name: &str| {
        json!({"hook_event_name":name, "session_id":session, "prompt":"please use the zzdemo skill",
        "last_assistant_message":"Working."})
    };
    send(&event("skill-a", "UserPromptSubmit"));
    let blocked = send(&event("skill-a", "Stop"));
    assert_eq!(blocked["allowed"], false, "{blocked}");
    assert_eq!(blocked["code"], "ARC_SKILL_NAMED");
    assert_eq!(send(&event("skill-a", "Stop"))["allowed"], true);
    send(&event("skill-b", "UserPromptSubmit"));
    send(
        &json!({"hook_event_name":"PostToolUse", "session_id":"skill-b", "tool_name":"Skill",
        "tool_input":{"skill":"legion:zzdemo"}}),
    );
    assert_eq!(send(&event("skill-b", "Stop"))["allowed"], true);
    let negated = |name: &str| {
        json!({"hook_event_name":name, "session_id":"skill-c", "prompt":"don't use the zzdemo skill",
        "last_assistant_message":"Working."})
    };
    send(&negated("UserPromptSubmit"));
    assert_eq!(send(&negated("Stop"))["allowed"], true);
    let _ = std::fs::remove_dir_all(&root);
}
