use serde_json::{json, Value};
use std::{io::Write, process::{Command, Stdio}};

fn invoke(payload: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion-hook"))
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env_remove("LEGION_M1_CONFIG")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(payload.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
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
fn claude_third_party_mcp_calls_leave_permissions_with_host() {
    for tool in ["mcp__Windows-MCP__Snapshot", "mcp__Windows-MCP__Click", "mcp__docs__query"] {
        let result = invoke(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
            "tool_input": {}
        }));
        assert_eq!(result["allowed"], true, "{result}");
        assert!(result["reason"].as_str().unwrap().contains(tool));
        assert!(result["reason"].as_str().unwrap().contains("could not be classified"));
        // An admitted hook must not grant a Claude permission override.
        assert!(result["hookSpecificOutput"]["permissionDecision"].is_null(), "{result}");
    }
}

#[test]
fn claude_classified_mcp_effects_remain_denied() {
    for (tool, input) in [
        ("mcp__files__write_file", json!({})),
        ("mcp__mail__send_message", json!({})),
        ("mcp__files__delete_file", json!({})),
        ("mcp__docs__query", json!({"operation": "delete"})),
    ] {
        let result = invoke(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
            "tool_input": input
        }));
        assert_eq!(result["allowed"], false, "{result}");
        assert_eq!(result["code"], "ARC_POLICY_DENIED");
        assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "deny");
    }
}
