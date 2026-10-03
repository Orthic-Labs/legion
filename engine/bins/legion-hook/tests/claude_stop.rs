use serde_json::{json, Value};
use std::{io::Write, process::{Command, Stdio}};

fn invoke(payload: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion-hook"))
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
