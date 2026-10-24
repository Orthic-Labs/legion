use serde_json::{json, Value};
use std::{fs, io::Write, path::PathBuf, process::{Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};

fn fixture() -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("legion-codex-stop-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn invoke(input: &Value, config: &PathBuf, codex: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion-hook"));
    if codex { command.args(["--host", "codex"]); }
    command.env("CODEX_HOME", config).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn stop() -> Value {
    json!({"hook_event_name":"Stop", "stop_hook_active":false,
        "session_id":"11111111-1111-4111-8111-111111111111",
        "turn_id":"22222222-2222-4222-8222-222222222222",
        "last_assistant_message":"x".repeat(100_000)})
}

#[test]
fn codex_stop_preserves_acceptance_when_cleanup_runtime_is_retired() {
    let root = fixture();
    fs::write(root.join("computer-use-stop.json"), json!({"command":[root.join("retired").join("codex-computer-use.exe"), "turn-ended"]}).to_string()).unwrap();
    let output = invoke(&stop(), &root, true);
    fs::remove_dir_all(root).unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), json!({}));
    #[cfg(windows)]
    assert!(String::from_utf8_lossy(&output.stderr).contains("LEGION_STOP_CLEANUP_FAILED"));
}

#[test]
fn codex_required_oracle_still_blocks_before_cleanup() {
    let root = fixture();
    fs::write(root.join("computer-use-stop.json"), "invalid-config").unwrap();
    let mut input = stop();
    input["verificationRequirement"] = json!("oracle");
    let output = invoke(&input, &root, true);
    fs::remove_dir_all(root).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("Oracle PASS"));
    assert!(!error.contains("LEGION_STOP_CLEANUP_FAILED"));
}

#[test]
fn default_native_transport_keeps_versioned_response() {
    let root = fixture();
    let output = invoke(&stop(), &root, false);
    fs::remove_dir_all(root).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["kind"], "legion-hook-response");
    assert_eq!(response["allowed"], true);
}
