//! Codex transport & optional completion cleanup. Native Guard owns decisions;
//! cleanup never changes them, including after Codex replaces its runtime.
use crate::{
    protocol::{HookRequest, HookResponse},
    response_value,
};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn project_response(response: &HookResponse) -> (i32, Value) {
    let mut output = json!({});
    if response.allowed {
        if let Some(context) = response_value(response).get("hookSpecificOutput") {
            output["hookSpecificOutput"] = context.clone();
        }
    }
    (if response.allowed { 0 } else { 2 }, output)
}

fn bounded_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn completion_notice(request: &HookRequest) -> Option<Value> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let session = request.payload.get("session_id")?.as_str()?;
    let turn = request.payload.get("turn_id")?.as_str()?;
    if !bounded_id(session) || !bounded_id(turn) {
        return None;
    }
    Some(json!({"type":"agent-turn-complete", "thread-id":session, "turn-id":turn}))
}

fn notifier_command(config_path: &Path) -> Result<Option<PathBuf>, String> {
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let command = value
        .get("command")
        .and_then(Value::as_array)
        .filter(|command| command.len() == 2 && command[1].as_str() == Some("turn-ended"))
        .ok_or("invalid computer-use completion notifier")?;
    let executable = command[0]
        .as_str()
        .ok_or("invalid computer-use completion notifier")?;
    let executable = PathBuf::from(executable);
    if !executable.is_absolute()
        || executable.file_name().and_then(|name| name.to_str()) != Some("codex-computer-use.exe")
    {
        return Err("invalid computer-use completion notifier".into());
    }
    Ok(Some(executable))
}

#[cfg(windows)]
fn notify_computer_use(request: &HookRequest) -> Result<(), String> {
    let Some(notice) = completion_notice(request) else {
        return Ok(());
    };
    let config_root = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".codex")))
        .ok_or("Codex home unavailable for completion cleanup")?;
    let Some(executable) = notifier_command(&config_root.join("computer-use-stop.json"))? else {
        return Ok(());
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let mut command = tokio::process::Command::new(executable);
        command
            .args(["turn-ended", &notice.to_string()])
            .creation_flags(0x08000000)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let child = command.spawn().map_err(|error| error.to_string())?;
        let output = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| "computer-use completion cleanup timed out".to_owned())?
        .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "computer-use notifier exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(500)
                    .collect::<String>()
            ))
        }
    })
}

#[cfg(not(windows))]
fn notify_computer_use(_request: &HookRequest) -> Result<(), String> {
    Ok(())
}

pub fn emit_response(response: &HookResponse, request: Option<&HookRequest>) -> i32 {
    let (exit_code, output) = project_response(response);
    if exit_code != 0 {
        eprintln!("{}", response.reason);
        return exit_code;
    }
    if let Some(request) = request {
        if let Err(error) = notify_computer_use(request) {
            eprintln!("LEGION_STOP_CLEANUP_FAILED: {error}");
        }
    }
    if writeln!(io::stdout().lock(), "{output}").is_err() {
        return 2;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop() -> HookRequest {
        HookRequest::parse(
            &serde_json::to_vec(&json!({"hook_event_name":"Stop",
            "session_id":"11111111-1111-4111-8111-111111111111",
            "turn_id":"22222222-2222-4222-8222-222222222222",
            "last_assistant_message":"x".repeat(100_000)}))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn long_turn_cleanup_contains_only_valid_identity() {
        let request = stop();
        let notice = completion_notice(&request).unwrap();
        assert_eq!(
            notice,
            json!({"type":"agent-turn-complete",
            "thread-id":request.payload["session_id"], "turn-id":request.payload["turn_id"]})
        );
        assert!(notice.to_string().len() < 200);
        let mut invalid = request.clone();
        invalid.payload["turn_id"] = Value::String("x".repeat(100_000));
        assert!(completion_notice(&invalid).is_none());
        invalid.event_type = "PreToolUse".into();
        assert!(completion_notice(&invalid).is_none());
    }

    #[test]
    fn host_projection_preserves_gate_and_session_policy() {
        let allowed = crate::dispatch(stop());
        assert_eq!(project_response(&allowed), (0, json!({})));
        let mut required = stop();
        required.payload["verificationRequirement"] = json!("oracle");
        assert_eq!(project_response(&crate::dispatch(required)).0, 2);
        let session = HookResponse::allowed("SessionStart", "context");
        let (exit, output) = project_response(&session);
        assert_eq!(exit, 0);
        assert_eq!(
            output["hookSpecificOutput"]["additionalContext"],
            crate::SESSION_START_CONTEXT
        );
        assert!(output.get("kind").is_none());
    }

    #[test]
    fn absent_notifier_is_optional() {
        let missing = std::env::temp_dir().join(format!(
            "legion-absent-{}-{}",
            std::process::id(),
            crate::unix_nanos()
        ));
        assert_eq!(notifier_command(&missing).unwrap(), None);
    }
}
