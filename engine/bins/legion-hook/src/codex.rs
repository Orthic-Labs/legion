//! Codex transport & optional completion cleanup. Native Guard owns decisions;
//! cleanup never changes them, including after Codex replaces its runtime.
//!
//! Codex PreToolUse/PostToolUse frames are normalised to the shape the Guard
//! already classifies (`normalize_request`), and the host answer is limited to
//! what Codex honours: deny is exit 2 with the reason on stderr (Codex has no
//! `ask` outcome), and `updatedInput` is passed only in a shape Codex accepts.
use crate::{
    protocol::{HookRequest, HookResponse},
    response_value,
};
use serde_json::{json, Map, Value};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn project_response(response: &HookResponse) -> (i32, Value) {
    let mut output = json!({});
    if response.allowed {
        if let Some(context) = response_value(response).get("hookSpecificOutput") {
            output["hookSpecificOutput"] = context.clone();
        }
    }
    // Only events the host can block exit 2. A denial on a lifecycle or
    // observation event (SessionStart, UserPromptSubmit, PostToolUse,
    // Notification, ...) must not turn an internal failure into a host error.
    // Unidentified events stay blocking so a malformed frame still fails closed.
    let blocking = !matches!(
        response.event_type.as_str(),
        "SessionStart"
            | "SubagentStart"
            | "SubagentStop"
            | "UserPromptSubmit"
            | "PostCompact"
            | "PostToolUse"
            | "PostToolUseFailure"
            | "Notification"
            | "session-start"
            | "subagent-start"
            | "subagent-stop"
            | "user-prompt-submit"
            | "post-compact"
            | "post-effect"
            | "post-effect-failure"
            | "ci-boundary"
    );
    (if response.allowed || !blocking { 0 } else { 2 }, output)
}

/// `LEGION_HOOK_OFF` check id: when listed, Codex frames reach the Guard
/// exactly as Codex sent them.
pub const NORMALIZE_CHECK_ID: &str = "codex-normalize";

const PATCH_BEGIN: &str = "*** Begin Patch";
const PATCH_HEADERS: [(&str, PatchOp); 4] = [
    ("*** Add File: ", PatchOp::Add),
    ("*** Update File: ", PatchOp::Update),
    ("*** Delete File: ", PatchOp::Delete),
    ("*** Move to: ", PatchOp::MoveTo),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatchOp {
    Add,
    Update,
    Delete,
    MoveTo,
}

impl PatchOp {
    fn label(self) -> &'static str {
        match self {
            PatchOp::Add => "add",
            PatchOp::Update => "update",
            PatchOp::Delete => "delete",
            PatchOp::MoveTo => "move-to",
        }
    }
}

fn hook_off(list: Option<&str>, id: &str) -> bool {
    list.is_some_and(|list| {
        list.split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(id))
    })
}

/// Codex names for its shell tools. Codex reports shell commands and unified
/// exec as `Bash`; the rest cover builds that report the raw tool name.
fn is_shell_alias(name: &str) -> bool {
    matches!(
        name,
        "exec_command"
            | "functions.exec_command"
            | "functions.exec"
            | "unified_exec"
            | "local_shell"
            | "container.exec"
    )
}

fn is_apply_patch(name: &str) -> bool {
    matches!(name, "apply_patch" | "functions.apply_patch")
}

/// The patch text of an `apply_patch` call: Codex sends it as
/// `tool_input.command`; other builds use `input`/`patch` or an argv array.
fn patch_text(input: &Value) -> Option<&str> {
    fn from_value(value: &Value) -> Option<&str> {
        match value {
            Value::String(text) => Some(text.as_str()),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .find(|item| item.contains(PATCH_BEGIN)),
            _ => None,
        }
    }
    match input {
        Value::Object(map) => ["command", "input", "patch"]
            .iter()
            .find_map(|key| map.get(*key).and_then(from_value)),
        other => from_value(other),
    }
}

/// Every file header in a patch, in order. Body lines are always prefixed
/// (` `, `+`, `-`, `@@`), so a header can never be file content.
fn parse_patch_files(patch: &str) -> Vec<(PatchOp, String)> {
    patch
        .lines()
        .filter_map(|line| {
            PATCH_HEADERS.iter().find_map(|(prefix, op)| {
                line.strip_prefix(*prefix)
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .map(|path| (*op, path.to_owned()))
            })
        })
        .collect()
}

/// Join and normalise `.`/`..` without touching the filesystem.
fn lexical_join(base: &str, relative: &str) -> String {
    let combined = format!("{base}/{relative}").replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for component in combined.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let root = if combined.starts_with('/') { "/" } else { "" };
    format!("{root}{}", parts.join("/"))
}

/// Patch paths are relative to the session `cwd`; the Guard's protected-path
/// check is textual, so resolve them before it sees them.
fn resolve_path(cwd: Option<&str>, path: &str) -> String {
    let path = path.trim();
    let absolute = path.starts_with(['/', '\\', '~']) || path.as_bytes().get(1) == Some(&b':');
    match cwd.filter(|cwd| !cwd.trim().is_empty()) {
        Some(cwd) if !absolute => lexical_join(cwd.trim(), path),
        _ => path.to_owned(),
    }
}

/// Rewrite an `apply_patch` frame as the file edit it is. Left as sent when no
/// file header parses, so a format change in Codex degrades to the old path
/// rather than to a guess.
fn normalize_apply_patch(payload: &mut Map<String, Value>, tool: String) {
    let Some(files) = payload
        .get("tool_input")
        .and_then(patch_text)
        .map(parse_patch_files)
        .filter(|files| !files.is_empty())
    else {
        return;
    };
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let paths = files
        .iter()
        .map(|(_, path)| resolve_path(cwd.as_deref(), path))
        .collect::<Vec<_>>();
    let operations = files.iter().map(|(op, _)| op.label()).collect::<Vec<_>>();
    let tool_input = json!({
        "file_path": paths[0],
        "paths": paths,
        "operations": operations,
    });
    payload.insert("codex_tool_name".into(), Value::String(tool));
    payload.insert("tool_name".into(), Value::String("Edit".into()));
    payload.insert("tool_input".into(), tool_input);
}

/// Map a Codex frame onto the names and fields the Guard classifies.
///
/// - Codex shell tools (`exec_command`, ...) become `Bash`; the command stays
///   at `tool_input.command`.
/// - `apply_patch` becomes a file `Edit` with `tool_input.file_path` (first
///   file) and `tool_input.paths` (all files, resolved against `cwd`). The raw
///   patch text is dropped from `tool_input`: the Guard judges `command`
///   fields as shell text, and file contents in a patch are not commands.
/// - The original name is kept in `codex_tool_name`; every Codex frame gets
///   `legion_host: "codex"` so host-specific checks can tell it apart.
///
/// Nothing here denies; a frame that does not match is left unchanged.
pub fn normalize_request(request: &mut HookRequest) {
    let kill_switch = std::env::var("LEGION_HOOK_OFF").ok();
    normalize_request_with(request, kill_switch.as_deref());
}

fn normalize_request_with(request: &mut HookRequest, kill_switch: Option<&str>) {
    if hook_off(kill_switch, NORMALIZE_CHECK_ID) {
        return;
    }
    let tool_event = request.is_pre_effect() || request.is_post_effect();
    let Some(payload) = request.payload.as_object_mut() else {
        return;
    };
    payload.insert("legion_host".into(), Value::String("codex".into()));
    if !tool_event {
        return;
    }
    let Some(tool) = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    if is_shell_alias(&tool) {
        payload.insert("codex_tool_name".into(), Value::String(tool));
        payload.insert("tool_name".into(), Value::String("Bash".into()));
    } else if is_apply_patch(&tool) {
        normalize_apply_patch(payload, tool);
    }
}

/// Codex accepts `updatedInput` on an allowed PreToolUse only as a string
/// `command` for Bash/apply_patch, or an arguments object for other tools; any
/// other shape fails the hook run. A rewrite Legion cannot express that way is
/// dropped, which leaves the original input in force.
fn updated_input_supported(payload: &Value, updated: &Value) -> bool {
    let original = payload
        .get("codex_tool_name")
        .or_else(|| payload.get("tool_name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if is_apply_patch(original) {
        return false;
    }
    if original == "Bash" || is_shell_alias(original) {
        return updated.get("command").is_some_and(Value::is_string);
    }
    updated.is_object()
}

fn drop_unsupported_updated_input(output: &mut Value, request: Option<&HookRequest>) {
    let Some(specific) = output
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let Some(updated) = specific.get("updatedInput") else {
        return;
    };
    if request.is_some_and(|request| updated_input_supported(&request.payload, updated)) {
        return;
    }
    specific.remove("updatedInput");
    if specific.get("permissionDecision").and_then(Value::as_str) == Some("allow") {
        specific.remove("permissionDecision");
        specific.remove("permissionDecisionReason");
    }
    if specific.len() <= 1 {
        if let Some(object) = output.as_object_mut() {
            object.remove("hookSpecificOutput");
        }
    }
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
    let (exit_code, mut output) = project_response(response);
    drop_unsupported_updated_input(&mut output, request);
    if !response.allowed {
        eprintln!("{}", response.reason);
    }
    if exit_code != 0 {
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
    fn only_blocking_events_exit_two_on_denial() {
        for event in ["PreToolUse", "pre-effect", "Stop", "stop", "unknown"] {
            let denied = HookResponse::denied(event, "ARC_X", "no", "strong");
            assert_eq!(project_response(&denied).0, 2, "{event}");
        }
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "PostToolUse",
            "Notification",
        ] {
            let denied = HookResponse::denied(event, "ARC_X", "no", "strong");
            assert_eq!(project_response(&denied).0, 0, "{event}");
        }
    }

    fn frame(value: Value) -> HookRequest {
        HookRequest::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn codex_pre(event: &str, tool: &str, input: Value) -> HookRequest {
        frame(json!({
            "hook_event_name": event,
            "cwd": "/Users/a/proj",
            "tool_name": tool,
            "tool_input": input,
            "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
        }))
    }

    const PATCH: &str = "*** Begin Patch\n*** Add File: src/new.rs\n+fn main() {}\n*** Update File: ../.ssh/config\n@@\n-old\n+new\n*** Move to: moved/config\n*** Delete File: /abs/gone.txt\n*** End Patch";

    #[test]
    fn bash_frames_keep_their_shape_and_gain_the_host_marker() {
        let mut request = codex_pre("PreToolUse", "Bash", json!({"command": "git status"}));
        normalize_request_with(&mut request, None);
        assert_eq!(request.payload["tool_name"], "Bash");
        assert_eq!(
            request.payload["tool_input"],
            json!({"command": "git status"})
        );
        assert_eq!(request.payload["legion_host"], "codex");
        assert!(request.payload.get("codex_tool_name").is_none());
    }

    #[test]
    fn codex_shell_aliases_become_bash_and_keep_the_command() {
        for alias in ["exec_command", "functions.exec_command", "functions.exec"] {
            let mut request = codex_pre("PreToolUse", alias, json!({"command": "ls"}));
            normalize_request_with(&mut request, None);
            assert_eq!(request.payload["tool_name"], "Bash", "{alias}");
            assert_eq!(request.payload["codex_tool_name"], alias);
            assert_eq!(request.payload["tool_input"]["command"], "ls");
        }
    }

    #[test]
    fn apply_patch_becomes_a_file_edit_with_every_path_resolved() {
        let mut request = codex_pre("PreToolUse", "apply_patch", json!({"command": PATCH}));
        normalize_request_with(&mut request, None);
        assert_eq!(request.payload["tool_name"], "Edit");
        assert_eq!(request.payload["codex_tool_name"], "apply_patch");
        let input = &request.payload["tool_input"];
        assert!(
            input.get("command").is_none(),
            "patch text must not reach the shell checks"
        );
        assert_eq!(input["file_path"], "/Users/a/proj/src/new.rs");
        assert_eq!(
            input["paths"],
            json!([
                "/Users/a/proj/src/new.rs",
                "/Users/a/.ssh/config",
                "/Users/a/proj/moved/config",
                "/abs/gone.txt"
            ])
        );
        assert_eq!(
            input["operations"],
            json!(["add", "update", "move-to", "delete"])
        );
        assert!(crate::is_protected_write_path("/Users/a/.ssh/config"));
    }

    #[test]
    fn normalised_apply_patch_reaches_the_guard_as_a_file_write() {
        let mut ordinary = codex_pre("PreToolUse", "apply_patch", json!({"command": PATCH}));
        normalize_request_with(&mut ordinary, None);
        let effect = crate::effect_request(&ordinary).unwrap().unwrap();
        assert_eq!(effect.effect_class, crate::EffectClass::FILE_WRITE);
        assert_eq!(effect.target, "/Users/a/proj/src/new.rs");

        let secret_patch =
            "*** Begin Patch\n*** Update File: ../.ssh/authorized_keys\n@@\n+key\n*** End Patch";
        let mut protected = codex_pre(
            "PreToolUse",
            "apply_patch",
            json!({"command": secret_patch}),
        );
        normalize_request_with(&mut protected, None);
        let effect = crate::effect_request(&protected).unwrap().unwrap();
        assert_eq!(effect.effect_class, crate::EffectClass::CREDENTIAL_ACCESS);
    }

    #[test]
    fn post_tool_use_frames_are_normalised_like_pre_tool_use() {
        let mut request = codex_pre("PostToolUse", "apply_patch", json!({"command": PATCH}));
        request.payload["tool_response"] = json!("Success");
        normalize_request_with(&mut request, None);
        assert_eq!(request.payload["tool_name"], "Edit");
        assert_eq!(request.payload["tool_response"], "Success");
    }

    #[test]
    fn unparseable_patches_and_other_events_are_left_as_sent() {
        let mut request = codex_pre(
            "PreToolUse",
            "apply_patch",
            json!({"command": "not a patch"}),
        );
        normalize_request_with(&mut request, None);
        assert_eq!(request.payload["tool_name"], "apply_patch");
        assert_eq!(
            request.payload["tool_input"],
            json!({"command": "not a patch"})
        );

        let mut stop = codex_pre("Stop", "apply_patch", json!({"command": PATCH}));
        normalize_request_with(&mut stop, None);
        assert_eq!(stop.payload["tool_name"], "apply_patch");
        assert_eq!(stop.payload["legion_host"], "codex");
    }

    #[test]
    fn kill_switch_hands_the_frame_to_the_guard_untouched() {
        let mut request = codex_pre("PreToolUse", "apply_patch", json!({"command": PATCH}));
        let before = request.payload.clone();
        normalize_request_with(&mut request, Some("other, Codex-Normalize"));
        assert_eq!(request.payload, before);
        assert!(!hook_off(Some("other"), NORMALIZE_CHECK_ID));
        assert!(!hook_off(None, NORMALIZE_CHECK_ID));
    }

    #[test]
    fn patch_headers_inside_file_content_are_not_paths() {
        let patch =
            "*** Begin Patch\n*** Add File: a.txt\n+*** Add File: /etc/passwd\n*** End Patch";
        assert_eq!(
            parse_patch_files(patch),
            vec![(PatchOp::Add, "a.txt".to_owned())]
        );
        assert_eq!(
            patch_text(&json!(["apply_patch", patch])),
            Some(patch),
            "argv-style apply_patch"
        );
    }

    #[test]
    fn relative_paths_resolve_lexically_against_cwd() {
        assert_eq!(lexical_join("/a/b", "../c/./d"), "/a/c/d");
        assert_eq!(
            lexical_join("C:\\Users\\x", ".ssh\\config"),
            "C:/Users/x/.ssh/config"
        );
        assert_eq!(resolve_path(Some("/a/b"), "/etc/hosts"), "/etc/hosts");
        assert_eq!(resolve_path(Some("/a/b"), "~/.zshrc"), "~/.zshrc");
        assert_eq!(resolve_path(Some("/a/b"), "C:\\x\\y"), "C:\\x\\y");
        assert_eq!(resolve_path(None, "src/a.rs"), "src/a.rs");
        assert_eq!(resolve_path(Some(" "), "src/a.rs"), "src/a.rs");
    }

    #[test]
    fn codex_destructive_bash_is_denied_with_exit_two() {
        let mut request = frame(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/x"},
        }));
        normalize_request_with(&mut request, None);
        let (exit, output) = project_response(&crate::dispatch(request));
        assert_eq!(exit, 2);
        assert_eq!(
            output,
            json!({}),
            "deny is exit 2 plus stderr, never stdout JSON"
        );
    }

    #[test]
    fn ask_has_no_codex_outcome_and_denies() {
        let ask = HookResponse::ask("PreToolUse", "ARC_USER_CONFIRMATION_REQUIRED", "confirm");
        assert_eq!(project_response(&ask), (2, json!({})));
    }

    #[test]
    fn updated_input_is_passed_only_in_a_shape_codex_accepts() {
        let allowed = HookResponse::allowed("PreToolUse", "ok")
            .with_updated_input(json!({"command": "cargo build"}));
        let (_, mut output) = project_response(&allowed);
        assert_eq!(
            output["hookSpecificOutput"]["updatedInput"]["command"],
            "cargo build"
        );
        let bash = codex_pre(
            "PreToolUse",
            "Bash",
            json!({"command": "cargo build --no-cache"}),
        );
        drop_unsupported_updated_input(&mut output, Some(&bash));
        assert_eq!(
            output["hookSpecificOutput"]["updatedInput"]["command"],
            "cargo build"
        );

        for (request, updated) in [
            (Some(&bash), json!({"file_path": "x"})),
            (None, json!({"command": "cargo build"})),
        ] {
            let allowed = HookResponse::allowed("PreToolUse", "ok").with_updated_input(updated);
            let (_, mut output) = project_response(&allowed);
            drop_unsupported_updated_input(&mut output, request);
            assert_eq!(output, json!({}));
        }

        let mut patch = codex_pre("PreToolUse", "apply_patch", json!({"command": PATCH}));
        normalize_request_with(&mut patch, None);
        let allowed = HookResponse::allowed("PreToolUse", "ok")
            .with_updated_input(json!({"command": "*** Begin Patch"}));
        let (_, mut output) = project_response(&allowed);
        drop_unsupported_updated_input(&mut output, Some(&patch));
        assert_eq!(
            output,
            json!({}),
            "a rewritten patch is never sent to Codex"
        );
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
