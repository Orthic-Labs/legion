#![forbid(unsafe_code)]

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use legion_application::{NativeApplication, NativeApplicationConfig};
use legion_contracts::{AgentId, EffectClass, EffectRequest, RequestId, TaskId};
use serde_json::{Map, Value};

mod error;
mod protocol;

use error::HookError;
use protocol::{HookRequest, HookResponse};

/// Translate one versioned host frame into an explicit, strongly enforced
/// decision. Lifecycle/post-effect observations are safe to acknowledge;
/// pre-effect frames must carry enough typed identity to reach native policy.
pub fn dispatch(request: HookRequest) -> HookResponse {
    let event_type = request.event_type.clone();
    if let Err(error) = request.validate() {
        return response_for_error(event_type, error);
    }

    if request.is_lifecycle() {
        return HookResponse::allowed(request.event_type, "lifecycle observation accepted");
    }
    if request.is_post_effect() {
        return HookResponse::allowed(request.event_type, "post-effect observation accepted");
    }
    if !request.is_pre_effect() {
        return HookResponse::denied(
            request.event_type,
            "ARC_HOST_EVENT_INVALID",
            "unsupported hook event",
            "strong",
        );
    }

    if is_destructive_command(&request.payload) {
        return HookResponse::denied(
            request.event_type,
            "ARC_EFFECT_CLASS_UNAUTHORIZED",
            "destructive command class is blocked; use a bounded, reversible alternative",
            "strong",
        );
    }
    if rewrite_push_requires_approval(&request.payload) {
        return HookResponse::denied(
            request.event_type,
            "ARC_APPROVAL_REQUIRED",
            "git push rewrites published history and needs a target-bound approval",
            "strong",
        );
    }

    let effect = match effect_request(&request) {
        Ok(effect) => effect,
        Err(message) => {
            return HookResponse::denied(
                request.event_type,
                "ARC_HOST_EVENT_INVALID",
                message,
                "strong",
            )
        }
    };

    let application = match native_application() {
        Ok(application) => application,
        Err(_) => {
            return HookResponse::denied(
                request.event_type,
                "ARC_NATIVE_POLICY_UNAVAILABLE",
                "native policy configuration is unavailable",
                "strong",
            )
        }
    };

    authorize_effect(request.event_type, &effect, application.as_ref())
}

fn authorize_effect(
    event_type: String,
    effect: &EffectRequest,
    application: Option<&NativeApplication>,
) -> HookResponse {
    match application {
        Some(application) => match application.authorize_hook(effect) {
            Ok(()) => HookResponse::allowed(event_type, "authorized"),
            Err(_) => HookResponse::denied(
                event_type,
                "ARC_POLICY_DENIED",
                "native policy denied effect",
                "strong",
            ),
        },
        // Hook stdin has no prompt, contract, or policy context. Hard gates
        // already ran in dispatch; absent explicit native policy, ambient
        // authority supplies the remaining decision.
        None => HookResponse::allowed(event_type, "ambient effect accepted"),
    }
}

fn response_for_error(event_type: String, error: HookError) -> HookResponse {
    if matches!(&error, HookError::InvalidRequest(message) if message == "event type is unsupported")
    {
        return HookResponse::denied(
            event_type,
            "ARC_HOST_EVENT_INVALID",
            "unsupported hook event",
            "strong",
        );
    }
    let health = match &error {
        HookError::InvalidRequest(_)
        | HookError::MalformedInput(_)
        | HookError::UnsupportedVersion(_) => "strong",
        HookError::Io(_) | HookError::Serialization(_) => "unsupported",
    };
    HookResponse::denied(event_type, error.code(), error.public_message(), health)
}

fn native_application() -> Result<Option<NativeApplication>, String> {
    let source = match std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        Ok(source) => source,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if source.trim().is_empty() {
        return Err("native application configuration is empty".into());
    }
    NativeApplicationConfig::from_versioned_source(&source)
        .and_then(NativeApplicationConfig::build)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn effect_request(request: &HookRequest) -> Result<EffectRequest, String> {
    let payload = request
        .payload
        .as_object()
        .ok_or_else(|| "request payload must be a JSON object".to_owned())?;
    let source = payload
        .get("effectRequest")
        .or_else(|| payload.get("effect_request"))
        .and_then(Value::as_object)
        .unwrap_or(payload);
    let effect = source
        .get("effect")
        .and_then(Value::as_object)
        .unwrap_or(source);
    let tool_name = first_string(source, &["toolName", "tool_name"])
        .or_else(|| first_string(payload, &["toolName", "tool_name"]));
    let command = command_value(source).or_else(|| command_value(payload));
    let class_name = first_string(effect, &["effectClass", "effect_class"])
        .or_else(|| first_string(source, &["effectClass", "effect_class"]))
        .or_else(|| first_string(payload, &["effectClass", "effect_class"]));
    let effect_class = parse_effect_class(
        class_name.as_deref(),
        tool_name.as_deref(),
        command.as_deref(),
    )
    .ok_or_else(|| "effect class is missing or unsupported".to_owned())?;

    let tool_input = source
        .get("tool_input")
        .or_else(|| source.get("toolInput"))
        .or_else(|| payload.get("tool_input"))
        .or_else(|| payload.get("toolInput"))
        .and_then(Value::as_object);
    let target = first_string(effect, &["target"])
        .or_else(|| first_string(source, &["target"]))
        .or_else(|| first_string(payload, &["target"]))
        .or_else(|| {
            tool_input.and_then(|input| first_string(input, &["file_path", "path", "url", "query"]))
        })
        .or_else(|| command.clone())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "effect target is missing".to_owned())?;
    let operation = first_string(effect, &["operation"])
        .or_else(|| first_string(source, &["operation"]))
        .or_else(|| first_string(payload, &["operation"]))
        .or_else(|| tool_name.clone())
        .or_else(|| Some(default_operation(effect_class).to_owned()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "effect operation is missing".to_owned())?;

    let source_revision = first_string(source, &["sourceRevision", "source_revision"])
        .or_else(|| first_string(payload, &["sourceRevision", "source_revision"]))
        .or_else(|| {
            std::env::var("LEGION_SOURCE_REVISION")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| resolve_source_revision(payload))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "source revision is missing".to_owned())?;

    let request_id = typed_id(
        first_string(source, &["requestId", "request_id"]).or_else(|| {
            first_string(
                payload,
                &[
                    "requestId",
                    "request_id",
                    "tool_use_id",
                    "toolUseId",
                    "eventId",
                    "event_id",
                ],
            )
        }),
        "native-hook-request",
        RequestId::new,
    )?;
    let task_id = typed_id(
        first_string(source, &["taskId", "task_id"])
            .or_else(|| first_string(payload, &["taskId", "task_id"])),
        "native-hook-task",
        TaskId::new,
    )?;
    let requested_by = typed_id(
        first_string(
            source,
            &["requestedBy", "requested_by", "agentId", "agent_id"],
        )
        .or_else(|| {
            first_string(
                payload,
                &["requestedBy", "requested_by", "agentId", "agent_id"],
            )
        }),
        "native-hook",
        AgentId::new,
    )?;
    let mut approval_required = first_bool(source, &["approvalRequired", "approval_required"])
        .or_else(|| first_bool(payload, &["approvalRequired", "approval_required"]))
        .unwrap_or(false);
    if matches!(effect_class, EffectClass::VCS_PUSH) && command_has_rewrite_flag(command.as_deref())
    {
        // Rewrite approvals must be explicit and target-bound. This adapter
        // has no approval store, so never turn one into an implicit allow.
        approval_required = true;
    }

    let preview = first_string(effect, &["preview"])
        .or_else(|| first_string(source, &["preview"]))
        .or_else(|| first_string(payload, &["preview"]));
    let effect = EffectRequest {
        schema_version: 1,
        request_id,
        task_id,
        requested_by,
        effect_class,
        target,
        operation,
        preview,
        source_revision,
        approval_required,
    };
    effect
        .validate()
        .map_err(|error| format!("invalid effect request: {error}"))?;
    Ok(effect)
}

fn typed_id<T>(
    value: Option<String>,
    fallback: &str,
    constructor: fn(String) -> Result<T, legion_contracts::ContractError>,
) -> Result<T, String> {
    constructor(value.unwrap_or_else(|| fallback.to_owned()))
        .map_err(|error| format!("invalid hook identity: {error}"))
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

fn command_value(object: &Map<String, Value>) -> Option<String> {
    first_string(object, &["command", "cmd"])
        .or_else(|| {
            object
                .get("tool_input")
                .or_else(|| object.get("toolInput"))
                .and_then(Value::as_object)
                .and_then(|input| first_string(input, &["command", "cmd"]))
        })
        .or_else(|| {
            object
                .get("effectRequest")
                .or_else(|| object.get("effect_request"))
                .and_then(Value::as_object)
                .and_then(command_value)
        })
}

fn parse_effect_class(
    class_name: Option<&str>,
    tool_name: Option<&str>,
    command: Option<&str>,
) -> Option<EffectClass> {
    if let Some(class_name) = class_name {
        let normalized = class_name
            .trim()
            .replace(&['-', ' ', '/'][..], "_")
            .to_ascii_uppercase();
        return match normalized.as_str() {
            "FILE_WRITE" | "WRITE" => Some(EffectClass::FILE_WRITE),
            "FILE_DELETE" | "DELETE" => Some(EffectClass::FILE_DELETE),
            "FILE_MOVE" | "MOVE" => Some(EffectClass::FILE_MOVE),
            "COMMAND_EXEC" | "EXECUTE" | "SHELL" => Some(EffectClass::COMMAND_EXEC),
            "NETWORK_EGRESS" | "NETWORK" | "CONNECT" => Some(EffectClass::NETWORK_EGRESS),
            "PROCESS_SPAWN" | "SPAWN" => Some(EffectClass::PROCESS_SPAWN),
            "CREDENTIAL_ACCESS" | "CREDENTIALS" => Some(EffectClass::CREDENTIAL_ACCESS),
            "DEPENDENCY_INSTALL" | "INSTALL" => Some(EffectClass::DEPENDENCY_INSTALL),
            "VCS_COMMIT" | "COMMIT" => Some(EffectClass::VCS_COMMIT),
            "VCS_PUSH" | "PUSH" => Some(EffectClass::VCS_PUSH),
            "PUBLISH" => Some(EffectClass::PUBLISH),
            _ => None,
        };
    }

    let tool = tool_name.unwrap_or_default();
    match tool {
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => Some(EffectClass::FILE_WRITE),
        "WebFetch" | "WebSearch" => Some(EffectClass::NETWORK_EGRESS),
        "shell" | "shell_command" | "Bash" | "PowerShell" | "apply_patch" => {
            Some(command_effect_class(command))
        }
        _ if command.is_some() => Some(command_effect_class(command)),
        _ => None,
    }
}

fn command_effect_class(command: Option<&str>) -> EffectClass {
    let command = command.unwrap_or_default().trim().to_ascii_lowercase();
    if contains_command_pair(&command, "git", "push") {
        EffectClass::VCS_PUSH
    } else if contains_command_pair(&command, "git", "commit") {
        EffectClass::VCS_COMMIT
    } else if contains_command_pair(&command, "npm", "install")
        || contains_command_pair(&command, "npm", "ci")
        || contains_command_pair(&command, "pnpm", "install")
        || contains_command_pair(&command, "pnpm", "add")
        || contains_command_pair(&command, "yarn", "install")
        || contains_command_pair(&command, "yarn", "add")
        || contains_command_pair(&command, "cargo", "install")
        || contains_command_pair(&command, "cargo", "add")
    {
        EffectClass::DEPENDENCY_INSTALL
    } else {
        EffectClass::COMMAND_EXEC
    }
}

fn contains_command_pair(command: &str, first: &str, second: &str) -> bool {
    command
        .split(|character| matches!(character, ';' | '&' | '|' | '\n'))
        .any(|segment| {
            let mut tokens = segment.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == first && tokens.next() == Some(second) {
                    return true;
                }
            }
            false
        })
}

fn default_operation(effect_class: EffectClass) -> &'static str {
    match effect_class {
        EffectClass::FILE_WRITE => "write",
        EffectClass::FILE_DELETE => "delete",
        EffectClass::FILE_MOVE => "move",
        EffectClass::COMMAND_EXEC => "execute",
        EffectClass::NETWORK_EGRESS => "connect",
        EffectClass::PROCESS_SPAWN => "spawn",
        EffectClass::CREDENTIAL_ACCESS => "access",
        EffectClass::DEPENDENCY_INSTALL => "install",
        EffectClass::VCS_COMMIT => "commit",
        EffectClass::VCS_PUSH => "push",
        EffectClass::PUBLISH => "publish",
    }
}

fn command_has_rewrite_flag(command: Option<&str>) -> bool {
    let command = command.unwrap_or_default().to_ascii_lowercase();
    command.contains("--force")
        || command.contains("--delete")
        || command
            .split_whitespace()
            .any(|token| token == "-f" || token == "-d")
}

fn rewrite_push_requires_approval(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let Some(command) = command_value(object) else {
        return false;
    };
    let command = command.trim().to_ascii_lowercase();
    contains_command_pair(&command, "git", "push") && command_has_rewrite_flag(Some(&command))
}

fn is_destructive_command(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let Some(command) = command_value(object) else {
        return false;
    };
    let command = command.to_ascii_lowercase();
    let destructive_segment = |segment: &str| {
        let segment = segment.trim_start();
        if let Some(rest) = segment.strip_prefix("rm") {
            let rest = rest.trim_start();
            if rest.starts_with("--recursive") {
                return true;
            }
            if let Some(option) = rest.split_whitespace().next() {
                if option.starts_with('-') && option.contains('r') {
                    return true;
                }
            }
        }
        (segment.starts_with("remove-item") && segment.contains("-recurse"))
            || contains_command_pair(segment, "git", "clean")
            || segment.starts_with("dropdb")
            || contains_command_pair(segment, "terraform", "apply")
            || contains_command_pair(segment, "terraform", "destroy")
    };
    command
        .split(|character| matches!(character, ';' | '&' | '|'))
        .any(destructive_segment)
        || command
            .split('|')
            .collect::<Vec<_>>()
            .windows(2)
            .any(|parts| {
                let left = parts[0].trim_start();
                let is_curl = left.split_whitespace().any(|token| token == "curl");
                is_curl && {
                    let right = parts[1].trim_start();
                    right.starts_with("sh") || right.starts_with("bash")
                }
            })
}

fn resolve_source_revision(payload: &Map<String, Value>) -> Option<String> {
    let workspace = first_string(payload, &["cwd", "workspace"])
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let git_dir = resolve_git_dir(&workspace)?;
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    if valid_revision(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference = head.strip_prefix("ref: ")?.trim();
    if !valid_git_reference(reference) {
        return None;
    }
    let common_dir = resolve_common_git_dir(&git_dir).unwrap_or_else(|| git_dir.clone());
    for root in [&git_dir, &common_dir] {
        if let Ok(value) = fs::read_to_string(root.join(reference)) {
            let value = value.trim();
            if valid_revision(value) {
                return Some(value.to_ascii_lowercase());
            }
        }
    }
    for root in [&git_dir, &common_dir] {
        if let Some(value) = revision_from_packed_refs(root, reference) {
            return Some(value);
        }
    }
    None
}

fn resolve_git_dir(workspace: &Path) -> Option<PathBuf> {
    // A tool call may run from any subdirectory of the checkout, so walk toward the
    // filesystem root until a `.git` marker appears. Resolving only `workspace/.git`
    // denied every effect raised from a subdirectory, which locked the shell out.
    workspace.ancestors().find_map(git_dir_at)
}

fn git_dir_at(workspace: &Path) -> Option<PathBuf> {
    let marker = workspace.join(".git");
    if marker.is_dir() {
        return Some(marker);
    }
    let marker_text = fs::read_to_string(&marker).ok()?;
    let relative = marker_text.trim().strip_prefix("gitdir: ")?.trim();
    let candidate = PathBuf::from(relative);
    Some(if candidate.is_absolute() {
        candidate
    } else {
        workspace.join(candidate)
    })
}

fn resolve_common_git_dir(git_dir: &Path) -> Option<PathBuf> {
    let value = fs::read_to_string(git_dir.join("commondir")).ok()?;
    let relative = PathBuf::from(value.trim());
    Some(if relative.is_absolute() {
        relative
    } else {
        git_dir.join(relative)
    })
}

fn revision_from_packed_refs(git_dir: &Path, reference: &str) -> Option<String> {
    let packed = fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            return None;
        }
        let mut fields = line.split_whitespace();
        let revision = fields.next()?;
        let name = fields.next()?;
        (name == reference && valid_revision(revision)).then(|| revision.to_ascii_lowercase())
    })
}

fn valid_git_reference(reference: &str) -> bool {
    !reference.is_empty()
        && !Path::new(reference).is_absolute()
        && reference
            .split(['/', '\\'])
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_request() -> Result<Vec<u8>, HookError> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| HookError::Io(error.to_string()))?;
    if input.iter().all(u8::is_ascii_whitespace) {
        return Err(HookError::invalid("request is empty"));
    }
    Ok(input)
}

fn write_response(response: HookResponse) -> Result<(), HookError> {
    let bytes = serde_json::to_vec(&response.to_value())
        .map_err(|error| HookError::Serialization(error.to_string()))?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout
        .write_all(&bytes)
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .flush()
        .map_err(|error| HookError::Io(error.to_string()))
}

fn error_response(error: HookError) -> HookResponse {
    response_for_error("unknown".into(), error)
}

fn main() {
    let response = match read_request() {
        Ok(input) => match HookRequest::parse(&input) {
            Ok(request) => dispatch(request),
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    };
    let _ = write_response(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn effect(effect_class: EffectClass) -> EffectRequest {
        EffectRequest {
            schema_version: 1,
            request_id: RequestId::new("test-request").expect("valid test request id"),
            task_id: TaskId::new("test-task").expect("valid test task id"),
            requested_by: AgentId::new("test-agent").expect("valid test agent id"),
            effect_class,
            target: "test-target".into(),
            operation: default_operation(effect_class).into(),
            preview: None,
            source_revision: "test-revision".into(),
            approval_required: false,
        }
    }

    fn pre_effect(command: &str) -> HookRequest {
        HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
        }
    }

    fn temporary_repository() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "legion-hook-source-revision-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join(".git/refs/heads")).expect("create test git directory");
        root
    }

    #[test]
    fn source_revision_reads_git_metadata_without_spawning() {
        let root = temporary_repository();
        let revision = "0123456789abcdef0123456789abcdef01234567";
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write HEAD");
        fs::write(root.join(".git/refs/heads/main"), format!("{revision}\n"))
            .expect("write loose ref");
        let payload = json!({"cwd": root.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision)
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn source_revision_resolves_from_a_subdirectory() {
        let root = temporary_repository();
        let revision = "abcdef0123456789abcdef0123456789abcdef01";
        fs::write(
            root.join(".git/HEAD"),
            "ref: refs/heads/main
",
        )
        .expect("write HEAD");
        fs::write(
            root.join(".git/refs/heads/main"),
            format!(
                "{revision}
"
            ),
        )
        .expect("write loose ref");
        let nested = root.join("engine/bins/legion-hook");
        fs::create_dir_all(&nested).expect("create nested directory");
        let payload = json!({"cwd": nested.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision),
            "a tool call from a subdirectory must still resolve the checkout revision"
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn multi_edit_classifies_as_file_write() {
        assert_eq!(
            parse_effect_class(None, Some("MultiEdit"), None),
            Some(EffectClass::FILE_WRITE),
            "MultiEdit is matched in hooks.json and must classify, not fail closed"
        );
    }

    #[test]
    fn source_revision_reads_packed_refs_without_spawning() {
        let root = temporary_repository();
        let revision = "89abcdef0123456789abcdef0123456789abcdef";
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write HEAD");
        fs::write(
            root.join(".git/packed-refs"),
            format!("# pack-refs with: peeled\n{revision} refs/heads/main\n"),
        )
        .expect("write packed refs");
        let payload = json!({"workspace": root.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision)
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn absent_policy_allows_every_effect_class() {
        for effect_class in [
            EffectClass::FILE_WRITE,
            EffectClass::FILE_DELETE,
            EffectClass::FILE_MOVE,
            EffectClass::COMMAND_EXEC,
            EffectClass::NETWORK_EGRESS,
            EffectClass::PROCESS_SPAWN,
            EffectClass::CREDENTIAL_ACCESS,
            EffectClass::DEPENDENCY_INSTALL,
            EffectClass::VCS_COMMIT,
            EffectClass::VCS_PUSH,
            EffectClass::PUBLISH,
        ] {
            let response = authorize_effect("PreToolUse".into(), &effect(effect_class), None);
            assert!(response.allowed, "ambient effect denied: {effect_class:?}");
            assert!(response.code.is_none());
            assert_eq!(response.enforcement_health, "strong");
        }
    }

    #[test]
    fn hard_gates_precede_ambient_fallback() {
        for (command, code) in [
            (
                "rm -rf /tmp/legion-hook-test",
                "ARC_EFFECT_CLASS_UNAUTHORIZED",
            ),
            (
                "echo ok; rm -fr /tmp/legion-hook-test",
                "ARC_EFFECT_CLASS_UNAUTHORIZED",
            ),
            ("git push --force origin main", "ARC_APPROVAL_REQUIRED"),
            ("git  push --delete origin main", "ARC_APPROVAL_REQUIRED"),
        ] {
            let response = dispatch(pre_effect(command));
            assert!(!response.allowed, "hard gate allowed: {command}");
            assert_eq!(response.code.as_deref(), Some(code));
            assert_eq!(response.enforcement_health, "strong");
        }
    }

    #[test]
    fn unknown_event_dispatch_fails_closed() {
        let response = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "unknown-event".into(),
            payload: json!({}),
        });
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_HOST_EVENT_INVALID"));
        assert_eq!(response.enforcement_health, "strong");
    }
}
