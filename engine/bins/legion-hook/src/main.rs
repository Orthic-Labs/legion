#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Instant;

use legion_application::{NativeApplication, NativeApplicationConfig};
use legion_contracts::{AgentId, EffectClass, EffectRequest, RequestId, TaskId};
use legion_runtime::RuntimeError;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

mod error;
mod protocol;

use error::HookError;
use protocol::{HookRequest, HookResponse};

/// Typed seam to canonical native policy/runtime APIs. The hook only forwards
/// the host event and lifecycle context; it never interprets policy rules.
pub trait NativeApi: Send + Sync {
    fn invoke(
        &self,
        operation: &str,
        arguments: &Value,
        context: &HookContext,
    ) -> Result<Value, RuntimeError>;
}

#[derive(Clone)]
pub struct HookContext {
    deadline: Instant,
    cancellation: CancellationToken,
}

impl HookContext {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Run one hook invocation without a composition root. This path is
/// intentionally fail-closed; hosts must use `dispatch_with_application`.
pub async fn dispatch(request: HookRequest) -> HookResponse {
    let event_type = request.event_type.clone();
    if let Err(error) = request.validate() {
        return response_for_error(event_type, error);
    }
    if !request.is_effectful() {
        return HookResponse::allowed(request.event_type);
    }
    response_for_error(
        event_type,
        HookError::RuntimeUnavailable("native application is not configured".into()),
    )
}

/// Run one hook invocation against the explicitly supplied shared native
/// application. The adapter owns framing and lifecycle only; policy, provider
/// registry, storage, and worker state remain in the application.
pub async fn dispatch_with_application(
    request: HookRequest,
    application: Arc<NativeApplication>,
) -> HookResponse {
    let api = NativeApplicationApi::new(application);
    dispatch_with(request, &api).await
}

pub async fn dispatch_with<A: NativeApi>(request: HookRequest, api: &A) -> HookResponse {
    let event_type = request.event_type.clone();
    if let Err(error) = request.validate() {
        return response_for_error(event_type, error);
    }
    let started = Instant::now();
    let cancellation = request.cancellation();
    if cancellation.is_cancelled() {
        return response_for_error(request.event_type, HookError::Cancelled);
    }
    let deadline = request.deadline(started);
    if Instant::now() >= deadline {
        return response_for_error(request.event_type, HookError::DeadlineExceeded);
    }

    // A blocking hook is effect-scoped. Events with no effect do not require a
    // policy runtime and remain observable to their host. An effect-bearing
    // request must have the injected native runtime available; this thin
    // executable never invents policy or falls back to an interpreter.
    if request.is_effectful() {
        let context = HookContext {
            deadline,
            cancellation,
        };
        let arguments = Value::Object(request.payload.into_iter().collect());
        let result = api.invoke("hook.pre_tool_use", &arguments, &context);
        if context.is_cancelled() {
            return response_for_error(request.event_type, HookError::Cancelled);
        }
        if Instant::now() >= context.deadline() {
            return response_for_error(request.event_type, HookError::DeadlineExceeded);
        }
        return match result {
            Ok(value) => native_response(request.event_type, value),
            Err(error) => response_for_error(request.event_type, error.into()),
        };
    }
    HookResponse::allowed(request.event_type)
}

/// Hook-to-application forwarding adapter. It converts the versioned hook
/// payload into the canonical effect request and delegates authorization once.
pub struct NativeApplicationApi {
    application: Arc<NativeApplication>,
}

impl NativeApplicationApi {
    pub fn new(application: Arc<NativeApplication>) -> Self {
        Self { application }
    }
}

impl NativeApi for NativeApplicationApi {
    fn invoke(&self, _: &str, arguments: &Value, _: &HookContext) -> Result<Value, RuntimeError> {
        let object = arguments
            .as_object()
            .ok_or_else(|| RuntimeError::InvalidTask("hook payload must be an object".into()))?;
        let target = target_field(object).unwrap_or_else(|| "hook".into());
        let operation = string_field(object, "operation")
            .or_else(|| string_field(object, "tool_name"))
            .unwrap_or_else(|| "hook.pre_tool_use".into());
        let requested_by =
            AgentId::new(string_field(object, "agent_id").unwrap_or_else(|| "legion-hook".into()))
                .map_err(|error| RuntimeError::Policy(error.to_string()))?;
        let request_id = RequestId::new(
            string_field(object, "request_id")
                .or_else(|| string_field(object, "tool_use_id"))
                .unwrap_or_else(|| format!("hook:{operation}:{target}")),
        )
        .map_err(|error| RuntimeError::Policy(error.to_string()))?;
        let task_id = TaskId::new(
            string_field(object, "task_id")
                .or_else(|| string_field(object, "tool_use_id"))
                .unwrap_or_else(|| request_id.as_str().to_owned()),
        )
        .map_err(|error| RuntimeError::Policy(error.to_string()))?;
        let request = EffectRequest {
            schema_version: 1,
            request_id,
            task_id,
            requested_by,
            effect_class: effect_class(object),
            target,
            operation,
            preview: string_field(object, "preview"),
            source_revision: string_field(object, "source_revision")
                .unwrap_or_else(|| "legion-hook-protocol-v1".into()),
            approval_required: object
                .get("approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        self.application
            .authorize_hook(&request)
            .map_err(|error| RuntimeError::Policy(error.to_string()))?;
        Ok(json!({"allowed": true, "code": "allowed", "reason": "native policy authorized"}))
    }
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn target_field(object: &serde_json::Map<String, Value>) -> Option<String> {
    string_field(object, "target")
        .or_else(|| string_field(object, "path"))
        .or_else(|| {
            object
                .get("tool_input")
                .and_then(Value::as_object)
                .and_then(|input| string_field(input, "file_path"))
        })
        .or_else(|| {
            object
                .get("tool_input")
                .and_then(Value::as_object)
                .and_then(|input| string_field(input, "command"))
        })
        .or_else(|| string_field(object, "cwd"))
}

fn effect_class(object: &serde_json::Map<String, Value>) -> EffectClass {
    let tool = string_field(object, "tool_name");
    match string_field(object, "effect_class")
        .or_else(|| tool.clone())
        .as_deref()
    {
        Some("FILE_WRITE") => EffectClass::FILE_WRITE,
        Some("FILE_DELETE") => EffectClass::FILE_DELETE,
        Some("FILE_MOVE") => EffectClass::FILE_MOVE,
        Some("NETWORK_EGRESS") => EffectClass::NETWORK_EGRESS,
        Some("PROCESS_SPAWN") => EffectClass::PROCESS_SPAWN,
        Some("VCS_COMMIT") => EffectClass::VCS_COMMIT,
        Some("VCS_PUSH") => EffectClass::VCS_PUSH,
        Some("PUBLISH") => EffectClass::PUBLISH,
        Some("Write" | "Edit" | "NotebookEdit") => EffectClass::FILE_WRITE,
        _ => EffectClass::COMMAND_EXEC,
    }
}

fn native_response(event_type: String, value: Value) -> HookResponse {
    let Some(object) = value.as_object() else {
        return response_for_error(
            event_type,
            HookError::RuntimeUnavailable("native API returned a non-object response".into()),
        );
    };
    let Some(allowed) = object.get("allowed").and_then(Value::as_bool) else {
        return response_for_error(
            event_type,
            HookError::RuntimeUnavailable("native API response omitted allowed".into()),
        );
    };
    let code = object
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("native_denied");
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("native API decision");
    if allowed {
        HookResponse {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::RESPONSE_KIND,
            event_type,
            allowed,
            code: None,
            reason: reason.into(),
            enforcement_health: "strong",
        }
    } else {
        HookResponse::denied(event_type, code, reason, "strong")
    }
}

fn response_for_error(event_type: String, error: HookError) -> HookResponse {
    let health = match error {
        HookError::InvalidRequest(_)
        | HookError::MalformedInput(_)
        | HookError::UnsupportedVersion(_) => "strong",
        HookError::Cancelled | HookError::DeadlineExceeded => "strong",
        HookError::RuntimeUnavailable(_) | HookError::Io(_) | HookError::Serialization(_) => {
            "unsupported"
        }
    };
    HookResponse::denied(event_type, error.code(), error.public_message(), health)
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

fn load_application() -> Result<Arc<NativeApplication>, HookError> {
    let input = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG").map_err(|_| {
        HookError::RuntimeUnavailable(
            "versioned native application configuration is missing".into(),
        )
    })?;
    NativeApplicationConfig::from_versioned_json(&input)
        .and_then(NativeApplicationConfig::build)
        .map(Arc::new)
        .map_err(|error| {
            HookError::RuntimeUnavailable(format!(
                "native application configuration rejected: {error}"
            ))
        })
}

fn main() {
    let response = match read_request() {
        Ok(input) => match HookRequest::parse(&input) {
            Ok(request) => match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(runtime) if request.is_effectful() => match load_application() {
                    Ok(application) => {
                        runtime.block_on(dispatch_with_application(request, application))
                    }
                    Err(error) => response_for_error(request.event_type, error),
                },
                Ok(runtime) => runtime.block_on(dispatch(request)),
                Err(error) => error_response(HookError::RuntimeUnavailable(error.to_string())),
            },
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    };
    let _ = write_response(response);
}

#[allow(dead_code)]
fn _cancellation_token_is_runtime_owned(token: CancellationToken) -> CancellationToken {
    token
}
