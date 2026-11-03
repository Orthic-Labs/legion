use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    error::McpError,
    tools::{NativeApi, ToolService, PROTOCOL_VERSION},
};

/// A release identity that has already passed the full runtime/integration
/// comparison. The release owner decides the identity shape; the transport
/// returns it unchanged to the MCP client after successful initialization.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedReleaseBinding {
    identity: Value,
}

impl VerifiedReleaseBinding {
    pub fn new(identity: Value) -> Self {
        Self { identity }
    }

    pub fn identity(&self) -> &Value {
        &self.identity
    }
}

/// A fail-closed binding outcome. Its repair text is intentionally the only
/// failure detail carried across the MCP boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingFailure {
    repair: String,
}

impl BindingFailure {
    pub fn new(repair: impl Into<String>) -> Self {
        Self {
            repair: repair.into(),
        }
    }

    pub fn repair(&self) -> &str {
        &self.repair
    }
}

/// Verifies that the current runtime and client assets form one release before
/// MCP tools become visible. The later release/application composition owns
/// the concrete manifest checks; this transport remains independent of it.
pub trait ReleaseBindingGate: Send + Sync {
    fn verify_binding(&self) -> Result<VerifiedReleaseBinding, BindingFailure>;
}

impl<F> ReleaseBindingGate for F
where
    F: Fn() -> Result<VerifiedReleaseBinding, BindingFailure> + Send + Sync,
{
    fn verify_binding(&self) -> Result<VerifiedReleaseBinding, BindingFailure> {
        self()
    }
}

/// Safe placeholder for a composition that has no release verifier yet.
/// It prevents accidental tools exposure while preserving the exact repair
/// instruction that a real verifier would return.
pub struct RejectingBindingGate {
    failure: BindingFailure,
}

impl RejectingBindingGate {
    pub fn new(repair: impl Into<String>) -> Self {
        Self {
            failure: BindingFailure::new(repair),
        }
    }
}

impl ReleaseBindingGate for RejectingBindingGate {
    fn verify_binding(&self) -> Result<VerifiedReleaseBinding, BindingFailure> {
        Err(self.failure.clone())
    }
}

enum SessionState {
    AwaitingInitialization,
    Ready(VerifiedReleaseBinding),
    BindingFailed(BindingFailure),
}

/// One reusable MCP server instance. It keeps the caller-provided API for its
/// entire lifetime and exposes no socket, daemon, process, interpreter, or
/// shell execution path.
pub struct Server<A> {
    tools: ToolService<A>,
    binding_gate: Arc<dyn ReleaseBindingGate>,
    state: Mutex<SessionState>,
}

impl<A: NativeApi> Server<A> {
    pub fn new<G>(api: Arc<A>, binding_gate: Arc<G>) -> Self
    where
        G: ReleaseBindingGate + 'static,
    {
        Self {
            tools: ToolService::new(api),
            binding_gate,
            state: Mutex::new(SessionState::AwaitingInitialization),
        }
    }

    pub async fn handle(&self, request: Value) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(error_response(Value::Null, McpError::InvalidRequest));
        };
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        let notification = !object.contains_key("id");
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return (!notification).then(|| error_response(id, McpError::InvalidRequest));
        }
        let method = match object.get("method").and_then(Value::as_str) {
            Some(value) => value,
            None => return (!notification).then(|| error_response(id, McpError::InvalidRequest)),
        };
        if method == "notifications/initialized" || method == "notifications/cancelled" {
            return None;
        }
        let result = match method {
            "initialize" => self.initialize(),
            "tools/list" => self.list_tools(),
            "tools/call" => self.call(object.get("params")).await,
            _ => Err(McpError::MethodNotFound),
        };
        if notification {
            None
        } else {
            Some(match result {
                Ok(value) => success_response(id, value),
                Err(error) => error_response(id, error),
            })
        }
    }

    fn initialize(&self) -> Result<Value, McpError> {
        let mut state = recover_lock(&self.state);
        let binding = match &*state {
            SessionState::Ready(binding) => binding.clone(),
            SessionState::BindingFailed(failure) => {
                return Err(McpError::ReleaseBinding(failure.repair().to_owned()))
            }
            SessionState::AwaitingInitialization => match self.binding_gate.verify_binding() {
                Ok(binding) => {
                    *state = SessionState::Ready(binding.clone());
                    binding
                }
                Err(failure) => {
                    let repair = failure.repair().to_owned();
                    *state = SessionState::BindingFailed(failure);
                    return Err(McpError::ReleaseBinding(repair));
                }
            },
        };
        Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "legion", "version": env!("CARGO_PKG_VERSION")},
            "releaseIdentity": binding.identity(),
        }))
    }

    fn list_tools(&self) -> Result<Value, McpError> {
        self.require_ready()?;
        Ok(json!({"tools": self.tools.definitions()}))
    }

    async fn call(&self, params: Option<&Value>) -> Result<Value, McpError> {
        self.require_ready()?;
        let params = params
            .and_then(Value::as_object)
            .ok_or(McpError::InvalidParams)?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or(McpError::InvalidParams)?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        Ok(self.tools.call(name, &arguments).await)
    }

    fn require_ready(&self) -> Result<(), McpError> {
        match &*recover_lock(&self.state) {
            SessionState::AwaitingInitialization => Err(McpError::InitializationRequired),
            SessionState::Ready(_) => Ok(()),
            SessionState::BindingFailed(failure) => {
                Err(McpError::ReleaseBinding(failure.repair().to_owned()))
            }
        }
    }
}

pub async fn run_stdio<A, G>(api: Arc<A>, binding_gate: Arc<G>) -> std::io::Result<()>
where
    A: NativeApi,
    G: ReleaseBindingGate + 'static,
{
    let server = Server::new(api, binding_gate);
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => server.handle(request).await,
            Err(_) => Some(error_response(Value::Null, McpError::Parse)),
        };
        if let Some(response) = response {
            write_response(&mut stdout, &response).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error_response(id: Value, error: McpError) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":error.code(),"message":error.message(),"data":error.data()}})
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Value,
) -> std::io::Result<()> {
    writer.write_all(response.to_string().as_bytes()).await?;
    writer.write_all(b"\n").await
}
