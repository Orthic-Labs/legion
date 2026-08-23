use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    error::McpError,
    tools::{NativeApi, ToolService, PROTOCOL_VERSION},
};

pub struct Server<A> {
    tools: ToolService<A>,
}

impl<A: NativeApi> Server<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self {
            tools: ToolService::new(api),
        }
    }

    pub fn handle(&self, request: Value) -> Option<Value> {
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
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "legion", "version": "0.1.0"}
            })),
            "tools/list" => Ok(json!({"tools": crate::tools::tool_definitions()})),
            "tools/call" => self.call(object.get("params")),
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

    fn call(&self, params: Option<&Value>) -> Result<Value, McpError> {
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
        Ok(self.tools.call(name, &arguments))
    }
}

pub async fn run_stdio<A: NativeApi>(api: Arc<A>) -> std::io::Result<()> {
    let server = Server::new(api);
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => server.handle(request),
            Err(_) => Some(error_response(Value::Null, McpError::Parse)),
        };
        if let Some(response) = response {
            stdout.write_all(response.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error_response(id: Value, error: McpError) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":error.code(),"message":error.message()}})
}

#[allow(dead_code)]
async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Value,
) -> std::io::Result<()> {
    writer.write_all(response.to_string().as_bytes()).await?;
    writer.write_all(b"\n").await
}
