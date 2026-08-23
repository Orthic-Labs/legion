use std::{path::Path, sync::Arc};

use legion_application::{
    NativeApplication, NativeApplicationError, NativeOperation, NativeOperationResult, ReportFormat,
};
use legion_runtime::RuntimeError;
use serde_json::{json, Map, Value};

use crate::error::McpError;

pub const PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_OUTPUT_BYTES: usize = 1_000_000;

/// The MCP adapter delegates semantics to this canonical API. It does not own policy,
/// provider selection, filesystem inspection, or report generation.
pub trait NativeApi: Send + Sync {
    fn invoke(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError>;
}

/// Concrete seam used by the binary to bind the protocol to the canonical
/// engine. The adapter forwards requests without interpreting engine payloads.
pub trait NativeEngine: Send + Sync {
    fn execute_tool(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError>;
}

pub struct EngineAdapter {
    engine: Arc<dyn NativeEngine>,
}

impl EngineAdapter {
    pub fn new(engine: Arc<dyn NativeEngine>) -> Self {
        Self { engine }
    }
}

impl NativeApi for EngineAdapter {
    fn invoke(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError> {
        self.engine.execute_tool(operation, arguments)
    }
}

/// MCP-to-application forwarding adapter. It owns no policy, provider, or
/// report state; one explicitly composed `NativeApplication` serves every
/// request handled by this process.
pub struct NativeApplicationEngine {
    application: Arc<NativeApplication>,
}

impl NativeApplicationEngine {
    pub fn new(application: Arc<NativeApplication>) -> Self {
        Self { application }
    }
}

impl NativeEngine for NativeApplicationEngine {
    fn execute_tool(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError> {
        let native_operation = match operation {
            "legion_list_providers"
            | "legion_list_languages"
            | "legion_list_families"
            | "legion_list_skills" => NativeOperation::Catalog,
            "legion_get_run" | "legion_get_finding" | "legion_explain" => {
                NativeOperation::Report(ReportFormat::Json)
            }
            "legion_doctor" => NativeOperation::Doctor {
                repository_id: required_root(arguments)?,
            },
            "legion_plan" => NativeOperation::Plan {
                repository_id: required_root(arguments)?,
                providers: self.application.provider_specs(),
                signing_key: None,
            },
            "legion_audit" => NativeOperation::Audit {
                repository_id: required_root(arguments)?,
                providers: self.application.provider_specs(),
                signing_key: None,
            },
            "legion_verify" => NativeOperation::Verify {
                repository_id: required_root(arguments)?,
                providers: self.application.provider_specs(),
                signing_key: None,
            },
            _ => {
                return Err(RuntimeError::Policy(
                    "unsupported native MCP operation".into(),
                ))
            }
        };
        let result = invoke_application(Arc::clone(&self.application), native_operation)?;
        operation_result(operation, arguments, result)
    }
}

fn invoke_application(
    application: Arc<NativeApplication>,
    operation: NativeOperation,
) -> Result<NativeOperationResult, RuntimeError> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                RuntimeError::Policy(format!("native application runtime unavailable: {error}"))
            })?;
        runtime
            .block_on(application.invoke(operation))
            .map_err(application_error)
    })
    .join()
    .map_err(|_| RuntimeError::Policy("native application invocation panicked".into()))?
}

fn application_error(error: NativeApplicationError) -> RuntimeError {
    RuntimeError::Policy(format!("native application operation failed: {error}"))
}

fn required_root(arguments: &Value) -> Result<String, RuntimeError> {
    arguments
        .get("root")
        .and_then(Value::as_str)
        .filter(|root| !root.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| RuntimeError::InvalidTask("root is required".into()))
}

fn operation_result(
    operation: &str,
    arguments: &Value,
    result: NativeOperationResult,
) -> Result<Value, RuntimeError> {
    match result {
        NativeOperationResult::Catalog(catalog) => {
            let entries = catalog
                .entries
                .iter()
                .map(|entry| entry.canonical_id.clone())
                .collect::<Vec<_>>();
            Ok(json!({"version": catalog.schema_version, "entries": entries}))
        }
        NativeOperationResult::Report(report) => serde_json::from_str(&report)
            .map_err(|_| RuntimeError::Policy("native report was not valid JSON".into())),
        NativeOperationResult::Doctor {
            repository_id,
            inventory_digest,
            catalog_entries,
            provider_count,
        } => Ok(
            json!({"operation": operation, "root": repository_id, "status": "complete", "inventoryDigest": inventory_digest, "catalogEntries": catalog_entries, "providerCount": provider_count}),
        ),
        NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            providers,
        } => Ok(
            json!({"operation": operation, "root": repository_id, "status": "complete", "planDigest": plan_digest, "providers": providers}),
        ),
        NativeOperationResult::Audit(report) => Ok(json!({
            "operation": operation,
            "root": arguments.get("root"),
            "status": if report.gaps.is_empty() { "complete" } else { "partial" },
            "gaps": report.gaps,
        })),
        NativeOperationResult::Verification {
            repository_id,
            plan_digest,
            inventory_digest,
        } => Ok(
            json!({"operation": operation, "root": repository_id, "status": "complete", "planDigest": plan_digest, "inventoryDigest": inventory_digest}),
        ),
        NativeOperationResult::Invocation(outcome) => Ok(json!({
            "operation": operation,
            "root": arguments.get("root"),
            "status": if outcome.adjudication.complete { "complete" } else { "partial" },
            "gaps": outcome.adjudication.gaps,
        })),
    }
}

#[derive(Clone)]
pub struct ToolService<A> {
    api: Arc<A>,
}

impl<A: NativeApi> ToolService<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self { api }
    }

    pub fn call(&self, name: &str, arguments: &Value) -> Value {
        match dispatch(self.api.as_ref(), name, arguments) {
            Ok(value) => json!({
                "content": [{"type": "text", "text": value.to_string()}],
                "structuredContent": value,
                "isError": false
            }),
            Err(error) => json!({
                "content": [{"type": "text", "text": error.message()}],
                "isError": true
            }),
        }
    }
}

pub fn tool_definitions() -> Vec<Value> {
    let root = |mut properties: Map<String, Value>| {
        properties.insert("root".into(), json!({"type":"string","minLength":1}));
        json!({"type":"object","required":["root"],"additionalProperties":false,"properties":properties})
    };
    let closed = |properties: Map<String, Value>, required: &[&str]| json!({"type":"object","required":required,"additionalProperties":false,"properties":properties});
    vec![
        json!({"name":"legion_doctor","description":"Run legion doctor on a repository.","inputSchema":root(Map::new())}),
        json!({"name":"legion_plan","description":"Build and seal an audit plan.","inputSchema":root(properties([("profile", json!({"type":"string","enum":["fast","standard","full","release"]}))]))}),
        json!({"name":"legion_audit","description":"Run a complete audit.","inputSchema":root(properties([("profile", json!({"type":"string","enum":["fast","standard","full","release"]}))]))}),
        json!({"name":"legion_verify","description":"Verify a prior run out of band.","inputSchema":root(properties([("priorRun", json!({}))]))}),
        json!({"name":"legion_get_run","description":"Read a run artifact.","inputSchema":closed(properties([
            ("run", json!({"type":"string","minLength":1})), ("artifact", json!({"type":"string"}))
        ]), &["run"])}),
        json!({"name":"legion_get_finding","description":"Read a finding from a run.","inputSchema":closed(properties([
            ("run", json!({"type":"string","minLength":1})), ("findingId", json!({"type":"string","minLength":1}))
        ]), &["run","findingId"])}),
        json!({"name":"legion_explain","description":"Explain a finding or gap.","inputSchema":closed(properties([
            ("id", json!({"type":"string","minLength":1})), ("run", json!({"type":"string"}))
        ]), &["id"])}),
        json!({"name":"legion_list_providers","description":"List providers.","inputSchema":closed(Map::new(), &[])}),
        json!({"name":"legion_list_languages","description":"List languages.","inputSchema":closed(Map::new(), &[])}),
        json!({"name":"legion_list_families","description":"List audit families.","inputSchema":closed(Map::new(), &[])}),
        json!({"name":"legion_list_skills","description":"List bundled skills.","inputSchema":closed(Map::new(), &[])}),
    ]
}

fn properties(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn schema(name: &str) -> Option<Value> {
    tool_definitions()
        .into_iter()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|tool| tool.get("inputSchema").cloned())
}

fn dispatch<A: NativeApi>(api: &A, name: &str, arguments: &Value) -> Result<Value, McpError> {
    let Some(input_schema) = schema(name) else {
        return Err(McpError::ToolNotFound);
    };
    validate_arguments(&input_schema, arguments)?;
    validate_scope(name, arguments)?;
    let result = api.invoke(name, arguments).map_err(McpError::from)?;
    if serde_json::to_vec(&result)
        .map_err(|_| McpError::Backend)?
        .len()
        > MAX_OUTPUT_BYTES
    {
        return Err(McpError::OutputLimit);
    }
    Ok(result)
}

fn validate_arguments(schema: &Value, arguments: &Value) -> Result<(), McpError> {
    let Some(args) = arguments.as_object() else {
        return Err(McpError::InvalidParams);
    };
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(McpError::InvalidParams)?;
    if args.keys().any(|key| !properties.contains_key(key)) {
        return Err(McpError::InvalidParams);
    }
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !args.contains_key(required) {
            return Err(McpError::InvalidParams);
        }
    }
    for (key, rule) in properties {
        let Some(value) = args.get(key) else {
            continue;
        };
        if rule.get("type").and_then(Value::as_str) == Some("string") {
            let Some(text) = value.as_str() else {
                return Err(McpError::InvalidParams);
            };
            if rule
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|min| text.chars().count() < min as usize)
            {
                return Err(McpError::InvalidParams);
            }
            if let Some(options) = rule.get("enum").and_then(Value::as_array) {
                if !options.iter().any(|option| option.as_str() == Some(text)) {
                    return Err(McpError::InvalidParams);
                }
            }
        }
    }
    Ok(())
}

fn validate_scope(name: &str, arguments: &Value) -> Result<(), McpError> {
    let Some(args) = arguments.as_object() else {
        return Err(McpError::InvalidParams);
    };
    if [
        "legion_doctor",
        "legion_plan",
        "legion_audit",
        "legion_verify",
    ]
    .contains(&name)
    {
        let root = args
            .get("root")
            .and_then(Value::as_str)
            .ok_or(McpError::ScopeDenied)?;
        let path = Path::new(root);
        if root == "." || root == ".." || root.contains('\0') || !path.is_absolute() {
            return Err(McpError::ScopeDenied);
        }
    }
    for field in ["run", "artifact", "findingId", "id"] {
        if let Some(value) = args.get(field).and_then(Value::as_str) {
            if value.is_empty() || value.contains('\0') {
                return Err(McpError::ScopeDenied);
            }
        }
    }
    Ok(())
}
