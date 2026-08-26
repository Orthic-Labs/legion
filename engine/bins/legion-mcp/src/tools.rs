use std::{future::Future, pin::Pin, sync::Arc};

use legion_application::{
    NativeApplication, NativeApplicationError, NativeOperation, NativeOperationResult, ReportFormat,
};
use legion_runtime::RuntimeError;
use serde_json::{json, Map, Value};

use crate::error::McpError;

pub const PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_OUTPUT_BYTES: usize = 1_000_000;
pub type NativeFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, RuntimeError>> + Send + 'a>>;

/// The MCP adapter delegates semantics to this canonical API. It does not own policy,
/// provider selection, filesystem inspection, or report generation.
pub trait NativeApi: Send + Sync {
    /// The exact tool contract exposed by this API instance for its whole MCP
    /// session. The transport validates calls against this same snapshot.
    fn tool_definitions(&self) -> Vec<Value>;

    /// API-specific validation that cannot be represented by the MCP input
    /// schema. Generic callers use the safe no-op default; the legacy adapter
    /// keeps its existing repository and identifier scope checks.
    fn validate_tool_scope(&self, _operation: &str, _arguments: &Value) -> Result<(), McpError> {
        Ok(())
    }

    fn invoke(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError>;

    fn invoke_async<'a>(&'a self, operation: &'a str, arguments: &'a Value) -> NativeFuture<'a> {
        Box::pin(async move { self.invoke(operation, arguments) })
    }
}

/// Concrete seam used by the binary to bind the protocol to the canonical
/// engine. The adapter forwards requests without interpreting engine payloads.
pub trait NativeEngine: Send + Sync {
    fn tool_definitions(&self) -> Vec<Value>;

    fn validate_tool_scope(&self, operation: &str, arguments: &Value) -> Result<(), McpError>;

    fn execute_tool(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError>;

    fn execute_tool_async<'a>(
        &'a self,
        operation: &'a str,
        arguments: &'a Value,
    ) -> NativeFuture<'a> {
        Box::pin(async move { self.execute_tool(operation, arguments) })
    }
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
    fn tool_definitions(&self) -> Vec<Value> {
        self.engine.tool_definitions()
    }

    fn validate_tool_scope(&self, operation: &str, arguments: &Value) -> Result<(), McpError> {
        self.engine.validate_tool_scope(operation, arguments)
    }

    fn invoke(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError> {
        self.engine.execute_tool(operation, arguments)
    }

    fn invoke_async<'a>(&'a self, operation: &'a str, arguments: &'a Value) -> NativeFuture<'a> {
        self.engine.execute_tool_async(operation, arguments)
    }
}

/// MCP-to-application forwarding adapter. It owns no policy, provider, or
/// report state; one explicitly composed `NativeApplication` serves every
/// request handled by this process.
pub struct NativeApplicationEngine {
    application: Arc<NativeApplication>,
    repository_id: Option<String>,
}

impl NativeApplicationEngine {
    pub fn new(application: Arc<NativeApplication>) -> Self {
        Self {
            application,
            repository_id: None,
        }
    }

    pub fn for_repository(
        application: Arc<NativeApplication>,
        repository_id: impl Into<String>,
    ) -> Self {
        Self {
            application,
            repository_id: Some(repository_id.into()),
        }
    }
}

impl NativeEngine for NativeApplicationEngine {
    fn tool_definitions(&self) -> Vec<Value> {
        legacy_tool_definitions()
    }

    fn validate_tool_scope(&self, operation: &str, arguments: &Value) -> Result<(), McpError> {
        validate_legacy_scope(operation, arguments)
    }

    fn execute_tool(&self, operation: &str, arguments: &Value) -> Result<Value, RuntimeError> {
        let _ = (operation, arguments);
        Err(RuntimeError::Policy(NATIVE_ASYNC_ONLY_ERROR.into()))
    }

    fn execute_tool_async<'a>(
        &'a self,
        operation: &'a str,
        _arguments: &'a Value,
    ) -> NativeFuture<'a> {
        let application = Arc::clone(&self.application);
        let native_operation = match operation {
            "legion_list_providers"
            | "legion_list_languages"
            | "legion_list_families"
            | "legion_list_skills" => NativeOperation::Catalog,
            _ => {
                let Some(repository_id) = self.repository_id.clone() else {
                    return Box::pin(async {
                        Err(RuntimeError::Policy(NATIVE_ASYNC_ONLY_ERROR.into()))
                    });
                };
                match operation {
                    "legion_get_run" | "legion_get_finding" | "legion_explain" => {
                        NativeOperation::Report(ReportFormat::Json)
                    }
                    "legion_doctor" => NativeOperation::Doctor { repository_id },
                    "legion_plan" => NativeOperation::Plan {
                        repository_id: repository_id.clone(),
                        providers: application.provider_specs(),
                        signing_key: match audit_signing_key() {
                            Ok(key) => Some(key),
                            Err(error) => return Box::pin(async { Err(error) }),
                        },
                    },
                    "legion_audit" => NativeOperation::Audit {
                        repository_id: repository_id.clone(),
                        providers: application.provider_specs(),
                        signing_key: match audit_signing_key() {
                            Ok(key) => Some(key),
                            Err(error) => return Box::pin(async { Err(error) }),
                        },
                    },
                    "legion_verify" => NativeOperation::Verify {
                        repository_id,
                        providers: application.provider_specs(),
                        signing_key: match audit_signing_key() {
                            Ok(key) => Some(key),
                            Err(error) => return Box::pin(async { Err(error) }),
                        },
                    },
                    _ => {
                        return Box::pin(async {
                            Err(RuntimeError::Policy(
                                "unsupported native MCP operation".into(),
                            ))
                        })
                    }
                }
            }
        };
        Box::pin(async move {
            let result = application
                .invoke(native_operation)
                .await
                .map_err(application_error)?;
            operation_result(operation, result)
        })
    }
}

const NATIVE_ASYNC_ONLY_ERROR: &str =
    "native MCP application requires repository-bound asynchronous invocation";

fn application_error(error: NativeApplicationError) -> RuntimeError {
    RuntimeError::Policy(format!("native application operation failed: {error}"))
}

fn operation_result(operation: &str, result: NativeOperationResult) -> Result<Value, RuntimeError> {
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
            json!({"operation": operation, "repositoryId": repository_id, "status": "complete", "inventoryDigest": inventory_digest, "catalogEntries": catalog_entries, "providerCount": provider_count}),
        ),
        NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            plan_signature,
            providers,
        } => Ok(
            json!({"operation": operation, "repositoryId": repository_id, "status": "complete", "planDigest": plan_digest, "planSignature": plan_signature, "providers": providers}),
        ),
        NativeOperationResult::Audit(report) => Ok(json!({
            "operation": operation,
            "status": if report.gaps.is_empty() { "complete" } else { "partial" },
            "planDigest": report.plan_digest,
            "planSignature": report.plan_signature,
            "plannedProviders": report.planned_providers,
            "selectedLenses": report.selected_lenses,
            "lensesRan": report.lenses_ran,
            "gaps": report.gaps,
        })),
        NativeOperationResult::Verification {
            repository_id,
            plan_digest,
            inventory_digest,
        } => Ok(
            json!({"operation": operation, "repositoryId": repository_id, "status": "complete", "planDigest": plan_digest, "inventoryDigest": inventory_digest}),
        ),
        NativeOperationResult::Invocation(outcome) => Ok(json!({
            "operation": operation,
            "status": if outcome.adjudication.complete { "complete" } else { "partial" },
            "gaps": outcome.adjudication.gaps,
        })),
    }
}

fn audit_signing_key() -> Result<Vec<u8>, RuntimeError> {
    std::env::var_os("AUDIT_PLAN_SIGNING_KEY")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().as_bytes().to_vec())
        .ok_or_else(|| {
            RuntimeError::Policy("host-injected audit plan signing key is missing".into())
        })
}

#[derive(Clone)]
pub struct ToolService<A> {
    api: Arc<A>,
    definitions: Vec<Value>,
}

impl<A: NativeApi> ToolService<A> {
    pub fn new(api: Arc<A>) -> Self {
        let definitions = api.tool_definitions();
        Self { api, definitions }
    }

    pub fn definitions(&self) -> &[Value] {
        &self.definitions
    }

    pub async fn call(&self, name: &str, arguments: &Value) -> Value {
        match dispatch(self.api.as_ref(), &self.definitions, name, arguments).await {
            Ok(value) => json!({
                "content": [{"type": "text", "text": value.to_string()}],
                "structuredContent": success_envelope(value),
                "isError": false
            }),
            Err(error) => json!({
                "content": [{"type": "text", "text": error.tool_message()}],
                "structuredContent": failure_envelope(&error),
                "isError": true,
            }),
        }
    }
}

fn legacy_tool_definitions() -> Vec<Value> {
    let closed = |properties: Map<String, Value>, required: &[&str]| json!({"type":"object","required":required,"additionalProperties":false,"properties":properties});
    let output_schema = output_schema();
    let tool = |name: &str, description: &str, input_schema: Value| json!({"name":name,"description":description,"inputSchema":input_schema,"outputSchema":output_schema,"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}});
    vec![
        tool("legion_doctor","Use this when checking native repository configuration. Do not use for running an audit.",closed(Map::new(), &[])),
        tool("legion_plan","Use this when creating an audit plan. Do not use for executing an audit.",closed(properties([("profile", json!({"type":"string","enum":["fast","standard","full","release"]}))]), &[])),
        tool("legion_audit","Use this when running a complete audit. Do not use for planning only.",closed(properties([("profile", json!({"type":"string","enum":["fast","standard","full","release"]}))]), &[])),
        tool("legion_verify","Use this when verifying an audit binding. Do not use for running providers.",closed(properties([("priorRun", json!({}))]), &[])),
        tool("legion_get_run","Use this when reading a run artifact. Do not use for creating runs.",closed(properties([
            ("run", json!({"type":"string","minLength":1})), ("artifact", json!({"type":"string"}))
        ]), &["run"])),
        tool("legion_get_finding","Use this when reading a finding from a run. Do not use for changing findings.",closed(properties([
            ("run", json!({"type":"string","minLength":1})), ("findingId", json!({"type":"string","minLength":1}))
        ]), &["run","findingId"])),
        tool("legion_explain","Use this when explaining a finding or gap. Do not use for modifying audit state.",closed(properties([
            ("id", json!({"type":"string","minLength":1})), ("run", json!({"type":"string"}))
        ]), &["id"])),
        tool("legion_list_providers","Use this when listing providers. Do not use for executing providers.",closed(Map::new(), &[])),
        tool("legion_list_languages","Use this when listing supported languages. Do not use for changing configuration.",closed(Map::new(), &[])),
        tool("legion_list_families","Use this when listing audit families. Do not use for executing an audit.",closed(Map::new(), &[])),
        tool("legion_list_skills","Use this when listing bundled skills. Do not use for loading arbitrary paths.",closed(Map::new(), &[])),
    ]
}

fn output_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["status","data","error","truncated","continuationCursor"],"properties":{"status":{"type":"string","enum":["ok","error"]},"data":{},"error":{"oneOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["code","retryable","remediation"],"properties":{"code":{"type":"string"},"retryable":{"type":"boolean"},"remediation":{"type":"string"}}}]},"truncated":{"type":"boolean"},"continuationCursor":{"type":"null"}}})
}

fn success_envelope(data: Value) -> Value {
    json!({"status":"ok","data":data,"error":null,"truncated":false,"continuationCursor":null})
}

fn failure_envelope(error: &McpError) -> Value {
    json!({"status":"error","data":null,"error":error.data(),"truncated":false,"continuationCursor":null})
}

fn properties(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn schema(definitions: &[Value], name: &str) -> Option<Value> {
    definitions
        .iter()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|tool| tool.get("inputSchema").cloned())
}

async fn dispatch<A: NativeApi>(
    api: &A,
    definitions: &[Value],
    name: &str,
    arguments: &Value,
) -> Result<Value, McpError> {
    let Some(input_schema) = schema(definitions, name) else {
        return Err(McpError::ToolNotFound);
    };
    validate_arguments(&input_schema, arguments)?;
    api.validate_tool_scope(name, arguments)?;
    let result = api
        .invoke_async(name, arguments)
        .await
        .map_err(McpError::from)?;
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

fn validate_legacy_scope(_name: &str, arguments: &Value) -> Result<(), McpError> {
    let Some(args) = arguments.as_object() else {
        return Err(McpError::InvalidParams);
    };
    if args.contains_key("root") {
        return Err(McpError::InvalidParams);
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        legacy_tool_definitions, validate_legacy_scope, NativeApi, ToolService, MAX_OUTPUT_BYTES,
    };
    use crate::error::McpError;
    use legion_runtime::RuntimeError;
    use serde_json::{json, Value};

    struct TestApi {
        output: Value,
    }

    impl NativeApi for TestApi {
        fn tool_definitions(&self) -> Vec<Value> {
            vec![json!({
                "name": "test",
                "description": "Use this when testing. Do not use for production.",
                "inputSchema": {"type":"object","required":[],"additionalProperties":false,"properties":{}}
            })]
        }

        fn invoke(&self, _operation: &str, _arguments: &Value) -> Result<Value, RuntimeError> {
            Ok(self.output.clone())
        }
    }

    #[test]
    fn legacy_contract_has_exact_closed_tools_and_common_output_schema() {
        let definitions = legacy_tool_definitions();
        let names = definitions
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "legion_doctor",
                "legion_plan",
                "legion_audit",
                "legion_verify",
                "legion_get_run",
                "legion_get_finding",
                "legion_explain",
                "legion_list_providers",
                "legion_list_languages",
                "legion_list_families",
                "legion_list_skills",
            ]
        );
        let output = definitions[0]["outputSchema"].clone();
        for tool in definitions {
            assert!(!tool["description"].as_str().unwrap().is_empty());
            assert!(tool["description"]
                .as_str()
                .unwrap()
                .contains("Use this when"));
            assert!(tool["description"].as_str().unwrap().contains("Do not use"));
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool["inputSchema"].get("required").is_some());
            assert_eq!(tool["outputSchema"], output);
            assert_eq!(
                tool["annotations"],
                json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true})
            );
            assert!(tool["inputSchema"]["properties"].get("root").is_none());
        }
    }

    #[tokio::test]
    async fn async_call_returns_common_success_envelope() {
        let service = ToolService::new(Arc::new(TestApi {
            output: json!({"ok":true}),
        }));
        let result = service.call("test", &json!({})).await;
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["status"], "ok");
        assert_eq!(result["structuredContent"]["data"]["ok"], true);
        assert_eq!(result["structuredContent"]["error"], Value::Null);
        assert_eq!(
            result["structuredContent"]["continuationCursor"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn output_limit_is_typed_and_public_text_is_generic() {
        let service = ToolService::new(Arc::new(TestApi {
            output: Value::String("x".repeat(MAX_OUTPUT_BYTES + 1)),
        }));
        let result = service.call("test", &json!({})).await;
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["error"]["code"], "OUTPUT_LIMIT");
        assert_eq!(result["structuredContent"]["status"], "error");
        assert_eq!(
            result["content"][0]["text"],
            "tool output exceeded the configured limit"
        );
    }

    #[test]
    fn root_is_rejected_even_when_called_directly() {
        assert_eq!(
            validate_legacy_scope("legion_doctor", &json!({"root":"C:/x"})),
            Err(McpError::InvalidParams)
        );
    }
}
