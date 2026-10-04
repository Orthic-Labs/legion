//! Shared Apple operations for Legion's CLI & MCP transports.
//!
//! Process/API effects require explicit execution; planning and source analysis
//! remain useful without Xcode or account credentials. Host authorization is
//! enforced by the calling Legion transport before execution.
#![forbid(unsafe_code)]

pub mod app_store;
pub mod build_analysis;
pub mod diagnostics;
pub mod docs;
pub mod mobile;
pub mod preflight;
pub mod profiling;
pub mod swiftui_trace;

use serde_json::{json, Value};

/// One dispatch table for both native transports. Module catalogs describe
/// arguments, platform requirements, and upstream operation dispositions.
pub async fn invoke(operation: &str, arguments: &Value) -> Result<Value, String> {
    if !arguments.is_object() {
        return Err("Apple arguments must be a JSON object".into());
    }
    match operation {
        "catalog" => Ok(catalog()),
        "preflight" => preflight::invoke(arguments),
        "docs" => docs::invoke(arguments),
        "build-analysis" => build_analysis::invoke(arguments),
        "app-store" => app_store::invoke(arguments).await,
        "flamegraph" | "memgraph" | "memgraph.parse" | "build-log" => diagnostics::invoke(operation, arguments).await,
        "profile.parse" | "profile_parse" | "profile.symbols" | "profile_symbols" => profiling::invoke(operation, arguments),
        "swiftui-trace" => swiftui_trace::invoke(arguments),
        _ => mobile::invoke(operation, arguments).await,
    }
}

pub fn catalog() -> Value {
    json!({
        "schemaVersion": 1,
        "backend": "legion-apple",
        "operations": {
            "catalog": "Local operation discovery",
            "preflight": "PATH-only tool inventory; no processes or network",
            "docs": docs::catalog(),
            "build-analysis": build_analysis::catalog(),
            "app-store": app_store::catalog(),
            "mobile": mobile::catalog(),
            "swiftui-trace": swiftui_trace::catalog(),
            "profile.parse": "Parse bounded exported Instruments kperf XML into sampled addresses",
            "profile.symbols": "Rank sampled addresses, prepare bounded atos argv & assemble symbol CSV",
            "flamegraph": "Bounded trace analysis",
            "memgraph": "Bounded memory diagnostic analysis",
            "memgraph.parse": "Pure bounded leaks text analysis",
            "build-log": "Bounded Xcode build log analysis"
        }
    })
}

pub fn tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": "legion_apple",
        "description": "Native Apple development & App Store Connect operations. Use operation=catalog to discover typed operations. Execution requires host authorization; plans do not execute effects.",
        "inputSchema": {
            "type": "object",
            "required": ["operation"],
            "additionalProperties": false,
            "properties": {
                "operation": {"type": "string", "minLength": 1},
                "arguments": {"type": "object", "default": {}},
                "policyContext": {"type": "object"}
            }
        }
    })]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_requests_do_not_dispatch() {
        assert!(invoke("preflight", &Value::Null).await.is_err());
        assert!(invoke("not-an-operation", &json!({})).await.is_err());
    }

    #[tokio::test]
    async fn catalog_needs_no_credentials_or_platform() {
        let value = invoke("catalog", &json!({})).await.unwrap();
        assert_eq!(value["backend"], "legion-apple");
        assert!(value["operations"]["app-store"]["actions"].is_object());
    }
}
