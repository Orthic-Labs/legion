//! Port of `src/lib/platform/lifecycle/actions.mjs`.

use super::super::artifact_sanitize::sanitize_sensitive_value;
use super::super::contracts::require_capability;
use async_trait::async_trait;
use serde_json::{json, Value};

const ACTIONS: &[&str] = &[
    "launch", "foreground", "background", "suspend", "resume", "restart", "terminate", "install",
    "uninstall", "update", "rollback",
];

/// Mirrors the JS `adapter[action]()` shape: the adapter exposes a method
/// per lifecycle action; unsupported actions return `None`.
#[async_trait]
pub trait LifecycleAdapter: Send + Sync {
    async fn run(&self, action: &str) -> Option<Result<Value, String>>;
}

/// `runLifecycleAction({ action, adapter, capability, targetId, binding, destructive })`.
pub async fn run_lifecycle_action(
    action: &str,
    adapter: Option<&dyn LifecycleAdapter>,
    capability: Option<&Value>,
    target_id: Value,
    binding: Value,
    destructive: bool,
) -> Value {
    if !ACTIONS.contains(&action) {
        return lifecycle_receipt(&json!({
            "action": action, "targetId": target_id, "binding": binding, "status": "blocked",
            "coverageGaps": ["lifecycle-action-unsupported"],
        }));
    }
    let permitted = require_capability(capability, destructive);
    if !permitted.ok {
        return lifecycle_receipt(&json!({
            "action": action, "targetId": target_id, "binding": binding, "status": "blocked",
            "coverageGaps": [permitted.reason],
        }));
    }
    let adapter = match adapter {
        Some(a) => a,
        None => {
            return lifecycle_receipt(&json!({
                "action": action, "targetId": target_id, "binding": binding, "status": "unproven",
                "coverageGaps": ["lifecycle-adapter-missing"],
            }))
        }
    };
    match adapter.run(action).await {
        None => lifecycle_receipt(&json!({
            "action": action, "targetId": target_id, "binding": binding, "status": "unproven",
            "coverageGaps": ["lifecycle-adapter-missing"],
        })),
        Some(Ok(observed)) => {
            let status = observed.get("status").and_then(Value::as_str).unwrap_or("pass").to_string();
            let coverage_gaps = observed.get("coverageGaps").cloned().unwrap_or_else(|| json!([]));
            lifecycle_receipt(&json!({
                "action": action, "targetId": target_id, "binding": binding, "status": status,
                "observed": observed, "coverageGaps": coverage_gaps,
            }))
        }
        Some(Err(message)) => lifecycle_receipt(&json!({
            "action": action, "targetId": target_id, "binding": binding, "status": "error",
            "errors": [{"name": "Error", "message": message}], "coverageGaps": ["lifecycle-action-error"],
        })),
    }
}

/// `lifecycleReceipt(input)`.
pub fn lifecycle_receipt(input: &Value) -> Value {
    let safe = sanitize_sensitive_value(input, &[]).value;
    json!({
        "schemaVersion": 1,
        "kind": "legion-lifecycle-receipt",
        "action": safe.get("action").cloned().unwrap_or(Value::Null),
        "targetId": safe.get("targetId").cloned().unwrap_or(Value::Null),
        "binding": safe.get("binding").cloned().unwrap_or_else(|| json!({})),
        "status": safe.get("status").cloned().unwrap_or_else(|| Value::String("unproven".to_string())),
        "observed": safe.get("observed").cloned().unwrap_or(Value::Null),
        "errors": safe.get("errors").cloned().unwrap_or_else(|| json!([])),
        "coverageGaps": safe.get("coverageGaps").cloned().unwrap_or_else(|| json!([])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubAdapter;

    #[async_trait]
    impl LifecycleAdapter for StubAdapter {
        async fn run(&self, _action: &str) -> Option<Result<Value, String>> {
            Some(Ok(json!({"status": "pass"})))
        }
    }

    #[tokio::test]
    async fn blocked_on_unsupported_action() {
        let result = run_lifecycle_action("nuke", Some(&StubAdapter), None, Value::Null, json!({}), false).await;
        assert_eq!(result["status"], "blocked");
        assert_eq!(result["coverageGaps"][0], "lifecycle-action-unsupported");
    }

    #[tokio::test]
    async fn blocked_without_capability() {
        let result = run_lifecycle_action("launch", Some(&StubAdapter), None, Value::Null, json!({}), false).await;
        assert_eq!(result["status"], "blocked");
    }

    #[tokio::test]
    async fn passes_with_available_capability() {
        let cap = json!({"status": "available"});
        let result = run_lifecycle_action("launch", Some(&StubAdapter), Some(&cap), Value::Null, json!({}), false).await;
        assert_eq!(result["status"], "pass");
    }

    #[test]
    fn receipt_redacts_sensitive_fields() {
        let receipt = lifecycle_receipt(&json!({"action": "launch", "observed": {"password": "secret"}}));
        assert_eq!(receipt["observed"]["password"], "[REDACTED]");
    }
}
