//! Port of `src/lib/platform/faults/orchestrator.mjs`.

use super::injectors::validate_fault_injection;
use async_trait::async_trait;
use serde_json::{json, Value};

/// Mirrors the JS `adapter` shape: `inject`, `observe`, `recover`, and an
/// optional `cleanup`.
#[async_trait]
pub trait FaultAdapter: Send + Sync {
    async fn inject(&self, fault: &Value) -> Value;
    async fn observe(&self) -> Value;
    async fn recover(&self) -> Value;
    async fn cleanup(&self) {}
}

/// `orchestrateFault({ fault, adapter, capability, scenarioId, controls })`.
pub async fn orchestrate_fault(
    fault: Option<&Value>,
    adapter: &dyn FaultAdapter,
    capability: Option<&Value>,
    scenario_id: Option<&Value>,
    controls: &[Value],
) -> Value {
    let valid = validate_fault_injection(fault, capability);
    if valid.status != "pass" {
        return json!({
            "schemaVersion": 1,
            "kind": "legion-fault-receipt",
            "status": valid.status,
            "scenarioId": scenario_id.cloned().unwrap_or(Value::Null),
            "controls": controls,
            "activation": Value::Null,
            "recovery": Value::Null,
            "residualDamage": Value::Null,
            "coverageGaps": [valid.reason.unwrap_or("")],
        });
    }

    let fault_value = fault.cloned().unwrap_or(Value::Null);
    let activation = adapter.inject(&fault_value).await;
    let observed = adapter.observe().await;
    let recovery = adapter.recover().await;
    adapter.cleanup().await;

    let recovery_ok = recovery.get("ok").and_then(Value::as_bool).unwrap_or(false);
    json!({
        "schemaVersion": 1,
        "kind": "legion-fault-receipt",
        "status": if recovery_ok { "pass" } else { "partial" },
        "scenarioId": scenario_id.cloned().unwrap_or(Value::Null),
        "controls": controls,
        "activation": activation,
        "observed": observed,
        "recovery": recovery.clone(),
        "residualDamage": recovery.get("residualDamage").cloned().unwrap_or(Value::Null),
        "coverageGaps": Value::Array(vec![]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubAdapter;

    #[async_trait]
    impl FaultAdapter for StubAdapter {
        async fn inject(&self, _fault: &Value) -> Value {
            json!({"injected": true})
        }
        async fn observe(&self) -> Value {
            json!({"observed": true})
        }
        async fn recover(&self) -> Value {
            json!({"ok": true})
        }
    }

    #[tokio::test]
    async fn blocked_when_fault_not_bounded() {
        let cap = json!({"status": "available"});
        let fault = json!({"id": "f1"});
        let result = orchestrate_fault(Some(&fault), &StubAdapter, Some(&cap), None, &[]).await;
        assert_eq!(result["status"], "blocked");
    }

    #[tokio::test]
    async fn passes_with_successful_recovery() {
        let cap = json!({"status": "available"});
        let fault = json!({"id": "f1", "durationMs": 100});
        let result = orchestrate_fault(Some(&fault), &StubAdapter, Some(&cap), None, &[]).await;
        assert_eq!(result["status"], "pass");
    }
}
