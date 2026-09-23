//! Port of `src/lib/platform/journeys/runner.mjs`.

use super::super::contracts::{require_capability, terminal_scenario_receipt};
use super::assertions::evaluate_invariant;
use super::state_machine::transition;
use async_trait::async_trait;
use serde_json::{json, Value};

const TERMINAL_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

/// Mirrors the JS `adapter.execute(step)` contract.
#[async_trait]
pub trait JourneyAdapter: Send + Sync {
    async fn execute(&self, step: &Value) -> Option<Value>;
}

/// `runJourney({ scenario, adapter, capability, binding })`.
pub async fn run_journey(
    scenario: Option<&Value>,
    adapter: Option<&dyn JourneyAdapter>,
    capability: Option<&Value>,
    binding: Value,
) -> Value {
    let scenario_id = scenario.and_then(|s| s.get("id")).cloned().unwrap_or(Value::Null);
    let target_id = scenario.and_then(|s| s.get("targetId")).cloned().unwrap_or(Value::Null);
    let destructive = scenario.and_then(|s| s.get("destructive")).and_then(Value::as_bool).unwrap_or(false);

    let permitted = require_capability(capability, destructive);
    if !permitted.ok {
        return terminal_scenario_receipt(&json!({
            "scenarioId": scenario_id, "targetId": target_id, "status": "blocked", "binding": binding,
            "coverageGaps": [{"ok": false, "reason": permitted.reason}],
        }));
    }

    let steps_value = scenario.and_then(|s| s.get("steps"));
    let steps_array = steps_value.and_then(Value::as_array);
    let steps_valid = scenario.map(Value::is_object).unwrap_or(false)
        && steps_array.map(|arr| !arr.is_empty() && arr.iter().all(|s| s.is_object())).unwrap_or(false);
    if !steps_valid {
        return terminal_scenario_receipt(&json!({
            "scenarioId": scenario_id, "targetId": target_id, "status": "unproven", "binding": binding,
            "coverageGaps": ["journey-steps-invalid"],
        }));
    }
    let scenario = scenario.unwrap();
    let steps_array = steps_array.unwrap();

    let adapter = match adapter {
        Some(a) => a,
        None => {
            return terminal_scenario_receipt(&json!({
                "scenarioId": scenario_id, "targetId": target_id, "status": "unproven", "binding": binding,
                "coverageGaps": ["journey-adapter-missing"],
            }))
        }
    };

    let mut state = scenario.get("initialState").cloned().unwrap_or(Value::Null);
    let mut recorded_steps: Vec<Value> = Vec::new();
    let mut durable_state: Value = Value::Null;
    let machine = scenario.get("machine");

    for step in steps_array {
        let event = step.get("event").cloned().unwrap_or(Value::Null);
        let edge = transition(machine, &state, &event);
        if edge["status"] != "pass" {
            return terminal_scenario_receipt(&json!({
                "scenarioId": scenario_id, "targetId": target_id, "status": "blocked", "binding": binding,
                "steps": recorded_steps, "errors": [edge],
            }));
        }
        let result = match adapter.execute(step).await {
            Some(r) if r.is_object() => r,
            _ => {
                return terminal_scenario_receipt(&json!({
                    "scenarioId": scenario_id, "targetId": target_id, "status": "error", "binding": binding,
                    "steps": recorded_steps, "coverageGaps": ["journey-result-invalid"],
                }))
            }
        };
        let result_status = result.get("status").and_then(Value::as_str).unwrap_or("");
        let result_terminal = result.get("terminal").and_then(Value::as_bool).unwrap_or(false);
        if !TERMINAL_STATUSES.contains(&result_status) || !result_terminal {
            return terminal_scenario_receipt(&json!({
                "scenarioId": scenario_id, "targetId": target_id, "status": "error", "binding": binding,
                "steps": recorded_steps, "coverageGaps": ["journey-result-nonterminal"],
            }));
        }
        durable_state = result.get("durableState").cloned().unwrap_or(Value::Null);
        let assertion = evaluate_invariant(step.get("invariant"), result.get("observedState"));
        let step_status = if result_status != "pass" { result_status.to_string() } else {
            assertion.get("status").and_then(Value::as_str).unwrap_or("unproven").to_string()
        };
        recorded_steps.push(json!({
            "id": step.get("id").cloned().unwrap_or(Value::Null),
            "action": step.get("action").cloned().unwrap_or(Value::Null),
            "status": step_status,
            "expected": assertion.get("expected").cloned().unwrap_or(Value::Null),
            "actual": assertion.get("actual").cloned().unwrap_or(Value::Null),
            "observedState": result.get("observedState").cloned().unwrap_or(Value::Null),
            "durableState": durable_state,
        }));
        if step_status != "pass" {
            let final_status = if step_status == "fail" { "fail".to_string() } else { step_status.clone() };
            return terminal_scenario_receipt(&json!({
                "scenarioId": scenario_id, "targetId": target_id, "status": final_status, "binding": binding,
                "steps": recorded_steps, "observedState": result.get("observedState").cloned().unwrap_or(Value::Null),
                "durableState": durable_state,
            }));
        }
        if durable_state.is_null() {
            return terminal_scenario_receipt(&json!({
                "scenarioId": scenario_id, "targetId": target_id, "status": "unproven", "binding": binding,
                "steps": recorded_steps, "observedState": result.get("observedState").cloned().unwrap_or(Value::Null),
                "coverageGaps": ["journey-durable-state-missing"],
            }));
        }
        state = edge.get("to").cloned().unwrap_or(Value::Null);
    }

    terminal_scenario_receipt(&json!({
        "scenarioId": scenario_id, "targetId": target_id, "status": "pass", "binding": binding,
        "steps": recorded_steps, "observedState": {"state": state}, "durableState": durable_state,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubAdapter;

    #[async_trait]
    impl JourneyAdapter for StubAdapter {
        async fn execute(&self, _step: &Value) -> Option<Value> {
            Some(json!({"status": "pass", "terminal": true, "durableState": {"ok": true}, "observedState": {"ready": true}}))
        }
    }

    #[tokio::test]
    async fn blocked_when_capability_unavailable() {
        let scenario = json!({"id": "s1", "steps": [{"id": "step1", "event": "go"}]});
        let result = run_journey(Some(&scenario), Some(&StubAdapter), None, json!({})).await;
        assert_eq!(result["status"], "blocked");
    }

    #[tokio::test]
    async fn unproven_when_steps_invalid() {
        let cap = json!({"status": "available"});
        let scenario = json!({"id": "s1", "steps": []});
        let result = run_journey(Some(&scenario), Some(&StubAdapter), Some(&cap), json!({})).await;
        assert_eq!(result["status"], "unproven");
        assert_eq!(result["coverageGaps"][0], "journey-steps-invalid");
    }

    #[tokio::test]
    async fn passes_full_journey() {
        let cap = json!({"status": "available"});
        let scenario = json!({
            "id": "s1",
            "initialState": "idle",
            "machine": {"transitions": [{"from": "idle", "event": "go", "to": "done"}]},
            "steps": [{"id": "step1", "event": "go", "invariant": {"path": "ready", "equals": true}}],
        });
        let result = run_journey(Some(&scenario), Some(&StubAdapter), Some(&cap), json!({})).await;
        assert_eq!(result["status"], "pass");
        assert_eq!(result["steps"][0]["status"], "pass");
    }
}
