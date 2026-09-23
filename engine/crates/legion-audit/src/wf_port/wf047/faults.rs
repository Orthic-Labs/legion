//! Port of `src/providers/runtime/service/faults/index.mjs`
//! (`createServiceFixtureAdapter` / its `createFaultAdapter` alias).

use serde_json::{Map, Value};

/// Port of `SERVICE_RUNTIME_SCENARIOS` from
/// `src/providers/runtime/worker/index.mjs` — the one value this file
/// depends on from outside its own module.
pub const SERVICE_RUNTIME_SCENARIOS: &[&str] = &[
    "api-contract",
    "identity-authorization",
    "data-effect",
    "timeout-retry",
    "idempotency",
    "rate-cost-limit",
    "queue-ordering",
    "queue-duplicate",
    "poison-message",
    "backpressure",
    "worker-restart",
    "graceful-shutdown",
    "health-readiness",
    "migration",
    "capacity",
    "fault-recovery",
    "observability",
];

/// Port of `FIXTURE_STATUS`.
fn fixture_status(fixture: &str) -> &'static str {
    match fixture {
        "clean" => "pass",
        "defect" => "fail",
        "partial" => "partial",
        "stale-environment" => "unproven",
        "unsupported-runtime" => "blocked",
        _ => "blocked",
    }
}

/// Port of the object returned by `createServiceFixtureAdapter`'s
/// `execute({ id, binding })` method.
pub struct ServiceFixtureAdapter {
    fixture: String,
    on_execute: Option<Box<dyn FnMut(&str, &Value)>>,
}

impl ServiceFixtureAdapter {
    /// Port of `createServiceFixtureAdapter(fixture, { onExecute })`.
    pub fn new(fixture: impl Into<String>) -> Self {
        Self { fixture: fixture.into(), on_execute: None }
    }

    pub fn with_on_execute(mut self, on_execute: impl FnMut(&str, &Value) + 'static) -> Self {
        self.on_execute = Some(Box::new(on_execute));
        self
    }

    /// Port of `execute({ id, binding = {} })`.
    pub fn execute(&mut self, id: &str, binding: &Value) -> Value {
        let binding = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };
        if !SERVICE_RUNTIME_SCENARIOS.contains(&id) {
            return serde_json::json!({
                "status": "error",
                "terminal": true,
                "coverageGaps": ["unsupported-runtime-scenario"],
            });
        }
        if let Some(on_execute) = self.on_execute.as_mut() {
            on_execute(id, &binding);
        }
        let restartable = id == "worker-restart";
        let status = fixture_status(&self.fixture);
        serde_json::json!({
            "status": status,
            "terminal": true,
            "restartable": restartable,
            "evidence": { "fixture": self.fixture, "scenario": id, "binding": binding, "restartable": restartable },
            "cleanup": {
                "status": "pass",
                "deployment": binding.get("deployment").cloned().unwrap_or(Value::Null),
                "region": binding.get("region").cloned().unwrap_or(Value::Null),
                "datastore": binding.get("datastore").cloned().unwrap_or(Value::Null),
            },
        })
    }
}

/// Port of `createFaultAdapter` (an alias of `createServiceFixtureAdapter`
/// in JS).
pub fn create_fault_adapter(fixture: impl Into<String>) -> ServiceFixtureAdapter {
    ServiceFixtureAdapter::new(fixture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_scenario_errors() {
        let mut adapter = create_fault_adapter("clean");
        let out = adapter.execute("not-a-scenario", &Value::Object(Map::new()));
        assert_eq!(out["status"], "error");
        assert_eq!(out["terminal"], true);
        assert_eq!(out["coverageGaps"][0], "unsupported-runtime-scenario");
    }

    #[test]
    fn clean_fixture_passes_and_marks_restartable() {
        let mut adapter = create_fault_adapter("clean");
        let binding = serde_json::json!({ "deployment": "d1", "region": "r1", "datastore": "ds1" });
        let out = adapter.execute("worker-restart", &binding);
        assert_eq!(out["status"], "pass");
        assert_eq!(out["restartable"], true);
        assert_eq!(out["cleanup"]["deployment"], "d1");
    }

    #[test]
    fn defect_fixture_fails_and_unknown_fixture_is_blocked() {
        let mut defect = create_fault_adapter("defect");
        assert_eq!(defect.execute("idempotency", &Value::Null)["status"], "fail");
        let mut unknown = create_fault_adapter("something-else");
        assert_eq!(unknown.execute("idempotency", &Value::Null)["status"], "blocked");
    }

    #[test]
    fn on_execute_hook_runs_before_response() {
        let mut adapter = create_fault_adapter("clean").with_on_execute(|_id, _binding| {});
        let out = adapter.execute("capacity", &Value::Null);
        assert_eq!(out["status"], "pass");
    }
}
