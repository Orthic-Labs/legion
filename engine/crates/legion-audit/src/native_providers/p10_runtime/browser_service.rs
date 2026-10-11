//! Retained items of the legacy browser / native-surface / service runtime port.
//!
//! Kept: `SERVICE_RUNTIME_SCENARIOS` (asserted by the wf051 parity test) and
//! `ServiceFixtureAdapter` (no production caller). Exercise and receipt logic
//! reachable only from deleted tests was removed in the native-provider sweep.
use serde_json::Value;

pub const SERVICE_RUNTIME_SCENARIOS: [&str; 17] = [
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

/// Faithful port of `createServiceFixtureAdapter(fixture, { onExecute })`.
pub struct ServiceFixtureAdapter {
    fixture: String,
    on_execute: Option<Box<dyn Fn(&str, &Value) + Send + Sync>>,
}

impl ServiceFixtureAdapter {
    pub fn new(fixture: impl Into<String>) -> Self {
        Self {
            fixture: fixture.into(),
            on_execute: None,
        }
    }

    pub fn with_on_execute(
        mut self,
        callback: impl Fn(&str, &Value) + Send + Sync + 'static,
    ) -> Self {
        self.on_execute = Some(Box::new(callback));
        self
    }
}
