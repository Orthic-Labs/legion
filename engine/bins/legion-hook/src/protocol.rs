use std::time::{Duration, Instant};

use legion_contracts::task::RequestEnvelope;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

pub const SCHEMA_VERSION: u32 = 1;
pub const REQUEST_KIND: &str = "legion-hook-request";
pub const RESPONSE_KIND: &str = "legion-hook-response";
pub const DEFAULT_DEADLINE_MS: u64 = 120_000;

#[derive(Clone, Debug)]
pub struct HookRequest {
    pub schema_version: u32,
    pub kind: String,
    pub event_type: String,
    pub payload: Map<String, Value>,
    pub request_envelope: Option<RequestEnvelope>,
    pub deadline_ms: u64,
    pub cancelled: bool,
}

impl HookRequest {
    pub fn parse(input: &[u8]) -> Result<Self, crate::error::HookError> {
        let value: Value =
            serde_json::from_slice(input).map_err(crate::error::HookError::malformed)?;
        let object = value
            .as_object()
            .ok_or_else(|| crate::error::HookError::invalid("request must be a JSON object"))?;
        // Keep malformed/overflowing schema values on the fail-closed path.
        let schema_version = number(object, "schemaVersion")
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let kind = string(object, "kind").unwrap_or_default();
        let event_type = string(object, "eventType")
            .or_else(|| string(object, "hook_event_name"))
            .unwrap_or_default();
        let payload = object
            .get("payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| object.clone());
        let request_envelope = object
            .get("requestEnvelope")
            .or_else(|| object.get("request_envelope"))
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(crate::error::HookError::malformed)
            })
            .transpose()?;
        Ok(Self {
            schema_version,
            kind,
            event_type,
            payload,
            request_envelope,
            deadline_ms: number(object, "deadlineMs").unwrap_or(DEFAULT_DEADLINE_MS),
            cancelled: boolean(object, "cancelled").unwrap_or(false),
        })
    }

    pub fn validate(&self) -> Result<(), crate::error::HookError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(crate::error::HookError::unsupported_version(
                self.schema_version,
            ));
        }
        if self.kind != REQUEST_KIND {
            return Err(crate::error::HookError::invalid(
                "request kind is unsupported",
            ));
        }
        if self.event_type.trim().is_empty() {
            return Err(crate::error::HookError::invalid("event type is required"));
        }
        if self.deadline_ms == 0 {
            return Err(crate::error::HookError::invalid(
                "deadline must be positive",
            ));
        }
        if let Some(envelope) = &self.request_envelope {
            envelope
                .validate()
                .map_err(|error| crate::error::HookError::invalid(error.to_string()))?;
        }
        Ok(())
    }

    pub fn deadline(&self, started: Instant) -> Instant {
        started + Duration::from_millis(self.deadline_ms)
    }
    pub fn cancellation(&self) -> CancellationToken {
        let token = CancellationToken::new();
        if self.cancelled {
            token.cancel();
        }
        token
    }

    pub fn is_effectful(&self) -> bool {
        if self.event_type != "PreToolUse" {
            return false;
        }
        matches!(
            string(&self.payload, "tool_name").as_deref(),
            Some("Write" | "Edit" | "NotebookEdit" | "Bash")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookResponse {
    pub schema_version: u32,
    pub kind: &'static str,
    pub event_type: String,
    pub allowed: bool,
    pub code: Option<String>,
    pub reason: String,
    pub enforcement_health: &'static str,
}

impl HookResponse {
    pub fn allowed(event_type: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: RESPONSE_KIND,
            event_type: event_type.into(),
            allowed: true,
            code: None,
            reason: "allowed".into(),
            enforcement_health: "strong",
        }
    }

    pub fn denied(
        event_type: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
        health: &'static str,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: RESPONSE_KIND,
            event_type: event_type.into(),
            allowed: false,
            code: Some(code.into()),
            reason: reason.into(),
            enforcement_health: health,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("allowed".into(), Value::Bool(self.allowed));
        object.insert(
            "code".into(),
            self.code.clone().map(Value::String).unwrap_or(Value::Null),
        );
        object.insert(
            "enforcementHealth".into(),
            Value::String(self.enforcement_health.into()),
        );
        object.insert("eventType".into(), Value::String(self.event_type.clone()));
        object.insert("kind".into(), Value::String(self.kind.into()));
        object.insert("reason".into(), Value::String(self.reason.clone()));
        object.insert("schemaVersion".into(), Value::from(self.schema_version));
        Value::Object(object)
    }
}

fn string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}
fn number(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}
fn boolean(object: &Map<String, Value>, key: &str) -> Option<bool> {
    object.get(key).and_then(Value::as_bool)
}
