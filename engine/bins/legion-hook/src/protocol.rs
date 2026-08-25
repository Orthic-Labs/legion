use serde_json::{Map, Value};

pub const SCHEMA_VERSION: u32 = 1;
pub const REQUEST_KIND: &str = "legion-hook-request";
pub const RESPONSE_KIND: &str = "legion-hook-response";

#[derive(Clone, Debug)]
pub struct HookRequest {
    pub schema_version: u32,
    pub kind: String,
    pub event_type: String,
    pub payload: Value,
}

impl HookRequest {
    pub fn parse(input: &[u8]) -> Result<Self, crate::error::HookError> {
        let value: Value =
            serde_json::from_slice(input).map_err(crate::error::HookError::malformed)?;
        let object = value
            .as_object()
            .ok_or_else(|| crate::error::HookError::invalid("request must be a JSON object"))?;
        // Native host hooks send an unwrapped event object.  Normalize that
        // transport shape to this adapter's versioned frame without assigning
        // any meaning to the event payload. Supplied malformed/overflowing
        // values remain invalid rather than silently becoming version one.
        let schema_version = match object.get("schemaVersion") {
            None => SCHEMA_VERSION,
            Some(value) => value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0),
        };
        let kind = string(object, "kind").unwrap_or_else(|| REQUEST_KIND.into());
        let event_type = string(object, "eventType")
            .or_else(|| string(object, "hook_event_name"))
            .unwrap_or_default();
        let payload = object
            .get("payload")
            .cloned()
            .unwrap_or_else(|| value.clone());
        Ok(Self {
            schema_version,
            kind,
            event_type,
            payload,
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
        Ok(())
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
    pub fn unsupported(event_type: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: RESPONSE_KIND,
            event_type: event_type.into(),
            allowed: true,
            code: None,
            reason: "native hook enforcement is not available through this adapter".into(),
            enforcement_health: "unsupported",
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
