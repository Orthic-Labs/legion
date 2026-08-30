use serde_json::{Map, Value};

pub const SCHEMA_VERSION: u32 = 1;
pub const REQUEST_KIND: &str = "legion-hook-request";
pub const RESPONSE_KIND: &str = "legion-hook-response";

/// Host lifecycle names accepted by both retained Claude/Codex registrations
/// & the canonical Arcane event vocabulary. Unknown names are rejected before
/// any effect can be considered.
pub const SUPPORTED_EVENT_TYPES: &[&str] = &[
    "SessionStart",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
    "PostCompact",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "session-start",
    "subagent-start",
    "subagent-stop",
    "user-prompt-submit",
    "post-compact",
    "pre-effect",
    "post-effect",
    "post-effect-failure",
    "stop",
    "ci-boundary",
];

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
        if object.contains_key("payload")
            && object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "schemaVersion" | "kind" | "eventType" | "hook_event_name" | "payload"
                )
            })
        {
            return Err(crate::error::HookError::invalid(
                "request contains unknown frame fields",
            ));
        }
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
        let kind = match object.get("kind") {
            None => REQUEST_KIND.into(),
            Some(value) => value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| crate::error::HookError::invalid("request kind must be a string"))?,
        };
        let event_type = match (
            string(object, "eventType"),
            string(object, "hook_event_name"),
        ) {
            (Some(event_type), Some(hook_event_name)) if event_type != hook_event_name => {
                return Err(crate::error::HookError::invalid(
                    "event type fields disagree",
                ));
            }
            (Some(event_type), _) | (_, Some(event_type)) => event_type,
            (None, None) => String::new(),
        };
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
        if !SUPPORTED_EVENT_TYPES.contains(&self.event_type.as_str()) {
            return Err(crate::error::HookError::invalid(
                "event type is unsupported",
            ));
        }
        if !self.payload.is_object() {
            return Err(crate::error::HookError::invalid(
                "request payload must be a JSON object",
            ));
        }
        Ok(())
    }

    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "SessionStart"
                | "SubagentStart"
                | "SubagentStop"
                | "UserPromptSubmit"
                | "PostCompact"
                | "Stop"
                | "session-start"
                | "subagent-start"
                | "subagent-stop"
                | "user-prompt-submit"
                | "post-compact"
                | "stop"
                | "ci-boundary"
        )
    }

    pub fn is_pre_effect(&self) -> bool {
        matches!(self.event_type.as_str(), "PreToolUse" | "pre-effect")
    }

    pub fn is_post_effect(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "PostToolUse" | "PostToolUseFailure" | "post-effect" | "post-effect-failure"
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
    pub fn unsupported(event_type: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: RESPONSE_KIND,
            event_type: event_type.into(),
            allowed: false,
            code: Some("ARC_NATIVE_POLICY_UNAVAILABLE".into()),
            reason: "native hook enforcement is unavailable; effect is refused".into(),
            enforcement_health: "unsupported",
        }
    }

    pub fn allowed(event_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: RESPONSE_KIND,
            event_type: event_type.into(),
            allowed: true,
            code: None,
            reason: reason.into(),
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

        // Preserve native Claude/Codex blocking shapes alongside the typed
        // response envelope. Hosts ignore these fields when an event cannot
        // be blocked, while PreToolUse/Stop consume them directly.
        if !self.allowed && matches!(self.event_type.as_str(), "PreToolUse" | "pre-effect") {
            let mut specific = Map::new();
            specific.insert("hookEventName".into(), Value::String("PreToolUse".into()));
            specific.insert("permissionDecision".into(), Value::String("deny".into()));
            specific.insert(
                "permissionDecisionReason".into(),
                Value::String(self.reason.clone()),
            );
            object.insert("hookSpecificOutput".into(), Value::Object(specific));
        } else if !self.allowed && matches!(self.event_type.as_str(), "Stop" | "stop") {
            object.insert("decision".into(), Value::String("block".into()));
        }
        Value::Object(object)
    }
}

fn string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_string_frame_kind_is_rejected() {
        assert!(HookRequest::parse(br#"{"kind":42,"eventType":"Stop","payload":{}}"#).is_err());
    }

    #[test]
    fn unknown_event_is_rejected_by_validation() {
        let request = HookRequest::parse(br#"{"eventType":"unknown","payload":{}}"#)
            .expect("frame shape is valid");
        assert!(request.validate().is_err());
    }

    #[test]
    fn subagent_stop_is_a_valid_observation_event() {
        let request = HookRequest::parse(br#"{"eventType":"SubagentStop","payload":{}}"#)
            .expect("frame shape is valid");
        request.validate().expect("SubagentStop is registered");
        assert!(request.is_lifecycle());
        assert!(!request.is_pre_effect());
    }
}
