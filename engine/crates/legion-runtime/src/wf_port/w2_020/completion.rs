//! Port of `skills/designer/engine/scripts/live/completion.mjs`.
//!
//! Fully self-contained pure logic; nothing dropped.

use serde_json::Value;

/// Mirrors `completionTypeForAcceptResult(eventType, acceptResult)`.
///
/// `acceptResult` is modeled as an optional JSON object so callers that
/// already have a `serde_json::Value` (as most of this codebase's live-mode
/// wiring will) can pass it straight through; field lookups use the same
/// `?.` (missing-is-undefined) semantics as the JS.
pub fn completion_type_for_accept_result(event_type: &str, accept_result: Option<&Value>) -> &'static str {
    let handled = field_is_true(accept_result, "handled");
    let carbonize = field_is_true(accept_result, "carbonize");
    let mode_is_error = field_str(accept_result, "mode") == Some("error");
    let preview_mode_is_svelte = field_str(accept_result, "previewMode") == Some("svelte-component");

    if event_type == "discard" {
        return if handled { "discarded" } else { "error" };
    }
    if handled && carbonize {
        return "agent_done";
    }
    if handled {
        return "complete";
    }
    if mode_is_error {
        return "error";
    }
    if event_type == "accept" && preview_mode_is_svelte {
        return "error";
    }
    "agent_done"
}

/// Mirrors `completionAckForAcceptResult(eventId, completionType, acceptResult)`.
pub fn completion_ack_for_accept_result(event_id: &str, completion_type: &str, accept_result: Option<&Value>) -> Value {
    let mut ack = serde_json::json!({
        "ok": true,
        "type": completion_type,
    });

    if field_is_true(accept_result, "handled") && field_is_true(accept_result, "carbonize") {
        let obj = ack.as_object_mut().expect("ack is always an object");
        obj.insert("final".to_string(), Value::Bool(false));
        obj.insert("requiresComplete".to_string(), Value::Bool(true));
        obj.insert(
            "nextCommand".to_string(),
            Value::String(format!("live-complete.mjs --id {event_id}")),
        );
        obj.insert(
            "message".to_string(),
            Value::String(
                "Carbonize cleanup must be verified, then the session must be completed explicitly before polling again."
                    .to_string(),
            ),
        );
    }

    ack
}

fn field_is_true(value: Option<&Value>, key: &str) -> bool {
    value
        .and_then(|v| v.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn field_str<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a str> {
    value.and_then(|v| v.get(key)).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discard_handled_is_discarded() {
        let r = json!({"handled": true});
        assert_eq!(completion_type_for_accept_result("discard", Some(&r)), "discarded");
    }

    #[test]
    fn discard_unhandled_is_error() {
        assert_eq!(completion_type_for_accept_result("discard", None), "error");
        let r = json!({"handled": false});
        assert_eq!(completion_type_for_accept_result("discard", Some(&r)), "error");
    }

    #[test]
    fn handled_carbonize_is_agent_done() {
        let r = json!({"handled": true, "carbonize": true});
        assert_eq!(completion_type_for_accept_result("accept", Some(&r)), "agent_done");
    }

    #[test]
    fn handled_without_carbonize_is_complete() {
        let r = json!({"handled": true, "carbonize": false});
        assert_eq!(completion_type_for_accept_result("accept", Some(&r)), "complete");
        let r2 = json!({"handled": true});
        assert_eq!(completion_type_for_accept_result("accept", Some(&r2)), "complete");
    }

    #[test]
    fn mode_error_is_error() {
        let r = json!({"mode": "error"});
        assert_eq!(completion_type_for_accept_result("accept", Some(&r)), "error");
    }

    #[test]
    fn accept_svelte_component_preview_is_error() {
        let r = json!({"previewMode": "svelte-component"});
        assert_eq!(completion_type_for_accept_result("accept", Some(&r)), "error");
        // Same previewMode under a non-"accept" eventType does NOT hit that branch.
        assert_eq!(completion_type_for_accept_result("checkpoint", Some(&r)), "agent_done");
    }

    #[test]
    fn fallback_is_agent_done() {
        assert_eq!(completion_type_for_accept_result("checkpoint", None), "agent_done");
        assert_eq!(completion_type_for_accept_result("checkpoint", Some(&json!({}))), "agent_done");
    }

    #[test]
    fn ack_basic_has_no_extra_fields() {
        let ack = completion_ack_for_accept_result("abc12345", "complete", Some(&json!({"handled": true})));
        assert_eq!(ack, json!({"ok": true, "type": "complete"}));
    }

    #[test]
    fn ack_carbonize_adds_followup_fields() {
        let r = json!({"handled": true, "carbonize": true});
        let ack = completion_ack_for_accept_result("abc12345", "agent_done", Some(&r));
        assert_eq!(ack["ok"], json!(true));
        assert_eq!(ack["type"], json!("agent_done"));
        assert_eq!(ack["final"], json!(false));
        assert_eq!(ack["requiresComplete"], json!(true));
        assert_eq!(ack["nextCommand"], json!("live-complete.mjs --id abc12345"));
        assert_eq!(
            ack["message"],
            json!("Carbonize cleanup must be verified, then the session must be completed explicitly before polling again.")
        );
    }
}
