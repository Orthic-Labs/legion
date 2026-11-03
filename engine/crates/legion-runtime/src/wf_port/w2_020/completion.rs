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
pub fn completion_type_for_accept_result(
    event_type: &str,
    accept_result: Option<&Value>,
) -> &'static str {
    let handled = field_is_true(accept_result, "handled");
    let carbonize = field_is_true(accept_result, "carbonize");
    let mode_is_error = field_str(accept_result, "mode") == Some("error");
    let preview_mode_is_svelte =
        field_str(accept_result, "previewMode") == Some("svelte-component");

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
pub fn completion_ack_for_accept_result(
    event_id: &str,
    completion_type: &str,
    accept_result: Option<&Value>,
) -> Value {
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
            Value::String(format!(
                "legion script designer/live-complete --id {event_id}"
            )),
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
