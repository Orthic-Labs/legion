//! Port of `src/lib/platform/journeys/state-machine.mjs`.

use serde_json::{json, Value};

/// `transition(machine, state, event)`.
pub fn transition(machine: Option<&Value>, state: &Value, event: &Value) -> Value {
    let transitions = machine
        .and_then(|m| m.get("transitions"))
        .and_then(Value::as_array);
    let rule = transitions.and_then(|list| {
        list.iter()
            .find(|item| item.get("from") == Some(state) && item.get("event") == Some(event))
    });
    match rule {
        Some(rule) => json!({
            "status": "pass",
            "from": state,
            "event": event,
            "to": rule.get("to").cloned().unwrap_or(Value::Null),
        }),
        None => json!({
            "status": "blocked",
            "from": state,
            "event": event,
            "reason": "unsealed-transition",
        }),
    }
}
