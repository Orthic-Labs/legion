//! Port of `src/lib/platform/external/exercises.mjs`.

use serde_json::{json, Value};

/// `exerciseReceipt(input)`.
pub fn exercise_receipt(input: &Value) -> Value {
    let executed = input.get("executed").and_then(Value::as_bool).unwrap_or(false);
    let result = input.get("result").cloned().unwrap_or(Value::Null);
    let status = if executed && !result.is_null() && result != Value::Bool(false) {
        result
    } else {
        Value::String("unproven".to_string())
    };
    json!({
        "schemaVersion": 1,
        "kind": "legion-external-exercise-receipt",
        "exercise": input.get("exercise").cloned().unwrap_or(Value::Null),
        "status": status,
        "environment": input.get("environment").cloned().unwrap_or(Value::Null),
        "targetId": input.get("targetId").cloned().unwrap_or(Value::Null),
        "artifactDigest": input.get("artifactDigest").cloned().unwrap_or(Value::Null),
        "evidenceRefs": input.get("evidenceRefs").cloned().unwrap_or_else(|| json!([])),
        "limitations": input.get("limitations").cloned().unwrap_or_else(|| json!([])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unproven_when_not_executed() {
        let receipt = exercise_receipt(&json!({"exercise": "smoke"}));
        assert_eq!(receipt["status"], "unproven");
    }

    #[test]
    fn uses_result_when_executed() {
        let receipt = exercise_receipt(&json!({"executed": true, "result": "pass"}));
        assert_eq!(receipt["status"], "pass");
    }
}
