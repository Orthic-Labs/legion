//! Port of `src/lib/platform/journeys/assertions.mjs`.

use serde_json::{json, Value};

/// `evaluateInvariant(invariant, observed)`.
pub fn evaluate_invariant(invariant: Option<&Value>, observed: Option<&Value>) -> Value {
    let invariant = match invariant.and_then(Value::as_object) {
        Some(obj) => obj,
        None => return json!({"status": "unproven", "reason": "invariant-missing"}),
    };
    let path = invariant.get("path").and_then(Value::as_str).unwrap_or("");
    let actual = observed.and_then(|o| o.get(path)).cloned().unwrap_or(Value::Null);
    if let Some(equals) = invariant.get("equals") {
        let status = if &actual == equals { "pass" } else { "fail" };
        return json!({"status": status, "actual": actual, "expected": equals});
    }
    if let Some(exists) = invariant.get("exists") {
        let actual_bool = !matches!(actual, Value::Null | Value::Bool(false)) && actual != json!(0) && actual != json!("");
        let expected_bool = exists.as_bool().unwrap_or(false);
        let status = if actual_bool == expected_bool { "pass" } else { "fail" };
        return json!({"status": status, "actual": actual_bool, "expected": expected_bool});
    }
    json!({"status": "unproven", "reason": "invariant-operator-unsupported"})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn equals_operator_passes() {
        let invariant = json!({"path": "state", "equals": "ready"});
        let observed = json!({"state": "ready"});
        assert_eq!(evaluate_invariant(Some(&invariant), Some(&observed))["status"], "pass");
    }

    #[test]
    fn exists_operator_checks_truthiness() {
        let invariant = json!({"path": "handle", "exists": true});
        let observed = json!({"handle": "abc"});
        assert_eq!(evaluate_invariant(Some(&invariant), Some(&observed))["status"], "pass");
        let observed_missing = json!({});
        assert_eq!(evaluate_invariant(Some(&invariant), Some(&observed_missing))["status"], "fail");
    }

    #[test]
    fn unsupported_operator_is_unproven() {
        let invariant = json!({"path": "state"});
        assert_eq!(evaluate_invariant(Some(&invariant), None)["status"], "unproven");
    }
}
