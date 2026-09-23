//! Port of `src/lib/platform/faults/injectors.mjs`.

use serde_json::Value;

pub struct FaultDecision {
    pub status: &'static str,
    pub reason: Option<&'static str>,
}

/// `validateFaultInjection(fault, capability)`.
pub fn validate_fault_injection(fault: Option<&Value>, capability: Option<&Value>) -> FaultDecision {
    let cap_status = capability.and_then(|c| c.get("status")).and_then(Value::as_str);
    if cap_status != Some("available") {
        return FaultDecision { status: "unproven", reason: Some("fault-capability-unavailable") };
    }
    let has_id = fault.and_then(|f| f.get("id")).map(|v| !v.is_null()).unwrap_or(false);
    let duration_ms = fault.and_then(|f| f.get("durationMs")).and_then(Value::as_f64);
    if !has_id || duration_ms.map(|d| d < 1.0).unwrap_or(true) {
        return FaultDecision { status: "blocked", reason: Some("fault-not-bounded") };
    }
    let production = fault.and_then(|f| f.get("production")).and_then(Value::as_bool).unwrap_or(false);
    if production {
        return FaultDecision { status: "blocked", reason: Some("production-fault-forbidden") };
    }
    FaultDecision { status: "pass", reason: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn blocks_unbounded_fault() {
        let cap = json!({"status": "available"});
        let fault = json!({"id": "f1"});
        let decision = validate_fault_injection(Some(&fault), Some(&cap));
        assert_eq!(decision.status, "blocked");
        assert_eq!(decision.reason, Some("fault-not-bounded"));
    }

    #[test]
    fn blocks_production_fault() {
        let cap = json!({"status": "available"});
        let fault = json!({"id": "f1", "durationMs": 100, "production": true});
        let decision = validate_fault_injection(Some(&fault), Some(&cap));
        assert_eq!(decision.status, "blocked");
        assert_eq!(decision.reason, Some("production-fault-forbidden"));
    }

    #[test]
    fn passes_bounded_nonproduction_fault() {
        let cap = json!({"status": "available"});
        let fault = json!({"id": "f1", "durationMs": 100});
        assert_eq!(validate_fault_injection(Some(&fault), Some(&cap)).status, "pass");
    }
}
