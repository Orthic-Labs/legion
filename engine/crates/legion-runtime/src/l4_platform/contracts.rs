//! Port of `src/lib/platform/contracts.mjs`: shared receipt shapes and the
//! `sha256` digest helper used across the L4 platform surface.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const PLATFORM_CAPABILITY_STATUS: &[&str] =
    &["available", "unavailable", "unsupported", "permission-denied", "stale", "partial"];

pub const SCENARIO_STATUS: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

/// `sha256(value)`: digests a string as UTF-8, or any other JSON value via
/// its canonical `serde_json::to_string` serialization (matching
/// `JSON.stringify`).
pub fn sha256(value: &Value) -> String {
    let bytes = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    sha256_bytes(bytes.as_bytes())
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// `capabilityReceipt(input)`. Panics (mirrors the JS `throw`) if `status`
/// is not one of `PLATFORM_CAPABILITY_STATUS`; callers that need a
/// non-panicking path should validate the status first.
pub fn capability_receipt(input: &Value) -> Value {
    let status = input.get("status").and_then(Value::as_str).unwrap_or("unavailable");
    if !PLATFORM_CAPABILITY_STATUS.contains(&status) {
        panic!("unknown platform capability status: {status}");
    }
    json!({
        "schemaVersion": 1,
        "kind": "legion-platform-capability",
        "id": input.get("id").cloned().unwrap_or(Value::Null),
        "status": status,
        "isolation": input.get("isolation").cloned().unwrap_or(Value::Null),
        "resourceClaims": input.get("resourceClaims").cloned().unwrap_or_else(|| json!({})),
        "concurrencyKey": input.get("concurrencyKey").cloned().unwrap_or(Value::Null),
        "destructiveActionsAllowed": input.get("destructiveActionsAllowed").and_then(Value::as_bool).unwrap_or(false),
        "binding": input.get("binding").cloned().unwrap_or_else(|| json!({})),
        "checkedAt": input.get("checkedAt").cloned().unwrap_or(Value::Null),
        "limitations": input.get("limitations").cloned().unwrap_or_else(|| json!([])),
        "receipt": input.get("receipt").cloned().unwrap_or(Value::Null),
    })
}

/// `terminalScenarioReceipt(input)`.
pub fn terminal_scenario_receipt(input: &Value) -> Value {
    let status = input.get("status").and_then(Value::as_str).unwrap_or("unproven");
    if !SCENARIO_STATUS.contains(&status) {
        panic!("unknown scenario status: {status}");
    }
    let steps = input.get("steps").cloned().unwrap_or_else(|| json!([]));
    json!({
        "schemaVersion": 1,
        "kind": "legion-platform-scenario-receipt",
        "scenarioId": input.get("scenarioId").cloned().unwrap_or(Value::Null),
        "targetId": input.get("targetId").cloned().unwrap_or(Value::Null),
        "status": status,
        "terminal": true,
        "binding": input.get("binding").cloned().unwrap_or_else(|| json!({})),
        "preState": input.get("preState").cloned().unwrap_or(Value::Null),
        "expectedInvariant": input.get("expectedInvariant").cloned().unwrap_or(Value::Null),
        "observedState": input.get("observedState").cloned().unwrap_or(Value::Null),
        "durableState": input.get("durableState").cloned().unwrap_or(Value::Null),
        "steps": steps,
        "errors": input.get("errors").cloned().unwrap_or_else(|| json!([])),
        "recovery": input.get("recovery").cloned().unwrap_or(Value::Null),
        "artifacts": input.get("artifacts").cloned().unwrap_or_else(|| json!([])),
        "coverageGaps": input.get("coverageGaps").cloned().unwrap_or_else(|| json!([])),
    })
}

/// Result of `requireCapability`.
pub struct CapabilityCheck {
    pub ok: bool,
    pub reason: Option<String>,
}

/// `requireCapability(capability, operation)`. `destructive` mirrors
/// `operation.destructive`.
pub fn require_capability(capability: Option<&Value>, destructive: bool) -> CapabilityCheck {
    let status = capability.and_then(|c| c.get("status")).and_then(Value::as_str);
    if status != Some("available") {
        let status_label = status.unwrap_or("missing");
        return CapabilityCheck { ok: false, reason: Some(format!("capability-{status_label}")) };
    }
    if destructive {
        let allowed = capability
            .and_then(|c| c.get("destructiveActionsAllowed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !allowed {
            return CapabilityCheck { ok: false, reason: Some("destructive-action-forbidden".to_string()) };
        }
    }
    CapabilityCheck { ok: true, reason: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_prefixed_hex() {
        let digest = sha256(&json!("abc"));
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn require_capability_blocks_unavailable() {
        let check = require_capability(None, false);
        assert!(!check.ok);
        assert_eq!(check.reason.as_deref(), Some("capability-missing"));
    }

    #[test]
    fn require_capability_blocks_destructive_without_allowance() {
        let cap = json!({"status": "available", "destructiveActionsAllowed": false});
        let check = require_capability(Some(&cap), true);
        assert!(!check.ok);
        assert_eq!(check.reason.as_deref(), Some("destructive-action-forbidden"));
    }

    #[test]
    fn require_capability_allows_available_nondestructive() {
        let cap = json!({"status": "available"});
        assert!(require_capability(Some(&cap), false).ok);
    }
}
