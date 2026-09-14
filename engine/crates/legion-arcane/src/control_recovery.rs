use crate::error::ArcaneError;
use serde_json::{json, Value};

const RECOVERY_SCHEMA: &str = "arcane.control-recovery.v1";

pub fn recover_control_state(
    input: &Value,
    authenticate: &dyn Fn(&Value) -> bool,
    repair: &dyn Fn(&Value, &Value) -> Result<Value, ArcaneError>,
    verify: &dyn Fn(&Value, &Value) -> bool,
) -> Result<Value, ArcaneError> {
    let control_id = input
        .get("controlId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ArcaneError::typed("ARC_SCHEMA_INVALID", "controlId must be a non-empty string"))?;
    let authorization = input
        .get("authorization")
        .and_then(Value::as_object)
        .ok_or_else(|| ArcaneError::typed("ARC_SCHEMA_INVALID", "authorization must be an object"))?;
    if authorization.get("controlId").and_then(Value::as_str) != Some(control_id)
        || authorization.get("operation").and_then(Value::as_str) != Some("RECOVER_CONTROL_STATE")
    {
        return Ok(json!({
            "schema": RECOVERY_SCHEMA,
            "allowed": false,
            "code": "ARC_RECOVERY_SCOPE_DENIED",
            "controlId": control_id,
        }));
    }
    let authorization_value = Value::Object(authorization.clone());
    if !authenticate(&authorization_value) {
        return Ok(json!({
            "schema": RECOVERY_SCHEMA,
            "allowed": false,
            "code": "ARC_RECOVERY_AUTH_REQUIRED",
            "controlId": control_id,
        }));
    }
    let state = input.get("state").cloned().unwrap_or(Value::Null);
    let context = json!({ "controlId": control_id, "authorization": authorization });
    let recovered = match repair(&state, &context) {
        Ok(value) => value,
        Err(error) => {
            return Ok(json!({
                "schema": RECOVERY_SCHEMA,
                "allowed": false,
                "code": "ARC_RECOVERY_QUARANTINED",
                "controlId": control_id,
                "quarantine": {
                    "originalState": state,
                    "reasonCode": error.code(),
                },
            }));
        }
    };
    if !verify(&recovered, &context) {
        return Ok(json!({
            "schema": RECOVERY_SCHEMA,
            "allowed": false,
            "code": "ARC_RECOVERY_VERIFY_FAILED",
            "controlId": control_id,
            "quarantine": {
                "originalState": state,
                "recoveredState": recovered,
                "reasonCode": "ARC_RECOVERY_VERIFY_FAILED",
            },
        }));
    }
    Ok(json!({
        "schema": RECOVERY_SCHEMA,
        "allowed": true,
        "code": "ARC_RECOVERY_RESUMED",
        "controlId": control_id,
        "replacementState": recovered,
        "preservedState": state,
        "verification": "PASS",
    }))
}
