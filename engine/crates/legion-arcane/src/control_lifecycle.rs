use crate::error::ArcaneError;
use serde_json::{json, Value};

const SCHEMA: &str = "arcane.control-lifecycle-assessment.v1";

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a serde_json::Map<String, Value>, ArcaneError> {
    value.as_object().ok_or_else(|| {
        ArcaneError::typed("ARC_SCHEMA_INVALID", format!("{name} must be an object"))
    })
}

fn passing_eval(proof: &Value) -> bool {
    proof.get("status").and_then(Value::as_str) == Some("PASS")
        && proof.get("fresh").and_then(Value::as_bool) == Some(true)
}

pub fn assess_control_retirement(input: &Value) -> Result<Value, ArcaneError> {
    let record = object(input.get("record").unwrap_or(&Value::Null), "record")?;
    let status = record
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ArcaneError::typed("ARC_SCHEMA_INVALID", "record.status must be RETIRED or SUPERSEDED")
        })?;
    if status != "RETIRED" && status != "SUPERSEDED" {
        return Err(ArcaneError::typed(
            "ARC_SCHEMA_INVALID",
            "record.status must be RETIRED or SUPERSEDED",
        ));
    }
    let consumer_scan =
        object(input.get("consumerScan").unwrap_or(&Value::Null), "consumerScan")?;
    let obligation_disposition = object(
        input.get("obligationDisposition").unwrap_or(&Value::Null),
        "obligationDisposition",
    )?;
    let mut failures = Vec::new();
    if consumer_scan.get("complete").and_then(Value::as_bool) != Some(true) {
        failures.push(json!({ "code": "ARC_RETIREMENT_CONSUMER_SCAN_MISSING" }));
    }
    let live = consumer_scan.get("liveConsumers").and_then(Value::as_array);
    if live.is_none() || !live.unwrap().is_empty() {
        failures.push(json!({
            "code": "ARC_RETIREMENT_LIVE_CONSUMERS",
            "consumers": consumer_scan.get("liveConsumers").cloned().unwrap_or(Value::Null),
        }));
    }
    let open = obligation_disposition.get("open").and_then(Value::as_array);
    if obligation_disposition.get("complete").and_then(Value::as_bool) != Some(true)
        || open.is_none()
        || !open.unwrap().is_empty()
    {
        failures.push(json!({
            "code": "ARC_RETIREMENT_OBLIGATIONS_OPEN",
            "obligations": obligation_disposition.get("open").cloned().unwrap_or(Value::Null),
        }));
    }
    if input
        .get("migrationEvidence")
        .and_then(|value| value.get("completed"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        failures.push(json!({ "code": "ARC_RETIREMENT_MIGRATION_EVIDENCE_MISSING" }));
    }
    if !passing_eval(input.get("evalProof").unwrap_or(&Value::Null)) {
        failures.push(json!({ "code": "ARC_RETIREMENT_EVAL_PROOF_MISSING" }));
    }
    let allowed = failures.is_empty();
    let retained_status = if status == "SUPERSEDED" {
        "DEPRECATED"
    } else {
        "ACTIVE"
    };
    Ok(json!({
        "schema": SCHEMA,
        "allowed": allowed,
        "code": if allowed { "ARC_RETIREMENT_ALLOWED" } else { "ARC_RETIREMENT_DENIED" },
        "controlId": record.get("control_id").cloned().unwrap_or(Value::Null),
        "status": if allowed { json!(status) } else { json!(retained_status) },
        "failures": failures,
    }))
}
