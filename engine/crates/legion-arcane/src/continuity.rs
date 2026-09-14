use crate::error::ArcaneError;
use legion_contracts::canonical_digest;
use serde_json::{json, Value};

pub fn rehydrate_untrusted_data(envelope: &Value) -> Result<Value, ArcaneError> {
    if envelope.get("schema").and_then(Value::as_str) != Some("rehydration-envelope.v1")
        || envelope.get("trust").and_then(Value::as_str) != Some("UNTRUSTED_DATA")
    {
        return Err(ArcaneError::typed(
            "REHYDRATION_REJECTED",
            "rehydration envelope must be typed UNTRUSTED_DATA",
        ));
    }
    let content_digest = envelope
        .get("content_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ArcaneError::typed("REHYDRATION_REJECTED", "rehydration content digest mismatch")
        })?;
    if !content_digest.starts_with("sha256:") {
        return Err(ArcaneError::typed(
            "REHYDRATION_REJECTED",
            "rehydration content digest mismatch",
        ));
    }
    let payload = envelope.get("payload").cloned().unwrap_or(Value::Null);
    let expected = canonical_digest(&payload)?;
    if expected != content_digest {
        return Err(ArcaneError::typed(
            "REHYDRATION_REJECTED",
            "rehydration content digest mismatch",
        ));
    }
    Ok(json!({
        "data": payload,
        "authority_granted": false,
        "instruction_status": "DATA_ONLY",
        "preference_write_allowed": false,
        "effect_downgrade_allowed": false,
    }))
}
