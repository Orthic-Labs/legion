//! Port of `src/lib/providers/sdk/result.mjs`.

use sha2::{Digest, Sha256};

use serde_json::{json, Value};

/// Faithful port of the module-private `digest` helper:
/// ```js
/// const digest = (value) => `sha256:${createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex')}`;
/// ```
/// Relies on `serde_json`'s `preserve_order` feature (enabled workspace-wide)
/// so object key order in `serde_json::to_string` matches JS `JSON.stringify`
/// insertion order for any `Value` built the same way the caller built it.
fn digest(value: &Value) -> String {
    let normalized = if value.is_null() { Value::Null } else { value.clone() };
    let json_text = serde_json::to_string(&normalized).expect("Value serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(json_text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

const TERMINAL: &[&str] = &[
    "pass", "fail", "partial", "unproven", "skipped", "error", "pending", "missing", "candidates", "blocked",
];

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Faithful port of `normalizeProviderResult(provider, result = {})`.
pub fn normalize_provider_result(provider: &Value, result: &Value) -> Value {
    let empty = json!({});
    let result = if result.is_null() { &empty } else { result };

    let gaps: Vec<Value> = result
        .get("coverageGaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let requested_status = match result.get("status").and_then(Value::as_str) {
        Some("measured") => Some("pass".to_owned()),
        Some(other) => Some(other.to_owned()),
        None => None,
    };
    let status = requested_status
        .as_deref()
        .filter(|candidate| TERMINAL.contains(candidate))
        .unwrap_or("unproven")
        .to_owned();

    let complete = result.get("complete").and_then(Value::as_bool).unwrap_or(false)
        && gaps.is_empty()
        && ["pass", "fail", "candidates"].contains(&status.as_str());

    let denominator = result
        .get("denominator")
        .filter(|v| !v.is_null())
        .or_else(|| result.get("coverage").filter(|v| !v.is_null()))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let denominator_digest_field = denominator.get("denominatorDigest").and_then(Value::as_str);
    let denominator_digest = match denominator_digest_field {
        Some(value) if is_sha256_digest(value) => value.to_owned(),
        _ => digest(&denominator),
    };

    // `Number.isInteger(...)` in JS: `serde_json::Value::as_i64` already
    // returns `None` for a non-integer-stored JSON number, matching that.
    let expected = denominator.get("expected").and_then(Value::as_i64).unwrap_or(0);
    let examined = denominator.get("examined").and_then(Value::as_i64).unwrap_or(0);

    let candidates = result.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default();
    let findings = result.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
    let degradation = result
        .get("degradation")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| gaps.clone());

    let provider_id = provider.get("id").cloned().unwrap_or(Value::Null);
    let family = provider.get("family").cloned().unwrap_or(Value::Null);
    let component_ids = result.get("componentIds").cloned().unwrap_or_else(|| json!([]));
    let limitations = result.get("limitations").cloned().unwrap_or_else(|| json!([]));
    let raw_artifacts = result
        .get("rawArtifacts")
        .filter(|v| !v.is_null())
        .or_else(|| result.get("artifacts").filter(|v| !v.is_null()))
        .cloned()
        .unwrap_or_else(|| json!([]));

    json!({
        "schemaVersion": 1,
        "provider": provider_id,
        "applicable": result.get("applicable").and_then(Value::as_bool).unwrap_or(true),
        "required": result.get("required").and_then(Value::as_bool).unwrap_or(true),
        "status": if complete { Value::String(status) } else { Value::String("unproven".to_owned()) },
        "complete": complete,
        "coverage": {
            "denominatorDigest": denominator_digest,
            "expected": expected,
            "examined": examined,
        },
        "candidates": candidates,
        "findings": findings,
        "coverageGaps": gaps,
        "degradation": degradation,
        "details": {
            "family": family,
            "componentIds": component_ids,
            "limitations": limitations,
            "rawArtifacts": raw_artifacts,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn measured_status_normalizes_to_pass_when_complete() {
        let provider = json!({"id": "p", "family": "security"});
        let result = json!({"status": "measured", "complete": true, "findings": []});
        let normalized = normalize_provider_result(&provider, &result);
        assert_eq!(normalized["status"], "pass");
        assert_eq!(normalized["complete"], true);
        assert_eq!(normalized["provider"], "p");
    }

    #[test]
    fn incomplete_result_forces_unproven_status() {
        let provider = json!({"id": "p"});
        let result = json!({"status": "pass", "complete": false});
        let normalized = normalize_provider_result(&provider, &result);
        assert_eq!(normalized["status"], "unproven");
        assert_eq!(normalized["complete"], false);
    }

    #[test]
    fn non_terminal_status_falls_back_to_unproven_request() {
        let provider = json!({"id": "p"});
        let result = json!({"status": "not-a-status", "complete": true});
        let normalized = normalize_provider_result(&provider, &result);
        // status starts as 'unproven' (not terminal-passthrough) and IS in
        // ['pass','fail','candidates']? no -> complete becomes false via the
        // membership check, so overall status is 'unproven'.
        assert_eq!(normalized["status"], "unproven");
        assert_eq!(normalized["complete"], false);
    }

    #[test]
    fn nonempty_coverage_gaps_force_incomplete() {
        let provider = json!({"id": "p"});
        let result = json!({"status": "pass", "complete": true, "coverageGaps": ["gap"]});
        let normalized = normalize_provider_result(&provider, &result);
        assert_eq!(normalized["complete"], false);
        assert_eq!(normalized["status"], "unproven");
        assert_eq!(normalized["coverageGaps"], json!(["gap"]));
    }

    #[test]
    fn denominator_digest_is_reused_when_valid_sha256() {
        let provider = json!({"id": "p"});
        let good = format!("sha256:{}", "a".repeat(64));
        let result = json!({"denominator": {"denominatorDigest": good.clone()}});
        let normalized = normalize_provider_result(&provider, &result);
        assert_eq!(normalized["coverage"]["denominatorDigest"], good);
    }

    #[test]
    fn denominator_digest_is_computed_when_missing_or_invalid() {
        let provider = json!({"id": "p"});
        let result = json!({"denominator": {"denominatorDigest": "not-a-digest"}});
        let normalized = normalize_provider_result(&provider, &result);
        let value = normalized["coverage"]["denominatorDigest"].as_str().unwrap();
        assert!(value.starts_with("sha256:"));
        assert_ne!(value, "not-a-digest");
    }

    #[test]
    fn falls_back_to_coverage_field_when_denominator_absent() {
        let provider = json!({"id": "p"});
        let result = json!({"coverage": {"expected": 5, "examined": 3}});
        let normalized = normalize_provider_result(&provider, &result);
        assert_eq!(normalized["coverage"]["expected"], 5);
        assert_eq!(normalized["coverage"]["examined"], 3);
    }

    #[test]
    fn empty_result_defaults_are_applied() {
        let provider = json!({"id": "p"});
        let normalized = normalize_provider_result(&provider, &Value::Null);
        assert_eq!(normalized["schemaVersion"], 1);
        assert_eq!(normalized["applicable"], true);
        assert_eq!(normalized["required"], true);
        assert_eq!(normalized["status"], "unproven");
        assert_eq!(normalized["complete"], false);
        assert_eq!(normalized["candidates"], json!([]));
        assert_eq!(normalized["findings"], json!([]));
    }
}
