use crate::decision::{decision, is_record};
use serde_json::{json, Value};

fn matches_expected(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    let (Some(actual), Some(expected)) = (actual.as_object(), expected.as_object()) else {
        return false;
    };
    expected
        .iter()
        .all(|(key, value)| actual.get(key).is_some_and(|actual| matches_expected(actual, value)))
}

pub fn verify_command_result(
    observed: &Value,
    expected_output: Option<&Value>,
) -> Value {
    let exit_code = observed.get("exitCode").and_then(Value::as_i64);
    if exit_code != Some(0) {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            Some("command exit status is not successful"),
            json!({ "exitCode": exit_code }),
        );
    }
    let expected_output = expected_output.filter(|value| is_record(value));
    if expected_output.is_none() {
        return decision(
            false,
            Some("ARC_SCHEMA_INVALID"),
            Some("expected command output must be structured"),
            json!({}),
        );
    }
    let structured_output = observed.get("structuredOutput");
    if !structured_output.is_some_and(is_record) {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            Some("command did not emit structured output"),
            json!({}),
        );
    }
    if !matches_expected(structured_output.unwrap(), expected_output.unwrap()) {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            Some("command structured output does not satisfy expectation"),
            json!({}),
        );
    }
    decision(
        true,
        None,
        None,
        json!({
            "exitCode": exit_code,
            "structuredOutput": structured_output,
        }),
    )
}
