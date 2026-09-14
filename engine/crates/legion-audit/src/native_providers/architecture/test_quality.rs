use super::common::{gap, object_input, truthy, Analysis};
use serde_json::Value;
pub fn classify_test_gap(value: Option<&str>) -> &str {
    match value {
        Some("missing") => "missing-coverage",
        Some("weak") => "weak-oracle",
        Some("fake") => "fake-completion",
        _ => "unproven-pattern",
    }
}
pub fn test_quality_finding(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    if !truthy(object.get("evidencePath")) || !truthy(object.get("contract")) {
        return Err("test-quality evidence and contract required".into());
    }
    let mut result = object.clone();
    result.insert(
        "kind".into(),
        Value::String(classify_test_gap(object.get("kind").and_then(Value::as_str)).into()),
    );
    result.insert(
        "adjudicationRequired".into(),
        Value::Bool(truthy(object.get("subjective"))),
    );
    Ok(Value::Object(result))
}
pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let observations = object
        .get("artifacts")
        .and_then(|v| v.get("testQuality"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut findings = Vec::new();
    let mut gaps = Vec::new();
    for observation in &observations {
        match test_quality_finding(observation) {
            Ok(row) => findings.push(row),
            Err(error) => gaps
                .push(serde_json::json!({"kind":"test-quality-evidence-invalid","reason":error})),
        }
    }
    if observations.is_empty() {
        gaps.push(gap("test-quality-denominator-zero"));
    }
    let mut result = Analysis::new(
        if !gaps.is_empty() {
            "unproven"
        } else if !findings.is_empty() {
            "fail"
        } else {
            "pass"
        },
        gaps.is_empty(),
        serde_json::json!({"kind":"test-quality-observations","expected":observations.len(),"examined":findings.len()}),
    );
    result.findings = findings;
    result.coverage_gaps = gaps;
    Ok(result)
}
