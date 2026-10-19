use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::{limit_runtime_evidence, validate_refs},
};
use serde_json::Value;

/// Compare supplied values; this does not authenticate either observation.
pub fn compatibility_finding(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    for key in ["producerVersion", "consumerVersion", "platform", "contract"] {
        if !truthy(object.get(key)) {
            return Err("bound compatibility context required".into());
        }
    }
    if object.get("expected").is_none()
        || object.get("observed").is_none()
        || !object
            .get("evidenceRefs")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    {
        return Err("expected observed compatibility evidence required".into());
    }
    Ok(
        serde_json::json!({"producerVersion":object["producerVersion"],"consumerVersion":object["consumerVersion"],"platform":object["platform"],"contract":object["contract"],"expected":object["expected"],"observed":object["observed"],"evidenceRefs":object["evidenceRefs"],"status":if object["expected"] == object["observed"] {"compatible"} else {"incompatible"},"certificationClaim":false,"comparisonScope":"caller-supplied-values"}),
    )
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let records = object
        .get("artifacts")
        .and_then(|value| value.get("compatibility"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut result = Analysis::new(
        "unproven",
        false,
        serde_json::json!({"kind":"compatibility-contracts","expected":records.len(),"examined":0}),
    );
    if records.is_empty() {
        result.status = "unproven".into();
        result.complete = false;
        result
            .coverage_gaps
            .push(gap("compatibility-denominator-unavailable"));
    }
    let mut examined = 0;
    let mut comparisons = Vec::new();
    for record in &records {
        match compatibility_finding(record) {
            Ok(normalized) => {
                let errors = validate_refs(normalized.get("evidenceRefs"), &authority);
                if errors.is_empty() {
                    examined += 1;
                    comparisons.push(normalized);
                } else {
                    result.coverage_gaps.push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":errors.join(",")}));
                }
            }
            Err(error) => result
                .coverage_gaps
                .push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":error})),
        }
    }
    result.extras.insert("protocolValidation".into(), serde_json::json!({
        "scope":"caller-supplied-values-and-reference-metadata", "expected":records.len(), "examined":examined
    }));
    result
        .extras
        .insert("comparisons".into(), Value::Array(comparisons));
    limit_runtime_evidence(&mut result);
    Ok(result)
}
