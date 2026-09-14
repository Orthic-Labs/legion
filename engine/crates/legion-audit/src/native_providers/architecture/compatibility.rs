use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::validate_refs,
};
use serde_json::Value;

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
        serde_json::json!({"producerVersion":object["producerVersion"],"consumerVersion":object["consumerVersion"],"platform":object["platform"],"contract":object["contract"],"expected":object["expected"],"observed":object["observed"],"evidenceRefs":object["evidenceRefs"],"status":if object["expected"] == object["observed"] {"compatible"} else {"incompatible"}}),
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
        "pass",
        true,
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
    for record in records {
        match compatibility_finding(&record) {
            Ok(normalized) => {
                let errors = validate_refs(normalized.get("evidenceRefs"), &authority);
                if errors.is_empty() {
                    examined += 1;
                    if normalized["status"] == "incompatible" {
                        result.findings.push(normalized);
                    }
                } else {
                    result.coverage_gaps.push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":errors.join(",")}));
                }
            }
            Err(error) => result
                .coverage_gaps
                .push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":error})),
        }
    }
    result.denominator["examined"] = Value::from(examined);
    if !result.coverage_gaps.is_empty() {
        result.status = "unproven".into();
        result.complete = false;
    } else if !result.findings.is_empty() {
        result.status = "fail".into();
        result.complete = false;
    }
    Ok(result)
}
