use super::common::{gap, object_input, truthy, Analysis};
use serde_json::Value;

pub fn architecture_finding(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    if !object
        .get("dependencyPath")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        return Err("architecture finding requires dependency path".into());
    }
    if !truthy(object.get("scenario")) {
        return Err("architecture finding requires representative scenario".into());
    }
    if !object
        .get("affectedConsumers")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        return Err("architecture finding requires affected consumers".into());
    }
    let mut output = serde_json::Map::new();
    output.insert("schemaVersion".into(), Value::from(1));
    output.insert("edgeConfidence".into(), Value::String("observed".into()));
    output.extend(object.clone());
    Ok(Value::Object(output))
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let edges = object
        .get("projection")
        .and_then(|value| value.get("auditFacts"))
        .and_then(|value| value.get("dependencyEdges"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut result = Analysis::new(
        if edges.is_empty() { "unproven" } else { "pass" },
        !edges.is_empty(),
        serde_json::json!({"kind":"dependency-edges","expected":edges.len(),"examined":edges.len()}),
    );
    if edges.is_empty() {
        result
            .coverage_gaps
            .push(gap("architecture-graph-unavailable"));
    }
    Ok(result)
}
