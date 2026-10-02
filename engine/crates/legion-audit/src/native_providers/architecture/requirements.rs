use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::validate_refs,
};
use serde_json::Value;
const STATES: &[&str] = &[
    "implemented-and-verified",
    "implemented-unverified",
    "missing",
    "contradicted",
    "ambiguous",
    "superseded",
    "deferred",
    "unproven",
    "aspirational",
];

pub fn trace_requirement(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    if !truthy(object.get("id"))
        || !truthy(object.get("authority"))
        || !truthy(object.get("owner"))
        || !object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| STATES.contains(&status))
    {
        return Err("invalid requirement disposition".into());
    }
    let evidence = object
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if object["status"] == "implemented-and-verified" && evidence.is_empty() {
        return Err("verified requirement requires evidence".into());
    }
    let mut result = object.clone();
    result.insert("evidence".into(), Value::Array(evidence));
    if !result.contains_key("edges") || result["edges"].is_null() {
        result.insert("edges".into(), Value::Array(Vec::new()));
    }
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn requirement(status: Value) -> Value {
        json!({
            "id": "req-1",
            "authority": "product",
            "owner": "team",
            "status": status,
        })
    }

    #[test]
    fn accepts_every_requirement_status() {
        for status in STATES {
            let mut value = requirement(json!(status));
            if *status == "implemented-and-verified" {
                value["evidence"] = json!(["evidence-1"]);
            }
            assert!(trace_requirement(&value).is_ok(), "{status}");
        }
    }

    #[test]
    fn rejects_missing_non_string_and_unknown_statuses() {
        for status in [None, Some(json!(42)), Some(json!("unknown"))] {
            let mut value = requirement(status.clone().unwrap_or(Value::Null));
            if status.is_none() {
                value.as_object_mut().unwrap().remove("status");
            }
            assert!(trace_requirement(&value).is_err());
        }
    }

    #[test]
    fn rejects_missing_required_metadata() {
        for field in ["id", "authority", "owner"] {
            let mut value = requirement(json!("missing"));
            value.as_object_mut().unwrap().remove(field);
            assert!(trace_requirement(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn verified_requires_non_empty_evidence() {
        for evidence in [None, Some(json!([]))] {
            let mut value = requirement(json!("implemented-and-verified"));
            if let Some(evidence) = evidence {
                value["evidence"] = evidence;
            }
            assert!(trace_requirement(&value).is_err());
        }
    }

    #[test]
    fn verified_accepts_non_empty_evidence_array() {
        let value = requirement(json!("implemented-and-verified"));
        let value = {
            let mut value = value;
            value["evidence"] = json!(["evidence-1"]);
            value
        };
        let output = trace_requirement(&value).unwrap();
        assert_eq!(output["evidence"], json!(["evidence-1"]));
    }

    #[test]
    fn non_verified_missing_evidence_normalizes_to_empty_array() {
        let output = trace_requirement(&requirement(json!("missing"))).unwrap();
        assert_eq!(output["evidence"], json!([]));
    }
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let requirements = object
        .get("artifacts")
        .and_then(|v| v.get("requirements"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut normalized = Vec::new();
    let mut gaps = Vec::new();
    for requirement in &requirements {
        match trace_requirement(requirement) {
            Ok(row) => {
                if row["status"] == "implemented-and-verified" {
                    let errors = validate_refs(row.get("evidence"), &authority);
                    if !errors.is_empty() {
                        gaps.push(serde_json::json!({"kind":"requirement-trace-invalid","reason":errors.join(",")}));
                        continue;
                    }
                }
                normalized.push(row)
            }
            Err(error) => {
                gaps.push(serde_json::json!({"kind":"requirement-trace-invalid","reason":error}))
            }
        }
    }
    if requirements.is_empty() {
        gaps.push(gap("requirement-denominator-zero"));
    }
    let findings = normalized
        .iter()
        .filter(|row| {
            !matches!(
                row["status"].as_str(),
                Some("implemented-and-verified" | "superseded" | "deferred" | "aspirational")
            )
        })
        .cloned()
        .collect();
    let mut result = Analysis::new(
        if gaps.is_empty() { "pass" } else { "unproven" },
        gaps.is_empty(),
        serde_json::json!({"kind":"requirements","expected":requirements.len(),"examined":normalized.len()}),
    );
    result.findings = findings;
    result.coverage_gaps = gaps;
    Ok(result)
}
