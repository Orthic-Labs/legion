use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::validate_refs,
};
use serde_json::Value;

pub fn doc_claim(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    if !truthy(object.get("claim")) || !truthy(object.get("authority")) {
        return Err("document claim requires authority".into());
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unproven");
    let evidence = object
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if status == "verified" && evidence.is_empty() {
        return Err("verified document claim requires evidence".into());
    }
    Ok(
        serde_json::json!({"claim":object["claim"],"authority":object["authority"],"status":status,"evidence":evidence,"implementationInferred":false}),
    )
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let claims = object
        .get("artifacts")
        .and_then(|value| value.get("docClaims"))
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
    for claim in claims.iter() {
        match doc_claim(claim) {
            Ok(row) => {
                if row["status"] == "verified" {
                    let errors = validate_refs(row.get("evidence"), &authority);
                    if !errors.is_empty() {
                        gaps.push(serde_json::json!({"kind":"doc-claim-invalid","reason":errors.join(",")}));
                        continue;
                    }
                }
                normalized.push(row);
            }
            Err(error) => gaps.push(serde_json::json!({"kind":"doc-claim-invalid","reason":error})),
        }
    }
    if claims.is_empty() {
        gaps.push(gap("doc-claim-denominator-zero"));
    }
    let findings = normalized
        .iter()
        .filter(|row| row["status"] == "contradicted")
        .cloned()
        .collect::<Vec<_>>();
    let mut result = Analysis::new(
        if gaps.is_empty() { "pass" } else { "unproven" },
        gaps.is_empty(),
        serde_json::json!({"kind":"document-claims","expected":claims.len(),"examined":normalized.len()}),
    );
    result.findings = findings;
    result.coverage_gaps = gaps;
    Ok(result)
}
