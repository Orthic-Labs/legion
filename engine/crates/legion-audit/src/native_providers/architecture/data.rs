use super::{
    common::{object_input, Analysis},
    evidence,
};
use serde_json::Value;

/// Port of `frameworks/data/index.mjs::analyzeData`.
pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let models = object
        .get("artifacts")
        .and_then(|value| value.get("dataModels"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let qualified = models
        .iter()
        .filter(|model| {
            model.as_object().is_some_and(|model| {
                model
                    .get("path")
                    .is_some_and(|value| super::common::truthy(Some(value)))
                    && evidence::validate_refs(model.get("evidenceRefs"), &authority).is_empty()
            })
        })
        .count();
    let mut gaps = Vec::new();
    if models.is_empty() {
        gaps.push(super::common::gap("model-denominator-gap"));
    }
    if qualified != models.len() {
        gaps.push(super::common::gap("model-evidence-gap"));
    }
    let mut result = Analysis::new(
        if gaps.is_empty() {
            "measured"
        } else {
            "unproven"
        },
        gaps.is_empty(),
        serde_json::json!({"kind":"data-operations","expected":models.len(),"examined":qualified}),
    );
    result.include_findings = false;
    result.extras.insert("facts".into(), serde_json::json!({"integrity":[],"privacy":[],"performance":[],"reliability":[],"security":[]}));
    result.coverage_gaps = gaps;
    Ok(result)
}

pub use analyze as analyze_data;
