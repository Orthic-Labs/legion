use serde_json::{json, Value};

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.rust";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "rust",
    &["rs"],
    &[("rust", &["rs"])],
    &["metadata", "check", "lint", "test", "dependency"],
    &["features", "targets"],
);

pub fn analyze(input: &Value) -> Value {
    let mut output = analyze_language(&CONFIG, input);
    if input["unsafeKeywordCandidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        output["coverageGaps"].as_array_mut().expect("analyzer gaps").push(json!({
            "kind":"unsafe-assessment-unavailable", "context":"unsafe-soundness",
            "candidateLocations":input["unsafeKeywordCandidates"],
            "inventorySemantics":"conservative keyword candidates; no semantic soundness assessment",
        }));
        output["complete"] = json!(false);
    }
    if input["rustVariantGaps"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        output["coverageGaps"].as_array_mut().expect("analyzer gaps").push(json!({
            "kind":"unproven-build-variant", "context":"features-and-targets", "evidence":input["rustVariantGaps"],
        }));
        output["complete"] = json!(false);
    }
    output
}
