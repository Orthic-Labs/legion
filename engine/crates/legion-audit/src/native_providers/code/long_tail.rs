use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.long-tail";
pub const CONFIG: LanguageConfig =
    LanguageConfig::new("generic", &["*"], &[("generic", &["*"])], &[], &[]);

pub fn analyze(input: &Value) -> Value {
    let mut analysis = analyze_language(&CONFIG, input);
    let unsupported = input
        .get("unsupportedLanguageCoverage")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let extension = item.get("extension")?.as_str()?;
            let path_count = item.get("pathCount")?.as_u64()?;
            Some(serde_json::json!({
                "kind": "missing-language-provider",
                "language": extension,
                "extension": extension,
                "pathCount": path_count,
                "samplePaths": item.get("samplePaths").cloned().unwrap_or_else(|| serde_json::json!([])),
            }))
        })
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        analysis["complete"] = Value::Bool(false);
        if let Some(gaps) = analysis
            .get_mut("coverageGaps")
            .and_then(Value::as_array_mut)
        {
            gaps.extend(unsupported);
        }
    }
    analysis
}
