use serde_json::Value;

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
    analyze_language(&CONFIG, input)
}
