use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.go";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "go",
    &["go"],
    &[("go", &["go"])],
    &["module", "format", "vet", "test", "vulnerability"],
    &["modules", "buildTags"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
