use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.mobile";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "apple",
    &["swift", "m", "mm"],
    &[
        ("swift", &["swift"]),
        ("objectiveC", &["m"]),
        ("objectiveCpp", &["mm"]),
    ],
    &["compiler", "analyzer", "test"],
    &["platform"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
