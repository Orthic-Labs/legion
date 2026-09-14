use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.c-family";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "c-family",
    &["c", "cc", "cpp", "h", "hpp"],
    &[("c", &["c", "h"]), ("cpp", &["cc", "cpp", "hpp"])],
    &["compiler", "lint", "analyzer", "sanitizer", "test"],
    &["compileDatabase"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
