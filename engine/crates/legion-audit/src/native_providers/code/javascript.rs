use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.javascript";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "javascript",
    &["js", "jsx", "ts", "tsx"],
    &[
        ("javascript", &["js"]),
        ("typescript", &["ts"]),
        ("jsx", &["jsx"]),
        ("tsx", &["tsx"]),
    ],
    &["type", "lint", "build", "test"],
    &[],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
