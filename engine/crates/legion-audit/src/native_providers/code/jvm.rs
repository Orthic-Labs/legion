use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.jvm";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "jvm",
    &["java", "kt", "scala"],
    &[
        ("java", &["java"]),
        ("kotlin", &["kt"]),
        ("scala", &["scala"]),
    ],
    &["wrapper", "compile", "lint", "test", "dependency"],
    &["sourceSets"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
