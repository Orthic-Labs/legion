use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.dotnet";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "dotnet",
    &["cs", "fs", "vb"],
    &[
        ("csharp", &["cs"]),
        ("fsharp", &["fs"]),
        ("visualBasic", &["vb"]),
    ],
    &["restore", "build", "analyzer", "test"],
    &["targetFrameworks"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
