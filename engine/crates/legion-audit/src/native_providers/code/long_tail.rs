use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.long-tail";
pub const CONFIG: LanguageConfig =
    LanguageConfig::new("generic", &["*"], &[("generic", &["*"])], &[], &[]);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
