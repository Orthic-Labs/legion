use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.python";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "python",
    &["py"],
    &[("python", &["py"])],
    &["compile", "lint", "type", "test", "package"],
    &["packageRoots"],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
