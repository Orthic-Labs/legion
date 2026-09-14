use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.php-ruby";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "php",
    &["php"],
    &[("php", &["php"])],
    &["package", "lint", "type", "test", "security"],
    &[],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}
