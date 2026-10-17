use serde_json::Value;

use super::common::{analyze_language, LanguageConfig};

pub const PROVIDER_ID: &str = "code.php-ruby";
pub const CONFIG: LanguageConfig = LanguageConfig::new(
    "php",
    &["php", "rb"],
    &[("php", &["php"]), ("ruby", &["rb"])],
    &["package", "lint", "ruby-lint", "type", "test", "security"],
    &[],
);

pub fn analyze(input: &Value) -> Value {
    analyze_language(&CONFIG, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ruby_lint_receipts_do_not_become_php_lint_receipts() {
        let result = analyze(&json!({
            "files": [{"path": "app.rb"}, {"path": "app.php"}],
            "tools": {"ruby-lint": {"status": "pass", "identity": {"name": "rubocop", "version": "1.80.2"}, "artifactDigest": "sha256:fixture", "scope": {"runs": 1}}},
        }));
        let tools = result["toolEvidence"].as_array().unwrap();
        assert_eq!(
            tools.iter().find(|tool| tool["id"] == "ruby-lint").unwrap()["status"],
            "pass"
        );
        assert_eq!(
            tools.iter().find(|tool| tool["id"] == "lint").unwrap()["status"],
            "unavailable"
        );
    }
}
