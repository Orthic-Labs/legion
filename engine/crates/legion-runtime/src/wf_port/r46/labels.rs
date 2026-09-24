//! Port of the label/value helpers from `validate-dispatch.py`
//! (`authority_label_value`, `is_concrete`, `fenced_value_after`,
//! `LEGACY_AUTHORITY_LABELS`, `GENERIC_VALUES`, `ACTION_RE`, `PATH_RE`,
//! `BOUND_RE`), lines ~952-980, ~815-825.

use super::route_scan::label_value;
use regex::Regex;
use std::sync::OnceLock;

/// Port of `LEGACY_AUTHORITY_LABELS`.
pub fn legacy_authority_label(label: &str) -> Option<&'static str> {
    Some(match label {
        "**Alchemist gate:**" => "**Forge gate:**",
        "**Alchemist state reference:**" => "**Forge state reference:**",
        "**Alchemist verification:**" => "**Forge verification:**",
        "**Alchemist typed-stage binding:**" => "**Forge typed-stage binding:**",
        "**Route Alchemist binding:**" => "**Route Forge binding:**",
        _ => return None,
    })
}

/// Port of `authority_label_value()`.
pub fn authority_label_value(text: &str, label: &str) -> Option<String> {
    if let Some(value) = label_value(text, label) {
        return Some(value);
    }
    let legacy = legacy_authority_label(label)?;
    label_value(text, legacy)
}

/// Port of `GENERIC_VALUES`.
pub fn is_generic_value(normalized: &str) -> bool {
    matches!(
        normalized,
        "" | "fixture-value" | "value" | "example" | "placeholder" | "tbd" | "todo" | "n/a" | "none"
    )
}

/// Port of `is_concrete()`.
pub fn is_concrete(value: &str) -> bool {
    let normalized = value.trim().trim_matches('`').to_lowercase();
    normalized.chars().count() >= 8 && !is_generic_value(&normalized)
}

/// Port of `fenced_value_after()`: the body of the first fenced code block
/// following `label` in `block`, trimmed.
pub fn fenced_value_after(block: &str, label: &str) -> Option<String> {
    let pattern = format!(
        r"(?s){}\s*\n+\s*```[^\n]*\n(.*?)\n```",
        regex::escape(label)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(block)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

pub fn action_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(run|read|search|inspect|verify|retry|use|capture|preserve|stop|continue|compare|fetch|re-fetch|rebuild|isolate|measure|reduce|resume|record|check)\b",
        )
        .unwrap()
    })
}

pub fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[A-Za-z]:[\\/]|/)[^\s`|]+").unwrap())
}

pub fn bound_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d+\b").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_concrete_rejects_generic_and_short_values() {
        assert!(!is_concrete("tbd"));
        assert!(!is_concrete("`n/a`"));
        assert!(!is_concrete("short"));
        assert!(is_concrete("a genuinely specific value"));
    }

    #[test]
    fn authority_label_value_falls_back_to_legacy_label() {
        let text = "- **Forge gate:** REQUIRED: run_id=abc\n";
        assert_eq!(
            authority_label_value(text, "**Alchemist gate:**"),
            Some("REQUIRED: run_id=abc".to_string())
        );
        let direct = "- **Alchemist gate:** REQUIRED: run_id=xyz\n";
        assert_eq!(
            authority_label_value(direct, "**Alchemist gate:**"),
            Some("REQUIRED: run_id=xyz".to_string())
        );
    }

    #[test]
    fn fenced_value_after_extracts_first_block_body() {
        let block = "**Exact action / command:**\n\n```bash\ncargo test\n```\nmore text";
        assert_eq!(
            fenced_value_after(block, "**Exact action / command:**"),
            Some("cargo test".to_string())
        );
        assert_eq!(fenced_value_after(block, "**Missing:**"), None);
    }
}
