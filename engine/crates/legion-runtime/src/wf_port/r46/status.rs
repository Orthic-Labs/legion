//! Port of `status_errors()` from `validate-dispatch.py` (lines ~1830-1846).

use regex::Regex;
use std::sync::OnceLock;

fn status_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^STATUS:\s*(.+)$").unwrap())
}

/// Port of `status_errors()`.
pub fn status_errors(text: &str) -> Vec<String> {
    let allowed = [
        "COMPLETE",
        "COMPLETE_WITH_NOTES",
        "TRUE_BLOCKER",
        "COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER",
    ];
    let mut errors = Vec::new();
    let values: Vec<String> = status_line_re()
        .captures_iter(text)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();
    if values.len() != 1 {
        errors.push("return contract requires exactly one STATUS line".to_string());
    }
    for value in &values {
        if !allowed.contains(&value.trim()) {
            errors.push(format!("forbidden terminal status: {}", value.trim()));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exactly_one_status_line() {
        assert!(status_errors("no status here").iter().any(|e| e.contains("exactly one STATUS")));
        assert!(status_errors("STATUS: COMPLETE\nSTATUS: TRUE_BLOCKER\n")
            .iter()
            .any(|e| e.contains("exactly one STATUS")));
    }

    #[test]
    fn rejects_unknown_status_value() {
        let errors = status_errors("STATUS: MAYBE\n");
        assert!(errors.iter().any(|e| e == "forbidden terminal status: MAYBE"));
    }

    #[test]
    fn accepts_allowed_status_value() {
        assert!(status_errors("STATUS: COMPLETE_WITH_NOTES\n").is_empty());
    }
}
