//! Port of `BYPASS_PATTERNS`, `SECRET_PATTERNS`, and `PLACEHOLDER_RE` from
//! `validate-dispatch.py` (lines ~815-833, ~832).
//!
//! The regex crate has no lookaround/backreferences; every pattern below is
//! a direct, lookaround-free transliteration of the Python source (all of
//! the Python patterns already avoid both features).

use regex::Regex;
use std::sync::OnceLock;

/// Port of `BYPASS_PATTERNS`: `(name, pattern)` pairs, checked
/// case-insensitively.
pub const BYPASS_PATTERNS: &[(&str, &str)] = &[
    (
        "chat-context dependency",
        r"\b(as discussed|see above|from earlier|existing context|prior[- ](?:thread|chat|conversation) context|earlier[- ](?:thread|chat|conversation)|inherited context|remembered state|implicit credentials?|(?:old|earlier|prior)[- ](?:messages?|session|history))\b",
    ),
    (
        "externalized critical meaning",
        r"\b(?:read|follow)\s+(?:the\s+)?(?:guide|plan|runbook)\b",
    ),
    (
        "delegated judgment",
        r"\b(figure it out|use (your )?best judgment|whatever works)\b",
    ),
    ("unfinished placeholder", r"\b(TODO|TBD|TK)\b"),
    ("vague scope", r"\b(relevant files|usual commands|standard checks)\b"),
    ("optional requirement", r"\b(if needed|if possible|try to)\b"),
    (
        "non-operational instruction",
        r"\b(make it work|clean up|best effort|if appropriate|as needed)\b",
    ),
    (
        "vague quality claim",
        r"\b(ensure|handle|review)\s+(it|things|everything|properly|correctly)\b",
    ),
    ("uncertain instruction", r"\b(probably|might|soon|later)\b"),
];

/// Port of `SECRET_PATTERNS`. Case-sensitivity mirrors the Python source:
/// entries whose Python pattern carries `(?i)` are matched
/// case-insensitively here too; the rest are case-sensitive.
pub const SECRET_PATTERNS: &[(&str, &str, bool)] = &[
    ("OpenAI-like key", r"\bsk-[A-Za-z0-9_-]{20,}\b", false),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", false),
    ("Slack token", r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b", false),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", false),
    (
        "private key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        false,
    ),
    (
        "literal secret assignment",
        r"\b(password|api[_-]?key|secret|token)\s*[:=]\s*[`\x22']?[A-Za-z0-9+/=_-]{12,}",
        true,
    ),
    (
        "authorization header",
        r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}",
        true,
    ),
    (
        "bearer credential",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
        true,
    ),
];

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{[^{}\n]+\}\}").unwrap())
}

/// Port of `PLACEHOLDER_RE.search(text)`.
pub fn has_unfilled_placeholder(text: &str) -> bool {
    placeholder_re().is_match(text)
}

fn compiled(pattern: &str, case_insensitive: bool) -> Regex {
    let source = if case_insensitive {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    Regex::new(&source).unwrap_or_else(|e| panic!("bad pattern {pattern:?}: {e}"))
}

/// Port of the `BYPASS_PATTERNS` loop in `validate()` (case-insensitive,
/// first match per pattern only, exactly like Python's `re.search`).
pub fn bypass_pattern_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, pattern) in BYPASS_PATTERNS {
        let re = compiled(pattern, true);
        if let Some(m) = re.find(text) {
            errors.push(format!("{name}: forbidden phrase '{}'", m.as_str()));
        }
    }
    errors
}

/// Port of the `SECRET_PATTERNS` loop in `validate()` (only run when
/// `!allow_template`, per the Python source).
pub fn secret_pattern_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, pattern, case_insensitive) in SECRET_PATTERNS {
        let re = compiled(pattern, *case_insensitive);
        if re.is_match(text) {
            errors.push(format!("possible secret detected: {name}"));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bypass_phrase() {
        let errors = bypass_pattern_errors("please use your best judgment here");
        assert!(errors.iter().any(|e| e.starts_with("delegated judgment")));
    }

    #[test]
    fn detects_secret_pattern() {
        let errors = secret_pattern_errors("token: abcdefghijklmnopqrst");
        assert!(errors.iter().any(|e| e.contains("literal secret assignment")));
    }

    #[test]
    fn placeholder_detection() {
        assert!(has_unfilled_placeholder("value: {{fill me}}"));
        assert!(!has_unfilled_placeholder("value: concrete"));
    }

    #[test]
    fn no_false_positive_on_clean_text() {
        assert!(bypass_pattern_errors("this text is entirely concrete and specific").is_empty());
        assert!(secret_pattern_errors("this text is entirely concrete and specific").is_empty());
    }
}
