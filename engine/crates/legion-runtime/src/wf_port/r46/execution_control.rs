//! Port of `execution_control_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~1893-1955).

use super::labels::{action_re, fenced_value_after, is_concrete, path_re};
use super::route_scan::label_value;
use regex::Regex;

fn rules() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "**Resume / reset decision:**",
            r"^(?:RESET_REQUIRED:|RESUME_ALLOWED_IF:)\s*\S",
        ),
        (
            "**Invalid-window disposition:**",
            r"\bSTOP\b.*\b(?:DISCARD|PRESERVE)\b.*\bDO_NOT_COMMIT\b",
        ),
        ("**Authority refresh:**", r"^AUTHORITY_REFRESH:\s*\S"),
        ("**Frozen implementation proof:**", r"^HASH_VERIFY:\s*\S"),
        ("**Batch start gate:**", r"^PROHIBITED_UNTIL_CANARY_PASS\b"),
        (
            "**Defect classification gate:**",
            r"^DEFECT_ONLY_IF:.*\bPRODUCTION_PATH_PROVEN\b.*\bCANARY_PASS\b.*\bCANONICAL_CHECK_FAILS\b",
        ),
        (
            "**Mid-run authority update protocol:**",
            r"^STOP\s*->\s*DISCARD_INVALID_WINDOW\s*->\s*PULL_AUTHORITY\s*->\s*REVERIFY\s*->\s*RESTART_PREFLIGHT$",
        ),
    ]
}

fn rule_re(pattern: &str) -> Regex {
    Regex::new(&format!("(?is){pattern}")).unwrap()
}

/// Port of `execution_control_errors()`.
pub fn execution_control_errors(text: &str, allow_template: bool) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors = Vec::new();

    let invariants = label_value(text, "**Critical discriminating invariants:**").unwrap_or_default();
    if invariants.matches("INVARIANT:").count() < 3 {
        errors.push(
            "**Critical discriminating invariants:** requires at least three embedded INVARIANT entries"
                .to_string(),
        );
    }

    for (label, pattern) in rules() {
        let value = label_value(text, label).unwrap_or_default();
        if !rule_re(pattern).is_match(&value) {
            errors.push(format!("{label} lacks enforceable execution-control contract"));
        }
    }

    let production_path = label_value(text, "**Production path chain:**").unwrap_or_default();
    if !production_path.starts_with("PRODUCTION_PATH:") || production_path.matches("->").count() < 4 {
        errors.push(
            "**Production path chain:** requires PRODUCTION_PATH plus at least five ordered stages"
                .to_string(),
        );
    }

    let trace_link = label_value(text, "**Trace linkage contract:**").unwrap_or_default();
    if !trace_link.starts_with("TRACE_LINK:") || trace_link.matches("->").count() < 4 {
        errors.push(
            "**Trace linkage contract:** requires TRACE_LINK across expected, started, terminal, delivery, & value"
                .to_string(),
        );
    }

    for label in [
        "**Environment integrity step zero:**",
        "**Canary / one-unit preflight:**",
    ] {
        let command = fenced_value_after(text, label).unwrap_or_default();
        if !is_concrete(&command) || !action_re().is_match(&command) || !path_re().is_match(&command) {
            errors.push(format!("{label} requires exact action/command plus evidence path"));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_text() -> String {
        "- **Critical discriminating invariants:** INVARIANT: a INVARIANT: b INVARIANT: c\n\
- **Resume / reset decision:** RESET_REQUIRED: yes\n\
- **Invalid-window disposition:** STOP then DISCARD then DO_NOT_COMMIT\n\
- **Authority refresh:** AUTHORITY_REFRESH: pull\n\
- **Frozen implementation proof:** HASH_VERIFY: abc\n\
- **Batch start gate:** PROHIBITED_UNTIL_CANARY_PASS\n\
- **Defect classification gate:** DEFECT_ONLY_IF: PRODUCTION_PATH_PROVEN and CANARY_PASS and CANONICAL_CHECK_FAILS\n\
- **Mid-run authority update protocol:** STOP -> DISCARD_INVALID_WINDOW -> PULL_AUTHORITY -> REVERIFY -> RESTART_PREFLIGHT\n\
- **Production path chain:** PRODUCTION_PATH: A -> B -> C -> D -> E\n\
- **Trace linkage contract:** TRACE_LINK: A -> B -> C -> D -> E\n\
**Environment integrity step zero:**\n\n```bash\nrun /repo/step0.sh\n```\n\
**Canary / one-unit preflight:**\n\n```bash\nrun /repo/canary.sh\n```\n"
            .to_string()
    }

    #[test]
    fn passes_on_fully_specified_contract() {
        let errors = execution_control_errors(&valid_text(), false);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn allow_template_short_circuits() {
        assert!(execution_control_errors("", true).is_empty());
    }

    #[test]
    fn flags_insufficient_invariants() {
        let text = valid_text().replace(
            "INVARIANT: a INVARIANT: b INVARIANT: c",
            "INVARIANT: a",
        );
        let errors = execution_control_errors(&text, false);
        assert!(errors.iter().any(|e| e.contains("Critical discriminating invariants")));
    }
}
