//! Port of `execution_identity_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~1847-1887).

use super::labels::{action_re, fenced_value_after, is_concrete, path_re};
use super::route_scan::label_value;
use regex::Regex;

fn rules() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "**Required producer / actor:**",
            r"^PRODUCER:\s*\S.+\bPROOF_FIELD:\s*\S",
        ),
        ("**Allowed provenance / lineage:**", r"^ALLOW_ONLY:\s*\S"),
        (
            "**Forbidden producers / substitutes:**",
            r"^(?:FORBID:\s*\S|NONE_CHECKED\s+—\s+\S)",
        ),
        (
            "**Existing-work disposition:**",
            r"\bINVENTORY:\s*\S.+\bREJECT_IF_INCOMPATIBLE:\s*\S.+\bRESUME_ONLY_IF:\s*\S",
        ),
        (
            "**Substitution policy:**",
            r"^(?:NO_SUBSTITUTION\b|ALLOWED_EQUIVALENTS:\s*\S)",
        ),
        ("**Allowed result derivation:**", r"^DIRECT_ONLY:\s*\S"),
        ("**Forbidden result derivation:**", r"^FORBID:\s*\S"),
    ]
}

fn rule_re(pattern: &str) -> Regex {
    Regex::new(&format!("(?is){pattern}")).unwrap()
}

/// Port of `execution_identity_errors()`.
pub fn execution_identity_errors(text: &str, allow_template: bool) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors = Vec::new();
    for (label, pattern) in rules() {
        let value = label_value(text, label).unwrap_or_default();
        if !rule_re(pattern).is_match(&value) {
            errors.push(format!(
                "{label} lacks enforceable identity/provenance contract"
            ));
        }
    }

    let lifecycle = label_value(text, "**Required lifecycle chain:**").unwrap_or_default();
    if !lifecycle.starts_with("LIFECYCLE:") || lifecycle.matches("->").count() < 4 {
        errors.push(
            "**Required lifecycle chain:** requires LIFECYCLE plus at least five ordered states"
                .to_string(),
        );
    }

    let preflight = fenced_value_after(text, "**Lifecycle preflight:**").unwrap_or_default();
    if !is_concrete(&preflight)
        || !action_re().is_match(&preflight)
        || !path_re().is_match(&preflight)
    {
        errors.push(
            "**Lifecycle preflight:** requires exact action/command plus evidence path"
                .to_string(),
        );
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_text() -> String {
        "- **Required producer / actor:** PRODUCER: agent PROOF_FIELD: run_id\n\
- **Allowed provenance / lineage:** ALLOW_ONLY: direct\n\
- **Forbidden producers / substitutes:** FORBID: cached\n\
- **Existing-work disposition:** INVENTORY: scan REJECT_IF_INCOMPATIBLE: yes RESUME_ONLY_IF: match\n\
- **Substitution policy:** NO_SUBSTITUTION\n\
- **Allowed result derivation:** DIRECT_ONLY: yes\n\
- **Forbidden result derivation:** FORBID: indirect\n\
- **Required lifecycle chain:** LIFECYCLE: A -> B -> C -> D -> E\n\
**Lifecycle preflight:**\n\n```bash\nrun /repo/preflight.sh\n```\n"
            .to_string()
    }

    #[test]
    fn passes_on_fully_specified_contract() {
        assert!(execution_identity_errors(&valid_text(), false).is_empty());
    }

    #[test]
    fn allow_template_short_circuits() {
        assert!(execution_identity_errors("", true).is_empty());
    }

    #[test]
    fn flags_missing_lifecycle_chain_arrows() {
        let mut text = valid_text();
        text = text.replace(
            "LIFECYCLE: A -> B -> C -> D -> E",
            "LIFECYCLE: A -> B",
        );
        let errors = execution_identity_errors(&text, false);
        assert!(errors.iter().any(|e| e.contains("Required lifecycle chain")));
    }

    #[test]
    fn flags_missing_preflight_path() {
        let text = valid_text().replace("run /repo/preflight.sh", "run something");
        let errors = execution_identity_errors(&text, false);
        assert!(errors.iter().any(|e| e.contains("Lifecycle preflight")));
    }
}
