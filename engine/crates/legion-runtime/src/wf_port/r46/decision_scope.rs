//! Port of `decision_scope_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~1957-2140).

use super::labels::authority_label_value;
use super::route_scan::label_value;
use super::tables::table_rows;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn rules() -> &'static [(&'static str, &'static str)] {
    &[
        ("**Primary decision questions:**", r"\bQUESTION_1:\s*\S"),
        ("**Decision rule:**", r"^DECIDE_BY:\s*\S"),
        ("**Acceptance metrics only:**", r"^METRICS_ONLY:\s*\S"),
        ("**Diagnostics only:**", r"^DIAGNOSTIC_ONLY:\s*\S"),
        ("**Explicit forbidden scope:**", r"^FORBID:\s*\S"),
        ("**Workload / fixture roles:**", r"^WORKLOAD_ROLE:\s*\S"),
        (
            "**Ground-truth policy:**",
            r"^GROUND_TRUTH_SOURCE:\s*\S.*\bMEASURED_OUTPUT_NOT_GROUND_TRUTH\b",
        ),
        ("**Model / tool relevance rule:**", r"^LOAD_ONLY_IF_METRIC:\s*\S"),
        (
            "**Locked model / runtime route:**",
            r"^(?:ROUTE_LOCK:|NO_MODEL_ALLOWED:)\s*\S",
        ),
        ("**Recovery scope rule:**", r"^NO_SCOPE_EXPANSION:\s*\S"),
        ("**First-action readback:**", r"^READBACK_REQUIRED:\s*\S"),
        (
            "**Supervision cadence:**",
            r"^SUPERVISE:\s*.*\b\d+\b.*\b(?:minute|unit|step|action|command)s?\b",
        ),
    ]
}

fn rule_re(pattern: &str) -> Regex {
    Regex::new(&format!("(?is){pattern}")).unwrap()
}

fn allowed_semantics() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "ROUTINE",
            "EXPERIMENT",
            "BENCHMARK",
            "PERFORMANCE",
            "MODEL",
            "RESEARCH",
            "REPEATED_FAILURE",
        ]
        .into_iter()
        .collect()
    })
}

fn non_routine_semantics() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "EXPERIMENT",
            "BENCHMARK",
            "PERFORMANCE",
            "MODEL",
            "RESEARCH",
            "REPEATED_FAILURE",
        ]
        .into_iter()
        .collect()
    })
}

fn split_tokens(raw: &str) -> BTreeSet<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"[\s,|/+]+").unwrap());
    re.split(&raw.to_uppercase())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn alchemist_gate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^REQUIRED:\s*run_id=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        )
        .unwrap()
    })
}

fn scope_items(value: &str, prefix: &str) -> Vec<String> {
    let raw = if value.to_uppercase().starts_with(prefix) {
        &value[prefix.len()..]
    } else {
        value
    };
    static STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let strip_re = STRIP_RE.get_or_init(|| Regex::new(r"(?i)^(?:and|or)\s+").unwrap());
    static SPLIT_RE: OnceLock<Regex> = OnceLock::new();
    let split_re = SPLIT_RE.get_or_init(|| Regex::new(r"[,|;]").unwrap());
    split_re
        .split(raw)
        .filter(|item| item.trim().chars().count() >= 4)
        .map(|item| strip_re.replace(item.trim(), "").to_lowercase())
        .collect()
}

/// Port of `decision_scope_errors()`.
pub fn decision_scope_errors(text: &str, allow_template: bool) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors = Vec::new();

    let semantics_raw = label_value(text, "**Task semantics:**").unwrap_or_default();
    let semantics = split_tokens(&semantics_raw);
    let semantics_set: BTreeSet<&str> = semantics.iter().map(|s| s.as_str()).collect();
    if semantics.is_empty() || !semantics_set.is_subset(allowed_semantics()) {
        errors.push(
            "**Task semantics:** must use only ROUTINE, EXPERIMENT, BENCHMARK, PERFORMANCE, MODEL, RESEARCH, or REPEATED_FAILURE"
                .to_string(),
        );
    }

    for (label, pattern) in rules() {
        let value = label_value(text, label).unwrap_or_default();
        if !rule_re(pattern).is_match(&value) {
            errors.push(format!("{label} lacks enforceable decision-scope contract"));
        }
    }

    let alchemist_required = semantics_set.iter().any(|s| non_routine_semantics().contains(s));
    let alchemist_gate = authority_label_value(text, "**Alchemist gate:**").unwrap_or_default();
    let alchemist_state =
        authority_label_value(text, "**Alchemist state reference:**").unwrap_or_default();
    let alchemist_verify =
        authority_label_value(text, "**Alchemist verification:**").unwrap_or_default();

    if alchemist_required {
        if !alchemist_gate_re().is_match(&alchemist_gate) {
            errors.push(
                "**Alchemist gate:** non-routine semantic work requires REQUIRED run_id=<uuid>"
                    .to_string(),
            );
        } else if let Some((_, run_id)) = alchemist_gate.split_once('=') {
            let run_id = run_id.trim();
            let expected_a = format!("alchemist://run/{run_id}/state");
            let expected_b = format!("forge://run/{run_id}/state");
            if alchemist_state != expected_a && alchemist_state != expected_b {
                errors.push(
                    "**Alchemist state reference:** must bind exact required run_id".to_string(),
                );
            }
        }
        if alchemist_verify != "VERIFIED_NO_CRITICAL_OPEN" {
            errors.push(
                "**Alchemist verification:** non-routine semantic work requires VERIFIED_NO_CRITICAL_OPEN"
                    .to_string(),
            );
        }
    } else {
        static REQUIRED_RE: OnceLock<Regex> = OnceLock::new();
        let required_re =
            REQUIRED_RE.get_or_init(|| Regex::new(r"(?i)^REQUIRED:\s*run_id=").unwrap());
        static NOT_REQUIRED_RE: OnceLock<Regex> = OnceLock::new();
        let not_required_re =
            NOT_REQUIRED_RE.get_or_init(|| Regex::new(r"(?i)^NOT_REQUIRED:\s*\S").unwrap());
        if !(required_re.is_match(&alchemist_gate) || not_required_re.is_match(&alchemist_gate)) {
            errors.push(
                "**Alchemist gate:** must be REQUIRED run_id=<uuid> or NOT_REQUIRED: <reason>"
                    .to_string(),
            );
        }
        if alchemist_verify != "VERIFIED_NO_CRITICAL_OPEN" && alchemist_verify != "NOT_REQUIRED" {
            errors.push(
                "**Alchemist verification:** must be VERIFIED_NO_CRITICAL_OPEN or NOT_REQUIRED"
                    .to_string(),
            );
        }
        if alchemist_gate.starts_with("NOT_REQUIRED:") && alchemist_state != "NOT_REQUIRED" {
            errors.push(
                "**Alchemist state reference:** routine NOT_REQUIRED gate requires NOT_REQUIRED"
                    .to_string(),
            );
        }
    }

    let forbidden_raw = label_value(text, "**Explicit forbidden scope:**").unwrap_or_default();
    let forbidden_items = scope_items(&forbidden_raw, "FORBID:");
    let diagnostic_raw = label_value(text, "**Diagnostics only:**").unwrap_or_default();
    let diagnostic_items = scope_items(&diagnostic_raw, "DIAGNOSTIC_ONLY:");
    let ground_truth_raw = label_value(text, "**Ground-truth policy:**").unwrap_or_default();
    let measured_raw = ground_truth_raw
        .split_once("MEASURED_OUTPUT_NOT_GROUND_TRUTH:")
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let measured_items = scope_items(measured_raw, "");

    let acceptance = table_rows(
        text,
        "## 7. Verification & Acceptance Map",
        "## 8. Evidence & Artifact Contract",
    );
    let input_inventory = table_rows(
        text,
        "## 2. Source of Truth & Known State",
        "## 3. Scope & Ownership",
    );
    let required_inputs = label_value(text, "**Required inputs:**").unwrap_or_default().to_lowercase();
    let acceptance_metrics = label_value(text, "**Acceptance metrics only:**")
        .unwrap_or_default()
        .to_lowercase();
    let decision_rule = label_value(text, "**Decision rule:**").unwrap_or_default().to_lowercase();

    let full_trace = table_rows(
        text,
        "### Requirement-to-decision trace",
        "### Model, tool & dependency relevance",
    );
    let acceptance_trace: Vec<String> = full_trace
        .iter()
        .skip(1)
        .filter(|row| row.len() == 6 && row[1].trim_matches('`') == "ACCEPTANCE")
        .map(|row| row.join(" | ").to_lowercase())
        .collect();

    let mut forbidden_targets = String::new();
    for row in acceptance.iter().skip(1) {
        forbidden_targets.push_str(&row.join(" | ").to_lowercase());
        forbidden_targets.push('\n');
    }
    for row in input_inventory.iter().skip(1) {
        forbidden_targets.push_str(&row.join(" | ").to_lowercase());
        forbidden_targets.push('\n');
    }
    for item in &acceptance_trace {
        forbidden_targets.push_str(item);
        forbidden_targets.push('\n');
    }
    forbidden_targets.push_str(&required_inputs);
    forbidden_targets.push('\n');
    forbidden_targets.push_str(&acceptance_metrics);
    forbidden_targets.push('\n');
    forbidden_targets.push_str(&decision_rule);

    for forbidden_item in &forbidden_items {
        if forbidden_targets.contains(forbidden_item.as_str()) {
            errors.push(format!(
                "forbidden scope leaked into input/acceptance contract: {forbidden_item}"
            ));
        }
    }

    let mut diagnostic_targets = String::new();
    for row in acceptance.iter().skip(1) {
        diagnostic_targets.push_str(&row.join(" | ").to_lowercase());
        diagnostic_targets.push('\n');
    }
    for item in &acceptance_trace {
        diagnostic_targets.push_str(item);
        diagnostic_targets.push('\n');
    }
    diagnostic_targets.push_str(&acceptance_metrics);
    diagnostic_targets.push('\n');
    diagnostic_targets.push_str(&decision_rule);

    for diagnostic_item in &diagnostic_items {
        if diagnostic_targets.contains(diagnostic_item.as_str()) {
            errors.push(format!(
                "diagnostic-only item leaked into acceptance contract: {diagnostic_item}"
            ));
        }
    }

    let mut measured_targets = String::new();
    for row in input_inventory.iter().skip(1) {
        measured_targets.push_str(&row.join(" | ").to_lowercase());
        measured_targets.push('\n');
    }
    measured_targets.push_str(&required_inputs);

    for measured_item in &measured_items {
        if measured_targets.contains(measured_item.as_str()) {
            errors.push(format!(
                "measured output treated as prior input/acceptance requirement: {measured_item}"
            ));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_template_short_circuits() {
        assert!(decision_scope_errors("", true).is_empty());
    }

    #[test]
    fn flags_disallowed_semantics_token() {
        let text = "- **Task semantics:** SOMETHING_ELSE\n";
        let errors = decision_scope_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Task semantics")));
    }

    #[test]
    fn requires_alchemist_gate_for_non_routine_semantics() {
        let text = "- **Task semantics:** EXPERIMENT\n";
        let errors = decision_scope_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Alchemist gate")));
    }

    #[test]
    fn detects_forbidden_scope_leak_into_acceptance_table() {
        let text = "- **Explicit forbidden scope:** FORBID: legacy-python-path\n\
## 7. Verification & Acceptance Map\n\
| A | B |\n|---|---|\n| legacy-python-path | ok |\n\
## 8. Evidence & Artifact Contract\n";
        let errors = decision_scope_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("forbidden scope leaked")));
    }
}
