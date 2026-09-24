//! Port of the Markdown table walk from `validate-dispatch.py`:
//! `table_rows()`, `validate_table()`, `table_errors()`, and
//! `FAILURE_CLASSES` (lines ~1158-1444, ~813-814).

use super::labels::{action_re, is_concrete, path_re};
use super::route_scan::label_value;
use regex::Regex;
use std::sync::OnceLock;

pub const FAILURE_CLASSES: &[&str] = &[
    "PATH_OR_INPUT_MISSING",
    "TOOL_OR_DEPENDENCY_MISSING",
    "AUTH_OR_PERMISSION_FAILURE",
    "TRANSIENT_EXTERNAL_FAILURE",
    "INVALID_INPUT_OR_SCHEMA",
    "INTEGRITY_OR_HASH_MISMATCH",
    "DETERMINISTIC_COMMAND_FAILURE",
    "DIRTY_OR_CONFLICTING_STATE",
    "WRONG_PRODUCER_OR_PROVENANCE",
    "RESOURCE_OR_CAPACITY_FAILURE",
    "AMBIGUOUS_REQUIREMENT",
    "UNSAFE_OR_OUT_OF_SCOPE_ACTION",
    "UNKNOWN_FAILURE",
];

fn separator_row_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^:?-{3,}:?$").unwrap())
}

/// Port of `table_rows()`: the Markdown pipe-table rows found strictly
/// between `start_heading` and `end_heading`, with the separator row
/// dropped. Returns an empty vec when either heading is not found (`find`
/// semantics match Python's `str.find`).
pub fn table_rows(text: &str, start_heading: &str, end_heading: &str) -> Vec<Vec<String>> {
    let start = match text.find(start_heading) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let search_from = start + start_heading.len();
    let end = match text.get(search_from..).and_then(|rest| rest.find(end_heading)) {
        Some(i) => search_from + i,
        None => return Vec::new(),
    };
    let mut rows = Vec::new();
    for line in text[start..end].lines() {
        if !line.starts_with('|') {
            continue;
        }
        let trimmed = line.trim().trim_matches('|');
        let cells: Vec<String> = trimmed.split('|').map(|c| c.trim().to_string()).collect();
        if cells.iter().all(|c| separator_row_re().is_match(c)) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

/// Port of `validate_table()`.
pub fn validate_table(
    name: &str,
    rows: &[Vec<String>],
    width: usize,
    allow_template: bool,
    concrete_exceptions: &[&str],
) -> Vec<String> {
    if rows.len() < 2 {
        return vec![format!("{name} requires at least one data row")];
    }
    let mut errors = Vec::new();
    for (index, row) in rows[1..].iter().enumerate() {
        let index = index + 1;
        if row.len() != width {
            errors.push(format!("{name} row {index} must contain {width} cells"));
            continue;
        }
        if !allow_template {
            for (cell_index, cell) in row.iter().enumerate() {
                let cell_index = cell_index + 1;
                let normalized = cell.trim().trim_matches('`').to_uppercase();
                if !is_concrete(cell) && !concrete_exceptions.contains(&normalized.as_str()) {
                    errors.push(format!("{name} row {index} cell {cell_index} is too vague"));
                }
            }
        }
    }
    errors
}

/// Port of `table_errors()`. This is a faithful, section-by-section port
/// of the Python function's table shape/vagueness/cross-reference checks.
pub fn table_errors(text: &str, allow_template: bool) -> Vec<String> {
    let mut errors = Vec::new();

    let decision_trace = table_rows(
        text,
        "### Requirement-to-decision trace",
        "### Model, tool & dependency relevance",
    );
    errors.extend(validate_table(
        "requirement-to-decision trace",
        &decision_trace,
        6,
        allow_template,
        &["NONE"],
    ));
    let model_relevance = table_rows(
        text,
        "### Model, tool & dependency relevance",
        "## 1B. Authority, Correction & Global Re-Derivation",
    );
    errors.extend(validate_table("model/tool relevance", &model_relevance, 6, allow_template, &[]));

    let mut trace_classes: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if !allow_template {
        let allowed_classes = ["ACCEPTANCE", "DIAGNOSTIC", "EXECUTION_INPUT", "SAFETY", "FORBIDDEN"];
        for row in decision_trace.iter().skip(1) {
            if row.len() != 6 {
                continue;
            }
            let requirement_id = row[0].trim_matches('`').to_string();
            let requirement_class = row[1].trim_matches('`').to_string();
            trace_classes.insert(requirement_id.clone(), requirement_class.clone());
            if !allowed_classes.contains(&requirement_class.as_str()) {
                errors.push(format!("requirement trace {requirement_id} has invalid class: {requirement_class}"));
            }
        }
        for (required_id, required_class) in [
            ("PRODUCER_IDENTITY", "ACCEPTANCE"),
            ("LIFECYCLE_CHAIN", "ACCEPTANCE"),
            ("NO_SUBSTITUTION", "ACCEPTANCE"),
            ("DIAGNOSTIC_ONLY", "DIAGNOSTIC"),
            ("EXECUTION_INPUT", "EXECUTION_INPUT"),
            ("FORBIDDEN_SCOPE", "FORBIDDEN"),
        ] {
            if trace_classes.get(required_id).map(|s| s.as_str()) != Some(required_class) {
                errors.push(format!("requirement trace missing {required_id} class {required_class}"));
            }
        }
        let allow_forbid_re = Regex::new(r"(?i)^(?:ALLOW|FORBID):\s*\S").unwrap();
        for row in model_relevance.iter().skip(1) {
            if row.len() != 6 {
                continue;
            }
            let metric_raw = row[1].trim_matches('`').to_string();
            let metric = metric_raw.to_uppercase();
            let decision = row[4].trim_matches('`').to_string();
            if !allow_forbid_re.is_match(&decision) {
                errors.push("model/tool relevance decision must be ALLOW: or FORBID:".to_string());
            }
            let decision_upper = decision.to_uppercase();
            if decision_upper.starts_with("ALLOW:") && (metric.starts_with("NONE") || metric.starts_with("N/A")) {
                errors.push(
                    "model/tool relevance cannot ALLOW a load that produces no acceptance metric".to_string(),
                );
            }
            if decision_upper.starts_with("ALLOW:") {
                let acceptance_metrics = label_value(text, "**Acceptance metrics only:**").unwrap_or_default().to_lowercase();
                if !acceptance_metrics.contains(&metric_raw.to_lowercase()) {
                    errors.push("allowed model/tool metric is not named in acceptance metrics".to_string());
                }
                if row[2].trim_matches('`').to_uppercase().starts_with("NO_MODEL_ALLOWED:") {
                    errors.push("allowed model/tool conflicts with NO_MODEL_ALLOWED route".to_string());
                }
            }
        }
    }

    let inherited_disposition = table_rows(
        text,
        "### Inherited instruction disposition",
        "## 1C. Goal Route & Critical Path",
    );
    errors.extend(validate_table(
        "inherited instruction disposition",
        &inherited_disposition,
        6,
        allow_template,
        &["NONE", "ALIGNED", "CONFLICTS", "NO_DECISION_VALUE"],
    ));

    let stage_funnel = table_rows(text, "### Stage decision funnel", "### Typed stage records");
    errors.extend(validate_table("stage decision funnel", &stage_funnel, 10, allow_template, &[]));
    let typed_stages = table_rows(text, "### Typed stage records", "### Fixture-stage ownership");
    errors.extend(validate_table("typed stage records", &typed_stages, 10, allow_template, &[]));
    let fixture_ownership = table_rows(text, "### Fixture-stage ownership", "## 2. Source of Truth & Known State");
    errors.extend(validate_table("fixture-stage ownership", &fixture_ownership, 7, allow_template, &[]));

    let preconditions = table_rows(text, "## 4. Preconditions", "## 4A. Execution Path, Reset & Gate Isolation");
    errors.extend(validate_table("preconditions", &preconditions, 3, allow_template, &[]));

    let execution_path = table_rows(text, "### Production execution path", "### Gate isolation matrix");
    errors.extend(validate_table("production execution path", &execution_path, 6, allow_template, &[]));
    let gate_scope = table_rows(text, "### Gate isolation matrix", "### Phase-scoped substitution matrix");
    errors.extend(validate_table("gate isolation matrix", &gate_scope, 5, allow_template, &[]));
    let substitution_scope = table_rows(text, "### Phase-scoped substitution matrix", "## 5. Execution Procedure");
    errors.extend(validate_table("phase-scoped substitution matrix", &substitution_scope, 4, allow_template, &[]));

    if !allow_template {
        let execution_ids: std::collections::HashSet<String> =
            execution_path.iter().skip(1).filter(|r| !r.is_empty()).map(|r| r[0].trim_matches('`').to_string()).collect();
        for required_stage in [
            "ENTRY_POINT",
            "MORPHER_OR_HOOK",
            "PRODUCER_OR_RUNTIME",
            "DELIVERY",
            "VALUE_OR_ACCEPTANCE",
        ] {
            if !execution_ids.contains(required_stage) {
                errors.push(format!("production execution path missing stage: {required_stage}"));
            }
        }
        let gate_ids: std::collections::HashSet<String> =
            gate_scope.iter().skip(1).filter(|r| !r.is_empty()).map(|r| r[0].trim_matches('`').to_string()).collect();
        for required_gate in ["QUALIFICATION_GATE", "END_TO_END_GATE"] {
            if !gate_ids.contains(required_gate) {
                errors.push(format!("gate isolation matrix missing gate: {required_gate}"));
            }
        }
        let phase_ids: std::collections::HashSet<String> =
            substitution_scope.iter().skip(1).filter(|r| !r.is_empty()).map(|r| r[0].trim_matches('`').to_string()).collect();
        for required_phase in ["CURRENT_GATE", "OTHER_PHASES"] {
            if !phase_ids.contains(required_phase) {
                errors.push(format!("phase-scoped substitution matrix missing row: {required_phase}"));
            }
        }
    }

    let evidence = table_rows(text, "## 2. Source of Truth & Known State", "## 3. Scope & Ownership");
    errors.extend(validate_table("evidence inventory", &evidence, 6, allow_template, &[]));

    let task_graph = table_rows(text, "## 3. Scope & Ownership", "## 4. Preconditions");
    errors.extend(validate_table("task graph", &task_graph, 6, allow_template, &[]));

    let active = table_rows(text, "## 0. Dispatch Control", "## 1. Mission");
    errors.extend(validate_table("active dispatch inventory", &active, 4, allow_template, &[]));
    if !allow_template {
        let overlap_re = Regex::new(r"\b(NO_OVERLAP|SERIALIZED)\b").unwrap();
        for row in active.iter().skip(1) {
            if row.len() == 4 && !overlap_re.is_match(&row[3]) {
                errors.push("active dispatch inventory lacks NO_OVERLAP or SERIALIZED decision".to_string());
            }
        }
    }

    let recovery = table_rows(text, "## 6. Failure Decision & Recovery Matrix", "## 7. Verification & Acceptance Map");
    let recovery_data: Vec<&Vec<String>> = if recovery.is_empty() { Vec::new() } else { recovery[1..].iter().collect() };
    let mut by_class: std::collections::HashMap<String, &Vec<String>> = std::collections::HashMap::new();
    for cells in &recovery_data {
        if !cells.is_empty() {
            by_class.insert(cells[0].trim_matches('`').to_string(), cells);
        }
    }
    let blocker_terms = [
        Regex::new(r"(?i)\b(all|every)\b.*\b(branch|recovery|attempt)").unwrap(),
        Regex::new(r"(?i)\b(evidence|log|stderr|receipt)\b").unwrap(),
        Regex::new(r"(?i)\b(missing input|external input|unblock input)\b").unwrap(),
    ];
    let observable_re = Regex::new(r"(?i)\b(exit|exists|matches|passes|returns|status|hash|count)\b").unwrap();
    for failure_class in FAILURE_CLASSES {
        let cells = match by_class.get(*failure_class) {
            None => {
                errors.push(format!("missing recovery row: {failure_class}"));
                continue;
            }
            Some(cells) => *cells,
        };
        if cells.len() != 7 {
            errors.push(format!("recovery row {failure_class} must contain 7 cells"));
            continue;
        }
        if !allow_template {
            for (index, cell) in cells.iter().enumerate().skip(1) {
                if !is_concrete(cell) {
                    errors.push(format!("recovery row {failure_class} cell {} is too vague", index + 1));
                }
            }
            if !cells[2].contains("1.") || !cells[2].contains("2.") {
                errors.push(format!("recovery row {failure_class} requires primary + second branch"));
            }
            if !action_re().is_match(&cells[2]) || !action_re().is_match(&cells[3]) {
                errors.push(format!("recovery row {failure_class} lacks actionable recovery/degraded path"));
            }
            if !super::labels::bound_re().is_match(&cells[4]) {
                errors.push(format!("recovery row {failure_class} lacks numeric retry/stop bound"));
            }
            if !observable_re.is_match(&cells[5]) {
                errors.push(format!("recovery row {failure_class} lacks observable proceed condition"));
            }
            if !cells[6].contains("TRUE_BLOCKER") {
                errors.push(format!("recovery row {failure_class} lacks explicit TRUE_BLOCKER threshold"));
            }
            let escalation = &cells[6];
            if blocker_terms.iter().any(|pattern| !pattern.is_match(escalation)) {
                errors.push(format!("recovery row {failure_class} TRUE_BLOCKER lacks exhausted-recovery proof"));
            }
        }
    }

    let acceptance = table_rows(text, "## 7. Verification & Acceptance Map", "## 8. Evidence & Artifact Contract");
    errors.extend(validate_table("acceptance map", &acceptance, 5, allow_template, &[]));
    if !allow_template {
        let acceptance_ids: std::collections::HashSet<String> =
            acceptance.iter().skip(1).filter(|r| !r.is_empty()).map(|r| r[0].trim_matches('`').to_string()).collect();
        for required_id in ["PRODUCER_IDENTITY", "LIFECYCLE_CHAIN", "NO_SUBSTITUTION"] {
            if !acceptance_ids.contains(required_id) {
                errors.push(format!("acceptance map missing identity gate: {required_id}"));
            }
        }
        for row in acceptance.iter().skip(1) {
            if row.len() != 5 {
                continue;
            }
            let requirement_id = row[0].trim_matches('`').to_string();
            if !path_re().is_match(&row[3]) {
                errors.push("acceptance row lacks explicit evidence path".to_string());
            }
            if trace_classes.get(&requirement_id).map(|s| s.as_str()) != Some("ACCEPTANCE") {
                errors.push(format!("acceptance requirement lacks ACCEPTANCE decision trace: {requirement_id}"));
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_drops_separator_row_and_stops_at_end_heading() {
        let text = "## Start\n| a | b |\n| --- | --- |\n| 1 | 2 |\n## End\n| 3 | 4 |\n";
        let rows = table_rows(text, "## Start", "## End");
        assert_eq!(rows, vec![vec!["a".to_string(), "b".to_string()], vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn table_rows_missing_heading_is_empty() {
        assert!(table_rows("no headings here", "## Start", "## End").is_empty());
    }

    #[test]
    fn validate_table_requires_data_row() {
        let errors = validate_table("t", &[vec!["h".to_string()]], 1, false, &[]);
        assert_eq!(errors, vec!["t requires at least one data row"]);
    }

    #[test]
    fn validate_table_flags_vague_cells_unless_excepted() {
        let rows = vec![vec!["h".to_string()], vec!["none".to_string()]];
        assert!(validate_table("t", &rows, 1, false, &[]).iter().any(|e| e.contains("too vague")));
        assert!(validate_table("t", &rows, 1, false, &["NONE"]).is_empty());
    }

    #[test]
    fn table_errors_reports_missing_recovery_rows() {
        let errors = table_errors("", false);
        assert!(errors.iter().any(|e| e.contains("missing recovery row: PATH_OR_INPUT_MISSING")));
    }
}
