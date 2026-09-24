//! Integration tests for packet r46b's Markdown dispatch-document helpers
//! (`legion_runtime::wf_port::r46::{headings,steps,tables,status,script_gate}`).

use legion_runtime::wf_port::r46::{ordered_heading_errors, status_errors, step_errors, table_rows, REQUIRED_HEADINGS};

#[test]
fn ordered_heading_errors_is_clean_for_headings_in_declared_order() {
    let text = REQUIRED_HEADINGS.join("\nbody text\n");
    assert!(ordered_heading_errors(&text).is_empty());
}

#[test]
fn ordered_heading_errors_flags_reversed_headings() {
    let text = format!("{}\n{}\n", REQUIRED_HEADINGS[1], REQUIRED_HEADINGS[0]);
    let errors = ordered_heading_errors(&text);
    assert!(errors.iter().any(|e| e.contains("heading out of order")));
}

#[test]
fn status_errors_single_allowed_value_is_clean() {
    assert!(status_errors("STATUS: TRUE_BLOCKER\n").is_empty());
}

#[test]
fn step_errors_flags_missing_step_marker() {
    let errors = step_errors("## 5. Execution Procedure\nno steps declared\n", false);
    assert_eq!(errors, vec!["missing execution step: expected '### Step N — name'".to_string()]);
}

#[test]
fn table_rows_extracts_pipe_rows_between_headings() {
    let text = "## A\n| id | val |\n| --- | --- |\n| ROW1 | x |\n## B\n";
    let rows = table_rows(text, "## A", "## B");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1][0], "ROW1");
}
