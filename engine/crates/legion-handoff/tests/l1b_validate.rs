//! Tests for the L1b `validate_handoff.py` port.

use legion_handoff::l1b_port::{concrete, label_value, normalized_path, table_rows, validate_handoff};

fn template_text() -> String {
    // Minimal skeleton exercising ordered headings + all labels with
    // template-mode-acceptable (possibly empty) values, three resume steps,
    // and the five tables at their required widths.
    let mut s = String::new();
    s.push_str("# COLD-START HANDOFF: demo\n");
    s.push_str("## 0. Handoff Control\n");
    for label in legion_handoff::l1b_port::LABELS {
        if *label == "**Verification command:**"
            || *label == "**Validator command:**"
            || *label == "**Receiver receipt check:**"
        {
            s.push_str(&format!("- {label}\n"));
        } else {
            s.push_str(&format!("- {label} placeholder-value-x\n"));
        }
    }
    s.push_str("## 1. Intent & Mission\n");
    s.push_str("## 2. Current State\n");
    s.push_str("## 3. Environment & Active Work\n");
    s.push_str("## 4. Decisions, Invariants & User Corrections\n");
    s.push_str("| a | b | c | d | e |\n|---|---|---|---|---|\n| x | x | x | x | x |\n");
    s.push_str("## 5. Artifacts & Evidence\n");
    s.push_str("| a | b | c | d | e | f |\n|---|---|---|---|---|---|\n| x | x | x | x | x | x |\n");
    s.push_str("## 6. Failures, Dead Ends & Attempts\n");
    s.push_str("| a | b | c | d | e | f | g |\n|---|---|---|---|---|---|---|\n| x | x | x | x | x | x | x |\n");
    s.push_str("## 7. Learnings, Gotchas & Landmines\n");
    s.push_str("| a | b | c | d |\n|---|---|---|---|\n| x | x | x | x |\n");
    s.push_str("## 8. Open Loops & Context Gaps\n");
    s.push_str("| a | b | c | d | e | f |\n|---|---|---|---|---|---|\n| x | x | x | x | x | x |\n");
    s.push_str("## 9. Safety, Authority & Boundaries\n");
    s.push_str("## 10. Exact Resume Sequence\n");
    for i in 1..=3 {
        s.push_str(&format!("### Resume Step {i} — do a thing\n"));
        s.push_str("- **Owner:** somebody\n");
        s.push_str("- **Working directory / system:** /Volumes/D/claude/legion\n");
        s.push_str("- **Exact action:**\n\n```\nrun the verify command\n```\n");
        s.push_str("- **Expected result:** exit code zero success\n");
        s.push_str("- **Evidence path:** /Volumes/D/claude/legion/evidence.log\n");
        s.push_str("- **Timeout / retry:** 30 seconds, 2 retries\n");
        s.push_str("- **If failure:** stop and report the failure\n");
        s.push_str("- **Depends on:** previous step completion\n");
    }
    s.push_str("## 11. State Verification & Invalidation\n");
    s.push_str("## 12. First Output & Readback Contract\n");
    s.push_str("## 13. Ready-to-Paste First Message\nPlease READBACK the Proceed mode before continuing.\n");
    s.push_str("## 14. Context Gap Report\n");
    s.push_str("## 15. Handoff Author Gate\n");
    for _ in 0..18 {
        s.push_str("- [x] item\n");
    }
    s
}

#[test]
fn template_self_check_has_no_missing_heading_errors() {
    let text = template_text();
    let errors = validate_handoff(&text, true);
    assert!(
        errors.iter().all(|e| !e.starts_with("missing heading")),
        "unexpected heading errors: {errors:?}"
    );
}

#[test]
fn missing_heading_is_reported() {
    let text = "# COLD-START HANDOFF: demo\n## 1. Intent & Mission\n";
    let errors = validate_handoff(text, true);
    assert!(errors.iter().any(|e| e.contains("## 0. Handoff Control")));
}

#[test]
fn concrete_rejects_generic_and_short_values() {
    assert!(!concrete("todo"));
    assert!(!concrete("short"));
    assert!(concrete("READY"));
    assert!(concrete("a genuinely specific value"));
}

#[test]
fn label_value_extracts_trailing_text() {
    let text = "- **Handoff ID:** abc-123\n";
    assert_eq!(label_value(text, "**Handoff ID:**").as_deref(), Some("abc-123"));
    assert_eq!(label_value(text, "**Missing:**"), None);
}

#[test]
fn table_rows_skips_separator_row() {
    let text = "## 4. Decisions, Invariants & User Corrections\n| a | b | c | d | e |\n|---|---|---|---|---|\n| 1 | 2 | 3 | 4 | 5 |\n## 5. Artifacts & Evidence\n";
    let rows = table_rows(
        text,
        "## 4. Decisions, Invariants & User Corrections",
        "## 5. Artifacts & Evidence",
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1], vec!["1", "2", "3", "4", "5"]);
}

#[test]
fn normalized_path_lowercases_only_on_windows() {
    assert_eq!(normalized_path("/Volumes/D/Claude/legion", false), "/Volumes/D/Claude/legion");
    assert_eq!(normalized_path("/Volumes/D/Claude/legion", true), "/volumes/d/claude/legion");
    assert_eq!(normalized_path("C:/Users/adrian/", false), "C:/Users/adrian");
}

#[test]
fn banned_phrase_is_flagged() {
    let mut text = template_text();
    text.push_str("as discussed earlier, continue.\n");
    let errors = validate_handoff(&text, false);
    assert!(errors.iter().any(|e| e.contains("old-chat dependency")));
}

#[test]
fn secret_pattern_is_flagged_outside_template_mode() {
    let mut text = template_text();
    text.push_str("api_key: sk-abcdefghijklmnopqrstuvwx\n");
    let errors = validate_handoff(&text, false);
    assert!(errors.iter().any(|e| e.contains("possible secret detected")));
}

#[test]
fn secret_pattern_is_not_checked_in_template_mode() {
    let mut text = template_text();
    text.push_str("api_key: sk-abcdefghijklmnopqrstuvwx\n");
    let errors = validate_handoff(&text, true);
    assert!(!errors.iter().any(|e| e.contains("possible secret detected")));
}
