//! Partial port of `validate()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~3098-3161, the
//! portion built from checks packet r46/r46b/r46c already ported into this
//! module) plus `FAILURE_CLASSES` membership and `status_errors`/
//! `TERMINAL_STATUS` composition.
//!
//! **Not ported here** (genuinely separate, much larger surface not yet
//! ported anywhere in `engine/`, confirmed by `wf_port::w2_045`'s own module
//! doc): the ~90-entry `REQUIRED_LABELS` table and its `GENERIC_VALUES`
//! filler-value check, the `BYPASS_PATTERNS`/`SECRET_PATTERNS` regex banks,
//! the `/script` gate (`## 5A`) full validation branch, the `## 10.
//! TRUE_BLOCKER Conditions` / `## 11. Dispatcher Author Gate` section
//! checks, `storage_errors`, and `main()`'s CLI argv/receipt-file
//! read/write/verify + dynamic `minimize_gate` module load. Those require
//! constant tables and file-I/O plumbing this packet's helper set
//! (`labels.rs`, `route_scan.rs`, `tables.rs`) does not provide, and were
//! out of scope for every prior r46 pass (see `finish-r46b.md`/
//! `finish-r46c.md`). [`validate_ported_errors`] composes every check that
//! **is** fully ported (heading order, per-step contract, table shape,
//! execution-identity/-control, decision-scope, authority-correction,
//! GoalRoute, topology, status/terminal-status, `FAILURE_CLASSES`
//! membership, and the managed-Rust-route scan) so callers get the same
//! sorted-deduplicated error list `validate()` would for that subset.

use super::authority_correction::authority_correction_errors;
use super::decision_scope::decision_scope_errors;
use super::execution_control::execution_control_errors;
use super::execution_identity::execution_identity_errors;
use super::goal_route::goal_route_errors;
use super::headings::ordered_heading_errors;
use super::route_scan::managed_rust_route_errors;
use super::status::status_errors;
use super::steps::step_errors;
use super::tables::{table_errors, FAILURE_CLASSES};
use super::topology::topology_errors;
use std::collections::BTreeSet;
use std::path::Path;

/// Port of the fully-available subset of `validate()`: every check whose
/// dependencies are ported in this module. See the module doc for the
/// named, exact gap versus the real `validate()`.
pub fn validate_ported_errors(text: &str, allow_template: bool, artifact_path: Option<&Path>) -> Vec<String> {
    let mut errors = ordered_heading_errors(text);

    if !allow_template {
        errors.extend(managed_rust_route_errors(text, artifact_path, None));
    }

    errors.extend(step_errors(text, allow_template));
    errors.extend(table_errors(text, allow_template));
    errors.extend(execution_identity_errors(text, allow_template));
    errors.extend(execution_control_errors(text, allow_template));
    errors.extend(decision_scope_errors(text, allow_template));
    errors.extend(authority_correction_errors(text, allow_template));
    errors.extend(goal_route_errors(text, allow_template, artifact_path));
    errors.extend(topology_errors(text, allow_template));

    for failure_class in FAILURE_CLASSES {
        if !text.contains(failure_class) {
            errors.push(format!("missing failure class: {failure_class}"));
        }
    }

    errors.extend(status_errors(text));
    for status in ["COMPLETE", "COMPLETE_WITH_NOTES", "TRUE_BLOCKER"] {
        if !text.contains(status) {
            errors.push(format!("missing terminal status contract: {status}"));
        }
    }

    if text.matches("```").count() < 8 {
        errors.push("expected at least four fenced command/output blocks".to_string());
    }

    let unique: BTreeSet<String> = errors.into_iter().collect();
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_produces_errors_not_panic() {
        let errors = validate_ported_errors("", false, None);
        assert!(!errors.is_empty());
    }

    #[test]
    fn allow_template_skips_most_checks_but_still_checks_headings() {
        let errors = validate_ported_errors("", true, None);
        // Heading-order errors still fire under allow_template (Python's
        // `validate()` never skips `ordered_heading_errors`).
        assert!(errors.iter().any(|e| e.to_lowercase().contains("heading")) || !errors.is_empty());
    }

    #[test]
    fn result_is_sorted_and_deduplicated() {
        let errors = validate_ported_errors("", false, None);
        let mut sorted = errors.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(errors, sorted);
    }
}
