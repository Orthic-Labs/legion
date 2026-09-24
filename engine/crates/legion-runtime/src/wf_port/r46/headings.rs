//! Port of `REQUIRED_HEADINGS` and `ordered_heading_errors()` from
//! `validate-dispatch.py` (lines ~639-660, ~933-945).

pub const REQUIRED_HEADINGS: &[&str] = &[
    "# DISPATCH:",
    "## 0. Dispatch Control",
    "## 1. Mission",
    "## 1A. Decision & Experiment Question Lock",
    "## 1B. Authority, Correction & Global Re-Derivation",
    "## 1C. Goal Route & Critical Path",
    "## 1D. Experiment Topology & Workload Funnel",
    "## 2. Source of Truth & Known State",
    "## 3. Scope & Ownership",
    "## 4. Preconditions",
    "## 4A. Execution Path, Reset & Gate Isolation",
    "## 5. Execution Procedure",
    "## 5A. Script & Runner Gate",
    "## 6. Failure Decision & Recovery Matrix",
    "## 7. Verification & Acceptance Map",
    "## 8. Evidence & Artifact Contract",
    "## 9. Return & Integration Contract",
    "## 10. TRUE_BLOCKER Conditions",
    "## 11. Dispatcher Author Gate",
];

/// Port of `ordered_heading_errors()`.
pub fn ordered_heading_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut cursor: i64 = -1;
    for heading in REQUIRED_HEADINGS {
        match text.find(heading) {
            None => errors.push(format!("missing heading: {heading}")),
            Some(index) => {
                let index = index as i64;
                if index <= cursor {
                    errors.push(format!("heading out of order: {heading}"));
                } else {
                    cursor = index;
                }
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_missing_heading() {
        let errors = ordered_heading_errors("# DISPATCH: x\n## 0. Dispatch Control\n");
        assert!(errors.iter().any(|e| e.contains("missing heading: ## 1. Mission")));
    }

    #[test]
    fn reports_out_of_order_heading() {
        let text = "## 1. Mission\n# DISPATCH: x\n";
        let errors = ordered_heading_errors(text);
        assert!(errors.iter().any(|e| e == "heading out of order: # DISPATCH:"));
    }

    #[test]
    fn all_headings_in_order_is_clean_of_order_errors() {
        let text = REQUIRED_HEADINGS.join("\n");
        let errors = ordered_heading_errors(&text);
        assert!(errors.is_empty(), "{errors:?}");
    }
}
