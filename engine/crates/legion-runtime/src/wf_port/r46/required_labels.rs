//! Port of `REQUIRED_LABELS` from `validate-dispatch.py` (lines ~661-796)
//! and the label-presence/emptiness/genericness loop at the top of
//! `validate()` (lines ~3103-3117).

use super::labels::{authority_label_value, is_generic_value};

/// Port of `REQUIRED_LABELS`.
pub const REQUIRED_LABELS: &[&str] = &[
    "**Dispatch ID:**",
    "**Requester:**",
    "**Dispatcher:**",
    "**Executor:**",
    "**Verifier:**",
    "**Receiver:**",
    "**Mode:**",
    "**Execution host / OS:**",
    "**Shell:**",
    "**Working directory:**",
    "**Repository / branch:**",
    "**Baseline revision:**",
    "**Scoped Git status:**",
    "**User authorization:**",
    "**Dependency position:**",
    "**Parallel safety:**",
    "**Integration owner:**",
    "**Outcome:**",
    "**Definition of done:**",
    "**Non-goals:**",
    "**Task semantics:**",
    "**Primary decision questions:**",
    "**Decision rule:**",
    "**Acceptance metrics only:**",
    "**Diagnostics only:**",
    "**Explicit forbidden scope:**",
    "**Workload / fixture roles:**",
    "**Ground-truth policy:**",
    "**Model / tool relevance rule:**",
    "**Locked model / runtime route:**",
    "**Recovery scope rule:**",
    "**Alchemist gate:**",
    "**Alchemist state reference:**",
    "**Alchemist verification:**",
    "**First-action readback:**",
    "**Supervision cadence:**",
    "**Authority order:**",
    "**Correction state:**",
    "**Correction audit:**",
    "**Plan invalidation:**",
    "**Re-derivation status:**",
    "**Progress disposition:**",
    "**Inherited inventory reconciliation:**",
    "**Alchemist typed-stage binding:**",
    "**State A:**",
    "**State B:**",
    "**Goal success proof:**",
    "**Hard route constraints:**",
    "**Route mode:**",
    "**Selected route:**",
    "**Why fastest valid:**",
    "**Critical path:**",
    "**Bottleneck:**",
    "**Parallel lanes:**",
    "**Deleted / deferred work:**",
    "**Route Alchemist binding:**",
    "**Topology mode:**",
    "**Full-matrix authorization:**",
    "**Value-of-information rule:**",
    "**Declared launch ceiling:**",
    "**Declared minimum wall time:**",
    "**Launch estimate status:**",
    "**Launch-count reconciliation:**",
    "**Supervisor topology checkpoint:**",
    "**Broad selector policy:**",
    "**Authoritative inputs:**",
    "**Known state:**",
    "**Assumptions fixed by dispatcher:**",
    "**Context embedded from chat:**",
    "**Required rules / skills:**",
    "**Required producer / actor:**",
    "**Allowed provenance / lineage:**",
    "**Forbidden producers / substitutes:**",
    "**Existing-work disposition:**",
    "**Required lifecycle chain:**",
    "**Substitution policy:**",
    "**Allowed result derivation:**",
    "**Forbidden result derivation:**",
    "**Lifecycle preflight:**",
    "**OWN — may edit:**",
    "**READ — read only:**",
    "**FORBIDDEN:**",
    "**Dirty-work policy:**",
    "**Side effects / blast radius:**",
    "**Required tools / access:**",
    "**Tool versions:**",
    "**Environment variables:**",
    "**Access / credentials:**",
    "**Required inputs:**",
    "**Preflight command:**",
    "**Critical discriminating invariants:**",
    "**Resume / reset decision:**",
    "**Invalid-window disposition:**",
    "**Authority refresh:**",
    "**Production path chain:**",
    "**Frozen implementation proof:**",
    "**Trace linkage contract:**",
    "**Batch start gate:**",
    "**Defect classification gate:**",
    "**Mid-run authority update protocol:**",
    "**Environment integrity step zero:**",
    "**Canary / one-unit preflight:**",
    "**Script involved:**",
    "**No-script reason:**",
    "**Script ownership:**",
    "**Script path:**",
    "**Creation decision:**",
    "**Script skill:**",
    "**Gate evidence:**",
    "**Final verification command:**",
    "**Output paths:**",
    "**Logs / raw evidence:**",
    "**Hashes / counts / versions:**",
    "**Checkpoint / resume state:**",
    "**Evidence retention:**",
    "**Validated artifact path:**",
    "**Receipt path:**",
    "**Validator command:**",
    "**Receiver hash check:**",
];

/// Labels allowed to be present-but-empty (port of the inline set literal
/// in `validate()`, lines ~3105-3113).
const ALLOWED_EMPTY_LABELS: &[&str] = &[
    "**Preflight command:**",
    "**Final verification command:**",
    "**Validator command:**",
    "**Receiver hash check:**",
    "**Lifecycle preflight:**",
    "**Environment integrity step zero:**",
    "**Canary / one-unit preflight:**",
];

/// Port of the `REQUIRED_LABELS` loop in `validate()`.
pub fn required_label_errors(text: &str, allow_template: bool) -> Vec<String> {
    let mut errors = Vec::new();
    for label in REQUIRED_LABELS {
        match authority_label_value(text, label) {
            None => errors.push(format!("missing label: {label}")),
            Some(value) => {
                if value.is_empty() && !ALLOWED_EMPTY_LABELS.contains(label) {
                    errors.push(format!("empty value: {label}"));
                } else if !allow_template
                    && is_generic_value(value.trim().trim_matches('`').to_lowercase().as_str())
                {
                    errors.push(format!("generic filler value: {label}"));
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
    fn missing_labels_are_reported() {
        let errors = required_label_errors("", false);
        assert!(errors.iter().any(|e| e == "missing label: **Dispatch ID:**"));
    }

    #[test]
    fn allowed_empty_label_does_not_error() {
        let text = "- **Preflight command:**\n";
        let errors = required_label_errors(text, false);
        assert!(!errors.iter().any(|e| e.contains("empty value: **Preflight command:**")));
    }

    #[test]
    fn generic_value_is_reported_unless_allow_template() {
        let text = "- **Dispatch ID:** tbd\n";
        assert!(required_label_errors(text, false).iter().any(|e| e.contains("generic filler value")));
        assert!(!required_label_errors(text, true).iter().any(|e| e.contains("generic filler value")));
    }
}
