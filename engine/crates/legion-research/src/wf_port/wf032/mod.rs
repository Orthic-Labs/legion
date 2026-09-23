//! Port of `src/lib/research-core/tests/test_research_stopping.py`,
//! `workflows/__init__.py`, `workflows/legal/__init__.py`,
//! `workflows/legal/india/__init__.py`, and
//! `workflows/legal/india/consumer/__init__.py` (packet wf032, area
//! `src/lib/research-core`, target crate `legion-research`).
//!
//! Per file, checked against existing Rust coverage first:
//!
//! - `test_research_stopping.py` — **ALREADY-NATIVE-VERIFIED**. This test
//!   exercises `research-core/stopping.py`'s `decide(...)`, which is
//!   already fully ported at
//!   `crate::research_port::stopping::decide`/`StoppingInput`/
//!   `StoppingDecision` (see `src/research_port/stopping.rs`), with the
//!   same four cases (`coverage-complete`, `targeted-gap-search`,
//!   `no-material-gain`, `budget-exhausted`) already asserted 1:1 both as
//!   unit tests in that module and as an integration test in
//!   `tests/research_port_stopping.rs::stopping_matches_python_test_research_stopping`.
//!   Read the source directly to confirm: same decision order (budget
//!   exhaustion checked first, then full coverage, then stagnation
//!   `consecutive_no_gain >= 2`, else continue), same four reason strings,
//!   same `complete` computation in the budget-exhausted branch (`not
//!   unanswered and not gaps`), same `unanswered`/`blocking_gaps`
//!   dedup-and-sort via a set. No gap. This packet adds one more
//!   integration-level re-assertion below
//!   (`tests/wf_wf032.rs::stopping_matches_python_test_research_stopping_wf032`)
//!   against this packet's own crate-level import path, to close the loop
//!   for this specific assigned file without touching the existing
//!   `research_port` module (which this packet does not own).
//!
//! - `workflows/__init__.py`, `workflows/legal/__init__.py`,
//!   `workflows/legal/india/__init__.py`,
//!   `workflows/legal/india/consumer/__init__.py` — all four are empty
//!   Python package marker files (zero bytes, no statements, no
//!   re-exports, no `__all__`). They carry no runtime behaviour to port:
//!   a Python `__init__.py` with no content only makes its containing
//!   directory importable as a package, which has no Rust module-system
//!   equivalent to write (Rust modules are declared by `mod` statements
//!   in the owning `lib.rs`/`mod.rs`, which this packet does not own).
//!   Nothing is dropped here that Membrane/Blueprint touch either — these
//!   files do not reference Membrane or Blueprint at all. DROP: no
//!   content, nothing to port.
//!
//! This packet writes nothing outside `wf_port/wf032/**` and
//! `tests/wf_wf032.rs`.

#[cfg(test)]
mod tests {
    use crate::research_port::{decide, StoppingInput};

    // Re-assertion (not a redefinition) of the already-ported
    // `research-core/stopping.py::decide` behaviour, from this packet's
    // own module, per the wf032 assignment covering
    // `test_research_stopping.py`.
    #[test]
    fn stopping_matches_python_test_research_stopping_wf032() {
        let complete = decide(&StoppingInput {
            required_questions: vec!["price".into()],
            answered_questions: vec!["price".into()],
            consecutive_no_gain: 0,
            external_requests_used: 2,
            external_requests_budget: 12,
            blocking_gaps: vec![],
        });
        assert_eq!(complete.action, "stop");
        assert_eq!(complete.reason, "coverage-complete");
        assert!(complete.complete);
        assert!(complete.unanswered.is_empty());
        assert!(complete.blocking_gaps.is_empty());

        let search = decide(&StoppingInput {
            required_questions: vec!["price".into(), "privacy".into()],
            answered_questions: vec!["price".into()],
            consecutive_no_gain: 1,
            external_requests_used: 3,
            external_requests_budget: 12,
            blocking_gaps: vec!["privacy authority".into()],
        });
        assert_eq!(search.action, "continue");
        assert_eq!(search.reason, "targeted-gap-search");

        let stagnant = decide(&StoppingInput {
            required_questions: vec!["price".into(), "privacy".into()],
            answered_questions: vec!["price".into()],
            consecutive_no_gain: 2,
            external_requests_used: 4,
            external_requests_budget: 12,
            blocking_gaps: vec!["privacy authority".into()],
        });
        assert_eq!(stagnant.action, "stop");
        assert_eq!(stagnant.reason, "no-material-gain");
        assert!(!stagnant.complete);

        let exhausted = decide(&StoppingInput {
            required_questions: vec!["price".into()],
            answered_questions: vec![],
            consecutive_no_gain: 0,
            external_requests_used: 12,
            external_requests_budget: 12,
            blocking_gaps: vec![],
        });
        assert_eq!(exhausted.action, "stop");
        assert_eq!(exhausted.reason, "budget-exhausted");
        assert!(!exhausted.complete);
    }
}
