//! Integration-level parity test for wf032
//! (`src/lib/research-core/tests/test_research_stopping.py` plus four
//! empty `workflows/**/__init__.py` package markers), exercised against
//! the crate's public API.
//!
//! `test_research_stopping.py` is ALREADY-NATIVE-VERIFIED at
//! `legion_research::research_port::{decide, StoppingInput}`, already
//! wired into `src/lib.rs` (`pub mod research_port;`) and already
//! re-asserted at the integration level in
//! `tests/research_port_stopping.rs::stopping_matches_python_test_research_stopping`
//! and at the unit level inside `src/research_port/stopping.rs`. This
//! file adds one more re-assertion of the same four cases against this
//! packet's own test binary, per the wf032 assignment, without modifying
//! either existing file (neither is owned by this packet). See
//! `src/wf_port/wf032/mod.rs` for the full per-file disposition,
//! including why the four empty `__init__.py` files carry nothing to
//! port.
//!
//! NOTE: this file needs no `wf_port` wiring — `research_port` is already
//! declared `pub` in `src/lib.rs`, so this test compiles as soon as the
//! integrator adds `mod wf032;` under `wf_port` for the sibling unit
//! tests in `src/wf_port/wf032/mod.rs` (that addition is not required for
//! *this* file to compile, only for the crate's own `wf_port::wf032`
//! unit tests to run).

use legion_research::research_port::{decide, StoppingInput};

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
