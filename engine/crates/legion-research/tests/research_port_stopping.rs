//! Integration-level parity test for the P2-research packet, mirroring
//! `research-core/tests/test_research_stopping.py` against the crate's
//! public API (not the in-module unit tests in
//! `src/research_port/stopping.rs`, which exercise the same cases at the
//! unit level).
//!
//! NOTE: this file depends on the `pub mod research_port;` declaration
//! landing in `src/lib.rs` (a shared file this packet does not own — the
//! exact patch is in the packet report). Until that patch is applied by
//! the integrator, this test will not compile.

use legion_research::research_port::{decide, StoppingInput};

#[test]
fn stopping_matches_python_test_research_stopping() {
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
