//! N16: budget exhaustion, parallel race, timeout/retry & unverified overflow
//! never drop candidates, reuse spent budget or become clean. Requires the root
//! to re-export the pure review ledger (see packet A17 integration notes):
//! `#[doc(hidden)] pub use batch::{...}` in `review_runtime/mod.rs`.

use legion_audit::review_runtime::{
    graph_gap_labels, plan_waves, split_bundle, Completion, LedgerRefusal, ReviewLedger,
    VerifierReserve,
};
use serde_json::json;

fn ids(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[test]
fn bounded_parallel_race_dispatches_each_obligation_exactly_once() {
    let required = ids(&["a", "b", "c", "d"]);
    let ledger = ReviewLedger::new(1_000, VerifierReserve::plan(100, 3_000), &required);
    let wins = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for id in &required {
                    if ledger.reserve_author(id, 50).is_ok() {
                        wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
        }
    });
    assert_eq!(wins.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert_eq!(ledger.author_room_tokens(), 1_000 - 100 - 200);
}

#[test]
fn sequential_and_parallel_plans_consume_same_obligations() {
    let required = ids(&["a", "b", "c", "a"]);
    let mut seq: Vec<_> = plan_waves(&required, 1).concat();
    let mut par: Vec<_> = plan_waves(&required, 3).concat();
    seq.sort();
    par.sort();
    assert_eq!(seq, par);
    assert_eq!(seq, ids(&["a", "b", "c"]));
}

#[test]
fn timeout_keeps_candidates_and_spent_budget_and_never_completes() {
    let required = ids(&["a"]);
    let ledger = ReviewLedger::new(100, VerifierReserve::plan(20, 3_000), &required);
    ledger.reserve_author("a", 50).unwrap();
    ledger.record_candidates(ids(&["cand-1"]));
    ledger.abandon_author("a", "timeout").unwrap();
    assert_eq!(ledger.author_room_tokens(), 30);
    // Retry is explicit, charged fresh, and cannot reuse the spent 50.
    assert_eq!(
        ledger.reserve_retry("a", 31),
        Err(LedgerRefusal::AuthorBudgetExhausted("a".into()))
    );
    match ledger.completion() {
        Completion::Incomplete { unverified, gaps, .. } => {
            assert_eq!(unverified, ids(&["cand-1"]));
            assert!(gaps.iter().any(|g| g.starts_with("author-incomplete:a:")));
        }
        Completion::Complete => panic!("false clean"),
    }
}

#[test]
fn verifier_reserve_exhaustion_leaves_overflow_unverified_not_dropped() {
    let reserve = VerifierReserve::plan(10, 600);
    let (included, overflow) = reserve.partition(ids(&["c1", "c2", "c3"]));
    assert_eq!(included.len(), 2);
    assert_eq!(overflow, ids(&["c3"]));
    let required = ids(&["a"]);
    let ledger = ReviewLedger::new(100, reserve, &required);
    ledger.reserve_author("a", 10).unwrap();
    ledger.settle_author("a", Some(10)).unwrap();
    ledger.record_candidates(included.iter().chain(overflow.iter()).cloned());
    ledger.settle_verifier(&included, 10);
    match ledger.completion() {
        Completion::Incomplete { unverified, .. } => assert_eq!(unverified, overflow),
        Completion::Complete => panic!("overflow finding dropped"),
    }
}

#[test]
fn zero_finding_claim_needs_independent_verification() {
    let required = ids(&["a"]);
    let ledger = ReviewLedger::new(100, VerifierReserve::plan(10, 300), &required);
    ledger.reserve_author("a", 10).unwrap();
    ledger.settle_author("a", Some(5)).unwrap();
    ledger.record_zero_finding_claim("a");
    assert!(matches!(ledger.completion(), Completion::Incomplete { .. }));
    ledger.settle_verifier(&ids(&["scope:a"]), 5);
    assert_eq!(ledger.completion(), Completion::Complete);
}

#[test]
fn oversized_source_and_unknown_graph_remain_gaps() {
    let mut fits = |s: &[u32]| s.iter().sum::<u32>() <= 10;
    let split = split_bundle(vec![3, 3, 99], &mut fits, &|n| n.to_string());
    assert_eq!(split.gaps, ids(&["oversized-source:99"]));
    assert_eq!(split.oversized, vec![99]);
    assert_eq!(graph_gap_labels(&json!({})), ids(&["graph-context-absent"]));
    let partial = json!({"reviewContext":{"graphContext":{"freshness":"stale","unknowns":[]}}});
    assert_eq!(graph_gap_labels(&partial), ids(&["graph-freshness:stale"]));
}
