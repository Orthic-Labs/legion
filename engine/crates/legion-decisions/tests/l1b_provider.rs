//! Tests for the L1b `decision_provider.py` port.

use legion_decisions::l1b_port::{produce_candidate_set, CandidateSpec, LifecycleError};
use legion_decisions::{DecisionRecord, DecisionStatus};

fn record(id: &str, repo: &str, status: DecisionStatus) -> DecisionRecord {
    let mut r = DecisionRecord::new(repo, "scope-1", "task-1", "because reasons", status);
    r.id = id.to_string();
    r.created_at = "2026-01-01T00:00:00Z".to_string();
    r
}

fn spec(repo: &str) -> CandidateSpec {
    CandidateSpec {
        task: "demo task".to_string(),
        repository_id: repo.to_string(),
        scope_id: "scope-1".to_string(),
        ..CandidateSpec::default()
    }
}

#[test]
fn admits_single_current_record_per_stable_id() {
    let records = vec![record("architect:decision:abc123", "repo-a", DecisionStatus::Accepted)];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert_eq!(set.candidates.len(), 1);
    assert_eq!(set.candidates[0]["id"], "architect:decision:abc123");
}

#[test]
fn proposed_is_omitted_as_superseded_by_current_when_accepted_sibling_exists() {
    let mut proposed = record("architect:decision:same", "repo-a", DecisionStatus::Proposed);
    proposed.source_hash = "sha256:proposed".to_string();
    let mut accepted = record("architect:decision:same", "repo-a", DecisionStatus::Accepted);
    accepted.source_hash = "sha256:accepted".to_string();
    let records = vec![proposed, accepted];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert_eq!(set.candidates.len(), 1);
    assert_eq!(set.candidates[0]["id"], "architect:decision:same");
    assert!(set
        .omissions
        .iter()
        .any(|o| o["reason"] == "superseded_by_current" && o["id"] == "architect:decision:same:proposed"));
}

#[test]
fn stale_proposed_only_lineage_after_supersession_admits_nothing() {
    let mut proposed = record("architect:decision:retired", "repo-a", DecisionStatus::Proposed);
    proposed.source_hash = "sha256:p".to_string();
    let mut superseded = record("architect:decision:retired", "repo-a", DecisionStatus::Superseded);
    superseded.source_hash = "sha256:s".to_string();
    let records = vec![proposed, superseded];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert!(set.candidates.is_empty());
    assert!(set.omissions.is_empty());
}

#[test]
fn implemented_without_refs_warns_but_still_admits() {
    let record = record("architect:decision:impl1", "repo-a", DecisionStatus::Implemented);
    let records = vec![record];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert_eq!(set.candidates.len(), 1);
    assert_eq!(set.warnings.len(), 1);
    assert_eq!(set.warnings[0].code, "implementation_refs_missing");
}

#[test]
fn stale_graph_generation_is_downgraded_to_omission() {
    let mut rec = record("architect:decision:gen1", "repo-a", DecisionStatus::Accepted);
    rec.linked_graph_generation = "gen-old".to_string();
    let records = vec![rec];
    let mut s = spec("repo-a");
    s.linked_graph_generation = Some("gen-new".to_string());
    let set = produce_candidate_set(&s, &records, "edit").expect("ok");
    assert!(set.candidates.is_empty());
    assert_eq!(set.omissions.len(), 1);
    assert_eq!(set.omissions[0]["reason"], "stale_graph_generation");
}

#[test]
fn token_ceiling_is_fail_closed() {
    let mut rec = record("architect:decision:big", "repo-a", DecisionStatus::Accepted);
    rec.rationale = "x".repeat(1000);
    let records = vec![rec];
    let mut s = spec("repo-a");
    s.max_estimated_tokens = 1;
    let err = produce_candidate_set(&s, &records, "edit").expect_err("should exceed ceiling");
    let LifecycleError(message) = err;
    assert!(message.contains("exceed ceiling"));
}

#[test]
fn candidates_are_sorted_by_score_desc_then_id() {
    let records = vec![
        record("architect:decision:b", "repo-a", DecisionStatus::Proposed),
        record("architect:decision:a", "repo-a", DecisionStatus::Implemented),
    ];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert_eq!(set.candidates[0]["id"], "architect:decision:a");
    assert_eq!(set.candidates[1]["id"], "architect:decision:b:proposed");
}

#[test]
fn different_repository_records_are_excluded() {
    let records = vec![record("architect:decision:other", "repo-b", DecisionStatus::Accepted)];
    let set = produce_candidate_set(&spec("repo-a"), &records, "edit").expect("ok");
    assert!(set.candidates.is_empty());
}
