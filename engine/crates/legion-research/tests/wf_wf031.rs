//! Integration tests for packet wf031
//! (`src/lib/research-core/tests/{test_research_provider_fence,
//! test_research_resource_guard,test_research_route_effect_boundaries,
//! test_research_route_workspace,test_research_shards}.py` ->
//! `legion_research::wf_port::wf031`).
//!
//! Per file:
//! - `test_research_shards.py`, `test_research_provider_fence.py`,
//!   `test_research_resource_guard.py` are ALREADY-NATIVE-VERIFIED
//!   elsewhere (see `wf_port::wf031`'s module doc for exactly where); no
//!   new test is added here for them, to avoid duplicate coverage of code
//!   this packet does not own.
//! - `test_research_route_workspace.py`'s domain/gate/history half is
//!   re-asserted below directly (`route_workspace_domain_and_history_
//!   matches_python_test`); its `route_resolve.WORKSPACE` half has no Rust
//!   analogue (see the module doc).
//! - `test_research_route_effect_boundaries.py`'s stateful `run.py` half
//!   is ported at `wf_port::wf031::run_state`, whose own
//!   `route_effects_and_evidence_admission_are_frozen_route_bound` unit
//!   test is that Python file's scenario line-for-line
//!   (`RESEARCH_RUN_ROOT`-style temp root, `init_run`, `record_evidence`
//!   before grant fails, `grant`, `acquire` with an unauthorized override
//!   fails). This file adds no duplicate of that unit test; it instead
//!   exercises the same module through the crate's public path, plus the
//!   evidence-ledger block cases the Python file also asserts
//!   (`missing_policy`/`snippet`/`no_passage`), to prove the wf031 public
//!   API (not just its private `#[cfg(test)]` module) is wired correctly.

use legion_research::wf_port::wf025::ledger::validate_evidence;
use legion_research::wf_port::wf029::route_resolve::{context_from, resolve};
use legion_research::wf_port::wf031::run_state::{acquire_resolve_provider, grant, init_run, record_evidence};
use serde_json::json;

fn valid_evidence(overrides: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let mut row = json!({
        "id": "ev1",
        "url": "file:///tmp/source.md",
        "title": "Source",
        "publisher": "local-corpus",
        "retrieved_at": "2026-08-05",
        "locator": "chars:0-42",
        "quote_or_paraphrase": "Vendor X costs $29 per month.",
        "suggested_by": "seed:query:1",
        "seed_chain": ["seed:query:1"],
        "is_primary": true,
        "authority_role": "vendor-official",
        "instructionPolicy": "data_only",
    });
    for (k, v) in overrides {
        row[*k] = v.clone();
    }
    row
}

// Ported from research-core/tests/test_research_route_effect_boundaries.py's
// `ledger.validate_evidence` assertions.
#[test]
fn evidence_ledger_blocks_missing_policy_snippet_source_and_no_passage() {
    let mut missing_policy = valid_evidence(&[]);
    missing_policy.as_object_mut().unwrap().remove("instructionPolicy");
    assert!(validate_evidence(&[missing_policy])[0].blocked);

    let snippet = valid_evidence(&[("source_type", json!("search-snippet"))]);
    assert!(validate_evidence(&[snippet])[0].blocked);

    let no_passage = valid_evidence(&[("quote_or_paraphrase", json!(""))]);
    let verdict = &validate_evidence(&[no_passage])[0];
    assert!(verdict.blocked);
    assert!(verdict.reasons.iter().any(|r| r == "missing opened passage text"));
}

// Ported from research-core/tests/test_research_route_effect_boundaries.py's
// stateful run.py half, exercised through `legion_research`'s public path
// (the same scenario as `run_state`'s own unit test, kept here to prove
// wiring through `legion_research::wf_port::wf031`).
#[test]
fn run_state_public_api_enforces_frozen_route_effects() {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf031-it-run-state-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let context = context_from([("provider", json!("local-corpus"))]);
    let init = init_run("Verify Vendor X pricing", &context, Some(&dir)).unwrap();
    let run_id = init.run["run_id"].as_str().unwrap().to_string();

    let err = record_evidence(&run_id, &valid_evidence(&[]), Some(&dir)).unwrap_err();
    assert!(err.to_string().contains("route effects have not been granted"), "{err}");

    assert!(grant(&run_id, Some(&dir)).unwrap().ready);

    let err = acquire_resolve_provider(&run_id, Some("browser"), Some(&dir)).unwrap_err();
    assert!(err.to_string().contains("not authorized by frozen route provider"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

// Ported from research-core/tests/test_research_route_workspace.py's
// domain-detection/gate/history-source half (see this crate's
// `wf_port::wf031` module doc for why `route_resolve.WORKSPACE` itself has
// no Rust analogue to port).
#[test]
fn route_workspace_domain_and_history_matches_python_test() {
    let route = resolve("Could my TRT protocol explain this lab?", &Default::default()).unwrap();
    assert_eq!(route["domain"], json!("medical"));
    assert_eq!(route["subject"]["patient"]["kind"], json!("self"));
    let gates: Vec<&str> = route["human_gates"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gates.contains(&"confirm-personal-medical-route"));

    let history = std::env::temp_dir().join(format!(
        "legion-wf031-history-fixture-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&history, "patient: fixture\n").unwrap();
    let context = context_from([("history_source", json!(history.to_str().unwrap()))]);
    let route_with_history = resolve("Could my TRT protocol explain this lab?", &context).unwrap();
    let subject = &route_with_history["subject"]["patient"];
    assert_eq!(subject["history_source"], json!(history.to_str().unwrap()));
    assert_eq!(subject["history_available"], json!(true));
    let _ = std::fs::remove_file(&history);
}
