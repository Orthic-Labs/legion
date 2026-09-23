//! Integration tests for packet wf029
//! (`src/lib/research-core/{router,run,shards}.py` ->
//! `legion_research::wf_port::wf029`).
//!
//! No dedicated Python test file exists for `router/route_detect.py`,
//! `router/route_resolve.py`, or `run.py` under `src/lib/research-core/
//! tests/` at port time (checked via `find`/`grep`); the unit tests inside
//! each ported module already cover the behaviour those scripts implement,
//! ported from close reading of the source rather than from a test file.
//! `shards.py`'s own test (`test_research_shards.py`) is already ported at
//! `wf_port::wf023::shards`, which this chunk verified against
//! (`shards.py` is ALREADY-NATIVE-VERIFIED — see `wf_port::wf029`'s module
//! doc). This file instead exercises the wf029 modules end-to-end, the way
//! a caller (an eventual `run.rs` orchestrator) would chain them.

use legion_research::wf_port::wf029::route_resolve::{
    context_from, gate_verdicts, grant_effects, resolve, validate_route, Stage,
};
use legion_research::wf_port::wf029::run::{check_effects, resolve_acquire_provider, scale_budget};
use serde_json::json;

#[test]
fn end_to_end_general_route_resolves_grants_and_acquires() {
    let route = resolve("find competitor pricing pages", &Default::default()).unwrap();
    assert_eq!(route["domain"], "market");
    assert!(route["human_gates"].as_array().unwrap().is_empty());

    let (granted, verdicts) = grant_effects(&route, None).unwrap();
    assert!(verdicts.iter().all(|v| v["verdict"] == "ok"));
    validate_route(&granted, Stage::Grant).unwrap();

    check_effects(&granted, &["search", "extract"]).unwrap();
    // provider is 'domain-default' on the frozen route; acquire resolves it
    // to the concrete default for this domain (general/market -> browser).
    assert_eq!(granted["provider"], "domain-default");
    let provider = resolve_acquire_provider(&granted, None).unwrap();
    assert_eq!(provider, "browser");
}

#[test]
fn medical_self_route_blocks_grant_until_history_and_gate_approved() {
    let route = resolve("what dose of a drug should i take for my condition", &Default::default()).unwrap();
    assert_eq!(route["domain"], "medical");
    assert_eq!(route["subject"]["patient"]["kind"], "self");

    // Gate not yet approved: grant_effects yields no effects.
    let (ungranted, verdicts) = grant_effects(&route, None).unwrap();
    assert!(ungranted["allowed_effects"].as_array().unwrap().is_empty());
    assert!(verdicts.iter().any(|v| v["verdict"] != "ok"));

    // Approve the human gate, but history is still unavailable: still blocked.
    let mut approvals = serde_json::Map::new();
    approvals.insert(
        "confirm-personal-medical-route".to_string(),
        json!({"text": "operator confirms"}),
    );
    let (still_ungranted, verdicts2) = grant_effects(&route, Some(&approvals)).unwrap();
    assert!(still_ungranted["allowed_effects"].as_array().unwrap().is_empty());
    assert!(verdicts2.iter().any(|v| v["gate"] == "medical.history-available" && v["verdict"] == "block"));
}

#[test]
fn legal_india_consumer_procedure_reaches_grant_once_facts_supplied() {
    let context = context_from([
        ("domain", json!("legal")),
        ("operation", json!("procedure")),
        ("country", json!("IN")),
        ("area", json!("consumer")),
        ("issue", json!("refund for defective product")),
        ("pecuniary_value", json!(50000)),
        ("cause_of_action_date", json!("2026-01-15")),
        ("notice_status", json!("sent")),
    ]);
    let route = resolve("help me file a consumer complaint", &context).unwrap();
    assert!(route["human_gates"].as_array().unwrap().is_empty());

    let (granted, verdicts) = grant_effects(&route, None).unwrap();
    assert!(verdicts.iter().all(|v| v["verdict"] == "ok"));
    let effects: Vec<String> =
        granted["allowed_effects"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    // assurance is 'verified' for legal/procedure -> retraction-check + patch-sourced-draft granted.
    assert!(effects.contains(&"retraction-check".to_string()));
    assert!(effects.contains(&"patch-sourced-draft".to_string()));
    validate_route(&granted, Stage::Grant).unwrap();
}

#[test]
fn dossier_scale_requires_explicit_budget_before_run_could_start() {
    assert!(scale_budget("dossier", None).is_err());
    let budget = json!({"external_requests": 40, "workers": 3});
    assert_eq!(scale_budget("dossier", Some(&budget)).unwrap(), budget);

    let context = context_from([("scale", json!("dossier"))]);
    let route = resolve("comprehensive landscape scan across the market", &context).unwrap();
    assert_eq!(route["scale"], "dossier");
}

#[test]
fn gate_verdicts_matches_resolve_output_for_ungated_general_route() {
    let route = resolve("api latency benchmark comparison", &Default::default()).unwrap();
    let verdicts = gate_verdicts(&route, None);
    // Baseline verdicts always present regardless of domain.
    assert!(verdicts.iter().any(|v| v["gate"] == "notebooklm.answer-not-ledger" && v["verdict"] == "ok"));
    assert!(verdicts.iter().any(|v| v["gate"] == "discovery.provenance" && v["verdict"] == "ok"));
}
