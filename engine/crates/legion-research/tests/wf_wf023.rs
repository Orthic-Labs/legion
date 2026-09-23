//! Integration tests for packet wf023
//! (`src/lib/research-core/{active_run,citecheck,contradictions,control}.py`).
//!
//! Unit-level coverage (including the ports of
//! `research-core/tests/test_research_shards.py` and
//! `test_research_control.py`'s assertions) lives alongside the ported
//! modules under `src/wf_port/wf023/`. This file exercises the public API
//! end to end, across module boundaries, the way the Python CLIs chained
//! them (draft -> citecheck -> contradictions; run -> shard plan -> resume).

use legion_research::wf_port::wf023::{
    checkpoint_shard, citecheck_check, contradictions_derive, decide_stop, executable_runs,
    init_shards, resume_shards, selection, shard_id, ControlManifest, DecideStopRequest,
    PointerValue, RunManifest, RunRecord, ShardPlan, WorkItem,
};

use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[test]
fn citecheck_flags_unsupported_numeric_claim_in_a_realistic_draft() {
    let evidence = vec![
        json!({"id": "E1", "quote_or_paraphrase": "Vendor X lists a monthly seat price"}),
    ];
    let markdown = "\
Vendor X charges 49 dollars per seat per month. [+E1]
Vendor X was founded in 2004 and is privately held.
";
    let result = citecheck_check(markdown, &evidence);
    assert!(!result.ok);
    // The cited sentence has a number (49) absent from the evidence blob.
    assert_eq!(result.unsupported_or_partial_count, 1);
    assert_eq!(result.unsupported[0].evidence_id, "E1");
    // The uncited-but-factual second sentence is unbound.
    assert_eq!(result.unbound_count, 1);
}

#[test]
fn contradictions_and_citecheck_agree_on_a_disputed_pricing_claim() {
    let evidence = vec![
        json!({"id": "E1", "quote_or_paraphrase": "list price is 10 dollars", "independence_cluster": "vendor-site"}),
        json!({"id": "E2", "quote_or_paraphrase": "list price is 20 dollars", "independence_cluster": "review-site"}),
    ];
    let claims = vec![
        json!({"id": "c1", "stance_target": "price", "text": "Costs 10 dollars", "source_ids": ["E1"]}),
        json!({"id": "c2", "stance_target": "price", "text": "Costs 20 dollars", "source_ids": ["E2"]}),
    ];
    let derived = contradictions_derive(&claims, &evidence);
    assert_eq!(derived.contradictions.len(), 1);
    assert_eq!(derived.contradictions[0].kind, "numeric");
    assert!(derived.consensus.is_empty());

    // citecheck and contradictions are independent, complementary checks:
    // the E1 sentence's wording ("One source says it costs 10 dollars")
    // shares only "dollars" with its evidence's content words ("list",
    // "price", "dollars"), so per citecheck.py's `_verdict` (lines 56-74)
    // the lexical overlap is 1/5 = 0.20, below both the 0.55 "supported"
    // floor and the 0.25 floor that applies when the sentence has a
    // number present in the evidence — so E1 is "unsupported". E2's
    // sentence overlaps 1/3 = 0.33 with its evidence, clearing the
    // number-present 0.25 floor, so E2 is "supported". citecheck and
    // contradictions independently flag the same disputed claim.
    let markdown = "One source says it costs 10 dollars. [+E1]\nAnother says 20 dollars. [+E2]\n";
    let check_result = citecheck_check(markdown, &evidence);
    assert!(!check_result.ok, "{check_result:?}");
    assert_eq!(check_result.unsupported_or_partial_count, 1);
    assert_eq!(check_result.unsupported[0].evidence_id, "E1");
}

// ---- active_run + control, against an in-memory mock manifest store ----

#[derive(Default)]
struct MockManifest {
    runs: BTreeMap<String, RunRecord>,
    pointer: RefCell<Option<(String, String)>>,
    events: RefCell<Vec<(String, String, Value)>>,
    used: RefCell<BTreeMap<String, i64>>,
    budget: RefCell<BTreeMap<String, i64>>,
    plans: RefCell<BTreeMap<String, ShardPlan>>,
}

impl RunManifest for MockManifest {
    fn load_run(&self, run_id: &str) -> Result<RunRecord, String> {
        self.runs.get(run_id).cloned().ok_or_else(|| format!("no such run: {run_id}"))
    }
    fn candidate_run_ids(&self) -> Vec<String> {
        self.runs.keys().cloned().collect()
    }
    fn read_pointer(&self) -> Option<(String, String)> {
        self.pointer.borrow().clone()
    }
    fn write_pointer(&self, value: &PointerValue) {
        *self.pointer.borrow_mut() = Some((value.run_id.clone(), value.route_sha256.clone()));
    }
    fn delete_pointer(&self) {
        *self.pointer.borrow_mut() = None;
    }
    fn record_event(&self, run_id: &str, kind: &str, detail: Value) {
        self.events.borrow_mut().push((run_id.to_string(), kind.to_string(), detail));
    }
}

impl ControlManifest for MockManifest {
    fn external_requests_used(&self, run_id: &str) -> Result<i64, String> {
        Ok(*self.used.borrow().get(run_id).unwrap_or(&0))
    }
    fn external_requests_budget(&self, run_id: &str) -> Result<i64, String> {
        Ok(*self.budget.borrow().get(run_id).unwrap_or(&0))
    }
    fn persist_stopping_decision(&self, _run_id: &str, _decision: &Value) {}
    fn record_event(&self, run_id: &str, kind: &str, detail: Value) {
        RunManifest::record_event(self, run_id, kind, detail);
    }
    fn set_acquire_stage(&self, _run_id: &str, _status: &str, _detail: Option<&str>) {}
    fn load_shard_plan(&self, run_id: &str) -> Result<ShardPlan, String> {
        self.plans.borrow().get(run_id).cloned().ok_or_else(|| "no plan".to_string())
    }
    fn save_shard_plan(&self, run_id: &str, plan: &ShardPlan) {
        self.plans.borrow_mut().insert(run_id.to_string(), plan.clone());
    }
}

#[test]
fn a_run_selected_by_active_run_can_then_drive_control_stop_and_shard_flow() {
    let mut store = MockManifest::default();
    store.runs.insert(
        "run-1".into(),
        RunRecord {
            run_id: "run-1".into(),
            status: "acquiring".into(),
            route_sha256: "sha-1".into(),
            route_allows_effects: true,
        },
    );
    store.used.borrow_mut().insert("run-1".into(), 2);
    store.budget.borrow_mut().insert("run-1".into(), 12);

    // Exactly one executable run -> selection resolves it without a pointer.
    let sel = selection(&store);
    assert_eq!(sel.run_id.as_deref(), Some("run-1"));
    assert_eq!(executable_runs(&store), vec!["run-1".to_string()]);

    let run_id = sel.run_id.unwrap();

    let decision = decide_stop(
        &store,
        &run_id,
        DecideStopRequest {
            required_questions: vec!["price".into()],
            answered_questions: vec![],
            consecutive_no_gain: 0,
            blocking_gaps: vec!["privacy authority".into()],
        },
    )
    .unwrap();
    assert_eq!(decision.action, "continue");

    let plan = init_shards(
        &store,
        &run_id,
        &[
            WorkItem { key: "pricing".into(), payload: json!({"query": "price"}) },
            WorkItem { key: "privacy".into(), payload: json!({"query": "privacy"}) },
        ],
    )
    .unwrap();
    assert_eq!(plan.shards.len(), 2);
    assert_eq!(plan.shards[0].id, shard_id(&run_id, "pricing"));

    let first = plan.shards[0].id.clone();
    checkpoint_shard(&store, &run_id, &first, "running", None).unwrap();
    let mut artifacts = Map::new();
    artifacts.insert("evidence".into(), json!("pricing.jsonl"));
    checkpoint_shard(&store, &run_id, &first, "done", Some(&artifacts)).unwrap();

    let resumed = resume_shards(&store, &run_id).unwrap();
    // Only the untouched "privacy" shard (still pending) is resumable.
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].key, "privacy");
}
