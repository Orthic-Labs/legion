//! Integration-level parity test for wf030 (research-core entrypoint
//! parity + control/draft-integrity/effect-audit/legal-evidence test
//! files), exercised against the crate's public API rather than the
//! in-module unit tests those sibling packets already carry.
//!
//! NOTE: this file depends on `pub mod wf_port;` and, inside it,
//! `pub mod wf023;`, `pub mod wf024;`, `pub mod wf026;`, `pub mod wf028;`
//! landing in `src/lib.rs` / `src/wf_port/mod.rs` — files this packet does
//! not own, and modules this packet did not itself port (see
//! `src/wf_port/wf030/mod.rs` for why: every behaviour this packet's five
//! Python test files exercise is already ported and unit-tested there).
//! The exact patch is in the packet report (`wf030.md`). Until the
//! integrator applies it, this file will not compile — the same
//! prerequisite `tests/wf_wf024.rs` already documents for wf024's own
//! sibling-module dependency.

use std::fs;
use std::path::PathBuf;

use legion_research::wf_port::wf023::control::{
    checkpoint_shard, decide_stop, init_shards, resume_shards, ControlManifest, DecideStopRequest,
};
use legion_research::wf_port::wf023::shards::{ShardPlan, ShardRow, WorkItem};
use legion_research::wf_port::wf024::{domain_verify, draft_integrity, effect_audit};
use legion_research::wf_port::wf026::meter;
use legion_research::wf_port::wf028::resource_guard;
use legion_research::research_port::effects;
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf030")
}

// --- test_entrypoint_parity.py -------------------------------------------

#[test]
fn non_research_tools_have_no_effect_classification() {
    assert!(!effects::is_external("Read", None));
    assert!(!effects::is_worker("Read"));
}

#[test]
fn resource_guard_authorizes_sourced_draft_outside_forbidden_patterns() {
    let workspace = fixtures_dir();
    fs::create_dir_all(&workspace).ok();
    let source = workspace.join("source.md");
    fs::write(&source, "sourced draft\n").unwrap();
    let verdict = resource_guard::authorize(
        &["private/**".to_string()],
        "source.md",
        &workspace,
        true,
    );
    assert!(verdict.ok, "{:?}", verdict.reason);
}

#[test]
fn patch_guard_issues_a_receipt_stamped_with_research_core_issuer() {
    let workspace = fixtures_dir();
    fs::create_dir_all(&workspace).ok();
    let source = workspace.join("source.md");
    fs::write(&source, "sourced draft\n").unwrap();
    let key_path = workspace.join("key");
    let receipt = legion_research::wf_port::wf026::patch_guard::issue_receipt(
        &source,
        "run-parity",
        Some(&key_path),
    )
    .expect("issue_receipt should succeed");
    assert_eq!(receipt["issued_by"], json!("research-core.patch-guard"));
    assert!(receipt["signature"]
        .as_str()
        .unwrap()
        .starts_with("hmac-sha256:"));
}

// --- test_research_control.py --------------------------------------------

#[derive(Default)]
struct MockStore {
    used: i64,
    budget: i64,
    plans: RefCell<BTreeMap<String, ShardPlan>>,
}

impl ControlManifest for MockStore {
    fn external_requests_used(&self, _run_id: &str) -> Result<i64, String> {
        Ok(self.used)
    }
    fn external_requests_budget(&self, _run_id: &str) -> Result<i64, String> {
        Ok(self.budget)
    }
    fn persist_stopping_decision(&self, _run_id: &str, _decision: &Value) {}
    fn record_event(&self, _run_id: &str, _kind: &str, _detail: Value) {}
    fn set_acquire_stage(&self, _run_id: &str, _status: &str, _detail: Option<&str>) {}
    fn load_shard_plan(&self, run_id: &str) -> Result<ShardPlan, String> {
        self.plans
            .borrow()
            .get(run_id)
            .cloned()
            .ok_or_else(|| "no plan".to_string())
    }
    fn save_shard_plan(&self, run_id: &str, plan: &ShardPlan) {
        self.plans.borrow_mut().insert(run_id.to_string(), plan.clone());
    }
}

#[test]
fn stopping_and_shard_resume_state_persist_in_the_run_manifest() {
    let store = MockStore { used: 0, budget: 12, ..Default::default() };

    let decision = decide_stop(
        &store,
        "run-1",
        DecideStopRequest {
            required_questions: vec!["price".into()],
            answered_questions: vec!["price".into()],
            consecutive_no_gain: 0,
            blocking_gaps: vec![],
        },
    )
    .unwrap();
    assert_eq!(decision.reason, "coverage-complete");

    let plan = init_shards(
        &store,
        "run-1",
        &[
            WorkItem { key: "pricing".into(), payload: json!({"query": "price"}) },
            WorkItem { key: "privacy".into(), payload: json!({"query": "privacy"}) },
        ],
    )
    .unwrap();
    let first = plan.shards[0].id.clone();
    let second = plan.shards[1].id.clone();

    checkpoint_shard(&store, "run-1", &first, "running", None).unwrap();
    let mut artifacts = Map::new();
    artifacts.insert("evidence".into(), json!("pricing.jsonl"));
    checkpoint_shard(&store, "run-1", &first, "done", Some(&artifacts)).unwrap();
    checkpoint_shard(&store, "run-1", &second, "failed", None).unwrap();

    let resumed: Vec<ShardRow> = resume_shards(&store, "run-1").unwrap();
    assert_eq!(
        resumed.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        vec![second]
    );
}

// --- test_research_draft_integrity.py -------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn direct_and_post_patch_draft_mutations_are_blocked_by_hash_authority() {
    let dir = fixtures_dir().join("draft_integrity_run");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let draft = dir.join("draft.md");

    fs::write(&draft, "sourced\n").unwrap();
    let sourced_hash = sha256_hex(fs::read(&draft).unwrap().as_slice());
    let mut manifest = json!({"artifacts": {"sourced-draft": {"sha256": sourced_hash}}});
    assert_eq!(draft_integrity::check(&dir, &manifest)["ok"], json!(true));

    fs::write(&draft, "edited directly\n").unwrap();
    let result = draft_integrity::check(&dir, &manifest);
    assert_eq!(result["ok"], json!(false));
    assert!(result["reason"].as_str().unwrap().contains("differs"));

    fs::write(&draft, "sourced\n").unwrap();
    fs::write(dir.join("applied.patch"), "@@\n").unwrap();
    let missing = draft_integrity::check(&dir, &manifest);
    assert_eq!(missing["ok"], json!(false));
    assert!(missing["reason"]
        .as_str()
        .unwrap()
        .contains("patched-draft"));

    fs::write(&draft, "patched\n").unwrap();
    let patched_hash = sha256_hex(fs::read(&draft).unwrap().as_slice());
    manifest["artifacts"]["patched-draft"] = json!({"sha256": patched_hash});
    assert_eq!(draft_integrity::check(&dir, &manifest)["ok"], json!(true));

    fs::write(&draft, "changed after patch\n").unwrap();
    assert_eq!(draft_integrity::check(&dir, &manifest)["ok"], json!(false));

    let _ = fs::remove_dir_all(&dir);
}

// --- test_research_effect_audit.py ----------------------------------------

#[test]
fn hook_effect_receipts_reconcile_with_manifest_usage_and_budgets() {
    let manifest = json!({
        "usage": {"external_requests": 2, "workers_started": 1, "workers_active": 0},
        "budget": {"external_requests": 12, "workers": 1},
    });
    let events: Vec<Value> = vec![
        json!({"type": "budget.consumed", "effect": "external_request", "units": 1}),
        json!({"type": "budget.consumed", "effect": "external_request", "units": 1}),
        json!({"type": "budget.consumed", "effect": "worker", "worker_event": "start", "units": 1}),
        json!({"type": "budget.consumed", "effect": "worker", "worker_event": "finish", "units": 1}),
    ];
    assert_eq!(effect_audit::audit(&manifest, &events)["ok"], json!(true));

    let mut tampered = manifest.clone();
    tampered["usage"]["external_requests"] = json!(1);
    let result = effect_audit::audit(&tampered, &events);
    assert_eq!(result["ok"], json!(false));
    assert!(result["mismatches"]
        .as_object()
        .map(|m| m.contains_key("external_requests"))
        .unwrap_or(false));

    let mut malformed_events = events.clone();
    malformed_events.push(json!({"type": "budget.consumed", "effect": "worker", "worker_event": "finish", "units": 1}));
    let malformed = effect_audit::audit(&manifest, &malformed_events);
    assert_eq!(malformed["ok"], json!(false));
    assert!(!malformed["malformed"].as_array().unwrap().is_empty());
}

// --- test_research_legal_evidence_extensions.py ---------------------------

#[test]
fn legal_case_law_evidence_requires_forum_precedential_status_negative_treatment_current_as_of() {
    let route = json!({
        "domain": "legal",
        "subject": {"country": "IN", "area": "civil", "issue": "precedent support"},
        "forbidden_resources": [],
    });
    let claim = json!({"id": "cl1", "claim_type": "case-law", "source_ids": ["ev1"]});
    let incomplete = json!({
        "id": "ev1",
        "authority_type": "judgment",
        "forum": "High Court",
        "current_as_of": "2026-08-05",
    });
    let result = domain_verify::verify(&route, &[incomplete.clone()], &[claim.clone()]);
    assert_eq!(result["ok"], json!(false), "{result:?}");

    let mut complete = incomplete;
    complete["precedential_status"] = json!("binding");
    complete["negative_treatment"] = json!("none found");
    let result = domain_verify::verify(&route, &[complete], &[claim]);
    assert_eq!(result["ok"], json!(true), "{result:?}");
}
