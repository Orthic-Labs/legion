//! Port of `research-core/control.py`: durable acquisition control —
//! adaptive stopping and resumable shards.
//!
//! `control.py` is a thin manifest-backed wrapper: `decide_stop` reads the
//! run's budget from `manifest.load_run` and persists via
//! `manifest.attach_artifact`/`manifest.record_event`/`manifest.set_stage`;
//! `init_shards`/`checkpoint_shard`/`resume_shards` persist a
//! `shards.json` the same way. `manifest.py` is not yet ported under
//! `legion-research` (see `active_run.rs`'s module doc for the same gap),
//! so this module ports the decision logic against a `ControlManifest`
//! trait instead of a concrete manifest implementation.
//!
//! The adaptive-stopping decision itself (`stopping.decide`) is **already
//! ported and verified** at `crate::research_port::stopping::decide`
//! (ALREADY-NATIVE-VERIFIED) — this module only adds the
//! `external_requests_used`/`external_requests_budget` lookup and
//! persistence `decide_stop` layers on top, and re-exports the shard
//! functions ported in `shards.rs`.
//!
//! [`run_cli`] ports `main(argv)`'s `argparse` dispatch (`stop`/`shard-init`/
//! `shard-checkpoint`/`shard-resume`, including the `--input`/`--artifacts`
//! JSON file reads), closing the r55 CLI-entrypoint gap.

use std::fs;

use serde_json::{json, Map, Value};

use crate::research_port::stopping::{decide as stopping_decide, StoppingDecision, StoppingInput};
use crate::wf_port::wf023::shards::{self, ShardPlan, ShardRow, WorkItem};

/// Abstracts the parts of `manifest.py` that `control.py` reads/writes.
/// `decide_stop`/`init_shards`/`checkpoint_shard`/`resume_shards` persist
/// through this trait rather than a concrete manifest port (not yet
/// available in this crate; see the module doc).
pub trait ControlManifest {
    /// `run['usage']['external_requests']`.
    fn external_requests_used(&self, run_id: &str) -> Result<i64, String>;
    /// `run['budget']['external_requests']`.
    fn external_requests_budget(&self, run_id: &str) -> Result<i64, String>;
    /// `common.atomic_write_json(manifest.run_dir(run_id) / 'stopping.json', decision)`
    /// + `manifest.attach_artifact(run_id, 'stopping-decision', path)`.
    fn persist_stopping_decision(&self, run_id: &str, decision: &Value);
    /// `manifest.record_event(run_id, kind, detail)`.
    fn record_event(&self, run_id: &str, kind: &str, detail: Value);
    /// `manifest.set_stage(run_id, 'acquire', status, detail=...)`, called
    /// only when the decision's `action` is `'stop'`.
    fn set_acquire_stage(&self, run_id: &str, status: &str, detail: Option<&str>);
    /// Persisted shard plan read/write, backing `shards.json`.
    fn load_shard_plan(&self, run_id: &str) -> Result<ShardPlan, String>;
    fn save_shard_plan(&self, run_id: &str, plan: &ShardPlan);
}

/// Mirrors the `decide_stop(run_id, payload)` input, i.e. the caller's
/// payload before `external_requests_used`/`external_requests_budget` are
/// filled in from the run.
#[derive(Debug, Clone, Default)]
pub struct DecideStopRequest {
    pub required_questions: Vec<String>,
    pub answered_questions: Vec<String>,
    pub consecutive_no_gain: i64,
    pub blocking_gaps: Vec<String>,
}

fn decision_to_json(decision: &StoppingDecision) -> Value {
    json!({
        "action": decision.action,
        "reason": decision.reason,
        "complete": decision.complete,
        "unanswered": decision.unanswered,
        "blocking_gaps": decision.blocking_gaps,
    })
}

/// `decide_stop`.
pub fn decide_stop(
    store: &impl ControlManifest,
    run_id: &str,
    payload: DecideStopRequest,
) -> Result<StoppingDecision, String> {
    let external_requests_used = store.external_requests_used(run_id)?;
    let external_requests_budget = store.external_requests_budget(run_id)?;
    let decision = stopping_decide(&StoppingInput {
        required_questions: payload.required_questions,
        answered_questions: payload.answered_questions,
        consecutive_no_gain: payload.consecutive_no_gain,
        external_requests_used,
        external_requests_budget,
        blocking_gaps: payload.blocking_gaps,
    });
    store.persist_stopping_decision(run_id, &decision_to_json(&decision));
    store.record_event(run_id, "stopping.decided", decision_to_json(&decision));
    if decision.action == "stop" {
        let detail = if decision.complete { None } else { Some(decision.reason) };
        let status = if decision.complete { "done" } else { "blocked" };
        store.set_acquire_stage(run_id, status, detail);
    }
    Ok(decision)
}

/// `init_shards`.
pub fn init_shards(store: &impl ControlManifest, run_id: &str, work_items: &[WorkItem]) -> Result<ShardPlan, String> {
    let plan = shards::plan(run_id, work_items)?;
    store.save_shard_plan(run_id, &plan);
    store.record_event(run_id, "shards.planned", json!({"count": plan.shards.len()}));
    Ok(plan)
}

/// `checkpoint_shard`.
pub fn checkpoint_shard(
    store: &impl ControlManifest,
    run_id: &str,
    shard_id: &str,
    status: &str,
    artifacts: Option<&Map<String, Value>>,
) -> Result<ShardPlan, String> {
    let mut plan = store.load_shard_plan(run_id)?;
    shards::checkpoint(&mut plan, shard_id, status, artifacts)?;
    store.save_shard_plan(run_id, &plan);
    store.record_event(
        run_id,
        "shard.checkpoint",
        json!({
            "shard_id": shard_id,
            "status": status,
            "artifacts": artifacts.cloned().unwrap_or_default(),
        }),
    );
    Ok(plan)
}

/// `resume_shards`. Returns owned rows (not references into the store) so
/// the caller does not need the plan to outlive this call.
pub fn resume_shards(store: &impl ControlManifest, run_id: &str) -> Result<Vec<ShardRow>, String> {
    let plan = store.load_shard_plan(run_id)?;
    let rows: Vec<ShardRow> = shards::resumable(&plan).into_iter().cloned().collect();
    store.record_event(
        run_id,
        "shards.resumed",
        json!({"shard_ids": rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>()}),
    );
    Ok(rows)
}

fn shard_row_json(row: &ShardRow) -> Value {
    json!({
        "id": row.id,
        "key": row.key,
        "payload": row.payload,
        "status": row.status,
        "attempts": row.attempts,
        "artifacts": row.artifacts,
    })
}

fn shard_plan_json(plan: &ShardPlan) -> Value {
    json!({
        "schema_version": plan.schema_version,
        "run_id": plan.run_id,
        "shards": plan.shards.iter().map(shard_row_json).collect::<Vec<_>>(),
    })
}

fn str_list_field(payload: &Value, key: &str) -> Vec<String> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Port of `main(argv)`'s `argparse` dispatch: `stop --run-id --input`,
/// `shard-init --run-id --input`, `shard-checkpoint --run-id --shard-id
/// --status [--artifacts]`, `shard-resume --run-id`. `--input`/`--artifacts`
/// name JSON files read from disk exactly as `Path(args.input).read_text()`
/// does; the decision logic each subcommand dispatches to is already ported
/// above and is tested there against `ControlManifest` fakes, so only the
/// argv parsing and JSON-file loading are new here.
pub fn run_cli(store: &impl ControlManifest, args: &[String]) -> Result<Value, String> {
    let mut iter = args.iter();
    let command = iter.next().ok_or("command is required (stop|shard-init|shard-checkpoint|shard-resume)")?.clone();

    let mut run_id: Option<String> = None;
    let mut input: Option<String> = None;
    let mut shard_id_arg: Option<String> = None;
    let mut status: Option<String> = None;
    let mut artifacts_path: Option<String> = None;
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--run-id" => run_id = iter.next().cloned(),
            "--input" => input = iter.next().cloned(),
            "--shard-id" => shard_id_arg = iter.next().cloned(),
            "--status" => status = iter.next().cloned(),
            "--artifacts" => artifacts_path = iter.next().cloned(),
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }
    let run_id = run_id.ok_or("--run-id is required")?;

    match command.as_str() {
        "stop" => {
            let input = input.ok_or("--input is required")?;
            let text = fs::read_to_string(&input).map_err(|e| e.to_string())?;
            let payload: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let request = DecideStopRequest {
                required_questions: str_list_field(&payload, "required_questions"),
                answered_questions: str_list_field(&payload, "answered_questions"),
                consecutive_no_gain: payload.get("consecutive_no_gain").and_then(Value::as_i64).unwrap_or(0),
                blocking_gaps: str_list_field(&payload, "blocking_gaps"),
            };
            let decision = decide_stop(store, &run_id, request)?;
            Ok(decision_to_json(&decision))
        }
        "shard-init" => {
            let input = input.ok_or("--input is required")?;
            let text = fs::read_to_string(&input).map_err(|e| e.to_string())?;
            let items: Vec<Value> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let work_items: Vec<WorkItem> = items
                .iter()
                .map(|item| WorkItem {
                    key: item.get("key").and_then(Value::as_str).unwrap_or_default().to_string(),
                    payload: item.get("payload").cloned().unwrap_or(Value::Null),
                })
                .collect();
            let plan = init_shards(store, &run_id, &work_items)?;
            Ok(shard_plan_json(&plan))
        }
        "shard-checkpoint" => {
            let shard_id_arg = shard_id_arg.ok_or("--shard-id is required")?;
            let status = status.ok_or("--status is required")?;
            let artifacts = match artifacts_path {
                Some(path) => {
                    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
                    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                    value.as_object().cloned()
                }
                None => None,
            };
            let plan = checkpoint_shard(store, &run_id, &shard_id_arg, &status, artifacts.as_ref())?;
            Ok(shard_plan_json(&plan))
        }
        "shard-resume" => {
            let rows = resume_shards(store, &run_id)?;
            Ok(Value::Array(rows.iter().map(shard_row_json).collect()))
        }
        other => Err(format!("unknown command: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use serde_json::json;

    #[derive(Default)]
    struct MockStore {
        used: i64,
        budget: i64,
        events: RefCell<Vec<(String, String, Value)>>,
        stage: RefCell<Option<(String, Option<String>)>>,
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
        fn record_event(&self, run_id: &str, kind: &str, detail: Value) {
            self.events.borrow_mut().push((run_id.to_string(), kind.to_string(), detail));
        }
        fn set_acquire_stage(&self, _run_id: &str, status: &str, detail: Option<&str>) {
            *self.stage.borrow_mut() = Some((status.to_string(), detail.map(str::to_string)));
        }
        fn load_shard_plan(&self, run_id: &str) -> Result<ShardPlan, String> {
            self.plans.borrow().get(run_id).cloned().ok_or_else(|| "no plan".to_string())
        }
        fn save_shard_plan(&self, run_id: &str, plan: &ShardPlan) {
            self.plans.borrow_mut().insert(run_id.to_string(), plan.clone());
        }
    }

    // Ported from research-core/tests/test_research_control.py (adapted to
    // the trait-injected store, since manifest.py is not yet a Rust port).
    #[test]
    fn stopping_and_shard_resume_state_persist_via_the_store() {
        let store = MockStore { used: 2, budget: 12, ..Default::default() };

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

        let resumed = resume_shards(&store, "run-1").unwrap();
        assert_eq!(resumed.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), vec![second]);
    }

    #[test]
    fn budget_exhausted_stop_sets_blocked_stage_with_reason_detail() {
        let store = MockStore { used: 12, budget: 12, ..Default::default() };
        let decision = decide_stop(
            &store,
            "run-1",
            DecideStopRequest {
                required_questions: vec!["price".into()],
                answered_questions: vec![],
                consecutive_no_gain: 0,
                blocking_gaps: vec![],
            },
        )
        .unwrap();
        assert_eq!(decision.action, "stop");
        assert_eq!(store.stage.borrow().as_ref().unwrap().0, "blocked");
        assert_eq!(store.stage.borrow().as_ref().unwrap().1.as_deref(), Some("budget-exhausted"));
    }

    #[test]
    fn coverage_complete_stop_sets_done_stage_with_no_detail() {
        let store = MockStore { used: 1, budget: 12, ..Default::default() };
        decide_stop(
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
        assert_eq!(store.stage.borrow().as_ref().unwrap().0, "done");
        assert_eq!(store.stage.borrow().as_ref().unwrap().1, None);
    }

    #[test]
    fn continue_action_does_not_set_acquire_stage() {
        let store = MockStore { used: 1, budget: 12, ..Default::default() };
        decide_stop(
            &store,
            "run-1",
            DecideStopRequest {
                required_questions: vec!["price".into(), "privacy".into()],
                answered_questions: vec!["price".into()],
                consecutive_no_gain: 0,
                blocking_gaps: vec![],
            },
        )
        .unwrap();
        assert!(store.stage.borrow().is_none());
    }

    // --- run_cli --------------------------------------------------------

    fn temp_json_file(contents: &Value) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "legion-r55-wf023-control-{}-{}.json",
            std::process::id(),
            n
        ));
        std::fs::write(&path, serde_json::to_string(contents).unwrap()).unwrap();
        path
    }

    #[test]
    fn run_cli_stop_reads_input_file_and_decides() {
        let store = MockStore { used: 2, budget: 12, ..Default::default() };
        let input = temp_json_file(&json!({
            "required_questions": ["price"],
            "answered_questions": ["price"],
            "consecutive_no_gain": 0,
            "blocking_gaps": [],
        }));
        let result = run_cli(
            &store,
            &["stop".to_string(), "--run-id".to_string(), "run-1".to_string(), "--input".to_string(), input.to_string_lossy().into_owned()],
        )
        .unwrap();
        assert_eq!(result["reason"], json!("coverage-complete"));
        std::fs::remove_file(&input).ok();
    }

    #[test]
    fn run_cli_shard_init_then_checkpoint_then_resume_round_trips() {
        let store = MockStore::default();
        let input = temp_json_file(&json!([
            {"key": "pricing", "payload": {"query": "price"}},
            {"key": "privacy", "payload": {"query": "privacy"}},
        ]));
        let plan = run_cli(
            &store,
            &["shard-init".to_string(), "--run-id".to_string(), "run-1".to_string(), "--input".to_string(), input.to_string_lossy().into_owned()],
        )
        .unwrap();
        let first_id = plan["shards"][0]["id"].as_str().unwrap().to_string();
        std::fs::remove_file(&input).ok();

        let checkpointed = run_cli(
            &store,
            &[
                "shard-checkpoint".to_string(),
                "--run-id".to_string(),
                "run-1".to_string(),
                "--shard-id".to_string(),
                first_id.clone(),
                "--status".to_string(),
                "done".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(checkpointed["shards"][0]["status"], json!("done"));

        let resumed = run_cli(&store, &["shard-resume".to_string(), "--run-id".to_string(), "run-1".to_string()]).unwrap();
        // The first shard is done; only the second (still pending) resumes.
        assert_eq!(resumed.as_array().unwrap().len(), 1);
        assert_ne!(resumed[0]["id"], json!(first_id));
    }

    #[test]
    fn run_cli_missing_command_is_an_error() {
        let store = MockStore::default();
        let err = run_cli(&store, &[]).unwrap_err();
        assert!(err.contains("command is required"));
    }

    #[test]
    fn run_cli_stop_without_input_flag_is_an_error() {
        let store = MockStore::default();
        let err = run_cli(&store, &["stop".to_string(), "--run-id".to_string(), "run-1".to_string()]).unwrap_err();
        assert!(err.contains("--input is required"));
    }
}
