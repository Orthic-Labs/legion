//! Integration tests for packet r30: the full route dispatch ported from
//! `skills/designer/engine/scripts/live/manual-edit-routes.mjs` into
//! `legion_runtime::wf_port::w2_021::manual_edit_routes`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_runtime::wf_port::w2_021::manual_edit_routes::{
    handle_manual_edit_route, CommitManualEditsArgs, ManualEditRequest, ManualEditRoutesDeps,
    PendingManualEditBatchSummaryTotals,
};
use legion_runtime::wf_port::w2_021::manual_edits_buffer::count_by_page;
use serde_json::{json, Value};

fn tmp_dir(name: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "legion-r30-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Default)]
struct FakeDeps {
    cwd: PathBuf,
    token: String,
    copy_agent_mode: String,
    chat_active: bool,
    activity: RefCell<Vec<(String, Value)>>,
    transaction: RefCell<Option<Value>>,
    canceled_calls: RefCell<Vec<Option<String>>>,
    commit_result: RefCell<Option<Result<Value, String>>>,
    validate_error: Option<String>,
}

impl ManualEditRoutesDeps for FakeDeps {
    fn token(&self) -> String {
        self.token.clone()
    }
    fn project_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }
    fn copy_agent_mode(&self) -> String {
        self.copy_agent_mode.clone()
    }
    fn copy_agent_timeout_ms(&self) -> i64 {
        120_000
    }
    fn chat_agent_likely_active(&self) -> bool {
        self.chat_active
    }
    fn record_manual_edit_activity(&self, event: &str, payload: Value) {
        self.activity.borrow_mut().push((event.to_string(), payload));
    }
    fn manual_edit_status(&self) -> PendingManualEditBatchSummaryTotals {
        let counts = count_by_page(&self.cwd);
        PendingManualEditBatchSummaryTotals {
            total_count: counts.total_count,
            per_page: counts.per_page.into_iter().collect(),
        }
    }
    fn validate_manual_edits_event(&self, _msg: &Value) -> Option<String> {
        self.validate_error.clone()
    }
    fn read_transaction(&self) -> Option<Value> {
        self.transaction.borrow().clone()
    }
    fn rollback_transaction(&self, _page_url: Option<&str>, _reason: &str) -> Option<Value> {
        self.transaction.borrow_mut().take()
    }
    fn write_transaction(&self, _page_url: Option<&str>, _batch: &Value) -> Value {
        let t = json!({ "id": "txn-1" });
        *self.transaction.borrow_mut() = Some(t.clone());
        t
    }
    fn clear_transaction(&self, _transaction_id: &str) {
        *self.transaction.borrow_mut() = None;
    }
    fn cancel_pending_events(&self, page_url: Option<&str>) -> Vec<Value> {
        self.canceled_calls
            .borrow_mut()
            .push(page_url.map(|s| s.to_string()));
        Vec::new()
    }
    fn build_manual_edit_evidence(&self, _page_url: Option<&str>) -> Value {
        json!({ "entries": [{ "ops": [{ "ref": "r1" }] }] })
    }
    fn commit_manual_edits(&self, _args: CommitManualEditsArgs) -> Result<Value, String> {
        self.commit_result
            .borrow_mut()
            .take()
            .unwrap_or_else(|| Ok(json!({ "applied": [], "failed": [] })))
    }
}

fn base_deps(dir: &PathBuf) -> FakeDeps {
    FakeDeps {
        cwd: dir.clone(),
        token: "secret".to_string(),
        copy_agent_mode: "mock".to_string(),
        ..Default::default()
    }
}

#[test]
fn stash_unauthorized_without_token() {
    let dir = tmp_dir("stash-unauth");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-stash".into(),
        query: vec![],
        body: Some(Ok(json!({
            "token": "wrong",
            "id": "abcd1234",
            "pageUrl": "https://x/",
            "element": {},
            "ops": [],
        }))),
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 401);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stash_invalid_json_returns_400() {
    let dir = tmp_dir("stash-badjson");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-stash".into(),
        query: vec![],
        body: Some(Err("bad".into())),
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 400);
    assert_eq!(resp.body["error"], "Invalid JSON");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stash_then_get_round_trips_and_records_activity() {
    let dir = tmp_dir("stash-roundtrip");
    let deps = base_deps(&dir);
    let stash_req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-stash".into(),
        query: vec![],
        body: Some(Ok(json!({
            "token": "secret",
            "id": "abcd1234",
            "pageUrl": "https://x/",
            "element": {},
            "ops": [{ "ref": "r1", "newText": "hi" }],
        }))),
    };
    let resp = handle_manual_edit_route(&deps, &stash_req).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body["ok"], true);
    assert_eq!(resp.body["pendingCount"], 1);
    assert_eq!(deps.activity.borrow().last().unwrap().0, "manual_edit_stashed");

    let get_req = ManualEditRequest {
        method: "GET".into(),
        path: "/manual-edit-stash".into(),
        query: vec![
            ("token".into(), "secret".into()),
            ("pageUrl".into(), "https://x/".into()),
        ],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &get_req).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body["count"], 1);
    assert_eq!(resp.body["entries"].as_array().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_with_no_pending_edits_runs_mock_provider_and_reports_done() {
    let dir = tmp_dir("commit-empty");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-commit".into(),
        query: vec![("token".into(), "secret".into())],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body["applied"], json!([]));
    let events: Vec<String> = deps.activity.borrow().iter().map(|(e, _)| e.clone()).collect();
    assert!(events.contains(&"manual_edit_commit_started".to_string()));
    assert!(events.contains(&"manual_edit_commit_done".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_failure_rolls_back_transaction_and_returns_500() {
    let dir = tmp_dir("commit-fail");
    let deps = base_deps(&dir);
    // stage one edit so a transaction gets written.
    legion_runtime::wf_port::w2_021::manual_edits_buffer::stage_entry(
        &dir,
        "e1",
        "https://x/",
        None,
        vec![legion_runtime::wf_port::w2_021::manual_edits_buffer::ManualEditOp {
            ref_: Some("r1".into()),
            new_text: Some("hi".into()),
            ..Default::default()
        }],
    )
    .unwrap();
    *deps.commit_result.borrow_mut() = Some(Err("boom".into()));

    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-commit".into(),
        query: vec![("token".into(), "secret".into())],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 500);
    assert_eq!(resp.body["error"], "manual_edit_commit_failed");
    assert!(deps.transaction.borrow().is_none(), "transaction should be rolled back");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_async_mode_returns_202_immediately() {
    let dir = tmp_dir("commit-async");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-commit".into(),
        query: vec![("token".into(), "secret".into()), ("async".into(), "1".into())],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 202);
    assert_eq!(resp.body["status"], "started");
    // The background work still ran and recorded its activity.
    let events: Vec<String> = deps.activity.borrow().iter().map(|(e, _)| e.clone()).collect();
    assert!(events.contains(&"manual_edit_commit_done".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_repair_only_without_transaction_returns_409() {
    let dir = tmp_dir("commit-repair-409");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-commit".into(),
        query: vec![("token".into(), "secret".into()), ("repair".into(), "true".into())],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 409);
    assert_eq!(resp.body["error"], "manual_edit_repair_transaction_missing");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repair_decision_rollback_and_unsupported_action() {
    let dir = tmp_dir("repair-decision");
    let deps = base_deps(&dir);
    *deps.transaction.borrow_mut() = Some(json!({ "id": "txn-9" }));

    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-repair-decision".into(),
        query: vec![],
        body: Some(Ok(json!({ "token": "secret", "action": "rollback" }))),
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body["rollback"]["id"], "txn-9");
    assert!(deps.transaction.borrow().is_none());

    let bad_req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-repair-decision".into(),
        query: vec![],
        body: Some(Ok(json!({ "token": "secret", "action": "nope" }))),
    };
    let resp = handle_manual_edit_route(&deps, &bad_req).unwrap();
    assert_eq!(resp.status, 400);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn discard_removes_page_entries_and_cancels_events() {
    let dir = tmp_dir("discard");
    let deps = base_deps(&dir);
    legion_runtime::wf_port::w2_021::manual_edits_buffer::stage_entry(
        &dir,
        "e1",
        "https://x/",
        None,
        vec![legion_runtime::wf_port::w2_021::manual_edits_buffer::ManualEditOp {
            ref_: Some("r1".into()),
            new_text: Some("hi".into()),
            ..Default::default()
        }],
    )
    .unwrap();

    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit-discard".into(),
        query: vec![
            ("token".into(), "secret".into()),
            ("pageUrl".into(), "https://x/".into()),
        ],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body["discarded"], 1);
    assert_eq!(deps.canceled_calls.borrow().last().unwrap().as_deref(), Some("https://x/"));
    let counts = count_by_page(&dir);
    assert_eq!(counts.total_count, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_manual_edit_route_returns_410() {
    let dir = tmp_dir("legacy-410");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "POST".into(),
        path: "/manual-edit".into(),
        query: vec![],
        body: None,
    };
    let resp = handle_manual_edit_route(&deps, &req).unwrap();
    assert_eq!(resp.status, 410);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_route_returns_none() {
    let dir = tmp_dir("unknown");
    let deps = base_deps(&dir);
    let req = ManualEditRequest {
        method: "GET".into(),
        path: "/not-a-route".into(),
        query: vec![],
        body: None,
    };
    assert!(handle_manual_edit_route(&deps, &req).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
