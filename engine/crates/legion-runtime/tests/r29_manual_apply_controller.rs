//! Tests for packet r29's port of `createManualApplyController` (the
//! stateful part of `skills/designer/engine/scripts/live/manual-apply.mjs`)
//! as `legion_runtime::wf_port::w2_021::manual_apply::ManualApplyController`,
//! plus the newly-ported pure helpers (`splitManualApplyBatch`,
//! `validateManualApplyResultMessage`, evidence/transaction file I/O, ...).
//!
//! No network or real browser I/O is exercised: the controller's injected
//! callbacks are recorded in-memory fakes, and file I/O goes to a
//! process-unique temp directory.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use legion_runtime::wf_port::w2_021::manual_apply::{
    collect_manual_apply_files, compact_manual_apply_batch, count_manual_apply_ops,
    manual_apply_evidence_dir, manual_apply_transaction_path, normalize_manual_apply_evidence_path,
    normalize_project_file, split_manual_apply_batch, validate_manual_apply_result_message,
    write_manual_apply_transaction, ManualApplyCallbacks, ManualApplyController,
};
use serde_json::{json, Value};

fn tmp_dir(name: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "legion-r29-manual-apply-{name}-{}-{}-{}",
        std::process::id(),
        nanos,
        seq
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Default)]
struct RecordedCalls {
    enqueued: Vec<Value>,
    acknowledged: Vec<String>,
    flushed: usize,
    activity: Vec<(String, Value)>,
}

struct FakeCallbacks {
    recorded: Arc<Mutex<RecordedCalls>>,
}

impl ManualApplyCallbacks for FakeCallbacks {
    fn enqueue_event(&self, event: &Value) {
        self.recorded.lock().unwrap().enqueued.push(event.clone());
    }
    fn acknowledge_pending_event(&self, event_id: &str) {
        self.recorded.lock().unwrap().acknowledged.push(event_id.to_string());
    }
    fn flush_pending_polls(&self) {
        self.recorded.lock().unwrap().flushed += 1;
    }
    fn record_manual_edit_activity(&self, kind: &str, data: Value) {
        self.recorded.lock().unwrap().activity.push((kind.to_string(), data));
    }
}

fn sample_batch() -> Value {
    json!({
        "version": 1,
        "pageUrl": "/index.html",
        "count": 1,
        "entries": [{
            "id": "entry-1",
            "pageUrl": "/index.html",
            "stagedAt": "2026-01-01T00:00:00.000Z",
            "element": { "ref": "r1", "tagName": "h1", "classes": [], "textContent": "Hi" },
            "ops": [{
                "entryId": "entry-1",
                "ref": "r1",
                "tag": "h1",
                "originalText": "Hi",
                "newText": "Hello",
                "sourceHint": { "file": "src/index.html" },
            }],
        }],
    })
}

// ---------------------------------------------------------------------
// push_apply_event_and_wait: resolve / reject / timeout
// ---------------------------------------------------------------------

#[test]
fn push_apply_event_and_wait_resolves_via_another_thread() {
    let cwd = tmp_dir("resolve");
    let recorded = Arc::new(Mutex::new(RecordedCalls::default()));
    let controller = Arc::new(ManualApplyController::with_timeouts(
        cwd.clone(),
        FakeCallbacks { recorded: recorded.clone() },
        Duration::from_secs(5),
        120_000,
    ));

    let batch = sample_batch();
    let controller_for_dispatch = controller.clone();
    let dispatch = thread::spawn(move || controller_for_dispatch.push_apply_event_and_wait(&batch, Some("/index.html"), None, None));

    // Wait until the event is actually enqueued, then resolve it from "another
    // request" — matching how the real HTTP reply route is a separate
    // execution context from the dispatching one.
    let event_id = loop {
        if let Some(event) = recorded.lock().unwrap().enqueued.first().cloned() {
            break event.get("id").and_then(Value::as_str).unwrap().to_string();
        }
        thread::sleep(Duration::from_millis(5));
    };

    let ok = controller.resolve_deferred(
        &event_id,
        json!({ "status": "done", "appliedEntryIds": ["entry-1"], "failed": [], "files": ["src/index.html"], "notes": [] }),
    );
    assert!(ok);

    let result = dispatch.join().unwrap().unwrap();
    assert_eq!(result["status"], "done");
    assert_eq!(result["appliedEntryIds"][0], "entry-1");

    // Evidence file is removed once resolved.
    assert!(!manual_apply_evidence_dir(&cwd).join(format!("{event_id}.json")).exists());
    let activity_kinds: Vec<_> = recorded.lock().unwrap().activity.iter().map(|(k, _)| k.clone()).collect();
    assert!(activity_kinds.contains(&"manual_edit_apply_dispatched".to_string()));
}

#[test]
fn push_apply_event_and_wait_rejects() {
    let cwd = tmp_dir("reject");
    let recorded = Arc::new(Mutex::new(RecordedCalls::default()));
    let controller = Arc::new(ManualApplyController::with_timeouts(
        cwd,
        FakeCallbacks { recorded: recorded.clone() },
        Duration::from_secs(5),
        120_000,
    ));

    let batch = sample_batch();
    let controller_for_dispatch = controller.clone();
    let dispatch = thread::spawn(move || controller_for_dispatch.push_apply_event_and_wait(&batch, None, None, None));

    let event_id = loop {
        if let Some(event) = recorded.lock().unwrap().enqueued.first().cloned() {
            break event.get("id").and_then(Value::as_str).unwrap().to_string();
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(controller.reject_deferred(&event_id, Some("chat_agent_error")));

    let err = dispatch.join().unwrap().unwrap_err();
    assert_eq!(err, "chat_agent_error");
}

#[test]
fn push_apply_event_and_wait_times_out_and_tombstones() {
    let cwd = tmp_dir("timeout");
    let recorded = Arc::new(Mutex::new(RecordedCalls::default()));
    let controller = ManualApplyController::with_timeouts(
        cwd,
        FakeCallbacks { recorded: recorded.clone() },
        Duration::from_millis(50),
        120_000,
    );

    let batch = sample_batch();
    let err = controller.push_apply_event_and_wait(&batch, Some("/index.html"), None, None).unwrap_err();
    assert_eq!(err, "chat_agent_timeout");

    let event_id = recorded.lock().unwrap().enqueued[0]
        .get("id")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    assert!(controller.has_timed_out_id(&event_id));
    assert!(recorded.lock().unwrap().acknowledged.contains(&event_id));
    // resolving after timeout must fail: the deferred is already gone.
    assert!(!controller.resolve_deferred(&event_id, json!({"status": "done"})));
}

// ---------------------------------------------------------------------
// cancel_pending_events
// ---------------------------------------------------------------------

#[test]
fn cancel_pending_events_rejects_matching_deferreds_and_rolls_back() {
    let cwd = tmp_dir("cancel");
    std::fs::write(cwd.join("index.html"), "before").unwrap();
    let recorded = Arc::new(Mutex::new(RecordedCalls::default()));
    let controller = Arc::new(ManualApplyController::with_timeouts(
        cwd.clone(),
        FakeCallbacks { recorded: recorded.clone() },
        Duration::from_secs(5),
        120_000,
    ));

    let mut batch = sample_batch();
    batch["entries"][0]["ops"][0]["sourceHint"] = json!({ "file": "index.html" });
    let controller_for_dispatch = controller.clone();
    let batch_clone = batch.clone();
    let dispatch = thread::spawn(move || controller_for_dispatch.push_apply_event_and_wait(&batch_clone, Some("/index.html"), None, None));

    loop {
        if !recorded.lock().unwrap().enqueued.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    // Mutate the file after the snapshot was taken, simulating a partial
    // apply that must be rolled back on cancel.
    std::fs::write(cwd.join("index.html"), "after").unwrap();

    let canceled = controller.cancel_pending_events(Some("/index.html"), "manual_edit_discarded");
    assert_eq!(canceled.len(), 1);
    assert_eq!(canceled[0]["rolledBackFiles"][0], "index.html");
    assert_eq!(std::fs::read_to_string(cwd.join("index.html")).unwrap(), "before");

    let err = dispatch.join().unwrap().unwrap_err();
    assert_eq!(err, "manual_edit_discarded");
    assert_eq!(recorded.lock().unwrap().flushed, 1);
}

// ---------------------------------------------------------------------
// split_manual_apply_batch
// ---------------------------------------------------------------------

#[test]
fn split_manual_apply_batch_single_chunk_when_under_limit() {
    let batch = sample_batch();
    let chunks = split_manual_apply_batch(&batch, 3);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].meta.is_none());
    assert_eq!(count_manual_apply_ops(&chunks[0].batch), 1);
}

#[test]
fn split_manual_apply_batch_splits_by_max_ops() {
    let mut batch = sample_batch();
    let ops = batch["entries"][0]["ops"].as_array().unwrap()[0].clone();
    let mut entry2 = batch["entries"][0].clone();
    entry2["id"] = json!("entry-2");
    entry2["ops"] = json!([ops.clone(), ops.clone(), ops.clone()]);
    batch["entries"] = json!([batch["entries"][0].clone(), entry2]);

    let chunks = split_manual_apply_batch(&batch, 2);
    assert!(chunks.len() >= 2, "expected multiple chunks, got {}", chunks.len());
    let total_ops: usize = chunks.iter().map(|c| count_manual_apply_ops(&c.batch)).sum();
    assert_eq!(total_ops, 4);
    for chunk in &chunks {
        assert!(chunk.meta.is_some());
        assert!(count_manual_apply_ops(&chunk.batch) <= 2);
    }
}

// ---------------------------------------------------------------------
// push_batch_in_chunks_and_wait
// ---------------------------------------------------------------------

#[test]
fn push_batch_in_chunks_and_wait_aggregates_applied_and_failed() {
    let cwd = tmp_dir("chunks");
    let recorded = Arc::new(Mutex::new(RecordedCalls::default()));
    let controller = Arc::new(ManualApplyController::with_timeouts(
        cwd,
        FakeCallbacks { recorded: recorded.clone() },
        Duration::from_secs(5),
        120_000,
    ));

    let mut batch = sample_batch();
    let op = batch["entries"][0]["ops"][0].clone();
    let mut entry2 = batch["entries"][0].clone();
    entry2["id"] = json!("entry-2");
    entry2["ops"] = json!([op]);
    batch["entries"] = json!([batch["entries"][0].clone(), entry2]);
    // force a split: chunk size 1 with two single-op entries -> 2 chunks
    std::env::set_var("IMPECCABLE_LIVE_MANUAL_EDIT_CHUNK_SIZE", "1");

    let controller_for_dispatch = controller.clone();
    let batch_clone = batch.clone();
    let dispatch = thread::spawn(move || controller_for_dispatch.push_batch_in_chunks_and_wait(&batch_clone, Some("/index.html"), None));

    // Resolve every dispatched chunk as done for exactly the entries it
    // carries, however the controller chose to split the batch. A deadline
    // keeps a wiring regression from hanging the suite.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut already_resolved: std::collections::HashSet<String> = std::collections::HashSet::new();
    while !dispatch.is_finished() {
        assert!(std::time::Instant::now() < deadline, "controller never finished dispatching chunks");
        let pending: Vec<(String, Vec<Value>)> = {
            let recorded_guard = recorded.lock().unwrap();
            recorded_guard
                .enqueued
                .iter()
                .filter_map(|e| {
                    let id = e.get("id").and_then(Value::as_str)?.to_string();
                    if already_resolved.contains(&id) {
                        return None;
                    }
                    let entry_ids = e
                        .get("batch")
                        .and_then(|b| b.get("entries"))
                        .and_then(Value::as_array)
                        .map(|entries| entries.iter().filter_map(|en| en.get("id").cloned()).collect())
                        .unwrap_or_default();
                    Some((id, entry_ids))
                })
                .collect()
        };
        for (event_id, entry_ids) in pending {
            already_resolved.insert(event_id.clone());
            controller.resolve_deferred(
                &event_id,
                json!({ "status": "done", "appliedEntryIds": entry_ids, "failed": [], "files": [], "notes": [] }),
            );
        }
        thread::sleep(Duration::from_millis(5));
    }

    let result = dispatch.join().unwrap();
    std::env::remove_var("IMPECCABLE_LIVE_MANUAL_EDIT_CHUNK_SIZE");
    assert_eq!(result["status"], "done");
    let applied: Vec<&str> = result["appliedEntryIds"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(applied.contains(&"entry-1"));
    assert!(applied.contains(&"entry-2"));
}

// ---------------------------------------------------------------------
// validate_manual_apply_result_message
// ---------------------------------------------------------------------

#[test]
fn validate_manual_apply_result_message_accepts_well_formed_done() {
    let deferred_batch = sample_batch();
    let msg = json!({
        "id": "abc123",
        "data": {
            "status": "done",
            "appliedEntryIds": ["entry-1"],
            "failed": [],
            "files": ["src/index.html"],
            "notes": [],
        }
    });
    let result = validate_manual_apply_result_message(&msg, Some("abc123"), Some(&deferred_batch)).unwrap();
    assert_eq!(result["status"], "done");
}

#[test]
fn validate_manual_apply_result_message_rejects_done_with_no_applied_ids() {
    let deferred_batch = sample_batch();
    let msg = json!({
        "id": "abc123",
        "data": { "status": "done", "appliedEntryIds": [], "failed": [], "files": [], "notes": [] }
    });
    let err = validate_manual_apply_result_message(&msg, Some("abc123"), Some(&deferred_batch)).unwrap_err();
    assert_eq!(err["body"]["reason"], "done_result_missing_applied_entry_ids");
}

#[test]
fn validate_manual_apply_result_message_rejects_unknown_entry_id() {
    let deferred_batch = sample_batch();
    let msg = json!({
        "id": "abc123",
        "data": { "status": "done", "appliedEntryIds": ["not-in-batch"], "failed": [], "files": [], "notes": [] }
    });
    let err = validate_manual_apply_result_message(&msg, Some("abc123"), Some(&deferred_batch)).unwrap_err();
    assert_eq!(err["body"]["reason"], "applied_entry_id_not_in_event");
}

#[test]
fn validate_manual_apply_result_message_rejects_summary_shape() {
    let msg = json!({ "id": "abc123", "data": { "entries": [], "status": "done" } });
    let err = validate_manual_apply_result_message(&msg, Some("abc123"), None).unwrap_err();
    assert_eq!(err["body"]["reason"], "summary_result_not_allowed");
}

// ---------------------------------------------------------------------
// compact_manual_apply_batch / collect_manual_apply_files
// ---------------------------------------------------------------------

#[test]
fn compact_manual_apply_batch_flattens_ops_with_entry_id() {
    let cwd = tmp_dir("compact");
    let batch = sample_batch();
    let compacted = compact_manual_apply_batch(&batch, &cwd);
    assert_eq!(compacted["ops"].as_array().unwrap().len(), 1);
    assert_eq!(compacted["ops"][0]["entryId"], "entry-1");
    assert_eq!(compacted["entries"][0]["ops"][0]["originalText"], "Hi");
}

#[test]
fn collect_manual_apply_files_dedupes_and_relativizes() {
    let cwd = tmp_dir("collect");
    let batch = sample_batch();
    let files = collect_manual_apply_files(&batch, &["src/index.html".to_string()], &cwd);
    assert_eq!(files, vec!["src/index.html".to_string()]);
}

#[test]
fn normalize_project_file_rejects_escape() {
    let cwd = tmp_dir("escape");
    assert_eq!(normalize_project_file(Some("../../etc/passwd"), &cwd), None);
    assert_eq!(normalize_project_file(Some("src/a.html"), &cwd).as_deref(), Some("src/a.html"));
}

// ---------------------------------------------------------------------
// evidence path guard
// ---------------------------------------------------------------------

#[test]
fn normalize_manual_apply_evidence_path_rejects_escape_and_wrong_extension() {
    let cwd = tmp_dir("evidence-guard");
    let dir = manual_apply_evidence_dir(&cwd);
    std::fs::create_dir_all(&dir).unwrap();
    let ok = dir.join("abc.json");
    assert_eq!(
        normalize_manual_apply_evidence_path(Some(ok.to_str().unwrap()), &cwd),
        Some(ok)
    );
    assert_eq!(normalize_manual_apply_evidence_path(Some("../outside.json"), &cwd), None);
    assert_eq!(normalize_manual_apply_evidence_path(Some("abc.txt"), &cwd), None);
}

// ---------------------------------------------------------------------
// transaction round trip
// ---------------------------------------------------------------------

#[test]
fn write_and_read_manual_apply_transaction_round_trips() {
    let cwd = tmp_dir("transaction");
    std::fs::write(cwd.join("index.html"), "hello").unwrap();
    let mut batch = sample_batch();
    batch["entries"][0]["ops"][0]["sourceHint"] = json!({ "file": "index.html" });

    let tx = write_manual_apply_transaction(&cwd, Some("/index.html"), &batch).unwrap();
    assert!(manual_apply_transaction_path(&cwd).exists());
    assert_eq!(tx["files"][0]["file"], "index.html");
    assert_eq!(tx["files"][0]["content"], "hello");
}
