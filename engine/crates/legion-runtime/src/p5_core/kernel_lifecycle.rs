//! Ported from src/packages/kernel/lib/lifecycle.mjs (packet P5d).
//!
//! Faithful port of `TaskLifecycle`'s replay/apply state machine and its
//! `create`/`transition`/... mutators. JS serializes mutations through a
//! promise tail (`enqueue`); this port relies on `&mut self` to give the
//! same one-mutation-at-a-time guarantee synchronously.

use std::collections::HashMap;

use legion_catalog::json::{self, Value};

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};
use crate::p5_core::kernel_ids::validate_id;
use crate::p5_core::kernel_journal::JsonlJournal;

const INVOCATION_STATES: &[&str] = &[
    "ACCEPTED",
    "RUNNING",
    "INPUT_REQUIRED",
    "CANCELLED",
    "EXPIRED",
    "FAILED_INVOCATION",
    "COMPLETED",
];

fn is_terminal(state: &str) -> bool {
    matches!(state, "COMPLETED" | "FAILED_INVOCATION" | "EXPIRED")
}

fn allowed_targets(state: &str) -> &'static [&'static str] {
    match state {
        "ACCEPTED" => &["RUNNING", "CANCELLED", "EXPIRED", "FAILED_INVOCATION"],
        "RUNNING" => &["INPUT_REQUIRED", "CANCELLED", "EXPIRED", "FAILED_INVOCATION", "COMPLETED"],
        "INPUT_REQUIRED" => &["RUNNING", "CANCELLED", "EXPIRED", "FAILED_INVOCATION"],
        "CANCELLED" => &["RUNNING"],
        _ => &[],
    }
}

fn integrity_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "JOURNAL_CORRUPT",
        message,
        KernelErrorOptions {
            category: Some("integrity".to_string()),
            ..Default::default()
        },
    )
}

fn usage_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            ..Default::default()
        },
    )
}

#[derive(Debug, Clone)]
pub struct KernelTask {
    pub task_id: String,
    pub run_id: String,
    pub state: String,
    pub input: Value,
    pub created_at: String,
    pub updated_at: String,
    pub result: Option<Value>,
    pub pending_input: Option<Value>,
    pub idempotency_key: Option<String>,
    pub error: Option<Value>,
    pub cancellation_reason: Option<Value>,
}

/// Port of `class TaskLifecycle`.
pub struct TaskLifecycle {
    pub journal: JsonlJournal,
    tasks: HashMap<String, KernelTask>,
    idempotency: HashMap<String, String>,
}

impl TaskLifecycle {
    /// Port of `static async open(filePath)`.
    pub fn open(file_path: impl AsRef<std::path::Path>) -> Result<Self, KernelError> {
        let journal = JsonlJournal::open(file_path)?;
        let mut lifecycle = TaskLifecycle {
            journal,
            tasks: HashMap::new(),
            idempotency: HashMap::new(),
        };
        lifecycle.replay()?;
        Ok(lifecycle)
    }

    fn replay(&mut self) -> Result<(), KernelError> {
        for event in self.journal.all() {
            self.apply(&event)?;
        }
        Ok(())
    }

    fn apply(&mut self, event: &Value) -> Result<(), KernelError> {
        let event_type = event.get("eventType").and_then(Value::as_str).unwrap_or_default();
        if event_type == "task.created" {
            let task_id = event.get("taskId").and_then(Value::as_str).unwrap_or_default();
            let run_id = event.get("runId").and_then(Value::as_str).unwrap_or_default();
            if validate_id("task", task_id).is_err() || validate_id("run", run_id).is_err() {
                return Err(integrity_error("task creation contains invalid identity"));
            }
            if self.tasks.contains_key(task_id) {
                return Err(integrity_error(format!("duplicate task: {task_id}")));
            }
            let idempotency_key = event.get("idempotencyKey").and_then(Value::as_str).map(str::to_string);
            let recorded_at = event.get("recordedAt").and_then(Value::as_str).unwrap_or_default().to_string();
            self.tasks.insert(
                task_id.to_string(),
                KernelTask {
                    task_id: task_id.to_string(),
                    run_id: run_id.to_string(),
                    state: "ACCEPTED".to_string(),
                    input: event.get("input").cloned().unwrap_or(Value::Null),
                    created_at: recorded_at.clone(),
                    updated_at: recorded_at,
                    result: None,
                    pending_input: None,
                    idempotency_key: idempotency_key.clone(),
                    error: None,
                    cancellation_reason: None,
                },
            );
            if let Some(key) = idempotency_key {
                let lookup = format!("{run_id}\0{key}");
                if self.idempotency.contains_key(&lookup) {
                    return Err(integrity_error(format!("duplicate idempotency key: {key}")));
                }
                self.idempotency.insert(lookup, task_id.to_string());
            }
            return Ok(());
        }

        let task_id = event.get("taskId").and_then(Value::as_str).unwrap_or_default().to_string();
        let from = event.get("from").and_then(Value::as_str).unwrap_or_default().to_string();
        let to = event.get("to").and_then(Value::as_str).unwrap_or_default().to_string();
        let recorded_at = event.get("recordedAt").and_then(Value::as_str).unwrap_or_default().to_string();

        let current_state = self
            .tasks
            .get(&task_id)
            .map(|t| t.state.clone())
            .ok_or_else(|| integrity_error(format!("transition for unknown task: {task_id}")))?;

        if from != current_state
            || !INVOCATION_STATES.contains(&to.as_str())
            || is_terminal(&current_state)
            || !allowed_targets(&current_state).contains(&to.as_str())
        {
            return Err(KernelError::new(
                "JOURNAL_CORRUPT",
                format!("invalid replayed transition {from} -> {to}"),
                KernelErrorOptions {
                    category: Some("integrity".to_string()),
                    details: Some(json::json!({"taskId": task_id, "actualState": current_state})),
                    ..Default::default()
                },
            ));
        }

        let task = self.tasks.get_mut(&task_id).expect("checked above");
        task.state = to.clone();
        task.updated_at = recorded_at;
        match event_type {
            "task.input-required" => task.pending_input = event.get("payload").cloned(),
            "task.input-provided" => {
                if let (Some(base), Some(patch)) = (task.input.as_object_mut(), event.get("payload").and_then(Value::as_object)) {
                    for (k, v) in patch {
                        base.insert(k.clone(), v.clone());
                    }
                }
                task.pending_input = None;
            }
            "task.completed" => task.result = event.get("payload").cloned(),
            "task.failed" => task.error = event.get("payload").cloned(),
            "task.cancelled" => {
                task.cancellation_reason = event.get("payload").and_then(|p| p.get("reason")).cloned();
            }
            _ => {}
        }
        Ok(())
    }

    /// Port of `get(taskId)`.
    pub fn get(&self, task_id: &str) -> Result<KernelTask, KernelError> {
        validate_id("task", task_id)?;
        self.tasks
            .get(task_id)
            .cloned()
            .ok_or_else(|| {
                KernelError::new(
                    "TASK_NOT_FOUND",
                    format!("unknown task: {task_id}"),
                    KernelErrorOptions {
                        category: Some("precondition".to_string()),
                        ..Default::default()
                    },
                )
            })
    }

    /// Port of `create({ runId, input, taskId, idempotencyKey })`.
    pub fn create(
        &mut self,
        run_id: &str,
        input: Value,
        task_id: String,
        idempotency_key: Option<String>,
    ) -> Result<KernelTask, KernelError> {
        validate_id("run", run_id)?;
        validate_id("task", &task_id)?;
        if let Some(key) = &idempotency_key {
            if key.is_empty() {
                return Err(usage_error("idempotency key must be a non-empty string"));
            }
        }
        let idempotency_lookup = idempotency_key.as_ref().map(|k| format!("{run_id}\0{k}"));
        if let Some(lookup) = &idempotency_lookup {
            if let Some(existing) = self.idempotency.get(lookup).cloned() {
                return self.get(&existing);
            }
        }
        if self.tasks.contains_key(&task_id) {
            return self.get(&task_id);
        }
        let event = json::json!({
            "eventType": "task.created",
            "taskId": task_id,
            "runId": run_id,
            "input": input,
            "idempotencyKey": idempotency_key,
            "recordedAt": now_iso8601(),
        });
        let sealed = self.journal.append(event)?;
        self.apply(&sealed)?;
        self.get(&task_id)
    }

    fn transition(&mut self, task_id: &str, to: &str, event_type: &str, payload: Value) -> Result<KernelTask, KernelError> {
        let current = self.get(task_id)?;
        if !INVOCATION_STATES.contains(&to) {
            return Err(usage_error(format!("unknown invocation state: {to}")));
        }
        if is_terminal(&current.state) || !allowed_targets(&current.state).contains(&to) {
            return Err(KernelError::new(
                "TASK_ALREADY_TERMINAL",
                format!("task cannot transition {} -> {to}", current.state),
                KernelErrorOptions {
                    category: Some("precondition".to_string()),
                    details: Some(json::json!({"taskId": task_id, "from": current.state, "to": to})),
                    ..Default::default()
                },
            ));
        }
        let event = json::json!({
            "eventType": event_type,
            "taskId": task_id,
            "runId": current.run_id,
            "from": current.state,
            "to": to,
            "payload": payload,
            "recordedAt": now_iso8601(),
        });
        let sealed = self.journal.append(event)?;
        self.apply(&sealed)?;
        self.get(task_id)
    }

    pub fn start(&mut self, task_id: &str) -> Result<KernelTask, KernelError> {
        let current = self.get(task_id)?;
        if current.state == "RUNNING" {
            return Ok(current);
        }
        self.transition(task_id, "RUNNING", "task.started", Value::Null)
    }

    pub fn require_input(&mut self, task_id: &str, request: Value) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "INPUT_REQUIRED", "task.input-required", request)
    }

    pub fn provide_input(&mut self, task_id: &str, input: Value) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "RUNNING", "task.input-provided", input)
    }

    pub fn cancel(&mut self, task_id: &str, reason: Value) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "CANCELLED", "task.cancelled", json::json!({"reason": reason}))
    }

    pub fn resume(&mut self, task_id: &str) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "RUNNING", "task.resumed", Value::Null)
    }

    pub fn complete(&mut self, task_id: &str, result: Value) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "COMPLETED", "task.completed", result)
    }

    pub fn expire(&mut self, task_id: &str) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "EXPIRED", "task.expired", Value::Null)
    }

    pub fn fail(&mut self, task_id: &str, error: Value) -> Result<KernelTask, KernelError> {
        self.transition(task_id, "FAILED_INVOCATION", "task.failed", error)
    }
}

fn now_iso8601() -> String {
    crate::p5_core::kernel_stores::system_time_to_iso8601(std::time::SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() ^ (std::process::id() as u128))
            .wrapping_add(NEXT_ID.fetch_add(1, Ordering::Relaxed) as u128)
    }

    fn temp_journal_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("p5d-lifecycle-{label}-{}", nonce())).join("journal.jsonl")
    }

    fn valid_run_id() -> String {
        "run_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()
    }

    fn valid_task_id() -> String {
        "ktask_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()
    }

    #[test]
    fn create_then_get_round_trips() {
        let path = temp_journal_path("create");
        let mut lifecycle = TaskLifecycle::open(&path).unwrap();
        let task = lifecycle
            .create(&valid_run_id(), json::json!({"a": 1}), valid_task_id(), None)
            .unwrap();
        assert_eq!(task.state, "ACCEPTED");
        let fetched = lifecycle.get(&task.task_id).unwrap();
        assert_eq!(fetched.input["a"], 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn create_is_idempotent_by_key() {
        let path = temp_journal_path("idem");
        let mut lifecycle = TaskLifecycle::open(&path).unwrap();
        let run_id = valid_run_id();
        let first = lifecycle
            .create(&run_id, Value::Null, valid_task_id(), Some("key-1".to_string()))
            .unwrap();
        let second = lifecycle
            .create(&run_id, Value::Null, "ktask_01ARZ3NDEKTSV4RRFFQ69G5FAW".to_string(), Some("key-1".to_string()))
            .unwrap();
        assert_eq!(first.task_id, second.task_id);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn full_happy_path_transitions() {
        let path = temp_journal_path("happy");
        let mut lifecycle = TaskLifecycle::open(&path).unwrap();
        let task = lifecycle
            .create(&valid_run_id(), Value::Null, valid_task_id(), None)
            .unwrap();
        lifecycle.start(&task.task_id).unwrap();
        lifecycle.require_input(&task.task_id, json::json!({"ask": "more"})).unwrap();
        lifecycle.provide_input(&task.task_id, json::json!({"more": true})).unwrap();
        let completed = lifecycle.complete(&task.task_id, json::json!({"ok": true})).unwrap();
        assert_eq!(completed.state, "COMPLETED");
        assert_eq!(completed.result.unwrap()["ok"], true);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn terminal_task_rejects_further_transitions() {
        let path = temp_journal_path("terminal");
        let mut lifecycle = TaskLifecycle::open(&path).unwrap();
        let task = lifecycle
            .create(&valid_run_id(), Value::Null, valid_task_id(), None)
            .unwrap();
        lifecycle.start(&task.task_id).unwrap();
        lifecycle.complete(&task.task_id, Value::Null).unwrap();
        let error = lifecycle.start(&task.task_id).unwrap_err();
        assert_eq!(error.code, "TASK_ALREADY_TERMINAL");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn replay_reconstructs_state_from_journal_on_reopen() {
        let path = temp_journal_path("replay");
        let task_id = valid_task_id();
        {
            let mut lifecycle = TaskLifecycle::open(&path).unwrap();
            let task = lifecycle.create(&valid_run_id(), Value::Null, task_id.clone(), None).unwrap();
            lifecycle.start(&task.task_id).unwrap();
        }
        let reopened = TaskLifecycle::open(&path).unwrap();
        let task = reopened.get(&task_id).unwrap();
        assert_eq!(task.state, "RUNNING");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn get_rejects_unknown_task() {
        let path = temp_journal_path("missing");
        let lifecycle = TaskLifecycle::open(&path).unwrap();
        let error = lifecycle.get(&valid_task_id()).unwrap_err();
        assert_eq!(error.code, "TASK_NOT_FOUND");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
