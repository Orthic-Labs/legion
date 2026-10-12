//! Wires `w2_021::manual_edit_routes::handle_manual_edit_route` into this
//! packet's live HTTP server, closing the "manual-edit routes depend on
//! unported live/manual-edit-routes.mjs and live/manual-apply.mjs" gap
//! named in `finish-r24.md` — both are now ported (`w2_021::manual_edit_routes`,
//! `w2_021::manual_apply::ManualApplyController`), so this module is the
//! `ManualEditRoutesDeps` + `ManualApplyCallbacks` glue between them and
//! this server's `QueueState`/token/project root.
//!
//! The evidence builder is reused from `w2_018`; commit orchestration stays
//! in `r18`, with its chat-agent boundary injected through this server's
//! authenticated `/poll` queue.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::queue::QueueState;
use crate::wf_port::r18::commit_cli::{
    commit_manual_edits_with_chat_apply, CommitOptions, NativeChatApply,
};
use crate::wf_port::w2_018::copy_edit_agent::SystemProcessRunner;
use crate::wf_port::w2_018::evidence::build_manual_edit_evidence;
use crate::wf_port::w2_020::event_validation::validate_event;
use crate::wf_port::w2_021::manual_apply::{ManualApplyCallbacks, ManualApplyController};
use crate::wf_port::w2_021::manual_edit_routes::{
    CommitManualEditsArgs, ManualEditRoutesDeps, PendingManualEditBatchSummaryTotals,
};
use crate::wf_port::w2_021::manual_edits_buffer::count_by_page;

/// Bridges `ManualApplyController`'s callbacks to this server's queue:
/// `enqueueEvent`/`acknowledgePendingEvent` mirror the JS controller
/// pushing directly into `state.pendingEvents`, and `flushPendingPolls` is
/// a no-op here because this server's `/poll` handler already re-polls the
/// queue on a short sleep loop instead of JS's callback-resolution model
/// (see `http_server.rs`'s `DEFAULT_POLL_TIMEOUT`/`POLL_SLEEP_STEP` doc
/// comment for why that's the faithful synchronous equivalent).
pub struct QueueCallbacks<'a> {
    pub queue: &'a QueueState,
}

impl ManualApplyCallbacks for QueueCallbacks<'_> {
    fn enqueue_event(&self, event: &Value) {
        self.queue.enqueue_event(event.clone());
    }

    fn acknowledge_pending_event(&self, event_id: &str) {
        self.queue.acknowledge_pending_event(event_id);
    }

    fn flush_pending_polls(&self) {
        // No-op: see doc comment above.
    }

    fn record_manual_edit_activity(&self, kind: &str, data: Value) {
        self.queue.publish_manual_edit_activity(kind, data);
    }
}

pub struct LiveServerManualEditDeps<'a> {
    pub token: String,
    pub project_root: PathBuf,
    pub queue: &'a QueueState,
    pub controller: &'a ManualApplyController<QueueCallbacks<'a>>,
}

impl ManualEditRoutesDeps for LiveServerManualEditDeps<'_> {
    fn token(&self) -> String {
        self.token.clone()
    }

    fn project_cwd(&self) -> PathBuf {
        self.project_root.clone()
    }

    fn copy_agent_mode(&self) -> String {
        let mode = std::env::var("IMPECCABLE_LIVE_COPY_AGENT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if mode.is_empty() {
            "auto".to_string()
        } else {
            mode
        }
    }

    fn copy_agent_timeout_ms(&self) -> i64 {
        std::env::var("IMPECCABLE_LIVE_COPY_AGENT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn chat_agent_likely_active(&self) -> bool {
        // Only token-authenticated GET /poll requests affect this state.
        // This is transport availability, not host/session attestation.
        self.queue.agent_polling_connected()
    }

    fn record_manual_edit_activity(&self, event: &str, payload: Value) {
        self.queue.publish_manual_edit_activity(event, payload);
    }

    fn manual_edit_status(&self) -> PendingManualEditBatchSummaryTotals {
        let counts = count_by_page(&self.project_root);
        PendingManualEditBatchSummaryTotals {
            total_count: counts.total_count,
            per_page: counts.per_page.into_iter().collect(),
        }
    }

    fn validate_manual_edits_event(&self, msg: &Value) -> Option<String> {
        validate_event(Some(msg))
    }

    fn read_transaction(&self) -> Option<Value> {
        self.controller.read_transaction()
    }

    fn rollback_transaction(&self, page_url: Option<&str>, reason: &str) -> Option<Value> {
        self.controller.rollback_transaction(page_url, reason)
    }

    fn write_transaction(&self, page_url: Option<&str>, batch: &Value) -> Value {
        self.controller
            .write_transaction(page_url, batch)
            .unwrap_or_else(
                |e| json!({ "error": "transaction_write_failed", "message": e.to_string() }),
            )
    }

    fn clear_transaction(&self, transaction_id: &str) {
        self.controller.clear_transaction(Some(transaction_id));
    }

    fn cancel_pending_events(&self, page_url: Option<&str>) -> Vec<Value> {
        let canceled = self
            .controller
            .cancel_pending_events(page_url, "manual_edit_commit");
        for event in &canceled {
            if let Some(id) = event.get("id").and_then(Value::as_str) {
                self.queue.acknowledge_pending_event(id);
            }
        }
        canceled
    }

    fn build_manual_edit_evidence(&self, page_url: Option<&str>) -> Value {
        build_manual_edit_evidence(
            &self.project_root,
            &self.project_root.join(".impeccable").join("live"),
            page_url,
        )
    }

    fn commit_manual_edits(&self, args: CommitManualEditsArgs) -> Result<Value, String> {
        let mode = args.provider.as_deref().unwrap_or("");
        if matches!(mode, "codex" | "claude") {
            return Err(format!(
                "unavailable: {mode} manual-edit provider is not supported by the live server"
            ));
        }
        if !args.use_chat_route || !self.queue.agent_polling_connected() {
            return Err("unavailable: authenticated agent polling is not connected".to_string());
        }

        let env: std::collections::HashMap<String, String> = std::env::vars().collect();
        let timeout_ms = u64::try_from(args.timeout_ms)
            .ok()
            .filter(|value| *value > 0);
        let callback = |batch: &Value, page_url: Option<&str>, repair: Option<&Value>| {
            self.controller
                .push_batch_in_chunks_and_wait(batch, page_url, repair)
        };
        let native_chat_apply: &NativeChatApply<'_> = &callback;
        let result = commit_manual_edits_with_chat_apply(
            CommitOptions {
                cwd: self.project_root.clone(),
                page_url: args.page_url,
                provider: Some("chat".to_string()),
                env: &env,
                timeout_ms,
                repair_only: args.repair_only,
                transaction_id: args.transaction_id,
                batch: args.batch,
            },
            &SystemProcessRunner,
            Some(native_chat_apply),
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn manual_edit_callbacks_publish_flattened_sse_in_call_order() {
        let root = std::env::temp_dir().join(format!(
            "legion-manual-edit-activity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let queue = QueueState::new();
        let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &queue });
        let deps = LiveServerManualEditDeps {
            token: "tok".to_string(),
            project_root: root,
            queue: &queue,
            controller: &controller,
        };
        let cursor = queue.sse_cursor();

        QueueCallbacks { queue: &queue }.record_manual_edit_activity(
            "manual_edit_apply_dispatched",
            json!({ "type": "overridden", "id": "apply-1", "pageUrl": "/page" }),
        );
        deps.record_manual_edit_activity(
            "manual_edit_commit_done",
            json!({ "type": "overridden", "appliedCount": 1 }),
        );

        let events = queue.sse_messages_after(cursor);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].1["type"], "manual_edit_apply_dispatched");
        assert_eq!(events[0].1["id"], "apply-1");
        assert_eq!(events[0].1["pageUrl"], "/page");
        assert!(events[0].1.get("data").is_none());
        assert_eq!(events[1].1["type"], "manual_edit_commit_done");
        assert_eq!(events[1].1["appliedCount"], 1);
        assert!(events[1].1.get("data").is_none());
    }

    #[test]
    fn cancel_pending_manual_apply_removes_external_queue_event() {
        let root = std::env::temp_dir().join(format!(
            "legion-manual-edit-cancel-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let queue = QueueState::new();
        let controller = ManualApplyController::new(root.clone(), QueueCallbacks { queue: &queue });
        let deps = LiveServerManualEditDeps {
            token: "tok".to_string(),
            project_root: root.clone(),
            queue: &queue,
            controller: &controller,
        };
        let batch = json!({
            "entries": [{
                "id": "entry-cancel",
                "pageUrl": "http://localhost/page",
                "ops": [{ "file": "src/page.html", "type": "replace", "selector": "#hero", "value": "Updated" }]
            }]
        });
        thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                controller.push_apply_event_and_wait(
                    &batch,
                    Some("http://localhost/page"),
                    None,
                    None,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while queue.len() == 0 {
                assert!(Instant::now() < deadline, "manual apply event not queued");
                thread::sleep(Duration::from_millis(1));
            }
            let canceled = deps.cancel_pending_events(None);
            assert_eq!(canceled.len(), 1);
            assert_eq!(queue.len(), 0);
            assert_eq!(waiter.join().unwrap().unwrap_err(), "manual_edit_commit");
        });
        let _ = std::fs::remove_dir_all(&root);
    }
}
