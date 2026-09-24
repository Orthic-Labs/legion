//! Wires `w2_021::manual_edit_routes::handle_manual_edit_route` into this
//! packet's live HTTP server, closing the "manual-edit routes depend on
//! unported live/manual-edit-routes.mjs and live/manual-apply.mjs" gap
//! named in `finish-r24.md` — both are now ported (`w2_021::manual_edit_routes`,
//! `w2_021::manual_apply::ManualApplyController`), so this module is the
//! `ManualEditRoutesDeps` + `ManualApplyCallbacks` glue between them and
//! this server's `QueueState`/token/project root.
//!
//! Two pieces remain genuinely out of reach: `buildManualEditEvidence`
//! (`../live-manual-edit-evidence.mjs`) and `commitManualEdits`
//! (`../live-commit-manual-edits.mjs`) are both outside every packet ported
//! so far (they shell an LLM copy-edit agent) — `build_manual_edit_evidence`
//! and `commit_manual_edits` below return an explicit `not_implemented`
//! error naming the missing file, exactly like this server's other 501
//! routes, rather than fabricating a result.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::queue::QueueState;
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

    fn record_manual_edit_activity(&self, _kind: &str, _data: Value) {
        // `recordManualEditActivity` in JS appends to an in-memory activity
        // log surfaced only by the unported `/status` route's fuller
        // fields; dropped here rather than fabricated (see queue.rs's
        // `status_summary` doc comment for the same boundary).
    }
}

pub struct LiveServerManualEditDeps<'a> {
    pub token: String,
    pub project_root: PathBuf,
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
        std::env::var("IMPECCABLE_LIVE_COPY_AGENT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    }

    fn copy_agent_timeout_ms(&self) -> i64 {
        std::env::var("IMPECCABLE_LIVE_COPY_AGENT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn chat_agent_likely_active(&self) -> bool {
        // `chatAgentLikelyActive` in JS inspects live session-store state
        // (`live/session-store.mjs`) that isn't ported (same gap as the
        // `/annotation` route); false is the same "no chat agent" default
        // the JS falls back to when no session is recorded.
        false
    }

    fn record_manual_edit_activity(&self, _event: &str, _payload: Value) {}

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
            .unwrap_or_else(|e| json!({ "error": "transaction_write_failed", "message": e.to_string() }))
    }

    fn clear_transaction(&self, transaction_id: &str) {
        self.controller.clear_transaction(Some(transaction_id));
    }

    fn cancel_pending_events(&self, page_url: Option<&str>) -> Vec<Value> {
        self.controller.cancel_pending_events(page_url, "manual_edit_commit")
    }

    fn build_manual_edit_evidence(&self, _page_url: Option<&str>) -> Value {
        json!({
            "error": "not_implemented",
            "message": "buildManualEditEvidence depends on unported ../live-manual-edit-evidence.mjs",
        })
    }

    fn commit_manual_edits(&self, _args: CommitManualEditsArgs) -> Result<Value, String> {
        Err("commitManualEdits depends on unported ../live-commit-manual-edits.mjs".to_string())
    }
}
