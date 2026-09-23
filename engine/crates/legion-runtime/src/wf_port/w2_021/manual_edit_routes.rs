//! Port of `skills/designer/engine/scripts/live/manual-edit-routes.mjs`.
//!
//! `createManualEditRoutes` wires Node's raw HTTP `req`/`res` and calls into
//! `manual-apply.mjs`'s controller plus `../live-manual-edit-evidence.mjs`
//! and `../live-commit-manual-edits.mjs` (both outside this chunk's owned
//! files). That route-dispatch/HTTP plumbing is frontier and not ported.
//! Only the pure `summarizePendingManualEditBatch` helper is ported.

use std::path::Path;

use super::manual_edits_buffer::read_buffer;

#[derive(Debug, Clone, PartialEq)]
pub struct PendingManualEditBatchSummary {
    pub pending_entry_count: usize,
    pub pending_op_count: usize,
}

/// Port of `summarizePendingManualEditBatch(cwd, pageUrl = null)`. The JS
/// version wraps the read in try/catch and returns
/// `{ pendingSummaryError }` on failure; `read_buffer` here never errors
/// (unreadable/invalid buffers degrade to empty, matching `readBuffer`, not
/// `readBufferStrict`), so this always succeeds.
pub fn summarize_pending_manual_edit_batch(
    cwd: &Path,
    page_url: Option<&str>,
) -> PendingManualEditBatchSummary {
    let buffer = read_buffer(cwd);
    let entries: Vec<_> = buffer
        .entries
        .into_iter()
        .filter(|entry| match page_url {
            Some(p) => entry.page_url.as_deref() == Some(p),
            None => true,
        })
        .collect();
    let pending_op_count = entries.iter().map(|e| e.ops.len()).sum();
    PendingManualEditBatchSummary {
        pending_entry_count: entries.len(),
        pending_op_count,
    }
}
