//! Port of `skills/designer/engine/scripts/live-commit-manual-edits.mjs`
//! (packet r18).
//!
//! `wf_port::w2_017::commit_edits` already ports the fully pure helpers from
//! this file (`argVal`, `countOps`, `summarizeAppliedEntries`,
//! `normalizeFailedEntries`, `mergeFailedEntries`, `candidatesForEntry`,
//! `uniqueStrings`, `allEntryIds`, `mergeUniqueStrings`,
//! `repairAttemptLimit`, `escapeRegExp`, `normalizeVerificationText`,
//! `lineShowsAppliedOp`, `opHasLocator`, `lineMatchesManualEditLocator`,
//! `lineHasObjectKey`, `windowShowsAppliedOp`, `verificationTargetPassesLines`,
//! `summarizeRepairFailures`, `buildRepairBatch`). This module ports the next
//! layer: the source-verification pipeline that decides whether a staged
//! copy edit actually landed in the file it claims to (`normalizeRelativeFile`
//! through `verifyEntriesAfterRepair`), with real file I/O pushed behind the
//! [`SourceStore`] trait so the logic is testable with fakes.
//!
//! Not ported (documented frontier, same shape as the sibling
//! `wf_port::w2_021::manual_edit_routes` gap note):
//! - `snapshotRollbackFiles` / `collectRollbackFiles` / `scanRollbackDir` /
//!   `changedFilesSinceSnapshot` / `rollbackChangedFiles` /
//!   `collectApplyOwnedFiles` / `unreportedChangedFiles`: these walk the real
//!   project directory tree (`fs.readdirSync`, `fs.realpathSync`) rather than
//!   reading named files, which is a different I/O shape than `SourceStore`
//!   and not exercised by this chunk's tests.
//! - `clearAppliedEntries`: delegates to `live/manual-edits-buffer.mjs`
//!   (`readBuffer`/`writeBuffer`), already ported at
//!   `wf_port::w2_021::manual_edits_buffer`.
//! - `repairPostApplyValidation` and `main`: orchestrate the CLI entry point,
//!   which calls `runCopyEditBatchAgent` / `runCopyEditPostApplyChecks` from
//!   `live-copy-edit-agent.mjs` — a call out to an external AI runner
//!   process. There is no meaningful Rust port of "invoke an external AI
//!   agent and stream its stdout"; this stays the documented frontier.

pub mod verify;

pub use verify::{
    coupled_object_key_failures_for_op_ref, locator_targets_in_file, normalize_project_source_path,
    object_key_candidates_for_op, object_key_match_still_uses_original,
    sibling_candidates_for_entry, source_hint_window_failure, verification_failures_for_entries,
    verification_targets_for_op, verify_applied_entry, verify_entries_after_repair,
    InMemorySourceStore, SourceStore,
};
