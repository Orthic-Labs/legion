//! wf_port chunk w2_021 (area `skills/designer/engine/scripts`, target crate
//! `legion-runtime`).
//!
//! Source files assigned to this chunk:
//!   - `skills/designer/engine/scripts/live/insert-ui.mjs`            -> [`insert_ui`]
//!   - `skills/designer/engine/scripts/live/manual-apply.mjs`         -> [`manual_apply`]
//!   - `skills/designer/engine/scripts/live/manual-edit-routes.mjs`   -> [`manual_edit_routes`]
//!   - `skills/designer/engine/scripts/live/manual-edits-buffer.mjs`  -> [`manual_edits_buffer`]
//!   - `skills/designer/engine/scripts/live/session-store.mjs`        -> [`session_store`]
//!
//! `git grep` across `engine/` for `createLiveSessionStore`, `stageEntry`,
//! `createManualEditRoutes`, `createManualApplyController`,
//! `detectInsertAxisFromStyle` came back empty: no prior native coverage
//! exists, so every module below is a fresh port rather than a verification
//! of existing Rust.
//!
//! Each module ports the pure, self-contained logic of its source file
//! faithfully (same field names, same error strings, same precedence order).
//! Code that depends on files outside this chunk's ownership, or on a live
//! Node HTTP server / event-loop / real DOM, is documented as frontier and
//! NOT reimplemented here:
//!
//!   - `insert_ui`: fully ported, including `findInsertAnchorInDom` (behind
//!     a `DomQuery` trait so it stays testable without a live `Document`;
//!     see packet r28).
//!   - `manual_apply`: the module's `createManualApplyController` is a
//!     stateful controller wired to the live server's pending-event queue,
//!     deferred-promise map, and `recordManualEditActivity`/`enqueueEvent`
//!     callbacks supplied by `live.mjs` (outside this chunk). Only its pure
//!     helper functions (chunk splitting/merging, compaction, summarizing)
//!     are ported; the queue-driving orchestration is frontier.
//!   - `manual_edit_routes`: fully ported (packet r30), including
//!     `createManualEditRoutes`'s full route dispatch for all five routes
//!     (`handle_manual_edit_route`). Its own injected dependencies
//!     (`getToken`, `manualApply`, `recordManualEditActivity`,
//!     `getManualEditStatus`, `chatAgentLikelyActive`) and its two
//!     out-of-chunk direct imports (`buildManualEditEvidence` from
//!     `../live-manual-edit-evidence.mjs`, `commitManualEdits` from
//!     `../live-commit-manual-edits.mjs`) are all `ManualEditRoutesDeps`
//!     trait methods, so the dispatch is tested with fakes and never opens a
//!     real HTTP socket, subprocess, or browser.
//!   - `session_store`/`manual_edits_buffer`: `resolveProjectRoot`'s
//!     project-root-walk (in `../context.mjs`, outside this chunk) is not
//!     reimplemented; callers pass the resolved project root directly as
//!     `cwd`, matching every call site in this chunk's own files.

pub mod insert_ui;
pub mod manual_apply;
pub mod manual_edit_routes;
pub mod manual_edits_buffer;
pub mod session_store;
