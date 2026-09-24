//! Port of chunk `w2_019` (area `skills/designer/engine/scripts`, files
//! `live-poll.mjs`, `live-resume.mjs`, `live-server.mjs`, `live-status.mjs`,
//! `live-target.mjs`).
//!
//! All five source files are CLI/HTTP-server entry points for the "live
//! variant mode" agent protocol: they read `process.argv`, talk to a
//! long-running Node `http` server over `fetch`/SSE, spawn sibling scripts
//! with `execFileSync`, and read/write project files. None of that process,
//! network, or child-process orchestration has a return-value contract to
//! port without a live HTTP server and an OS process boundary, so per this
//! chunk's scope only the pure, deterministic decision/formatting/state
//! logic in each file is ported here, mirrored 1:1 in
//! [`crate::wf_port::w2_019`]'s submodules:
//!
//! - [`live_poll`]: `live-poll.mjs`'s `--reply` argv parsing and
//!   validation, the poll-reply JSON payload shape, the "does this event
//!   type need an agent `--reply`" set, the manual-apply banner text, the
//!   `live-accept.mjs` argv builder for `accept`/`discard` events, and the
//!   "is this event id still pending" predicate. The actual `fetch`
//!   long-poll loop, `execFileSync` accept-script dispatch, and stdout
//!   streaming are not ported.
//! - [`live_resume`]: `live-resume.mjs`'s manual-apply resume-hint text
//!   builder, its event-summarization helper, and its `--id` argv parser.
//! - [`resume`] (packet r23): the rest of `live-resume.mjs`'s `resumeCli()`
//!   — loading the durable session-store journal via
//!   `crate::wf_port::w2_021::session_store::LiveSessionStore` (now ported
//!   in chunk w2_021), deriving `nextAction` from the resulting snapshot's
//!   phase/pending event, and the `run`/`--help` CLI entry point. Closes
//!   the gap [`live_resume`] left open.
//! - [`live_status`]: `live-status.mjs` in full — the "find the pending
//!   `manual_edit_apply` event" selection logic, the `statusCli` payload
//!   assembly (`liveServer` field subset, `activeSessions` fallback, the
//!   three-way `recoveryHint` branch reusing `live_resume`'s hint text),
//!   and the CLI entrypoint itself via `live_status::run`, which takes a
//!   `StatusEnv` trait object so the `fetch`/server-info-file/session-store
//!   reads stay behind a fake-able seam instead of live I/O.
//! - [`live_target`]: `live-target.mjs` in full — `resolveLiveTarget`'s
//!   absolute-path/`targetOptions` derivation, plus the CLI entrypoint via
//!   `live_target::run`, which wires in the argv parse
//!   (`crate::p8_designer::target_args::parse_target_path`) and
//!   project-root discovery (`crate::wf_port::w2_010::context::resolve_project_root`)
//!   already ported elsewhere in this crate, closing the gap this file
//!   previously left open.
//! - [`live_server`]: `live-server.mjs`'s in-memory pending-event queue —
//!   enqueue/lease/acknowledge/cancel-anonymous-exit, the lease-expiry
//!   "next wakeup" computation, and the "is an agent poll currently
//!   connected" predicate. The HTTP request handler, SSE broadcast, port
//!   probing, and file-backed manual-edit/session-store integrations are
//!   not ported.

pub mod live_poll;
pub mod live_resume;
pub mod live_server;
pub mod live_status;
pub mod live_target;
pub mod resume;
