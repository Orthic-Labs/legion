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
//!   Reading the durable session-store journal is not ported (owned by
//!   `live/session-store.mjs`, outside this chunk).
//! - [`live_status`]: `live-status.mjs`'s "find the pending
//!   `manual_edit_apply` event, preferring the live server's view over the
//!   durable session store's" selection logic. The `fetch`/session-store
//!   reads that produce its inputs are not ported.
//! - [`live_target`]: `live-target.mjs`'s `resolveLiveTarget` absolute-path
//!   and `targetOptions` derivation, taking an already-resolved target path
//!   and project root as input (argv parsing via `parseTargetPath` and
//!   project-root discovery via `resolveProjectRoot` are owned by other,
//!   unported chunks' files: `lib/target-args.mjs` and `context.mjs`).
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
