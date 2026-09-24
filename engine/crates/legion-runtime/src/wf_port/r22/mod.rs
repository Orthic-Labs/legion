//! Chunk r22: Rust port of the pure/testable logic in
//! `skills/designer/engine/scripts/live-insert.mjs` and
//! `skills/designer/engine/scripts/live-poll.mjs`.
//!
//! Both source files are thin CLI wrappers around a much larger dependency
//! graph that is *not* part of this packet's owned files and is mostly
//! unported (`full-Q1.md`, `full-P8-designer.md`):
//! - `live-insert.mjs` imports element-finding/CSS-authoring helpers from
//!   `./live-wrap.mjs` (`buildSearchQueries`, `findElement`,
//!   `findAllElements`, `filterByText`, `findFileWithQuery`,
//!   `detectCommentSyntax`, `detectStyleMode`, `buildCssAuthoring`,
//!   `buildCssSelectorPrefixExamples`) and Svelte-component scaffolding from
//!   `./live/svelte-component.mjs` — neither file is in this packet and
//!   neither is ported elsewhere yet.
//! - `live-poll.mjs` talks HTTP to a local `live-server.mjs` process (itself
//!   `NOT-STARTED` per `full-Q1.md`: "1135-line local dev HTTP server + CDP
//!   orchestrator"), shells out to `live-accept.mjs` (also unported) via
//!   `execFileSync`, and resolves server info through
//!   `lib/impeccable-paths.mjs::readLiveServerInfo` (only partially ported
//!   in chunk `q_q1`, and only for the pure path-derivation half).
//!
//! Porting the two files' CLI entry points (`insertCli`, `pollCli`) faithfully
//! would require re-implementing or depending on all of the above, which are
//! out of scope for this packet. What *is* self-contained — pure functions
//! with no filesystem, network, or child-process I/O — is ported in full
//! below, one submodule per source file, mirroring the source's exports and
//! behavior exactly. The CLI/network/process orchestration is left
//! NOT-PORTED; see `finish-r22.md` for the itemized gap list.

pub mod live_insert;
pub mod live_poll;
