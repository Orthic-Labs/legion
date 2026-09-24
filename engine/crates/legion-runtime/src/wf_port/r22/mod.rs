//! Chunk r22: Rust port of `skills/designer/engine/scripts/live-insert.mjs`
//! and `skills/designer/engine/scripts/live-poll.mjs`, including their CLI
//! entry points (`insertCli` -> `live_insert::run`, `pollCli` ->
//! `live_poll::run`).
//!
//! The original packet left both entry points NOT-PORTED because their
//! dependencies (`./live-wrap.mjs`, `./live/svelte-component.mjs`,
//! `live-server.mjs`, `live-accept.mjs`, `lib/impeccable-paths.mjs`) were
//! outside the packet and unported. All of those now exist elsewhere in
//! this crate (`w2_020::wrap`, `w2_022::svelte_component`, `r24`,
//! `w2_016::live_accept`, `q_q1::paths`/`r24::server_info`), so this
//! follow-up pass (packet r22r24) wires the entry points against them:
//! - `live_insert::run` mirrors `insertCli()` exactly, including
//!   `resolveElementMatch`.
//! - `live_poll::run` mirrors `pollCli()`; the HTTP calls to the local
//!   `live-server.mjs` use `reqwest::blocking`, and the JS
//!   `execFileSync('node', ['live-accept.mjs', ...])` step calls
//!   `w2_016::live_accept::run` in-process instead of shelling out to a
//!   Node subprocess, since that script is itself now a Rust module in this
//!   same crate rather than an external file to invoke.

pub mod live_insert;
pub mod live_poll;
