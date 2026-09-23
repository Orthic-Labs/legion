//! Port of the `skills/designer/engine/scripts/live-*.mjs` CLI helpers
//! (chunk w2_018).
//!
//! Ported from:
//! - `live-copy-edit-agent.mjs` -> [`copy_edit_agent`]
//! - `live-discard-manual-edits.mjs` -> [`discard`]
//! - `live-inject.mjs` -> [`inject`]
//! - `live-insert.mjs` -> [`insert`]
//! - `live-manual-edit-evidence.mjs` -> [`evidence`]
//!
//! Shared dependency `skills/designer/engine/scripts/live/manual-edits-buffer.mjs`
//! is ported here as [`buffer`] since it has no existing Rust port in this
//! tree and both `live-discard-manual-edits.mjs` and
//! `live-manual-edit-evidence.mjs` depend on it.
//!
//! See `w2_018.md` in this crate's port report for scope gaps: `live-insert.mjs`
//! and `live-inject.mjs`'s CLI drivers additionally depend on
//! `live-wrap.mjs`, `live/svelte-component.mjs`, and `live/sveltekit-adapter.mjs`,
//! none of which have an existing Rust port and none of which are in this
//! chunk's owned scope; only the self-contained pure logic of those two
//! scripts is ported here.

pub mod buffer;
pub mod copy_edit_agent;
pub mod discard;
pub mod evidence;
pub mod inject;
pub mod insert;
