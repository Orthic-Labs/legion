//! Chunk w2_016: `skills/designer/engine/scripts/lib/*` config/paths helpers
//! and `skills/designer/engine/scripts/live-accept.mjs`.
//!
//! - `impeccable_config`: port of `lib/impeccable-config.mjs` (unified
//!   `.impeccable/config.json` reader/writer, detector ignore-rule
//!   filtering, hook consent, git-exclude marker maintenance).
//! - `impeccable_paths`: port of `lib/impeccable-paths.mjs` (path layout for
//!   `.impeccable/`, live server info, sessions/annotations dirs). Takes an
//!   already-resolved project root instead of calling `resolveProjectRoot`
//!   itself — see the module doc for why.
//! - `live_accept`: port of `live-accept.mjs`'s marker-wrapper accept/
//!   discard core (HTML/JSX/Vue/Astro path). The Svelte-component accept
//!   path and the on-disk manual-edits buffer I/O are out of this chunk's
//!   owned files and are not ported — see the module doc for the exact gap.
//!
//! `lib/is-generated.mjs` and `lib/target-args.mjs` are already natively
//! ported and verified at `crate::p8_designer::{is_generated, target_args}`;
//! this chunk does not re-port them.

pub mod impeccable_config;
pub mod impeccable_paths;
pub mod live_accept;
