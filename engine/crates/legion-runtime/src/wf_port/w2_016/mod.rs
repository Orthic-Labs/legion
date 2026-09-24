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
//! - `live_accept`: port of `live-accept.mjs`, including the CLI argv
//!   entrypoint (`run`), the marker-wrapper accept/discard core (HTML/JSX/
//!   Vue/Astro path), on-disk manual-edits-buffer delegation, and dispatch
//!   into `svelte_component` for the Svelte-component accept path.
//! - `svelte_component`: port of `live/svelte-component.mjs`'s
//!   accept-time surface (`findSvelteComponentManifest`,
//!   `inlineSvelteComponentAccept`, `removeSvelteComponentSession`,
//!   `applyDeferredSvelteComponentAccepts`), used by `live_accept`'s CLI
//!   path. Scaffold-time functions are out of scope (owned by the
//!   live-wrap chunk).
//!
//! `lib/is-generated.mjs` and `lib/target-args.mjs` are already natively
//! ported and verified at `crate::p8_designer::{is_generated, target_args}`;
//! this chunk does not re-port them.

pub mod impeccable_config;
pub mod impeccable_paths;
pub mod live_accept;
pub mod svelte_component;
