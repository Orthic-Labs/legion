//! Port of the Impeccable "Live Mode" Svelte scripts (chunk w2_022):
//! `skills/designer/engine/scripts/live/{svelte-component,sveltekit-adapter,
//! ui-core,vocabulary}.mjs`, plus the vendored
//! `skills/designer/engine/scripts/modern-screenshot.umd.js`.
//!
//! Each submodule documents exactly what was ported and what was left for
//! a follow-up (filesystem/session orchestration with no current Rust
//! caller); `modern-screenshot.umd.js` is a vendored third-party
//! DOM-to-canvas screenshot library (Canvas/Worker/DOM APIs only) with no
//! server-side Rust equivalent and is not ported here.

pub mod svelte_component;
pub mod sveltekit_adapter;
pub mod ui_core;
pub mod vocabulary;
