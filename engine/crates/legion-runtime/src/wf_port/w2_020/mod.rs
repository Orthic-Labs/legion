//! wf_port chunk w2_020 (area `skills/designer/engine/scripts`, target crate
//! `legion-runtime`).
//!
//! Source files assigned to this chunk:
//!   - `skills/designer/engine/scripts/live-wrap.mjs`                    -> [`wrap`]
//!   - `skills/designer/engine/scripts/live.mjs`                        -> [`live_cli`]
//!   - `skills/designer/engine/scripts/live/browser-script-parts.mjs`   -> [`browser_script_parts`]
//!   - `skills/designer/engine/scripts/live/completion.mjs`             -> [`completion`]
//!   - `skills/designer/engine/scripts/live/event-validation.mjs`       -> [`event_validation`]
//!
//! No prior native coverage was found (`git grep` across `engine/` for
//! `validateEvent`, `completionTypeForAcceptResult`,
//! `assembleLiveBrowserScript`, `VISUAL_ACTIONS` came back empty), so every
//! module below is a fresh port rather than a verification of existing Rust.
//!
//! Each module ports the pure (non-CLI, non-network) logic of its source
//! file faithfully — same field names, same validation error strings, same
//! precedence order. CLI plumbing (`process.argv`, `process.exit`,
//! `console.log`/`console.error`) and filesystem/process orchestration that
//! depends on sibling scripts outside this chunk's owned files (e.g.
//! `context.mjs`, `live-inject.mjs`, `live-target.mjs`, `live-server.mjs`,
//! `lib/impeccable-paths.mjs`, `lib/is-generated.mjs`,
//! `live/manual-edits-buffer.mjs`, `live/svelte-component.mjs`,
//! `live/insert-ui.mjs`, `live/vocabulary.mjs`) is documented in the module
//! header and NOT reimplemented here; the frontier is called out per
//! function.

pub mod browser_script_parts;
pub mod completion;
pub mod event_validation;
pub mod live_cli;
pub mod wrap;
pub mod wrap_cli;

pub use wrap_cli::wrap_cli;
