//! wf_port chunk w2_010 (area `skills/designer/engine/scripts`, target crate
//! `legion-runtime`).
//!
//! Source files assigned to this chunk:
//!   - `skills/designer/engine/scripts/context-signals.mjs` -> [`context_signals`]
//!   - `skills/designer/engine/scripts/context.mjs`          -> [`context`]
//!   - `skills/designer/engine/scripts/critique-storage.mjs` -> [`critique_storage`]
//!   - `skills/designer/engine/scripts/detect-csp.mjs`       -> [`detect_csp`]
//!   - `skills/designer/engine/scripts/detect.mjs`           -> DROP, see below
//!
//! No prior native coverage was found for any of these five files (`git grep`
//! across `engine/` for their exported function/command names came back
//! empty), so all four ported modules are fresh ports rather than
//! verification of existing Rust.
//!
//! `detect.mjs` is intentionally NOT ported: it is a 21-line CLI shim that
//! resolves a path to a bundled `detect-antipatterns.mjs` (candidate paths:
//! `./detector/detect-antipatterns.mjs` or
//! `../../cli/engine/detect-antipatterns.mjs`) and calls its exported
//! `detectCli()`. There is no algorithm in this file to port — it contains
//! only `fs.existsSync` path resolution and a dynamic `import()` + call. The
//! actual detector it delegates to (`detect-antipatterns.mjs`) is a
//! different file, out of this chunk's scope, and is not touched here. See
//! `w2_010.md` for the full gap note.
//!
//! Each ported module documents, in its own header, exactly what was
//! carried over and what was deliberately left as a CLI-only or
//! network-only concern (frontier boundaries: argv/stdout plumbing and the
//! `context.mjs` skill self-update network poll).

pub mod context;
pub mod context_signals;
pub mod critique_storage;
pub mod detect_csp;
