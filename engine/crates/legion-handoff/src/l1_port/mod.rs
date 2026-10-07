//! L1 literal port of `src/lib/handoff/transcript_handoff.py`.
//!
//! Pointer discovery plus native continuity normalization live together here
//! so installed Legion no longer depends on a resident Membrane executable.

pub mod cli;
pub mod continuity;
pub mod pointer;

pub use cli::{run, RunEnv};
pub use continuity::{normalize, verify_context_receipt, ContinuityContext, ContinuityInput};
pub use pointer::{
    build_pointer, candidates, normalized_path, paste_prompt, read_header, resolve_source,
    Platform, SourcePointer,
};
