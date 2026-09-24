//! L1 literal port of `src/lib/handoff/transcript_handoff.py`.
//!
//! Ports only the pointer-construction half of the Python module: locating a
//! host transcript, computing the immutable prefix pointer (byte cutoff +
//! sha256), and formatting the cold-start paste prompt. The Python module's
//! `request_continuity` shelled out to an external `membrane` binary; Membrane
//! is gone from Legion (Blueprint/Membrane now live only in CodeRight), so
//! that transport lane is intentionally not ported — only the bootstrap
//! pointer/paste-prompt path is (see `cli.rs`'s module doc comment).

pub mod cli;
pub mod pointer;

pub use cli::{run, RunEnv};
pub use pointer::{
    build_pointer, candidates, normalized_path, paste_prompt, read_header, resolve_source,
    Platform, SourcePointer,
};
