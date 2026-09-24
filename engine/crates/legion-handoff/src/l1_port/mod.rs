//! L1 literal port of `src/lib/handoff/transcript_handoff.py`.
//!
//! Ports only the pointer-construction half of the Python module: locating a
//! host transcript, computing the immutable prefix pointer (byte cutoff +
//! sha256), and formatting the cold-start paste prompt. The Python module's
//! `request_continuity` shells out to an external `membrane` binary; that
//! transport hop is out of scope for a pure-Rust literal port and is not
//! reproduced here (see the L1 packet report for disposition).

pub mod cli;
pub mod pointer;

pub use cli::{run, ContinuityRunner, RealContinuityRunner, RunEnv};
pub use pointer::{
    build_pointer, candidates, normalized_path, paste_prompt, read_header, resolve_source,
    Platform, SourcePointer,
};
