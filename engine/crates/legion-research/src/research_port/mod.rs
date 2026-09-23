//! Faithful Rust port of `src/lib/research-core/*.py` (packet P2-research).
//!
//! Owned entirely by this packet. See
//! `/private/tmp/.../scratchpad/loss/full-P2-research.md` for the per-file
//! port status table.

pub mod common;
pub mod effects;
pub mod failure_taxonomy;
pub mod query;
pub mod stopping;

pub use common::{append_jsonl, atomic_write_json, atomic_write_text, sha256_text, today, utc_now};
pub use effects::{is_external, is_worker};
pub use failure_taxonomy::classify;
pub use query::persist as query_persist;
pub use stopping::{decide, StoppingDecision, StoppingInput};
