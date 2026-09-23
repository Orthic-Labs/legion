//! wf049: port of `src/providers/runtime/web/{infrastructure,integration,journey-plan,matrix,operations}/index.mjs`.
//!
//! Owned by chunk wf049. See the chunk report
//! (`scratchpad/loss/wf/wf049.md` in the originating session) for the
//! `Cargo.toml` dependency patch needed before [`infrastructure`] and
//! [`operations`] can perform real Ed25519 signature verification.

pub mod infrastructure;
pub mod integration;
pub mod journey_plan;
pub mod matrix;
pub mod operations;
mod shared;
