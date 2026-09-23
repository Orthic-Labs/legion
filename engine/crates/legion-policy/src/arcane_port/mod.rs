//! Rust port of the legacy `src/lib/contracts/arcane/**`,
//! `src/lib/cognitive/arcane/**`, `src/lib/verification/arcane/**`, and
//! `src/lib/guard/**` JS sources (packet P1-arcane).
//!
//! This module is additive only: JS remains the source of truth until CI
//! parity is proven and a later packet deletes it. See
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/full-P1.md`
//! for the per-file port ledger and remaining work.
//!
//! NOTE for the integration owner: this module is not yet wired into the
//! crate root. Add `pub mod arcane_port;` to `engine/crates/legion-policy/src/lib.rs`
//! (see the report's "shared-file patches" section) before running
//! `cargo test` against it.

pub mod errors;
