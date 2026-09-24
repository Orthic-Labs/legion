//! wf006 — Rust port of `src/lib/guard/compat/audit/{receipt-auth,
//! receipt-store}.mjs` and `src/lib/guard/compat/effects/{capability-store,
//! preeffect-correlation,preeffect-gate}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it. See the wf006 report at
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/wf/wf006.md`
//! for per-file status and the dependency patch this module would like once
//! wired in (to replace the local `canonical` module with
//! `legion-contracts::canonical` + `sha2`/`hmac`). `preeffect_gate` now
//! covers the full `PreEffectGate` class (packet r48), not just the
//! utilities.
//!
//! NOTE for the integration owner: not yet wired into the crate root. Add
//! `pub mod wf_port;` to `engine/crates/legion-policy/src/lib.rs` and
//! `pub mod wf006;` to `engine/crates/legion-policy/src/wf_port/mod.rs`
//! before running `cargo test` against it.

pub mod canonical;
pub mod capability_store;
pub mod errors;
pub mod preeffect_correlation;
pub mod preeffect_gate;
pub mod receipt_auth;
pub mod receipt_store;
