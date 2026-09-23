//! wf067 — Rust port of `src/lib/contracts/arcane/{authority-binding-store,
//! authority-invocation-proof,authority,canonical,ids}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it. See the wf067 report at
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/wf/wf067.md`
//! for per-file status and the dependency patch this module would like once
//! wired in.
//!
//! NOTE for the integration owner: not yet wired into the crate root. Add
//! `pub mod wf_port;` to `engine/crates/legion-policy/src/lib.rs` (if not
//! already present from another wf packet) and `pub mod wf067;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` before running
//! `cargo test` against it.

pub mod authority;
pub mod binding_store;
pub mod canonical;
pub mod errors;
pub mod ids;
pub mod invocation_proof;
pub mod json_parse;
