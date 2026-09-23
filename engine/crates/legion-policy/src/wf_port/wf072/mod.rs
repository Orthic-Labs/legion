//! wf072 — Rust port of `src/lib/verification/arcane/{evidence-envelope,
//! evidence-migration,evidence-registry,gate-validity,ingest}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it. See the wf072 report at
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/wf/wf072.md`
//! for per-file status, scope gaps, and the dependency patch this module
//! would like once wired in.
//!
//! NOTE for the integration owner: not yet wired into the crate root. Add
//! `pub mod wf_port;` to `engine/crates/legion-policy/src/lib.rs` (if not
//! already present from another wf packet) and `pub mod wf072;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` before running
//! `cargo test` against it.

pub mod evidence_envelope;
pub mod evidence_migration;
pub mod evidence_registry;
pub mod gate_validity;
pub mod ingest;
pub mod support;
