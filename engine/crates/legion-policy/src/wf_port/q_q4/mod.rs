//! Chunk q_q4 (packet Q4) — Rust port of
//! `src/lib/verification/arcane/completion-evidence.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it.
//!
//! See [`completion_evidence`] for the ported function and its documented
//! gap (the surrounding registry/authority/receipt-store types are taken
//! as injected trait objects rather than hard-wired to
//! `evidence-registry.mjs` / `receipt-auth.mjs` Rust ports, neither of
//! which exists in this workspace yet).

pub mod completion_evidence;
