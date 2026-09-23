//! Chunk wf070 (area `src/lib/verification`, target crate `legion-policy`).
//!
//! Rust port of:
//!   - `src/lib/verification/arcane/architecture-event-store.mjs`  -> [`event_store`]
//!   - `src/lib/verification/arcane/architecture-fingerprints.mjs` -> [`fingerprints`]
//!   - `src/lib/verification/arcane/architecture-router.mjs`       -> [`router`]
//!   - `src/lib/verification/arcane/architecture-state.mjs`        -> [`state`]
//!   - `src/lib/verification/arcane/assurance-packet.mjs`          -> [`assurance_packet`]
//!
//! This module is additive only: the JS files remain source of truth until
//! CI parity is proven and a later packet deletes them.
//!
//! `canon` is a local, self-contained port of the *rules* in
//! `src/lib/contracts/arcane/canonical.mjs` and `.../ids.mjs` (canonical
//! JSON, sha256 digests, HMAC-SHA256 signing, format-faithful id minting).
//! It duplicates logic that belongs in a shared `arcane_port` module once
//! one exists there — this owner may create files only under
//! `wf_port/wf070/**`, and `legion-policy`'s `Cargo.toml` and
//! `arcane_port/mod.rs` are both outside that scope. See the wf070 report
//! for the consolidation this should collapse into.
//!
//! NOTE for the integration owner: wire `pub mod wf070;` into
//! `wf_port/mod.rs` (alongside the existing `pub mod wf002;`).

pub mod assurance_packet;
pub mod canon;
pub mod event_store;
pub mod fingerprints;
pub mod router;
pub mod state;
