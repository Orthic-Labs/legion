//! Chunk wf002 (area `src/lib/cognitive`, target crate `legion-policy`).
//!
//! Rust port of:
//!   - `src/lib/cognitive/arcane/host/policy-inject.mjs`  -> [`policy_inject`]
//!   - `src/lib/cognitive/arcane/minimize.mjs`             -> [`minimize`]
//!   - `src/lib/cognitive/arcane/route-envelope.mjs`       -> [`route_envelope`]
//!
//! `src/lib/cognitive/arcane/stop-shape.mjs` and
//! `src/lib/cognitive/arcane/user-intent.mjs` are NOT ported here — see the
//! wf002 report for why (heavy multi-pattern regex; `legion-policy` has no
//! `regex` crate dependency and this owner may not edit `Cargo.toml`).
//!
//! This module is additive only: the JS files remain source of truth until
//! CI parity is proven and a later packet deletes them.

mod json;

pub mod minimize;
pub mod policy_inject;
pub mod route_envelope;
