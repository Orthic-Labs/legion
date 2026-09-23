//! wf075: faithful Rust ports of
//! `src/lib/verification/arcane/s11-bindings/m7-production.mjs`,
//! `src/lib/verification/arcane/scoped-acceptance.mjs`, and
//! `src/lib/verification/arcane/seal-reachability.mjs`.
//!
//! This owner may write only under `wf_port/wf075/**` and
//! `tests/wf_wf075.rs`. Cross-module wiring (`pub mod wf_port;` in
//! `legion-policy`'s `src/lib.rs`, `pub mod wf075;` here, and — since
//! `m7_production` depends on wf070's `ArchitectureEventStore`/state
//! primitives — `pub mod wf070;` alongside it) is the integration owner's
//! job; see the wf075 report for the exact patch.

pub mod m7_production;
pub mod scoped_acceptance;
pub mod seal_reachability;
