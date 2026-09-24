//! Packet r53 — faithful port of `src/lib/host/arcane/legacy-bridge.mjs` and
//! `src/lib/providers/sdk/index.mjs`.
//!
//! ## `legacy-bridge.mjs`
//!
//! `w2_047` (`wf_port::w2_047`) already ported four of the five files in its
//! `src/lib/host/arcane/*` scope and explicitly flagged `legacy-bridge.mjs`
//! as **NOT-STARTED**, for exactly two missing dependencies: `canonicalJson`/
//! `digestValue` (`contracts/arcane/canonical.mjs`) and `kernelStatus`
//! (`core/kernel-binding.mjs`). Both have since landed in this crate —
//! [`crate::wf_port::w2_046::canonical`] and
//! [`crate::wf_port::w2_040::kernel_binding`] — so this packet closes that
//! gap directly: [`legacy_bridge`] is the full port, reusing both modules
//! rather than re-deriving canonicalization or kernel status.
//!
//! `assertValid('legacy-envelope-v1', ...)` (`contracts/arcane/validate.mjs`)
//! has no Rust port anywhere in this crate (the closest, `legion-policy`'s
//! `wf068::validate`, is a generic JSON-Schema-subset engine parked in
//! another crate and not yet wired into this crate's dependency graph).
//! Rather than pull in a whole schema engine for one schema, this packet
//! ports the JS *validation outcome* for the one schema this file actually
//! validates against (`legacy-envelope-v1`) as explicit field checks —
//! `assets/schema-map.json`'s embedded copy of
//! `legacy-envelope-v1.schema.json`'s `required`/`const`/`type` rules,
//! asserted directly. `envelopeFor` is the only call site in the JS source
//! that invokes `assertValid`, and it is a fixed, hand-built shape (nine
//! fields, none caller-extensible), so this is a faithful, non-generic port
//! of that one call, not a shortcut around schema semantics generally.
//!
//! ## `providers/sdk/index.mjs`
//!
//! Pure re-export surface (`export { X } from './y.mjs'`, ten symbols across
//! four sibling modules: `dag.mjs`, `testkit.mjs`,
//! `registry/provider-contracts.mjs`, `registry/provider-registry.mjs`).
//! `git grep` at port time confirms `legion-provider-sdk`'s `registry.rs`
//! and `testkit.rs` already provide the Rust equivalents; see
//! `finish-r53.md` for the exact JS-symbol -> Rust-item table. Nothing new
//! to write for that file — it is a barrel module, not logic — and it is
//! safe to delete once callers import from `legion_provider_sdk` directly.

pub mod legacy_bridge;
