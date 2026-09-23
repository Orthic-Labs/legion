//! Chunk wf007 (area `src/lib/guard`, target crate `legion-policy`).
//!
//! Rust port of:
//!   - `src/lib/guard/compat/effects/replay.mjs`        -> [`replay`]
//!   - `src/lib/guard/compat/effects/user-approval.mjs`  -> [`user_approval`]
//!   - `src/lib/guard/compat/host/keys.mjs`               -> see wf007.md report;
//!     ALREADY-NATIVE-VERIFIED by `engine/crates/legion-arcane/src/key_ring.rs`
//!     (out of this crate's ownership, no file added here).
//!   - `src/lib/guard/compat/host/provision-keys.mjs`     -> [`provision_keys`]
//!   - `src/lib/guard/compat/policy/policy.mjs`           -> [`policy`] (partial —
//!     see module doc and the wf007 report for the untranslated remainder:
//!     JSON-Schema bundle validation, disk loading, and the two source-text
//!     conformance audits).
//!
//! `src/lib/cognitive/arcane/user-intent.mjs` (needed by `user_approval`'s
//! transcript admission check) is ported here too, as [`user_intent`], since
//! wf002 declined it for lack of a `regex` dependency — `legion-policy`
//! already depends on `regex` (see `Cargo.toml`), so that blocker does not
//! apply in this crate.
//!
//! This module is additive only: the JS files remain source of truth until
//! CI parity is proven and a later packet deletes them.
//!
//! NOTE for the integration owner: wire `pub mod wf007;` into
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (alongside the existing
//! `pub mod wf002;`).

pub mod canon;
pub mod json_parse;
pub mod policy;
pub mod provision_keys;
pub mod replay;
pub mod user_approval;
pub mod user_intent;
