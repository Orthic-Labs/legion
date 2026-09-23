//! wf069 — Rust port of five legacy JS Arcane verification modules under
//! `src/lib/verification/arcane/`:
//!
//!   - `adversarial-ai-reconstruction.mjs`   -> `reconstruction` (ported, full)
//!   - `adversarial-proportionality.mjs`     -> `proportionality` (ported, full)
//!   - `adversarial-ownership-economics.mjs` -> `ownership_economics` (ported, full)
//!   - `advisory-certification.mjs`          -> NOT PORTED (see report)
//!   - `advisory-profile.mjs`                -> NOT PORTED (see report)
//!
//! wf069 is self-contained (no new `Cargo.toml` dependency, per the porting
//! packet's constraint on this chunk) and defines its own small error/decision
//! vocabulary rather than depending on an unwired sibling `wf_port` module,
//! matching the precedent set by `wf_port::wf067`.

pub mod errors;
pub mod ownership_economics;
pub mod proportionality;
pub mod reconstruction;
