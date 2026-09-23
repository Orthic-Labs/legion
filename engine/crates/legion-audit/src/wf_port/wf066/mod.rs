//! wf066 — `tools/audit/render-report.mjs`, `tools/audit/security-chain-pipeline.mjs`,
//! and `tools/audit/security-pipeline.mjs`.
//!
//! ## Coverage found before porting
//!
//! The per-candidate/per-path adjudication primitives these two pipeline
//! files wrap already have full native coverage and are **not** re-ported
//! here:
//!
//! - `src/adapters/security-adjudication.mjs` (`createSecurityCandidate`,
//!   `createAdjudicationPacket`, `verifyAdjudicationPacket`,
//!   `finalizeSecurityVerdict`) → ported at
//!   [`crate::native_providers::reasoning::security_adjudication`] (see that
//!   module's own doc comment: "Port of
//!   `src/adapters/security-adjudication.mjs`").
//! - `src/adapters/security-chain-adjudication.mjs`
//!   (`createChainAdjudicationPacket`, `finalizeChainVerdict`) → ported at
//!   `legion_runtime::p5_core::adapters_chain_adjudication` (see that
//!   module's own doc comment: "Port of
//!   `src/adapters/security-chain-adjudication.mjs` (packet P5c)").
//! - `src/providers/security-suite.mjs`'s `deriveVariantQueries` → ported at
//!   [`crate::native_providers::p11d_quality::security_suite::derive_variant_queries`].
//!
//! What was **not** covered, and is ported in this module's two files:
//!
//! 1. [`security_pipeline`] — `tools/audit/security-pipeline.mjs`'s
//!    `prepareAdjudicationBundle`/`finalizeAdjudicationBundle` bundle
//!    wrappers (candidate normalization, per-candidate fresh-context
//!    packeting, duplicate/reused-context rejection, verdict finalization
//!    fan-out, and missing-variant-analysis detection). The file's `main()`
//!    CLI entry point is not ported — this chunk owns no `bins/` path to
//!    wire a CLI onto, and the CLI is a thin JSON-file wrapper around the
//!    same two functions.
//! 2. [`security_chain_pipeline`] — `tools/audit/security-chain-pipeline.mjs`'s
//!    `prepareChainAdjudicationBundle`/`finalizeChainAdjudicationBundle`
//!    bundle wrappers (one packet per eligible reconciled path, duplicate
//!    path-verdict rejection, per-path finalization fan-out).
//!
//! `tools/audit/render-report.mjs` (the facts.json + report.json → Markdown
//! renderer, including the quality gate, AU13 coverage gate, AU14
//! trajectory, decomposition-assessment evidence validator, and health
//! score) had no native counterpart anywhere in `engine/` and is ported in
//! full at [`render_report`].
//!
//! **Integrator wiring note:** this file adds `pub mod wf_port;` +
//! `pub mod wf066;` per the chunk contract; nothing else in the tree
//! references these modules yet, so nothing else needs to change for this
//! chunk to compile standalone.

pub mod render_report;
pub mod security_chain_pipeline;
pub mod security_pipeline;
