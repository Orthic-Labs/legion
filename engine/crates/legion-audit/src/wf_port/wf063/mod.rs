//! Port of `src/providers/security/packs/{supply-chain,supply-developer,uploads}.mjs`
//! and `src/providers/security/variant-analysis.mjs` (chunk wf063, area
//! `src/providers/security`, target crate `legion-audit`).
//!
//! None of these four files reference Membrane or Blueprint services: each
//! pack is a pure lexical (pattern-only) detector over repository text and
//! file paths already present in the frozen denominator, and
//! `variant-analysis.mjs` is a pure reconciliation function over
//! already-produced candidate/adjudication artifacts. Nothing was dropped
//! from this chunk on that basis.
//!
//! `common.rs` here ports the shared `Context`/`Observation` plumbing each
//! pack's `analyze(context)` needs (mirroring the sibling `wf060` chunk's
//! `common.rs` for the same style of pack), reproduced locally since this
//! module owns only its four listed files, not the shared JS helper
//! modules (`packs/pattern-pack.mjs`, `contracts.mjs`) themselves.
//! `variant_analysis.rs` depends on `crate::wf_port::wf052::contracts` for
//! `binding_from_plan`/`assert_artifact_binding`/`stable_id`/`digest`,
//! mirroring the sibling `wf055` chunk's precedent for reusing that one
//! canonical contracts port rather than re-implementing it.

pub mod common;
pub mod supply_chain;
pub mod supply_developer;
pub mod uploads;
pub mod variant_analysis;
