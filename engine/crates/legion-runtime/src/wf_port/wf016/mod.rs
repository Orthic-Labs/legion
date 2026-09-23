//! Port of `src/lib/remediation/{design-proposal,effect-graph,fix-contract,
//! mechanical}.mjs` and `src/lib/remediation/producers/config.mjs` (chunk
//! wf016).
//!
//! `git grep` over `engine/` for these functions/schemas/error messages
//! turned up no existing Rust coverage (`legion-runtime` has no
//! `remediation` module and no `effect_graph`/`fix_contract`/`mechanical`
//! anything before this chunk), so every file here is a fresh port rather
//! than a verification of pre-existing behaviour.
//!
//! Scope notes (see each submodule's doc comment for the exact source line):
//! - `mechanical.mjs` imports `STRUCTURAL_PRODUCERS`/`renderStructuralPreview`
//!   from `producers/structural.mjs`, which is **not** in this chunk's file
//!   list. [`mechanical::all_producers`] therefore currently returns only the
//!   config producers, and [`mechanical::render_preview`] returns `Err` for
//!   a structural-kind producer. Whoever owns `producers/structural.mjs`
//!   should extend both once that file is ported.
//! - `design-proposal.mjs` imports `reasoningProposal` from
//!   `reasoning-packets.mjs`, also not in this chunk. [`design_proposal`]
//!   uses a local, narrowly-scoped port of just the body-construction logic
//!   `designProposal` exercises (documented in `design_proposal.rs`); the
//!   real `reasoning-packets.mjs` port (and its own
//!   `untrusted-evidence-envelope.mjs` dependency) is separate follow-up
//!   work.
//!
//! The integrator wires this module in via `pub mod wf_port;` in
//! `legion-runtime/src/lib.rs` and `pub mod wf016;` in `wf_port/mod.rs`.

pub mod config_producer;
pub mod design_proposal;
pub mod effect_graph;
pub mod fix_contract;
pub mod mechanical;
mod util;

pub use config_producer::{config_producers, render_config_preview};
pub use design_proposal::{design_proposal, DesignProposalError, DesignProposalInput};
pub use effect_graph::{
    blocks_auto_apply, build_effect_graph, build_effect_graph_schema, compute_closure, matches_path, patch_effect_graph, BuildEffectGraphInput,
    EffectGraphError, PatchEffectGraphInput, EFFECT_GRAPH_SCHEMA_VERSION,
};
pub use fix_contract::{evaluate_fix_loop, fix_proposal, EvaluateFixLoopInput, FixLoopDecision, FixProposalInput, FIX_STOPS};
pub use mechanical::{
    all_producers, assert_producer_qualified, create_mechanical_proposal, manual_proposal, mechanical_ast_grep_proposal, mechanical_config_proposal,
    mechanical_dependency_proposal, mechanical_registry, mechanical_registry_json, plan_mechanical_remediation, producer_for, render_preview, Edit,
    MechanicalError, PreviewResult, Producer, RegistryEntry,
};
