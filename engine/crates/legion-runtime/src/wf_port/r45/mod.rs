//! Packet r45: `src/lib/core/inspect-product.mjs`,
//! `src/lib/core/plan-stages/control-baseline.mjs`,
//! `src/lib/core/plan-stages/registry.mjs`.
//!
//! `registry.mjs` needed no new work here: its static tables and the
//! `runPlanningStages` orchestrator were already ALREADY-NATIVE-VERIFIED at
//! `legion_runtime::p5_core::core_records::{PLANNING_STAGE_IDS,
//! required_stages_for}` and `legion_runtime::wf_port::w2_041::registry::
//! run_planning_stages` (see `w2_041/mod.rs`'s doc comment and `full-Q5.md`).
//!
//! `control-baseline.mjs`'s decision logic already had a faithful, complete
//! port at `w2_041::control_baseline::control_baseline_stage`, taking
//! `compileBaseline`/`evidenceCapabilities`/`capabilityImpacts` as injected
//! closures because those live on a different `Value` type
//! (`p5_core::controls_support::Value`) than this crate's other
//! `serde_json::Value`-based wf_port chunks. This packet closes that gap by
//! *extending* `w2_041/control_baseline.rs` directly (not duplicating it
//! here): see `w2_041::control_baseline::control_baseline_stage_live`, which
//! wires the real `w2_038::baseline::compile_baseline` and
//! `p5_core::controls_evidence::{evidence_capabilities, capability_impacts}`
//! through a small bidirectional JSON bridge (`json_to_cv`/`cv_to_json`).
//!
//! `inspect-product.mjs` had no prior port at all. [`inspect_product`] is a
//! complete, faithful port of the function's *own* logic: target/portfolio
//! digest recomputation (component/stack id fan-in, then re-digesting with
//! `w2_039::binding::digest`), the four-source gap union, the
//! `reportSkeleton` id-list assembly, and the final
//! `{schemaVersion, kind: "legion-product-inspection", ...}` envelope.
//! [`inspect_product::inspect_product_from_projection`] wires that assembly
//! to every real dependency `inspectProduct` composes — initial `git grep`
//! for JS-cased symbol names (`buildPortfolio`, `extractComponents`, etc.)
//! missed that these already exist under Rust-cased names in a *different*
//! module tree than `wf_port`:
//!
//! - `l3_inventory::product_targets::{discover_targets, build_portfolio}`
//! - `l3_inventory::components::extract_components`
//! - `l3_inventory::stacks::build_stack_graph`
//! - `l3_inventory::external_systems::discover_external_systems`
//! - `l3_inventory::release_contract::merge_release_contract`
//! - `l3_inventory::product_context::build_product_context`
//! - `l3_inventory::journeys::build_journeys`
//! - `w2_038::registry::load_control_packs` (packs loaded from
//!   `repo_root/registry/controls/packs/index.json` when
//!   `InspectProductOptions.packs` is `None`, matching `options.packs ??
//!   await loadControlPacks(ROOT)`)
//! - `w2_038::baseline::compile_baseline` /
//!   `p5_core::controls_evidence::{evidence_capabilities,
//!   capability_impacts}` (via this packet's new
//!   `w2_041::control_baseline::compile_baseline_and_impacts_json`)
//! - `w2_038::scenarios::compile_scenarios`
//!
//! `inspect_product_from_projection` is therefore **PORTED**, not
//! PORTED-PARTIAL: every dependency `inspectProduct` calls has a real,
//! wired Rust implementation. The only behavioural difference from the JS
//! source is unavoidable and not a gap: `loadControlPacks`'s JS `readFile`
//! is synchronous `std::fs::read_to_string` here (this whole port is
//! synchronous, matching how every other `wf_port`/`l3_inventory` chunk
//! already treats `inspectProduct`'s siblings).
//!
//! `pub mod r45;` wiring into `legion-runtime`'s `wf_port/mod.rs` (already
//! `pub mod wf_port;` in `lib.rs`) is applied by the integrator, per this
//! repo's port-brief convention of not editing that shared file directly.

pub mod inspect_product;
