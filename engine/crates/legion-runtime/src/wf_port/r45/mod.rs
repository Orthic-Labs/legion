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
//!
//! What `inspect_product` takes as **caller-supplied JSON inputs** rather
//! than computing itself: `discoverTargets` (candidates), `buildPortfolio`,
//! `extractComponents`, `buildStackGraph`, `discoverExternalSystems`,
//! `mergeReleaseContract`, `buildProductContext`, `buildJourneys`,
//! `loadControlPacks`, `compileBaseline`, `evidenceCapabilities`,
//! `capabilityImpacts`, `compileScenarios`. None of
//! `src/lib/inventory/{product-targets,components,stacks,external-systems,
//! journeys,release-contract,product-context}/**` has any Rust port in this
//! repository (confirmed by `git grep` across `engine/crates/*/src/wf_port`
//! turning up no `buildPortfolio`/`extractComponents`/`buildStackGraph`/
//! `discoverExternalSystems`/`buildJourneys`/`mergeReleaseContract`/
//! `buildProductContext` symbols — only incidental substring matches in
//! unrelated audit chunks). Those are large, independent subsystems
//! entirely outside this packet's three-file scope (`inspect-product.mjs`,
//! `plan-stages/control-baseline.mjs`, `plan-stages/registry.mjs`); porting
//! them is the exact missing capability that keeps this file
//! PORTED-PARTIAL rather than PORTED. `compileScenarios`
//! (`controls/scenarios/compile.mjs`) is likewise not ported (only
//! `w2_038::scenarios`'s narrower `pairwise`/registry helpers exist, not the
//! full composition function `inspectProduct` calls). `compileBaseline` and
//! `evidenceCapabilities`/`capabilityImpacts`, by contrast, now have real
//! native ports (`w2_038::baseline::compile_baseline`,
//! `p5_core::controls_evidence::{evidence_capabilities, capability_impacts}`)
//! after this packet's `control_baseline_stage_live` work above; a future
//! packet can wire `inspect_product`'s `baseline`/`capabilities`/
//! `claim_impact` parameters to those directly instead of taking them as
//! opaque JSON, the same way `control_baseline_stage_live` does.
//!
//! `pub mod r45;` wiring into `legion-runtime`'s `wf_port/mod.rs` (already
//! `pub mod wf_port;` in `lib.rs`) is applied by the integrator, per this
//! repo's port-brief convention of not editing that shared file directly.

pub mod inspect_product;
