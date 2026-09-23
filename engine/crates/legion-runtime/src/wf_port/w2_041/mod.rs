//! Port of `src/lib/core/plan-stages/{control-baseline,index,product-topology,
//! registry}.mjs` and `src/lib/core/reconcile-run.mjs` (chunk w2_041).
//!
//! ## Scope and what is faithfully ported here
//!
//! `registry.mjs`'s two static tables — `PLANNING_STAGE_IDS` and the
//! `REQUIRED` claim-level table — are **ALREADY-NATIVE-VERIFIED**: they are
//! ported byte-for-byte as `legion_runtime::p5_core::PLANNING_STAGE_IDS` and
//! `legion_runtime::p5_core::required_stages_for` (see
//! `src/p5_core/core_records.rs`, comment `plan-stages/registry.mjs:
//! PLANNING_STAGE_IDS, requiredStagesFor`). This module reuses those instead
//! of duplicating them. `index.mjs` is a pure re-export with no behaviour of
//! its own.
//!
//! What was *not* previously ported, and is ported in full here:
//!
//! - [`registry::run_planning_stages`] — the `runPlanningStages(stages,
//!   options, host)` async orchestration loop itself (as opposed to just its
//!   static tables): iterate `PLANNING_STAGE_IDS` in order, run whichever
//!   stage is registered for that id threading `artifacts` forward, record a
//!   gap for a required-but-unregistered stage, and fold every stage's
//!   `complete`/`status`/`detail`/`artifact` into the final `{status,
//!   complete, artifacts, gaps}` record.
//! - [`product_topology::product_topology_stage_result`] — the
//!   `productTopologyStage.run` decision function: given an already-built
//!   product-inspection artifact (the `inspectProduct` call itself is out of
//!   this chunk's owned files — `inspect-product.mjs` and everything under
//!   `inventory/*` it composes belong to other chunks), compute the same
//!   eleven-gap-class completeness verdict and `detail` string the JS
//!   computes.
//! - [`control_baseline::control_baseline_stage`] — the
//!   `controlBaselineStage.run` decision function: the
//!   topology-required/packs-required/denominator-zero/evidence-gap branching
//!   from `control-baseline.mjs`. `compileBaseline` (from
//!   `controls/baseline/compile.mjs`) and the `evidenceCapabilities` /
//!   `capabilityImpacts` calls it feeds into `capabilityImpacts` with are
//!   out-of-chunk dependencies (`capabilities.mjs` / `impacts.mjs` already
//!   have a native port at `legion_runtime::p5_core::controls_evidence`, but
//!   `compileBaseline` does not yet); both are taken as injected closures so
//!   the *stage decision logic* is faithfully, fully ported independent of
//!   who supplies those two computations.
//! - [`reconcile_run::reconcile_run`] — a complete, dependency-free port of
//!   `reconcileRun({plan, receipts, artifacts}, host)`: duplicate/unplanned
//!   terminal-receipt detection, binding- and denominator-mismatch detection
//!   (via a local `sameBinding`/`digest` reimplementation matching
//!   `binding.mjs`, since this chunk owns no shared module to add a public
//!   one to), per-provider reconciliation, and the full `audit-facts` record
//!   assembly including `provider_reconciliation`.
//!
//! `host.clock.now()` is threaded through as a caller-supplied `now_iso`
//! string rather than invoking a clock, matching how other ported chunks in
//! this crate treat host time (see `controls_evidence.rs`).

pub mod control_baseline;
pub mod product_topology;
pub mod reconcile_run;
pub mod registry;
