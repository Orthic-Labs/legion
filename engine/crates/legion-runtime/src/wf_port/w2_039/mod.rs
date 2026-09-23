//! Port chunk w2_039 (area `src/lib/core`, target crate `legion-runtime`).
//!
//! Source files and disposition:
//!
//! - `src/lib/core/binding.mjs` — **PORTED** in full, see [`binding`].
//! - `src/lib/core/execute-plan.mjs` — **PORTED-PARTIAL**: the pure
//!   `RunLedger` class is ported in full, see [`run_ledger`].
//!   `RuntimeAdmission` from the same file is **ALREADY-NATIVE-VERIFIED**
//!   (`legion_runtime::engine::RuntimeAdmission`, exported from crate root).
//!   `executePlan`/`asReceipt`/`skippedReceipt` are **NOT-STARTED**: they
//!   depend on `./execution-receipt.mjs`, `./scheduler.mjs`,
//!   `../providers/provider-executor.mjs` and `../providers/sdk/result.mjs`,
//!   none of which are in this chunk or owned by it.
//! - `src/lib/core/adjudicate-run.mjs` — **PORTED-PARTIAL**:
//!   `validateJudgmentReceipt` and the `mode==='disabled'||!reviewerAvailable`
//!   branch of `adjudicateSubjects` are ported in full, see [`judgment`].
//!   `prepareAdjudication` and the reviewer-enabled branch are
//!   **NOT-STARTED** (need `./judgment-packets.mjs` and
//!   `./reviewer-policy.mjs`, not in this chunk).
//! - `src/lib/core/audit.mjs` — **DROP**. Its only job is to orchestrate
//!   `host.membrane?.context?.(...)`, `inspectProduct`, `buildSealedPlan`,
//!   `executePlan`, `reconcileRun`, `adjudicateSubjects`, `finalizeRun` and
//!   `bindRepository` against a `RunArtifactStore`. Per the porting brief,
//!   Membrane/Blueprint integration is being dropped outright (the `packet`
//!   line reads `await host.membrane?.context?.({root})`), and every other
//!   collaborator (`inspect-product.mjs`, `reconcile-run.mjs`,
//!   `finalize-run.mjs`, `repository-binding.mjs`, `run-store.mjs`) lives
//!   outside this chunk. Nothing here is portable in isolation; see the
//!   w2_039 report for what a future chunk needs before this can move.
//! - `src/lib/core/build-plan.mjs` — **NOT-STARTED**. `buildSealedPlan`'s
//!   `DEFAULT_STAGES` wires in `productTopologyStage`
//!   (`./plan-stages/product-topology.mjs`), `controlBaselineStage`
//!   (`./plan-stages/control-baseline.mjs`) and `PLANNING_STAGE_IDS`
//!   (`./plan-stages/registry.mjs`), and its first default stage is
//!   `blueprint-packet` — a Membrane/Blueprint artifact this port is
//!   dropping. None of the `plan-stages/*` modules are in this chunk. See
//!   the report for the claim-ranking/stage-loop algorithm this file uses,
//!   which is small and generic and can be ported once its stage modules
//!   land.

pub mod binding;
pub mod judgment;
pub mod run_ledger;
