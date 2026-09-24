//! Port chunk w2_039 (area `src/lib/core`, target crate `legion-runtime`).
//!
//! Source files and disposition:
//!
//! - `src/lib/core/binding.mjs` — **PORTED** in full, see [`binding`].
//! - `src/lib/core/execute-plan.mjs` — **PORTED** in full (packet r44), see
//!   [`execute_plan`]. The pure `RunLedger` class was already ported, see
//!   [`run_ledger`]; `scheduleProviders`/`providerDependencies` are
//!   already native at `crate::p5_core::core_scheduler`;
//!   `executionReceipt`/`blocked` are already native at
//!   `crate::wf_port::w2_040::execution_receipt`. Packet r44 ports the
//!   remaining `normalizeProvider`/`denominator`/`asReceipt`/`executePlan`/
//!   `skippedReceipt` plus `normalizeProviderResult`
//!   (`src/lib/providers/sdk/result.mjs`, a pure dependency of `asReceipt`
//!   with no further dependency of its own). The one seam modeled as a
//!   trait rather than ported line-for-line: `executePlannedProvider`
//!   (`src/lib/providers/provider-executor.mjs`) dynamically imports
//!   provider modules and spawns external processes via
//!   `../host/sandbox-policy.mjs`/`./sdk/contracts.mjs`/
//!   `../qualification/schema-validator.mjs`, none in this packet — see
//!   [`execute_plan::ProviderExecutor`].
//! - `src/lib/core/adjudicate-run.mjs` — **PORTED** in full (packet r44),
//!   see [`judgment`]. `validateJudgmentReceipt` and the
//!   `mode==='disabled'||!reviewerAvailable` branch were already ported.
//!   Packet r44 adds `prepareAdjudication` and the reviewer-enabled branch
//!   of `adjudicateSubjects`, plus their two whole-file dependencies
//!   `buildJudgmentPacket` (`src/lib/core/judgment-packets.mjs`, one
//!   function) and `reviewerPolicy` (`src/lib/core/reviewer-policy.mjs`,
//!   one function) — both ported alongside since neither has any further
//!   dependency. The host `review(...)` call is modeled as
//!   [`judgment::Reviewer`].
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
//! - `src/lib/core/build-plan.mjs` — **PORTED-PARTIAL** (packet r44), see
//!   [`build_plan`]. The claim-ranking table, `requiredForClaim`, and the
//!   entire `buildSealedPlan` stage-loop/gap/digest algorithm are ported in
//!   full, generic over a [`build_plan::PlanStage`] trait. `DEFAULT_STAGES`'s
//!   concrete bodies (`productTopologyStage` → `inspectProduct`,
//!   `controlBaselineStage` → `controls/baseline` + `controls/evidence`)
//!   remain **NOT-STARTED**: neither dependency tree is in this packet or
//!   owned by it (`git grep -l "buildPortfolio\|extractComponents\|compileBaseline"
//!   engine/` — no hits at port time). The `blueprint-packet` default stage
//!   is dropped per the Membrane/Blueprint retirement.

//! - `src/lib/core/finalize-run.mjs` — **PORTED** in full (packet r44b),
//!   see [`finalize_run`]. `exitCodeForReport` was already native
//!   (`legion_runtime::p5_core::exit_taxonomy::exit_code_for_report`); the
//!   r44b [`finalize_run::exit_code_for_report`] is a thin JSON-report
//!   adapter onto that same function, not a second implementation.
//!   `finalizeRun({plan, facts, results, policy}, host)` is now ported,
//!   including its one real dependency `tools/audit/audit-finalize.mjs`'s
//!   `finalizeAudit` (272 lines, ported in full as
//!   [`finalize_run::finalize_audit`] — every helper:
//!   `requiredLenses`/`ranLenses`/`candidateGeneratorIds`/
//!   `isCandidateGenerator`/`providerFindings`/`redactedSecretCarrier`/
//!   `orphanSecurityVerdicts`/`securityFindings`/`nonSecurityGaps`/
//!   `canonicalCounts`). Not ported: `reportToSarif`
//!   (`scripts/report-to-sarif.mjs`) and `audit-finalize.mjs`'s CLI
//!   `main()` (argv/file I/O) — out of this packet's file list and host
//!   I/O respectively; a CLI caller reads the three JSON inputs and calls
//!   `finalize_audit` itself.
//! - `src/lib/core/index.mjs` — **PORTED-PARTIAL** (packet r44), see
//!   [`core_index`]. `writeRunManifest` is ported in full: it only needed
//!   this chunk's own `digest()` (`binding.rs`) plus the already-written
//!   `store.records()` data, taken as plain input so no `RunArtifactStore`
//!   trait needed inventing. The nine re-exports and the `buildPlan`/
//!   `verifyRun` wrappers remain **NOT-STARTED**: every one of them depends
//!   on `../../../tools/audit/audit-plan.mjs`,
//!   `../registry/provider-registry.mjs`, `./verify-run.mjs` and/or
//!   `../artifacts/run-store.mjs`, none in this packet.

pub mod binding;
pub mod build_plan;
pub mod core_index;
pub mod execute_plan;
pub mod finalize_run;
pub mod judgment;
pub mod run_ledger;
