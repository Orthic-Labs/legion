//! Port chunk w2_040 (area `src/lib/core`, target crate `legion-runtime`).
//!
//! Source files and disposition:
//!
//! - `src/lib/core/execution-receipt.mjs` — **PORTED** in full, see
//!   [`execution_receipt`]. `executionReceipt()` and `blocked()` are both
//!   pure value builders (a hash of an empty buffer for the default
//!   artifact stubs, then a plain record literal) with no I/O and no
//!   dependency outside this file, so the port is exact: same field names
//!   (translated to `snake_case`), same defaulting rules, same
//!   `SPAWN_STATUS` closed set and same `durationMs` arithmetic
//!   (`completedAt - startedAt`, `null` unless both are present).
//!
//! - `src/lib/core/kernel-binding.mjs` — **PORTED** in full, see
//!   [`kernel_binding`]. The seam is a small state machine (`bindKernel`,
//!   `kernelBound`, `kernelStatus`, `mintId`, `appendEvent`, `readObject`,
//!   `putObject`, `unbindKernel`) with no host-required primitives of its
//!   own: it fails closed with `ARC_KERNEL_PRIMITIVE_UNAVAILABLE`
//!   (already ported — `legion_policy::arcane_port::errors::ArcaneError`,
//!   used directly here) whenever a Kernel primitive is not bound.
//!
//!   One gap, flagged rather than silently patched over: `mintId`'s
//!   provisional-id fallback delegates in JS to
//!   `src/lib/contracts/arcane/ids.mjs`'s `mintId(family)`, which is
//!   **not** in this chunk, is not owned by it, and (checked at port time,
//!   `git grep -n "HANDLE_PREFIX\|fn mint_id" engine/`) has no existing
//!   Rust port under `legion-policy::arcane_port` — the only `mint_id` in
//!   the tree today is `legion_runtime::p5_core::kernel_ids::mint_id`,
//!   which is a different port (of `src/packages/kernel/lib/ids.mjs`, the
//!   Kernel's *own* id grammar/prefixes, packet P5d) with a different
//!   prefix table (e.g. `evt_` vs. Arcane's `ev_`) and a different
//!   argument shape (`kind, now, entropy` vs. Arcane's `family, now`). Reusing
//!   it here would silently swap Arcane's provisional-id grammar for the
//!   Kernel's. So [`kernel_binding::mint_id`] carries its own
//!   self-contained ULID mint (same Crockford alphabet, same
//!   monotonic-within-millisecond bump-the-random-tail behaviour as
//!   `src/lib/contracts/arcane/ids.mjs`'s `ulid()`) scoped to exactly the
//!   `HANDLE_PREFIX` table `kernel-binding.mjs` can reach through
//!   `mintId`. When `src/lib/contracts/arcane/ids.mjs` lands in its own
//!   chunk as `legion_policy::arcane_port::ids`, the integrator should
//!   delete this module's private `provisional` helper and call that
//!   instead — see the w2_040 report for the exact patch shape.
//!
//! - `src/lib/core/finalize-run.mjs` — **PORTED-PARTIAL**.
//!   `exitCodeForReport(report)` is **ALREADY-NATIVE-VERIFIED**:
//!   `legion_runtime::p5_core::exit_taxonomy::exit_code_for_report` (see
//!   `engine/crates/legion-runtime/src/p5_core/exit_taxonomy.rs`, doc
//!   comment "Ported from src/lib/errors.mjs (packet P5-runtime-core)") is
//!   byte-for-byte the same four-branch precedence
//!   (integrity → incomplete → policy-fail → pass → internal-error) over
//!   the same five optional report fields, already exercised by
//!   `p5_core_denominators_and_exit.rs`. Nothing to add.
//!   `finalizeRun({plan, facts, results, policy}, host)` itself is
//!   **NOT-STARTED**: its only statement besides field renaming is
//!   `await import('../../../tools/audit/audit-finalize.mjs')` then
//!   `finalizeAudit(...)`, i.e. it is a thin host-effectful wrapper
//!   (`host.clock.now()`) around `finalizeAudit`, which lives at
//!   `src/tools/audit/audit-finalize.mjs` — well outside this chunk and
//!   this crate's declared scope (`src/lib/core/**` only). Porting
//!   `finalizeRun` faithfully needs `finalizeAudit` ported first.
//!
//! - `src/lib/core/index.mjs` — **NOT-STARTED**. The whole file is
//!   deterministic-API glue: re-exports of nine sibling modules
//!   (`binding.mjs`, `execute-plan.mjs`, `reconcile-run.mjs`,
//!   `finalize-run.mjs`, `inspect-product.mjs`, `repository-binding.mjs`,
//!   `build-plan.mjs`, `verify-run.mjs`, `audit.mjs`) plus three thin
//!   wrapper functions (`buildPlan`, `verifyRun` — an alias of
//!   `verifySealedRun` — and `writeRunManifest`), every one of which
//!   depends on `../../../tools/audit/audit-plan.mjs`,
//!   `../registry/provider-registry.mjs`, `./verify-run.mjs`, and/or
//!   `../artifacts/run-store.mjs` — all outside `src/lib/core/**` and
//!   none owned by this chunk. `writeRunManifest` is the closest to
//!   portable (it only calls `store.records()`/`store.writeJson()` and
//!   this chunk's own `digest()`, ported at `binding.mjs` by w2_039, plus
//!   `Array.prototype.sort` over `records.filter(...).map(...)`), but its
//!   `store` parameter is `RunArtifactStore` from
//!   `../artifacts/run-store.mjs`, a stateful class this chunk does not
//!   own; porting it here would mean inventing that trait's shape rather
//!   than matching a real one. Left for the chunk that ports
//!   `run-store.mjs`.
//!
//! - `src/lib/core/inspect-product.mjs` — **NOT-STARTED** and not
//!   Membrane/Blueprint-tainted (no `host.membrane`/`host.blueprint`
//!   reference in the file, so nothing here is dropped by the
//!   Membrane/Blueprint retirement). `inspectProduct(options, host)` is a
//!   13-collaborator pipeline (`discoverTargets`, `buildPortfolio`,
//!   `extractComponents`, `buildStackGraph`, `discoverExternalSystems`,
//!   `mergeReleaseContract`, `buildProductContext`, `buildJourneys`,
//!   `loadControlPacks`, `compileBaseline`, `evidenceCapabilities`,
//!   `capabilityImpacts`, `compileScenarios`), all imported from
//!   `../inventory/**` and `../controls/**`, none in this chunk and none
//!   found ported anywhere under `engine/` at port time (`git grep -l
//!   "buildPortfolio\|extractComponents\|buildStackGraph\|compileBaseline"
//!   engine/` — no hits). It only calls this chunk's own `digest()`
//!   (`binding.mjs`, already ported by w2_039) for two lines re-digesting
//!   `target`/`portfolio` after stripping their prior digest — that
//!   detail is worth preserving whenever the pipeline it sits inside gets
//!   ported, but is not separable from the rest of the function today.

pub mod execution_receipt;
pub mod kernel_binding;
