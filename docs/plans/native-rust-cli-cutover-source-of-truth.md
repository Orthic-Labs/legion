# Legion native Rust CLI cutover — source of truth

**Status date:** 2026-09-15
**Repository:** Legion checkout
**Target:** Windows x86_64, local unsigned installed product
**Accepted completion:** 65%
**Rust compilation:** current source passed `pnpm run native:check:local` through RightKit — workspace, all targets, locked, release, `x86_64-pc-windows-msvc`, receipt `766c47de-d703-4fcc-863b-cfa70392b088`.
**Source parity diagnostic:** 141/141 rows match Node exactly against current compiled developer executable; 0 mismatched, 0 blocked, complete manifest coverage.
**Installer-build allowance remaining:** 0 of 3

This file supersedes prior chat summaries and completion estimates for this job. Update earned points only when listed evidence gate passes.

## Adjudication 2026-09-14

1. **Build allowance:** 0/3 is current authority; no installer builds remain authorized. The two builds this plan requires proceed only when Adrian grants at least two new builds after static gates pass.
2. **Score:** Accepted completion is 65%. Rust command-source implementation earns 25/25. Audit provider source earns 20/20 after exact 29-provider runtime dispatch coverage, authenticated 17-provider reasoning coverage, exact 32-provider legacy registry/route/selector coverage, production symbolic-tool resolution, sealed executable composition, and canonical async receipt/failure coverage. Source parity is 141/141 diagnostically, but parity points remain gated on a complete installed-executable run.
3. **Builds 1–3:** Historical failed-build evidence only (RightKit requests `9ae627dc-6e02-4e3d-a7a7-c7b28c830dfe`, `c81e465c-c774-4841-91e0-a09bbdf7540e`, `89c0575e-329d-4b55-ac09-e6de3c86f2d3`). All three failed during managed Rust compilation; none reached assembly, installer, or installed qualification; they qualify nothing about the current working tree.
4. **Parity gate:** Gate on 100% of a hashed behavior-row manifest (`tests/native-cli-characterization/fixtures.json`, SHA-256 recorded in build evidence), not on a fixed count of 75.
5. **Assurance edge:** Node help lists 32 commands but dispatches 31; `assurance` is the single known 32-help/31-dispatch edge (`node-help-only`), not an uncharacterized command.

## Job

Finish Legion's Node-to-Rust port without losing behavior. One product must remain: installer-owned `legion.exe` plus hook, MCP, assets, and client projections. Node CLI/runtime semantics must disappear only after compiled Rust executable proves equivalent inputs, outputs, exit codes, mutations, failures, repair behavior, and installed operation.

This job excludes GitHub CI, signing, publication, Mac work, command redesign, temporary shims, and checkout-composition fallback.

## Scoring

Percentage measures accepted end-to-end outcome, not lines written or time spent. These weights are fixed for this cutover.

| Acceptance area | Weight | Earned | Current evidence |
| --- | ---: | ---: | --- |
| Behavior baseline and inventory | 10 | 10 | 41-command union, 141 Node fixtures, 35 characterized subcommands, 25 Node/27 Rust nested routes with 0 mismatches, 0 uncharacterized Node commands |
| Rust command source implementation | 25 | 25 | `native-cli:inventory` is green: 0 stubs, 0 partials, 0 divergent, 0 unknown, 0 uncharacterized; current Rust source compiles and focused executable tests pass |
| Audit provider source implementation | 20 | 20 | All 29 runtime-script IDs execute through Rust adapters with exact set/identity/denominator/evidence tests. All 32 legacy IDs match frozen Node IDs/checks/selectors/roles/phases/tool semantics, dispatch through exact native/external routes, resolve symbolic project tools to sealed executables plus exact argv, and preserve typed success/failure/timeout/output/parser evidence. Production CLI composes this through `EffectExecutor`; all 17 reasoning IDs retain authenticated plan-bound success/failure/replay/tamper coverage |
| Compiler integration and local gate | 10 | 10 | Current workspace/all-target locked release check passed: RightKit receipt `766c47de-d703-4fcc-863b-cfa70392b088` |
| Rust behavior parity evidence | 15 | 0 | Fresh strict current-source diagnostic matches 141/141 rows with complete coverage. Points remain gated on qualifying installed-executable parity |
| Pre-cutover installed proof | 8 | 0 | Current working tree has not produced a qualified installer or stable install. Builds 1–3 are historical failed-build evidence only; all three failed during managed Rust compilation and never reached assembly, installer, or installed qualification, so they qualify nothing about the current tree |
| Node deletion, final installed proof, final commit | 12 | 0 | 34 Node runtime files remain; enforce gate fails; no final build or commit |
| **Total** | **100** | **65** | |

## Completed work

- Added native command modules under `engine/bins/legion/src/commands/`.
- Added Arcane state, contract, receipt, budget, key, run, and completion support under `engine/crates/legion-arcane/`.
- Added native audit provider families under `engine/crates/legion-audit/src/native_providers/`.
- Added provider registry loading and packaging path for `src/registry/providers.json`.
- Added 141 Node behavior fixtures and command inventory tooling under `scripts/native-cli/` and `tests/native-cli-characterization/`.
- Added Node-runtime surface gate at `scripts/check-native-cli-surface.mjs`.
- Added local cached compile gate:

  ```powershell
  pnpm run native:check:local
  ```

- Fixed all compiler errors currently visible across Rust workspace/all targets.
- Latest current-source compile check passed using RightKit target `D:\.rightkit-managed\rightkit-build-control\ws\19d3fa2de785\g\005\target` (receipt `66e20601-c5e6-4af8-8859-d8a3e679d29d`).

### Current implementation pass — 2026-09-14

- Fixed command-specific help, version/unknown-command output channels, state `--option=value` parsing, duplicate-surface file counts, and breach stderr diagnostics. Added isolated executable regression tests in `engine/bins/legion/tests/native_cutover_cli.rs`.
- Fixed a setup-health test fixture to supply resolved binding evidence. Added the complementary regression requiring an unproven opt-in binding to remain incomplete; production trust checks were not relaxed.
- Added plan-bound reasoning receipt verification and registry injection, with request freshness across executor lifetimes, verification-key validation before host invocation, and rejection of generic unauthenticated host executors. Fake-host tests are not production-host proof.
- Hardened parity evidence: missing/stale baselines, malformed observations, snapshot limits, duplicate/missing manifest rows, output/exit/stderr/mutation differences, and native-only unasserted mutations cannot pass. `captureOnly` is no longer treated as `nativeOnly`.
- Closed exact Node contracts for command help/errors, rules grammar/write receipts, bind/init Windows paths, governance JSON and receipt-store effects, harness output, MCP config, verify/report missing-file failures, and JSON insertion order.
- Fresh strict diagnostic: 141/141 matched, 0 mismatched, 0 blocked, 0 unmatched, 0 skipped; manifest SHA-256 `bd5cd3076779e7fb6972925a66ed993b9e309753747a6bbf04019325ab573806`.
- Static parity gate tests passed 30/30; recursive Node-surface record gate correctly reports remaining cutover files without failing record phase.
- Focused compiled-executable suite passed 10/10 through RightKit receipt `95f0d51c-d69b-4d91-803a-7a8f37553735`.
- Full locked release Rust workspace/all-features test run passed with 0 failures through RightKit receipt `2935536b-6c76-4442-be0b-5038c89523c`.
- Added cancellation-aware async Audit execution and canonical `ExternalProjectTool` injection for legacy checks. Immutable output is digest/size verified before parsing; unavailable, unauthorized, missing executable, timeout, cancellation, output-limit, and artifact failure remain typed incomplete states.
- Added exact runtime-provider set coverage for all 29 frozen `runtime-script` IDs and fixed missing `secrets.current-history` registry dispatch.
- Added compiled Rust migration-path coverage for init write/idempotency, bind refusal/no mutation, verify failure/integrity, completion authentication refusal, and state breach/recovery.
- Prior full locked release Rust workspace/all-features test run passed with 0 failures through RightKit receipt `0fc38d1a-f097-47a9-9e63-56116d093f96`; prior locked workspace/all-target compiler gate passed through receipt `c8efbd2b-8e1f-4f06-9b1d-e32deb338fcd`.
- Closed Audit's final five source points: exact 32-provider Node contract matrix; corrected Rust selectors/roles/tool labels; symbolic `project-build`/`project-lint`/`project-types`/package-tool resolution; absolute executable hashing plus production `EffectExecutor` composition; accepted finding exit codes, immutable artifact parsing, typed invalid-envelope degradation, and secret-free gitleaks projection.
- Focused Audit/effect suites passed 35/35 through RightKit receipt `8f2186ac-cf20-45f7-a490-21b4872ee15a`; final nested-Rust resolver proof passed 7/7 through receipt `bf83a81e-2d4c-4ebd-979c-c03312f49378`; compiled product parity passed 6/6 through receipt `48349e7d-c279-4a7b-840a-07e6ced1d7ab`; current full locked release Rust workspace/all-features tests passed with 0 failures through receipt `992742da-1f2a-401e-9f67-c872366410bd`; final locked workspace/all-target compiler gate passed through receipt `607e6bee-6af9-4a0d-bfe3-71e7d748e28d`.
- No Node runtime deletion, installer assembly/installation, final commit, or push was performed. Accepted completion is 65%.

## Remaining gaps

### Command semantics

- `assurance` now preserves Node's exact unknown-command behavior. Node help lists 32 commands but dispatches 31; `assurance` is the known `node-help-only` edge, not a newly implemented assurance feature or an uncharacterized command.
- Static command closure is complete: 41/41 union commands are characterized with 0 stubs, partials, divergent, unknown, or uncharacterized rows.
- Developer-executable parity is 141/141 with complete manifest coverage. This diagnostic proves source behavior parity but is deliberately non-qualifying for installed-product points.

### Audit execution

- All 29 frozen `runtime-script` IDs execute through Rust adapters with exact registry set, identity, denominator, evidence-authority, positive, and degradation coverage.
- All 32 frozen `legacy-check` IDs are wired by exact ID into `NativeProviderRegistry` and checked against Node identity, check, selector, role, phase, version, tool, and readiness records. Native filesystem checks execute in-process. External checks cross only canonical async `ExternalProjectTool`, validate immutable output digest/size, and preserve typed receipt failures.
- Symbolic external tools resolve through project metadata/local bins/PATH into absolute executable paths, exact argv, executable SHA-256, bounded environment, and Rust/Tauri working directories. Production Audit composes the resolver with `EffectExecutor`. Project/network/runtime checks remain typed incomplete without an authenticated sandbox receipt; no fallback or policy bypass exists.
- All 17 `reasoning-contract` IDs have typed plan-bound invocation, authenticated receipt verification, replay/tamper rejection, degradation, and report-path tests. Node's bare CLI also composes an unavailable reviewer by default; Rust preserves that behavior and exposes an injectable authenticated host seam. No separate production reviewer transport exists to port.
- Provider-by-provider source equivalence is closed for all 32 legacy contracts: success, invalid output, unavailable, unauthorized, missing executable, timeout, cancellation, output limit, artifact failure, denominator binding, route identity, and symbolic resolution are covered. Raw untyped JSON cannot become clean, and gitleaks secrets are redacted before projection.
- Full plan → audit → verify → report workflow has not been proven through installed Rust executable.

### Parity and product proof

- Fresh strict developer evidence matches 141/141 rows with exact stdout, stderr, exit code, and filesystem mutation comparison. Manifest identity is `bd5cd3076779e7fb6972925a66ed993b9e309753747a6bbf04019325ab573806`.
- No source-level parity rows remain. Qualifying parity must still run against stable `current`, its composition, and packaged assets; a checkout fallback is forbidden.
- Product tests have not all been moved from Node entrypoint to compiled Rust executable.
- Stable installed CLI, hook, MCP, projections, failure, repair, fresh install, upgrade, and reinstall remain unproven for current source.
- Node entrypoint and command modules remain present, so enforce phase correctly fails.

## Exact path from 65% to 100%

### 1. Finish real Rust behavior — complete

1. Connect all 32 legacy provider IDs to real Rust implementations through `NativeProviderRegistry`.
2. Preserve each provider's inputs, denominators, findings, evidence, source locations, degradation, process state, and failure contracts.
3. Connect all 17 reasoning providers to host invocation and authenticated receipt verification.
4. Preserve `assurance` help-only behavior and complete `audit` so inventory reports zero Rust partials.
5. Close remaining command behavior gaps without changing grammar or deprecating `rules` or `schedule`.

Exit gate:

```powershell
pnpm run native-cli:inventory
pnpm run native:check:local
```

Required result: 0 stubs, 0 partials, 0 uncharacterized commands, compiler exit 0.

Current result: met — 0 stubs, 0 partials, 0 divergent, 0 unknown, 0 uncharacterized; compiler exit 0.

### 2. Complete source-level test coverage

1. Expand success, usage-error, integrity-error, incomplete-state, mutation, and recovery fixtures until every command/subcommand/error path is covered. Current manifest: 141 rows, 41 commands, 35 characterized subcommands, 0 uncharacterized commands.
2. Port `tests/cli.test.mjs`, `tests/doctor.test.mjs`, `tests/bind.test.mjs`, and remaining product tests to invoke compiled Rust executable.
3. Map every Node behavior row to one passing Rust evidence row. Current developer diagnostic is complete at 141/141; installed qualification remains step 3.
4. Run Rust workspace/all-target tests through RightKit using same manifest, target, and release profile.
5. Rerun `pnpm run native:check:local` after every repair wave.

Required result: Rust tests green and 100% of rows in the hashed behavior-row manifest matched before installer build. Freeze `tests/native-cli-characterization/fixtures.json` as the behavior-row manifest, record its SHA-256 in build evidence, and gate on content-addressed manifest rows — not the fixed count 75. Any manifest change requires re-hash and re-gate.

### 3. Prove pre-cutover installed product

Do not delete Node yet. Create build evidence recording source revision, check/test receipts, cache path, assembly inputs, installer path, activation path, qualification path, and known failure boundaries.

Then run:

```powershell
pnpm run release:local:win:unsigned
pnpm run native-cli:parity-installed
```

Test stable installed `legion.exe`, `legion-hook.exe`, `legion-mcp.exe`, Claude projection, Codex opt-in projection, failure, repair, fresh install, upgrade, and reinstall.

Required result: installed parity green with Node still available as reference.

### 4. Cut over to one runtime

Only after step 3 passes:

1. Delete `src/bin/legion.mjs`.
2. Delete `src/lib/cli/**`.
3. Delete unused Node semantic modules proven unreachable by dependency closure.
4. Update remaining tests/scripts to compiled Rust executable.
5. Run:

   ```powershell
   node scripts/check-native-cli-surface.mjs --phase=enforce
   pnpm run native-cli:inventory
   pnpm run native:check:local
   ```

Required result: enforce gate green, no Node CLI/runtime semantics, Rust compilation green.

### 5. Prove deleted-Node installed product

Create a second build-evidence record from deleted-Node state, then run:

```powershell
pnpm run release:local:win:unsigned
pnpm run native-cli:parity-installed
```

Repeat stable installed CLI, hook, MCP, projection, failure, repair, fresh-install, upgrade, and reinstall checks.

Required result: installed product passes without Node CLI source or checkout fallback.

### 6. Commit final green cutover

Before commit, require all of these:

- `native:check:local` passes.
- Rust tests pass.
- Native inventory reports 0 stubs and 0 partials.
- 100% Node-to-Rust behavior rows pass.
- Surface enforce gate passes.
- Pre-cutover and deleted-Node installed qualifications pass.
- Stable installed product reports current CLI, hook, MCP, and projections.
- No unrelated user changes are staged.

Commit only this final green state. Push, CI, signing, publication, and Mac release work remain outside this job.

## Build discipline

Existing three-build allowance is exhausted. 0/3 is current authority; no installer builds remain authorized. Reaching 100% requires two successful installer builds: one before Node deletion and one after deletion. Those two builds proceed only when Adrian grants at least two new builds, and only after static gates pass (compile check, tests, parity fixtures, build evidence). Current compile gate passed under receipt `766c47de-d703-4fcc-863b-cfa70392b088`; current full locked release Rust workspace/all-features tests passed with 0 failures under receipt `992742da-1f2a-401e-9f67-c872366410bd`. A granted-build failure returns work to source diagnosis and cached check/test gates; it never triggers an immediate build loop, and each further build requires fresh authorization.

## 100% definition

100% means one compiler-clean, test-green Rust product; 100% of rows in the hashed behavior-row manifest passing against the compiled executable in both pre-cutover and deleted-Node installed proofs; no Node Legion runtime; two installed-product proofs in required order; green enforce gate; final cutover committed. Source presence or successful compilation alone never counts as completion.
