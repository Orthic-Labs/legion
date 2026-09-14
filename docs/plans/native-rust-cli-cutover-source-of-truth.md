# Legion native Rust CLI cutover — source of truth

**Status date:** 2026-09-14
**Repository:** `D:\Claude\legion`
**Target:** Windows x86_64, local unsigned installed product
**Accepted completion:** 50%
**Rust compilation:** green via `pnpm run native:check:local` through RightKit — workspace, all targets, locked, release, `x86_64-pc-windows-msvc`, 2.63 s, receipt `92701651-ded9-49d9-b22e-55b9c35718f5`. This makes the build-3 post-failure repair (`engine/bins/legion/src/commands/run.rs:480`) compile-proven; it remains installer-unproven.
**Installer-build allowance remaining:** 0 of 3

This file supersedes prior chat summaries and completion estimates for this job. Update earned points only when listed evidence gate passes.

## Adjudication 2026-09-14

1. **Build allowance:** 0/3 is current authority; no installer builds remain authorized. The two builds this plan requires proceed only when Adrian grants at least two new builds after static gates pass.
2. **Score:** Accepted completion is 50%, not 55%. The prior 5 parity-evidence points double-counted Node characterization; they return only when real Rust-matched behavior rows exist against a compiled current-tree executable.
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
| Behavior baseline and inventory | 10 | 10 | 41-command union, 75 Node fixtures, 12 nested subcommands, 0 uncharacterized Node commands |
| Rust command source implementation | 25 | 20 | Contract, run, completion, state, host, skills, doctor, rules, schedule, languages, providers, plan, verify, and report source exists and compiles; behavior parity is not complete |
| Audit provider source implementation | 20 | 10 | 29 runtime adapters exist; 32 legacy contracts exist but are not connected to real execution; 17 reasoning providers lack completed host-receipt flow |
| Compiler integration and local gate | 10 | 10 | `pnpm run native:check:local` checks workspace/all targets through RightKit release cache; receipt `92701651-ded9-49d9-b22e-55b9c35718f5` passed |
| Rust behavior parity evidence | 15 | 0 | Node baseline captured; zero Rust-matched behavior rows against a compiled executable. The only Rust characterization output (`dist/native-cli/rust-characterization/`, Sep 14 05:30) predates all three build-failure repair waves and is not qualifying evidence |
| Pre-cutover installed proof | 8 | 0 | Current working tree has not produced a qualified installer or stable install. Builds 1–3 are historical failed-build evidence only; all three failed during managed Rust compilation and never reached assembly, installer, or installed qualification, so they qualify nothing about the current tree |
| Node deletion, final installed proof, final commit | 12 | 0 | 34 Node runtime files remain; enforce gate fails; no final build or commit |
| **Total** | **100** | **50** | |

## Completed work

- Added native command modules under `engine/bins/legion/src/commands/`.
- Added Arcane state, contract, receipt, budget, key, run, and completion support under `engine/crates/legion-arcane/`.
- Added native audit provider families under `engine/crates/legion-audit/src/native_providers/`.
- Added provider registry loading and packaging path for `src/registry/providers.json`.
- Added 75 Node behavior fixtures and command inventory tooling under `scripts/native-cli/` and `tests/native-cli-characterization/`.
- Added Node-runtime surface gate at `scripts/check-native-cli-surface.mjs`.
- Added local cached compile gate:

  ```powershell
  pnpm run native:check:local
  ```

- Fixed all compiler errors currently visible across Rust workspace/all targets.
- Latest compile check passed in 2.63 seconds using RightKit target `D:\.rightkit-managed\rightkit-build-control\ws\19d3fa2de785\g\005\target`.

## Remaining gaps

### Command semantics

- `assurance` remains classified partial. Known edge: Node help lists 32 commands but dispatches 31; `assurance` is in Node's COMMANDS (`src/lib/cli/help.mjs`) with no dispatch case in `src/lib/cli/run.mjs` (`node-help-only`), and is Rust-classified partial. The 32/31 delta is this single known edge, not an uncharacterized command.
- `audit` remains classified partial.
- Contract, run, completion, state, host, skills, doctor, rules, schedule, languages, providers, plan, verify, and report compile but do not yet have complete Node-equivalence proof for success, failure, mutation, and exit-code paths.

### Audit execution

- `legacy_checks` describes 32 provider contracts but is not wired into `NativeProviderRegistry::execute`.
- Those 32 providers require real Rust execution and validated `ProviderResult` output, not contract-only declarations.
- Seventeen `reasoning-contract` providers still require host invocation, authenticated host receipts, degradation behavior, and report integration.
- Full plan → audit → verify → report workflow has not been proven through installed Rust executable.

### Parity and product proof

- Zero Rust behavior rows are matched against a compiled current-tree executable; prior Rust characterization output predates the build-failure repair waves and is non-qualifying. Capture gates on the hashed manifest.
- Product tests have not all been moved from Node entrypoint to compiled Rust executable.
- Stable installed CLI, hook, MCP, projections, failure, repair, fresh install, upgrade, and reinstall remain unproven for current source.
- Node entrypoint and command modules remain present, so enforce phase correctly fails.

## Exact path from 50% to 100%

### 1. Finish real Rust behavior

1. Connect all 32 legacy provider IDs to real Rust implementations through `NativeProviderRegistry`.
2. Preserve each provider's inputs, denominators, findings, evidence, source locations, degradation, process state, and failure contracts.
3. Connect all 17 reasoning providers to host invocation and authenticated receipt verification.
4. Complete `assurance` and `audit` so inventory reports zero Rust partials.
5. Close remaining command behavior gaps without changing grammar or deprecating `rules` or `schedule`.

Exit gate:

```powershell
pnpm run native-cli:inventory
pnpm run native:check:local
```

Required result: 0 stubs, 0 partials, 0 uncharacterized commands, compiler exit 0.

### 2. Complete source-level test coverage

1. Add success, usage-error, integrity-error, incomplete-state, mutation, and recovery fixtures for every command/subcommand.
2. Port `tests/cli.test.mjs`, `tests/doctor.test.mjs`, `tests/bind.test.mjs`, and remaining product tests to invoke compiled Rust executable.
3. Map every Node behavior row to one passing Rust evidence row.
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

Existing three-build allowance is exhausted. 0/3 is current authority; no installer builds remain authorized. Reaching 100% requires two successful installer builds: one before Node deletion and one after deletion. Those two builds proceed only when Adrian grants at least two new builds, and only after static gates pass (compile check, tests, parity fixtures, build evidence). The compile gate is already satisfied per receipt `92701651-ded9-49d9-b22e-55b9c35718f5`. A granted-build failure returns work to source diagnosis and cached check/test gates; it never triggers an immediate build loop, and each further build requires fresh authorization.

## 100% definition

100% means one compiler-clean, test-green Rust product; 100% of rows in the hashed behavior-row manifest passing against the compiled executable in both pre-cutover and deleted-Node installed proofs; no Node Legion runtime; two installed-product proofs in required order; green enforce gate; final cutover committed. Source presence or successful compilation alone never counts as completion.
