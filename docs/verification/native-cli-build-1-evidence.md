# Native CLI build 1 preflight evidence

**Build budget:** 0/3 used after 2026-09-14 07:13 IST authorization
**Build 1 state:** admitted for compile/install validation after static reconciliation

## 07:21 reconciliation finding

Initial Luna returns were not accepted as build-ready. Static review found shallow adapters in `contract`, governed-runtime, Audit, and metadata lanes that did not yet preserve all Node mutations, authentication, validation, outputs, and failures. Those lanes were returned for line-by-line parity work. Compiling now would knowingly spend a build on incomplete semantics.

- `node scripts/native-cli/inventory.mjs`: pass, 54 fixtures / 35 characterized commands / 0 uncharacterized Node commands.
- `node scripts/check-native-cli-surface.mjs --phase=record`: pass.
- `git diff --check`: pass.
- Coverage remains insufficient for the required 41-command Rust union and every subcommand/error path; coverage lane is expanding it before build.
- `contract` remains deliberately unwired until reachability, task budgets, host continuity, canonical keyring, executable-contract validation, and authenticated receipts are implemented.
- `node scripts/native-cli/capture-node-characterization.mjs`: 75/75 Node baseline fixtures pass expectation checks.
- `node scripts/native-cli/inventory.mjs`: 41/41 union commands characterized, 12 nested subcommands, 0 uncharacterized Node commands. Material mutation/error-path depth remains under lane review before build.
- `rightkit list`: Legion has no in-flight build, but one Membrane root build is running. Recheck immediately before build so Legion does not enter an expensive competing loop.
- No new product-local target exists; `engine/target` predates this work (last write 2026-08-26). Managed release route remains configured by `.rightkit-local-development.json`.
- Pre-cutover `node scripts/check-native-cli-surface.mjs --phase=enforce` reports exactly 34 expected Node-runtime files. This is deletion inventory, not a build failure; deletion remains gated on first installed parity proof.
- Audit executor trace found 29 production `runtime-script` providers still mapped to `src/providers/**.mjs`; native package ships none of those modules or Node runtime. Four disjoint Luna lanes now own code-language (10), architecture/framework (8), security/tooling (7), and legacy/governance (4) ports. Build remains blocked until native registry/executor integration covers all 29.
- `rightkit cargo metadata --locked --offline --format-version 1 --no-deps --manifest-path D:\Claude\legion\engine\Cargo.toml`: pass via managed broker; this was metadata only, not a build. Build budget remains 0/3.

## Intended outcome

One local unsigned Windows candidate built through `pnpm run release:local:win:unsigned`, installed to stable `current`, then exercised only through installed `legion.exe`.

## Source-to-installed path trace

| Stage | Source / control paths | Expected output | Failure risks to clear before build |
| --- | --- | --- | --- |
| Rust workspace graph | `engine/Cargo.toml`, `engine/Cargo.lock`, `engine/bins/legion/Cargo.toml` | One resolvable locked workspace | Missing member/dependency, stale lock, duplicate crate identity |
| Product command dispatch | `engine/bins/legion/src/cli.rs`, `engine/bins/legion/src/commands/mod.rs`, `engine/bins/legion/src/commands/*.rs` | Every union command reaches native implementation | Stub dispatch, private argument types, mismatched result/error types, lost exit semantics |
| Shared product semantics | `engine/crates/legion-*` | CLI, hook, and MCP share Rust-owned behavior | Node-only behavior omitted, duplicated state authority, incompatible receipts, checkout asset fallback |
| Characterization | `tests/native-cli-characterization/fixtures.json`, `scripts/native-cli/*` | Node baseline maps to Rust behavior | Missing subcommand/error path, nondeterministic fields compared literally, test silently invoking Node product CLI |
| Runtime exclusion | `scripts/check-native-cli-surface.mjs`, `src/bin/legion.mjs`, `src/lib/cli/**` | Record phase before parity; enforce phase after deletion | Premature deletion loses specification; late deletion leaves second runtime |
| Managed build/cache | `.rightkit-local-development.json`, `package.json`, RightKit broker | Warm external cache, one admitted root build | Concurrent root, local target fallback, direct Cargo, stale broker request, build-script recursion |
| Native assembly | `scripts/assemble-native-release.mjs`, release scripts | `legion.exe`, `legion-hook.exe`, `legion-mcp.exe`, assets, plugin | Wrong compiler artifact, stale binary, missing asset/catalog/plugin, repo-path leakage |
| Installer | `scripts/release/windows/legion.iss`, local Windows release route | Exact unsigned installer candidate | Inno failure, stale process lock, wrong version root, payload mismatch |
| Installed activation | `engine/crates/legion-runtime/src/release_binding.rs`, `engine/crates/legion-host/**` | Stable `%LOCALAPPDATA%\Orthic Labs\Legion\current` | Windows alias/LocalCache mismatch, broken ledger reclaim, projection drift, opt-in misclassification |
| Installed qualification | `scripts/release/windows/qualify-installed.mjs`, `scripts/native-cli/run-installed-parity.mjs` | Stable installed CLI/hook/MCP/projection/parity pass | Qualification tests staged bytes instead of installed bytes, Node fallback, incomplete command coverage, false clean |

## Required pre-build observations

- [x] All Luna lanes returned; owned diffs reconciled.
- [x] `contract` no longer uses common stub projection.
- [ ] Partial/unknown/divergent command wiring is source-complete for this candidate. Known exception: 32 legacy external checks require host-produced terminal receipts; 17 reasoning providers require host judgment receipts.
- [x] Every new crate/module is registered exactly once.
- [x] Static parsing, manifest metadata, Node syntax, and whitespace checks pass without compiling. Rustfmt reports style diffs in existing edited files, not parse failures.
- [x] Characterization inventory names every remaining unproven path.
- [x] RightKit reports no in-flight root build at 08:02 IST.
- [x] No product-local target/cache path was introduced.
- [x] Build command is exactly `pnpm run release:local:win:unsigned`.

Build 1 is not a parity claim. It validates compile, assembly, unsigned installer, activation, stable install, and installed qualification against the fully traced source. Any compile/installer failure will be recorded before repair; no blind rerun is allowed.

## Build 1 result

Failed during `native-release-build`; installer, activation, stable install, and parity did not run. RightKit request `9ae627dc-6e02-4e3d-a7a7-c7b28c830dfe`, elapsed 47.447 s, exit 101.

## Failure investigation

- `engine/crates/legion-arcane/src/budget.rs:270`: `u8` had no `to_vec`; corrected to `vec![b'\n']`.
- `engine/crates/legion-arcane/src/contract_lifecycle.rs:228`: conditional compare-and-swap returned `Value` where unit was required; result is now explicitly discarded after `?`.
- `engine/crates/legion-arcane/src/authority_invocation.rs:15`: bound-field array declared 21 but contained 20; declaration corrected to 20.
