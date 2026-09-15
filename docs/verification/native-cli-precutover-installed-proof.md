# Native CLI pre-cutover installed proof

**Purpose:** First local unsigned build, stable install, & installed parity before Node deletion.
**Source revision:** `23b4bba800bf220f1c140479b8e4836c89e6d41c` plus current working tree.
**Manifest:** 141 rows, SHA-256 `bd5cd3076779e7fb6972925a66ed993b9e309753747a6bbf04019325ab573806`.

## Pre-build evidence

- Node capture: 141/141 captured.
- Rust diagnostic: 141/141 matched; 0 mismatched, blocked, missing, or unexpected.
- Inventory: 41 commands; 35 subcommands; 0 stubs, partials, divergent, unknown, uncharacterized, or nested-route mismatches.
- Parity/surface tests: 30/30 passed.
- Locked release all-target compiler gate: passed through RightKit receipt `766c47de-d703-4fcc-863b-cfa70392b088`.
- Managed cache: `D:\.rightkit-managed\rightkit-build-control\ws\19d3fa2de785\g\005\target`.
- Inno compiler: `C:\Users\adrds\AppData\Local\Programs\Inno\ISCC.exe`.
- Authorization: `.rightkit-local-development.json` exists for local unsigned Windows installer work.

## Path trace

| Stage | Input | Expected output | Failure boundary |
| --- | --- | --- | --- |
| Build | `engine/Cargo.toml`, lockfile, Rust sources | Three release binaries in managed cache | compile, lock, cache provenance |
| Assembly | `scripts/assemble-native-release.mjs` | `dist/native/windows-x86_64/legion-0.3.14` | stale binary, missing asset/plugin/catalog |
| Installer | `scripts/release/windows/finalize-installer.mjs` | unsigned setup EXE under `dist/local-windows/installer` | Inno, payload, digest |
| Isolated qualification | `scripts/release/windows/qualify-installed.mjs` | qualified evidence under `dist/local-windows/qualification` | activation, CLI/hook/MCP/projection |
| Stable install | setup EXE | `%LOCALAPPDATA%\Orthic Labs\Legion\current` | rollback, stable-current binding, projection repair |
| Installed parity | `scripts/native-cli/run-installed-parity.mjs` | 141/141 against stable installed executable | Node fallback, manifest/provenance, output/mutation divergence |

Node runtime remains present until this proof passes. No signing, CI, publication, or Node deletion is part of this build.

## Build & install result

- `pnpm run release:local:win:unsigned`: build, assembly, unsigned installer, & isolated qualification passed.
- RightKit build receipt: `bdca23ae-58f5-4e1d-b82d-491fc92b50e8` (cached compile: 0.27s).
- Assembled runtime SHA-256: `f112696ba9b9fa7d42b19e0a82c89d4f15feae1ac853429ae0b0bfcb5f2032d4`.
- Installer: `dist/local-windows/installer/Legion-0.3.14-windows-x86_64-setup.exe`, SHA-256 `21ac61864aecb86893b101045161f96e21df6cc164c7f20912035e7fcd10e65e`.
- Isolated installer qualification: passed, including repair, status, doctor, Codex opt-in, forced-refresh rollback, stalled-child rollback, & uninstall.
- First stable activation timed out during `client-refresh`; installer rollback succeeded. Reusing the same setup after projections settled installed successfully with exit 0.
- Stable installed executable: `%LOCALAPPDATA%\Orthic Labs\Legion\current\bin\legion.exe`, version `0.3.14`.
- Installed executable SHA-256 equals assembled runtime SHA-256 exactly.
- Stable setup status: `complete`; stable current, Claude, Codex, Cursor, & Antigravity projections are current.

## Remaining proof defect

`pnpm run native-cli:parity-installed` initially stopped before executing parity rows because `local-verification.json` lacked `sourceTreeSha256`, manifest identity, installed executable digest, & installed origin. `scripts/native-cli/gate.mjs` requires those fields; `scripts/release/local-windows-development.mjs` now writes them.

## Build 2 preflight

- Evidence producer now records source-tree, manifest, installed executable, & installed-origin identity; focused tests pass 11/11.
- Installed parity executed 141 rows: 138 matched; only Codex harness verify/install/uninstall failed.
- Failure path: installed root resolves to `current/plugin`; harness registry lookup requires `plugin/share/legion/src/registry/host-projection.json`; assembly omitted that generated runtime asset.
- Repair: copy canonical `src/registry/host-projection.json` into exact installed plugin path & assert assembly source contains both destination & copy.
- Expected build 2 result: packaged file exists, stable installer activates, & all 141 installed rows match.

## Build 2 result

- Local unsigned build, assembly, isolated qualification, & stable install passed.
- RightKit build receipt: `ab54430f-43b4-4181-b9f7-82e5d342dfb7`.
- Installed parity: 141/141 matched.
- Installed-root assertion: every Codex skill link resolves under installer-owned stable `current/plugin/skills`; checkout root is rejected.

## Final cutover preflight

- Node product runtime deleted: `src/bin/legion.mjs`, `src/lib/cli/**`, obsolete Node host runtime, semantic evaluators, & paired tests.
- Frozen Node observations retained as compressed, immutable parity input at `tests/native-cli-characterization/node-baselines.br.json`.
- Installed/product tests resolve only installer-owned stable `current/bin/legion.exe`.
- Native surface enforcement: 0 Node runtime files.
- Inventory: 41/41 commands characterized; 0 stubs, partials, divergent, unknown, uncharacterized, or nested-route mismatches.
- Package closure uses workspace-pinned pnpm; no ambient npm dependency.
- Final build risk trace: compile → assembly asset closure → installer creation → isolated lifecycle qualification → stable activation → installed-only 141-row parity → stable CLI/hook/MCP/projection checks.
