# Native CLI zero-loss cutover

**Status:** IN PROGRESS
**Objective:** One Legion product. `legion.exe` is the sole runtime. JavaScript remains only for build, generation, lint, and test harnesses.

## Invariants

1. **Product composition** — `legion.exe` always loads Legion assets from the installed or staged release root. The current working directory is only the repository being operated on, never an alternate runtime source.
2. **Union target** — Required behavior is the union of Node (32 help commands, 31 dispatched) and Rust (41 commands). No command redesign, deprecation, or grammar changes during port.
3. **Doctor** — Installed-health and workspace-diagnostics sections report independently. Missing workspace context is `not-applicable`, not failure.
4. **Proof** — Local unsigned Windows build → fresh install → full installed-product suite. No CI delay gates.
5. **Deletion** — Remove Node CLI immediately when parity passes. No temporary shim.

## Seven steps

| Step | Script / artifact | Status |
| --- | --- | --- |
| 1 Freeze inventory | `node scripts/native-cli/inventory.mjs` → `docs/plans/native-cli-behavior-inventory.md` | wired |
| 2 Node characterization | `node scripts/native-cli/capture-node-characterization.mjs` | wired |
| 3 Factory vs functionality | `scripts/check-native-cli-surface.mjs --phase=record` | wired |
| 4 Port to Rust core | `engine/bins/legion/src/commands/*` | in progress |
| 5 Move consumers/tests | characterization + `tests/**/*.test.mjs` | pending |
| 6 Installed proof | `node scripts/native-cli/run-installed-parity.mjs` | wired |
| 7 Enforce deletion | `scripts/check-native-cli-surface.mjs --phase=enforce` | pending |

## Port order (dependency)

1. `init`, topology projections (`inspect`, `targets`, `components`, `stacks`, `controls`)
2. Governed runtime (`contract`, `run`, `budget`, `governance`, `completion`)
3. Audit (`plan`, `audit`, `verify`, `report`, `fix`, `explain`)
4. Doctor + bind (workspace + installed sections)
5. Peripheral projections (`hooks`, `mcp`, `harness`, `authority`, `minimize`, `host`, `state`)
6. Reconcile divergent grammars (`rules`, `schedule`) without changing user-facing flags
7. Assurance cutoff → delete Node CLI → `--phase=enforce`

## Completion definition

- Every former Node behavior has a proven Rust mapping (characterization corpus green).
- `src/bin/legion.mjs` and `src/lib/cli/**` deleted.
- `check-native-cli-surface.mjs --phase=enforce` passes.
- `pnpm run release:local:win:unsigned` passes; installed parity suite passes on stable `legion.exe`.
