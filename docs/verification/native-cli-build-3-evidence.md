# Native CLI build 3 preflight evidence

**Build budget:** 2/3 used
**Purpose:** Final permitted local unsigned compile→assembly→installer→stable-install attempt.

## End-to-end path trace

`pnpm run release:local:win:unsigned` drives managed RightKit Rust compilation, native release assembly, unsigned Inno packaging, stable-current installation, then installed qualification. Full source, cache, assembly, installer, activation, projection, and installed-qualification trace is recorded in `docs/verification/native-cli-build-1-evidence.md`.

## Build-2 failure closure

| Compiler failure | Exact repair | Repetition risk |
| --- | --- | --- |
| accessibility helper return treated as tuple | use returned details map directly | none; signature now matched |
| governance entry key inference | pass string literal without conversion | none; map API infers owned key |
| governance instant double dereference | pass existing string reference | none; function signature matched |
| security object borrowed keys | explicitly own each key | none; serde map contract matched |
| architecture truthy omitted true boolean | add explicit true arm | none; exhaustive match |

## Known downstream risks

- Compile may expose further errors hidden behind build-2 failures.
- Assembly must include `assets/registry/providers.json`; build script now copies it.
- Installer must activate only installer-owned stable `current`; no checkout fallback is allowed.
- Installed parity may expose semantic gaps even after successful packaging.
- Thirty-two legacy external-executor providers remain typed contracts rather than proven in-process executions; seventeen reasoning providers depend on host judgment receipts.
- Node deletion is prohibited until installed parity proves Rust coverage; one final build cannot honestly prove both pre-cutover and post-deletion installed states if the former fails.

## Final-attempt gates

- [x] Build-2 failure recorded with RightKit request ID.
- [x] Five compiler diagnoses repaired without scope expansion.
- [x] `git diff --check` passes.
- [x] Exact command remains `pnpm run release:local:win:unsigned`.
- [x] RightKit build lane is idle immediately before attempt.

## Build 3 result

**Failed during managed Rust compilation; installer not reached.**

- RightKit request: `89c0575e-329d-4b55-ac09-e6de3c86f2d3`
- Release phase elapsed: 16.030 seconds
- Failure: `engine/bins/legion/src/commands/run.rs:480` used unsupported JavaScript-style object spread inside Rust `json!`.
- Repair after failure: merge both object maps explicitly, then serialize `Value::Object`.
- Build budget is exhausted; repair is not compile-proven & no fourth attempt was started.

## Post-budget static evidence

- `git diff --check`: pass.
- Native inventory: 41/41 command union, 75 fixtures, 12 characterized subcommands, 0 uncharacterized Node commands, 0 Rust stubs, 2 Rust partial classifications (`assurance`, `audit`).
- Node characterization baseline rerun: 75/75 pass.
- Surface gate record phase: pass.
- Surface gate enforce phase: expected fail on 34 remaining Node runtime files; deletion was correctly withheld because installed Rust parity was never proven.
- Native provider dispatcher routes 29 ported runtime adapters, but its source rejects other providers with `requires typed host executor`; the 32-provider legacy contract registry is not wired into execution, while 17 reasoning providers still require host receipts.
- Installed product qualification, fresh install, upgrade, reinstall, hook, MCP, projection failure/repair, & post-cutover parity were not reached.
