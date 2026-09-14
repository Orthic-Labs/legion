# Native CLI build 2 preflight evidence

**Build budget:** 1/3 used
**Purpose:** Retry exact local unsigned compile→assembly→installer→stable-install path after build-1 compiler diagnosis.

## Path trace inherited & rechecked

Full source, cache, assembly, installer, activation, projection, and installed-qualification trace remains in `docs/verification/native-cli-build-1-evidence.md`. Build 1 reached managed Rust compilation, proving release script and RightKit admission paths. It did not reach assembly or installer.

## Build-1 failure closure

| Compiler failure | Exact repair | Repetition risk |
| --- | --- | --- |
| newline byte called `to_vec` | use one-byte vector | none; type is explicit |
| repair branch returned `Value` | bind/discard compare-and-swap result | `?` still preserves failure |
| proof field array length mismatch | declare actual 20 fields | authentication uses same field slice |

## Retry gates

- [x] No source broadening after diagnosis.
- [x] `git diff --check` passes.
- [x] Build remains exact `pnpm run release:local:win:unsigned`.
- [x] RightKit idle immediately before retry.

## Build 2 result

**Failed during managed Rust compilation; installer not reached.**

- RightKit request: `c81e465c-c774-4841-91e0-a09bbdf7540e`
- Elapsed: 25.847 seconds
- Failures were five localized type errors in newly added provider modules:
  - accessibility details helper destructured as tuple although it returns a map;
  - governance map-entry key type was ambiguous;
  - governance instant reference was dereferenced incorrectly;
  - security object helper supplied borrowed keys where owned keys are required;
  - architecture truthiness match omitted `Bool(true)`.
- All five repairs are direct type-contract corrections; no behavior or scope redesign.
