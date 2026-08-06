# Changelog

All notable changes to Nemesis are recorded here.

## [0.1.0-dev.0] — PR44 (full qualification)

- Added the full qualification runner (`scripts/qualify-release.mjs`) producing
  a versioned qualification bundle with an honest RELEASE/BLOCKED/
  INTERNAL_ONLY decision.
- Added the signed/notarized/attested release pipeline outlines for macOS,
  Windows, Linux, Homebrew, and winget channels; every channel is gated by the
  publication policy guard.
- Completed the end-to-end security lifecycle: model → candidates → attack
  paths → independent adjudication → variants → evidence synthesis → report.
- Qualification at PR44 reports `BLOCKED`: one preserved baseline test
  (`tests/provider-architecture.test.mjs` binding verification) plus the
  closed publication policy. No false-clean claim is possible.

## [0.1.0-dev.0] — PR05

- Added canonical `@orthic-labs/nemesis` package manifest with `nemesis` binary.
- Added `bin/nemesis.mjs` CLI entrypoint with subcommands `init`, `doctor`,
  `languages`, `providers`, `plan`, `audit`, `verify`, `explain`, `report`,
  `hooks`, `mcp`.
- Added stable exit taxonomy (0 pass, 1 policy fail, 2 incomplete, 3 internal,
  4 usage, 5 integrity) in `lib/errors.mjs`.
- Added public library surface `lib/index.mjs` exporting versioned core
  contracts.
- Existing top-level scripts remain compatibility entrypoints calling the same
  core surfaces during the deprecation window.

### PR00–PR04 (trust repair)

- Fixed out-of-band verification to compare a stable semantic projection
  instead of raw `facts.json` bytes (`PR01`).
- Centralized provider/security contracts and generated schemas (`PR02`).
- Enforced candidate-provider authority from the frozen plan record and
  replaced legacy `operator-audit` identity with Orthic Labs Nemesis (`PR03`).
- Added self-contained CI, publication guards, benchmark baseline, and
  standalone-checkout tests (`PR04`).
