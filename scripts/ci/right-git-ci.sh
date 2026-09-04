#!/usr/bin/env bash
set -euo pipefail

pnpm install --frozen-lockfile
pnpm legion:check
pnpm test

pnpm test:python

# Known-answer recall gate. The bench scores planted defects against
# negative controls and fails on any false positive, so a detector that
# flags everything cannot pass. It was lost when the skill became a
# product and the conformance suite has been dead at its ninth case since.
node bench/run-bench.mjs
node bench/run-provider-selection-benchmark.mjs
node tests/run-audit-conformance-tests.mjs

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    # Fail on a compile error before spending the test phase on it: a missing
    # dependency or a type mismatch used to surface only after the suite, or
    # later still in the installer build. Test compilation reuses this cache.
    cargo check --workspace --all-targets --locked
    cargo test --locked
    cargo build --locked --bins
  )

  pnpm native:assemble -- --profile debug --out "${RUNNER_TEMP}/legion-install" --force
  node scripts/ci/native-installed-smoke.mjs "${RUNNER_TEMP}/legion-install"
fi
