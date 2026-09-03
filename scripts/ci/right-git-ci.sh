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
node tests/run-audit-conformance-tests.mjs

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    cargo test --locked
    cargo build --locked --bins
  )

  pnpm native:assemble -- --profile debug --out "${RUNNER_TEMP}/legion-install" --force
  node scripts/ci/native-installed-smoke.mjs "${RUNNER_TEMP}/legion-install"
fi
