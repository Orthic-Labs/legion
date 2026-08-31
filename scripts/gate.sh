#!/usr/bin/env bash
set -euo pipefail

pnpm install --frozen-lockfile
pnpm legion:check
pnpm test

pnpm test:python

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    cargo test --locked
    cargo build --locked --bins
  )

  pnpm native:assemble -- --profile debug --out "${RUNNER_TEMP}/legion-install" --force
  node scripts/ci/native-installed-smoke.mjs "${RUNNER_TEMP}/legion-install"
fi
