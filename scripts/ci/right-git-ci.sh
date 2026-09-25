#!/usr/bin/env bash
set -euo pipefail

pnpm install --frozen-lockfile
pnpm legion:check

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    cargo check --workspace --all-targets --locked
    cargo test --locked
  )
fi

# Assemble the exact CI candidate and smoke the installed native CLI.
(cd engine && cargo build --locked --bins)
pnpm native:assemble --profile debug --out "${RUNNER_TEMP}/legion-install" --force
pnpm native:smoke "${RUNNER_TEMP}/legion-install"

# Known-answer recall gate. The bench scores planted defects against
# negative controls and fails on any false positive, so a detector that
# flags everything cannot pass. It was lost when the skill became a
# product and the conformance suite has been dead at its ninth case since.
# Recall, provider-selection, and conformance gates now run as native Rust
# integration tests covered by `cargo test` above:
#   engine/crates/legion-audit/tests/bench_recall.rs
#   engine/crates/legion-audit/tests/provider_selection_benchmark.rs
#   engine/crates/legion-audit/tests/audit_conformance.rs
