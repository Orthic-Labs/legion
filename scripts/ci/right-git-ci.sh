#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Run this build gate through the managed GitHub workflow." >&2
  exit 1
fi

pnpm install --frozen-lockfile
# Hosted runners own Cargo directly; local package scripts use the RightKit
# broker client, which is intentionally absent from hosted CI.
checks=(
  "check-canonical-names"
  "check-authority-parity"
  "check-blueprint-config"
  "check-portability"
  "check-version-parity"
  "generate-schemas --check"
  "check-dependency-closure"
  "check-publication-surface"
  "check-skill-references"
  "check-packed-import-closure"
  "check-distribution-contract"
  "check-release-obligations"
  "generate-codex-skill-sidecars --check"
  "generate-skill-catalog --check"
  "generate-host-projection --check"
  "refresh-local-skill-manifests --check"
  "generate-manifest --check"
  "generate-catalogs --check"
  "verify-plugin-parity --check --structural-only"
  "native-cli-inventory"
  "check-native-cli-surface"
)
for check in "${checks[@]}"; do
  read -r -a check_args <<< "$check"
  cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- "${check_args[@]}"
done

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    cargo check --workspace --all-targets --locked
    cargo test --locked
  )
fi

# Assemble the exact CI candidate and smoke the installed native CLI.
(cd engine && cargo build --locked --bins)
cargo run -q --locked --release --manifest-path engine/Cargo.toml -p xtask -- assemble-native-release --profile debug --out "${RUNNER_TEMP}/legion-install" --force
cargo run -q --locked --release --manifest-path engine/Cargo.toml -p xtask -- native-installed-smoke "${RUNNER_TEMP}/legion-install"

# Known-answer recall gate. The bench scores planted defects against
# negative controls and fails on any false positive, so a detector that
# flags everything cannot pass. It was lost when the skill became a
# product and the conformance suite has been dead at its ninth case since.
# Recall, provider-selection, and conformance gates now run as native Rust
# integration tests covered by `cargo test` above:
#   engine/crates/legion-audit/tests/bench_recall.rs
#   engine/crates/legion-audit/tests/provider_selection_benchmark.rs
#   engine/crates/legion-audit/tests/audit_conformance.rs
