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
  "check-skill-evals"
  "run-skill-evals"
  "check-retirements"
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
  "check-native-cli-surface --phase enforce"
)
for check in "${checks[@]}"; do
  read -r -a check_args <<< "$check"
  cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- "${check_args[@]}"
done

# The managed regenerate lane runs this gate on Linux to prove its pull
# request is consistent: derived-artifact checks above plus formatting. Full
# compile, test and installer validation stays on the Windows and macOS legs.
if [[ "${RUNNER_OS:-}" == "Linux" ]]; then
  (cd engine && cargo fmt --all -- --check)
  exit 0
fi

# Format and lint gate (formerly the ci.yml lint job): rustfmt drift and
# clippy::correctness findings fail the build; other warnings are allowed.
(cd engine && cargo fmt --all -- --check)

if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  (
    cd engine
    cargo clippy --workspace --all-targets --locked --keep-going -- -A warnings -D clippy::correctness
    cargo check --workspace --all-targets --locked
    cargo test --locked --no-fail-fast
  )
fi

# Planted-defect recall gate (formerly the ci.yml bench job). Runs on the
# macOS leg because dead-code, duplication and type checks must run inside
# sandbox-exec; provisions the scanners so a tool-missing class fails
# instead of skipping green.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  brew install gitleaks
  npm install -g knip jscpd typescript
  gitleaks version; knip --version; jscpd --version; tsc --version
  (cd engine && cargo test --locked -p legion-audit --test bench_recall -- --ignored --nocapture)
fi

# Apple bundle integrity (formerly apple-skills.yml): the workspace test run
# above already covers legion-apple, apple_skill_integrity, apple_cli,
# role_host_binding and canonical_mcp_schema; the enforce-phase native CLI
# surface check in the list above was the only step not already in this gate.

# Assemble the exact CI candidate and smoke the installed native CLI.
(cd engine && cargo build --locked --bins)
cargo run -q --locked --release --manifest-path engine/Cargo.toml -p xtask -- assemble-native-release --profile debug --out "${RUNNER_TEMP}/legion-install" --force
cargo run -q --locked --release --manifest-path engine/Cargo.toml -p xtask -- native-installed-smoke "${RUNNER_TEMP}/legion-install"

# Unsigned Windows development installer (formerly windows-development.yml);
# the managed ci.yml uploads dist/local-windows/installer/* as dev-windows-<sha>.
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  pwsh -NoProfile -NonInteractive -File scripts/release/local-windows-development.ps1 -BuildOnly
fi

# Known-answer recall gate. The bench scores planted defects against
# negative controls and fails on any false positive, so a detector that
# flags everything cannot pass. It was lost when the skill became a
# product and the conformance suite has been dead at its ninth case since.
# Recall, provider-selection, and conformance gates now run as native Rust
# integration tests covered by `cargo test` above:
#   engine/crates/legion-audit/tests/bench_recall.rs
#   engine/crates/legion-audit/tests/provider_selection_benchmark.rs
#   engine/crates/legion-audit/tests/audit_conformance.rs
