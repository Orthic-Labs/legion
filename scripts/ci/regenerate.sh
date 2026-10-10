#!/usr/bin/env bash
# Regenerates every derived artifact that the gate checks with --check,
# formats the Rust workspace and repairs a stale Cargo.lock. Runs only in the
# right-git managed `regenerate` lane, which opens a pull request with the
# result; nothing here commits or pushes.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Run regeneration through the managed GitHub workflow." >&2
  exit 1
fi

if ! cargo metadata --locked --format-version 1 --manifest-path engine/Cargo.toml > /dev/null; then
  echo "Cargo.lock is out of date; updating workspace members only."
  (cd engine && cargo update -w)
fi

dev() { cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- "$@"; }
dev generate-schemas
dev generate-codex-skill-sidecars
dev generate-skill-catalog
dev generate-host-projection
bundles=()
for skill_md in skills/*/SKILL.md; do
  bundles+=("$(basename "$(dirname "$skill_md")")")
done
dev refresh-local-skill-manifests "${bundles[@]}"
dev generate-manifest
dev generate-catalogs
dev native-cli-inventory

(cd engine && cargo fmt --all)
