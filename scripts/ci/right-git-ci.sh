#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Run this build gate through the managed GitHub workflow." >&2
  exit 1
fi

regenerate_workflow=false
if [[ "${GITHUB_WORKFLOW:-}" == "legion-regenerate" ]]; then
  regenerate_workflow=true
fi

if [[ "$regenerate_workflow" != "true" ]]; then
  if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "Refusing canonical regeneration: CI checkout is not clean before the gate." >&2
    exit 1
  fi
fi

pnpm install --frozen-lockfile

if [[ "$regenerate_workflow" != "true" ]]; then
  regen_log="$(mktemp)"
  regen_patch="$(mktemp)"
  trap 'rm -f "$regen_log" "$regen_patch"' EXIT
  if ! bash scripts/ci/regenerate.sh > "$regen_log" 2>&1; then
    cat "$regen_log" >&2
    echo "Canonical regeneration failed; stopping CI." >&2
    exit 1
  fi
  cat "$regen_log"

  if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    if [[ -n "$(git status --porcelain -- engine/Cargo.lock)" ]]; then
      echo "Cargo.lock drift: canonical lock update is included in the patch below."
    fi
    git diff --binary --no-ext-diff HEAD -- > "$regen_patch"
    while IFS= read -r -d '' path; do
      git diff --no-index --binary --no-ext-diff -- /dev/null "$path" >> "$regen_patch" || [[ "$?" -eq 1 ]]
    done < <(git ls-files --others --exclude-standard -z)
    echo "BEGIN_RIGHT_GIT_CANONICAL_REGEN_PATCH"
    cat "$regen_patch"
    echo "END_RIGHT_GIT_CANONICAL_REGEN_PATCH"
    echo "Canonical regeneration produced tracked or untracked changes; apply the patch and rerun CI." >&2
    exit 1
  fi
fi

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
  if cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- "${check_args[@]}"; then
    continue
  fi
  exit 1
done

# The managed regenerate lane runs this gate on Linux to prove its pull
# request is consistent: derived-artifact checks above plus formatting. Full
# compile, test and installer validation stays on the Windows and macOS legs.
if [[ "${RUNNER_OS:-}" == "Linux" ]]; then
  (cd engine && cargo fmt --all -- --check)
  exit 0
fi

# Provision pinned Chrome assets through RightKit before native qualification.
RIGHTKIT_CHROME_FOR_TESTING_ROOT="${RUNNER_TEMP}/rightkit-chrome-for-testing"
export RIGHTKIT_CHROME_FOR_TESTING_ROOT
RIGHTKIT_CHROME_FOR_TESTING="$(pnpm exec rightkit-qa-chrome install)"
export RIGHTKIT_CHROME_FOR_TESTING
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  RIGHTKIT_CHROME_HEADLESS_SHELL="$(pnpm exec rightkit-qa-chrome path --headless-shell)"
  export RIGHTKIT_CHROME_HEADLESS_SHELL
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

# Measure provider output separately from selection/routing & final adjudication.
# Run explicitly on both native hosts even when change detection skips workspace
# tests. Each registered provider must emit a current source/corpus-bound record.
export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-accuracy"
mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
(cd engine && cargo test --locked -p legion-audit \
  --test security_packs --test architecture_input_producer \
  --test code_provider_accuracy --test suite_provider_accuracy \
  --test legacy_file_accuracy --test artifact_provider_accuracy \
  file_only_provider_accuracy -- --nocapture --test-threads=1)
python3 scripts/ci/audit-provider-accuracy.py \
  --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
unset LEGION_PROVIDER_BENCHMARK_DIR

# Native fixture qualification is intentionally ignored by ordinary unit tests.
# Both native hosts must execute it after shared RightKit provisions pinned
# Chrome assets (plus Windows headless shell & sandbox ACLs). Require the exact
# two-test terminal count so a stale selector cannot pass without execution.
browser_fixture_log="${RUNNER_TEMP}/legion-native-fixture-qualification.log"
(cd engine && cargo test --locked -p legion-audit --lib native_fixture_qualification -- --ignored --nocapture --test-threads=1) 2>&1 | tee "$browser_fixture_log"
python3 - "$browser_fixture_log" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
results = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text, re.MULTILINE)
assert results and results[-1] == ("ok", "2", "0", "0"), results
print("Native browser fixture qualification: exactly two tests passed")
PY

# Planted-defect recall gate (formerly the ci.yml bench job). Runs on the
# macOS leg because dead-code, duplication and type checks must run inside
# sandbox-exec; provisions the scanners so a tool-missing class fails
# instead of skipping green.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  brew install gitleaks shellcheck zizmor kube-linter actionlint hadolint swiftlint
  # Official native Squawk release; avoid npm/Python wrapper substitutions.
  squawk_dir="${RUNNER_TEMP}/legion-scanners"
  mkdir -p "$squawk_dir"
  case "$(uname -m)" in
    arm64) squawk_asset=squawk-darwin-arm64; squawk_sha=6d96c07032109202a43802e212b2c592d48a11b208d661b2c8814a7eca4a984a ;;
    x86_64) squawk_asset=squawk-darwin-x64; squawk_sha=0369f5cc2beb7e224952d5d30068a92f9e23d65af99d7e7565c9a4fda916c379 ;;
    *) echo "Unsupported Squawk host architecture" >&2; exit 1 ;;
  esac
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://github.com/sbdchd/squawk/releases/download/v2.70.0/${squawk_asset}" \
    --output "$squawk_dir/squawk"
  printf '%s  %s\n' "$squawk_sha" "$squawk_dir/squawk" | shasum -a 256 --check
  chmod +x "$squawk_dir/squawk"
  export PATH="$squawk_dir:$PATH"
  npm install -g knip jscpd typescript
  gitleaks version; knip --version; jscpd --version; tsc --version
  (cd engine && cargo test --locked -p legion-audit --test bench_recall -- --ignored --nocapture)
  export LEGION_REAL_SCANNER_SCRATCH="${RUNNER_TEMP}/legion-real-scanner-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-external-provider-accuracy"
  mkdir -p "$LEGION_REAL_SCANNER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  (cd engine && cargo test --locked -p legion-audit --test external_scanner_accuracy \
    real_scanner_accuracy_shellcheck -- --ignored --nocapture --test-threads=1)
  python3 scripts/ci/audit-external-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-additional-scanner-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  (cd engine && cargo test --locked -p legion-audit --test additional_external_scanner_accuracy \
    real_scanner_accuracy -- --ignored --nocapture --test-threads=1)
  export LEGION_REAL_GIT_SCRATCH="${RUNNER_TEMP}/legion-real-git-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-real-git-accuracy"
  mkdir -p "$LEGION_REAL_GIT_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  (cd engine && cargo test --locked -p legion-audit --test legacy_git_accuracy \
    real_legacy_git_accuracy -- --ignored --nocapture --test-threads=1)
  python3 scripts/ci/audit-real-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" \
    --scanner-receipts "${RUNNER_TEMP}/legion-additional-scanner-accuracy" \
    --git-receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-squawk-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  (cd engine && cargo test --locked -p legion-audit --test more_external_scanner_accuracy \
    real_scanner_accuracy_squawk -- --ignored --nocapture --test-threads=1)
  export LEGION_REAL_LINTER_SCRATCH="${RUNNER_TEMP}/legion-real-linter-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-real-linter-accuracy"
  mkdir -p "$LEGION_REAL_LINTER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  (cd engine && cargo test --locked -p legion-audit --test real_legacy_linter_accuracy \
    real_legacy_linter_accuracy -- --ignored --nocapture --test-threads=1)
  unset LEGION_REAL_LINTER_SCRATCH
  unset LEGION_REAL_GIT_SCRATCH
  unset LEGION_REAL_SCANNER_SCRATCH LEGION_PROVIDER_BENCHMARK_DIR
fi

# Apple bundle integrity (formerly apple-skills.yml): the workspace test run
# above already covers legion-apple, apple_skill_integrity, apple_cli,
# role_host_binding and canonical_mcp_schema; the enforce-phase native CLI
# surface check in the list above was the only step not already in this gate.

# Assemble the exact CI candidate and smoke the installed native CLI.
export CARGO_INCREMENTAL=1
(cd engine && cargo build --locked --bins)
ci_target_root="$(cargo metadata --locked --no-deps --format-version 1 --manifest-path engine/Cargo.toml | node -e 'let input=""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => console.log(JSON.parse(input).target_directory.replace(/\\/g, "/")));')"
ci_binary_root="${ci_target_root}${CARGO_BUILD_TARGET:+/${CARGO_BUILD_TARGET}}/debug"
ci_xtask="${ci_binary_root}/xtask"
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  ci_xtask="${ci_xtask}.exe"
fi
test -f "$ci_xtask"
"$ci_xtask" assemble-native-release --profile debug --bin-dir "$ci_binary_root" --out "${RUNNER_TEMP}/legion-install" --force
"$ci_xtask" native-installed-smoke "${RUNNER_TEMP}/legion-install"

# Materialize isolated constructed semantic controls & native packets only.
# No model process, token reservation, reasoning execution or semantic score.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  LEGION_PROVIDER_REGISTRY="${RUNNER_TEMP}/legion-install/share/legion/assets/registry/providers.json" \
    python3 scripts/ci/audit-capsule-preflight.py \
      --root "$GITHUB_WORKSPACE" \
      --legion "${RUNNER_TEMP}/legion-install/bin/legion" \
      --out "${RUNNER_TEMP}/legion-capsule-preflight"
fi

# Real-repository affordability gate against a pinned public Ember checkout.
# The helper retains cold/warm plan-only cache checks, then runs one full
# deterministic audit with the same source, seat, run-token, call, and width caps.
# It validates bounded plan/facts artifacts and accepts exit 2 only with a
# persisted findings/incomplete report matching repository-audit-report output.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  python3 "${GITHUB_WORKSPACE}/scripts/ci/audit-ember-bounded.py" \
    --legion "${RUNNER_TEMP}/legion-install/bin/legion" \
    --provider-registry "${RUNNER_TEMP}/legion-install/share/legion/assets/registry/providers.json" \
    --runner-temp "${RUNNER_TEMP}"
fi

# Deterministic behavior benchmark: record a reproducible A/A × 2 sample against
# the assembled installed CLI. This lane never invokes model reasoning.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  bench_json="${RUNNER_TEMP}/audit-bench-behavior-deterministic.json"
  provider_registry="${RUNNER_TEMP}/legion-install/share/legion/assets/registry/providers.json"
  test -f "$provider_registry"
  set +e
  LEGION_PROVIDER_REGISTRY="$provider_registry" \
    "${GITHUB_WORKSPACE}/engine/target/debug/legion-dev" audit-bench \
    --legion "${RUNNER_TEMP}/legion-install/bin/legion" \
    --fixture audit-behavior \
    --repeats 2 \
    --aa \
    --work-dir "${RUNNER_TEMP}/audit-bench-behavior-work" \
    --keep \
    --json > "$bench_json"
  bench_status=$?
  set -e
  # Print machine-readable output before either runner or assertion failures exit.
  cat "$bench_json"
  if (( bench_status != 0 )); then
    exit "$bench_status"
  fi
  python3 - "$bench_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)

assert result["fixtureSplits"]["audit-behavior"] == "tuning"
assert result["caseErrors"] == [], result["caseErrors"]
assert result["splitResults"]["tuning"]["aaBand"] is not None
expected_raw_location_hits = {
    "audit-redis-session-no-ttl": 1,
    "audit-executable-download-unpinned": 1,
    "audit-redis-two-locations": 2,
}
data_provider = "legacy.data.internal-suite"
binary_provider = "legacy.security.binary-pins"
expected_applicable_providers = {
    "audit-redis-session-no-ttl": {data_provider, binary_provider},
    "audit-executable-download-unpinned": {binary_provider},
    "audit-redis-two-locations": {data_provider, binary_provider},
    "audit-redis-session-valid-ttl": {data_provider, binary_provider},
    "audit-map-set-clean": {data_provider, binary_provider},
    "audit-docs-url-clean": set(),
}
for arm in ("armA", "armB"):
    runs = result[arm]["runs"]
    assert len(runs) == 2, (arm, len(runs))
    for run in runs:
        counts = run["counts"]
        assert counts["plannedCases"] == 6, (arm, counts)
        assert counts["completedCases"] == 6, (arm, counts)
        assert counts["failedCases"] == 0, (arm, counts)
        assert counts["items"] == 4, (arm, counts)
    interval = result["splitResults"]["tuning"]["repeatIntervals"][arm]["wallTimeMs"]
    assert interval["status"] == "reported-empirical-range", (arm, interval)

behavior_groups = [
    (key, cases)
    for key, cases in result["caseOutcomes"].items()
    if key.endswith("/audit-behavior")
]
assert len(behavior_groups) == 4, (len(behavior_groups), result["caseOutcomes"])
for key, cases in behavior_groups:
    assert len(cases) == 6, (key, len(cases))
    assert all(case["status"] == "completed" for case in cases.values()), (key, cases)
    run_key = key.split("/", 1)[0] + "/audit-behavior"
    metrics = result["caseMetrics"][run_key]
    for case_id, expected_providers in expected_applicable_providers.items():
        audit_scope = metrics[case_id]["report"]["auditScope"]
        assert audit_scope["kind"] == "selected-provider-stage", (case_id, audit_scope)
        assert audit_scope["selectedProviders"] == [
            "legacy.data.internal-suite",
            "legacy.security.binary-pins",
        ], (case_id, audit_scope)
        assert audit_scope["complete"] is True, (case_id, audit_scope)
        raw = metrics[case_id]["report"]["rawAudit"]["rawScannerCandidates"]
        assert {row["provider"] for row in audit_scope["providers"] if row["applicable"] is True} == expected_providers, (case_id, audit_scope)
        for row in audit_scope["providers"]:
            if row["provider"] not in expected_providers:
                assert row["selectionStatus"] == "not-applicable", (case_id, row)
                assert row["inspection"] == "not-inspected", (case_id, row)
                assert row["eligibleDenominator"] == 0, (case_id, row)
        assert raw["status"] == "available", (case_id, raw)
        assert {row["provider"] for row in raw["candidateProviders"]} == expected_providers, (case_id, raw)
        if not expected_providers:
            assert raw["evidenceState"] == "not-applicable", (case_id, raw)
            assert raw["inspection"] == "not-inspected", (case_id, raw)
        if case_id in expected_raw_location_hits:
            assert raw["score"]["counts"]["locationHits"] == expected_raw_location_hits[case_id], (case_id, raw)
    for case_id in ("audit-redis-session-valid-ttl", "audit-map-set-clean", "audit-docs-url-clean"):
        raw = metrics[case_id]["report"]["rawAudit"]["rawScannerCandidates"]
        assert raw["status"] == "available", (case_id, raw)
        assert raw["count"] == 0, (case_id, raw)

print("deterministic audit-behavior selected-provider A/A × 2 assertions passed")
PY
fi

# Unsigned Windows development installer (formerly windows-development.yml);
# the managed ci.yml uploads dist/local-windows/installer/* as dev-windows-<sha>.
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  pwsh -NoProfile -NonInteractive -File scripts/release/local-windows-development.ps1 \
    -BuildOnly -PreassembledRoot "${RUNNER_TEMP}/legion-install" -XtaskBinary "$ci_xtask"
fi

# Unsigned macOS development installer (formerly macos-development.yml): the
# canonical installer app with compile-time in-place development activation,
# wrapped around the payload assembled above. The managed ci.yml zips it as
# dev-mac-unsigned-<sha>; signing binds the mode inside its executable.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  python3 scripts/release/macos/test-fixed-install.py --output-root "$RUNNER_TEMP/legion-fixed-install"
  dev_app="dist/dev-macos/Legion Installer.app"
  mkdir -p "$dev_app/Contents/MacOS" "$dev_app/Contents/Resources"
  swiftc -parse-as-library -D LEGION_DEVELOPMENT_INSTALL scripts/release/macos/LegionInstaller.swift -framework Cocoa -o "$dev_app/Contents/MacOS/Legion Installer"
  cp -R "${RUNNER_TEMP}/legion-install" "$dev_app/Contents/Resources/payload"
  node -p 'require("./release/version.json").version' > "$dev_app/Contents/Resources/version.txt"
  /usr/libexec/PlistBuddy -c 'Add :CFBundleExecutable string Legion Installer' "$dev_app/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string com.orthiclabs.legion.installer' "$dev_app/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c 'Add :CFBundlePackageType string APPL' "$dev_app/Contents/Info.plist"
  node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileEvidence } from "@rightkit/release/macos-file-evidence.mjs";

const root = path.resolve("dist/dev-macos");
const manifest = JSON.parse(readFileSync("packaging/macos/dev-sign-manifest.json", "utf8"));
const files = manifest.entries.map(({ file }) => {
  if (typeof file !== "string" || path.isAbsolute(file) || path.win32.isAbsolute(file) || file.split(/[\\/]/).includes("..")) {
    throw new Error(`Unsafe development payload path: ${file}`);
  }
  const target = path.resolve(root, file);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error(`Unsafe development payload path: ${file}`);
  return { path: file, sha256: fileEvidence(target).sha256 };
});
writeFileSync(path.join(root, "payload.json"), `${JSON.stringify({ schema: 1, files }, null, 2)}\n`);
NODE
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
