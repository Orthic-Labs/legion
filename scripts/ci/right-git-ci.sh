#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Run this build gate through the managed GitHub workflow." >&2
  exit 1
fi

# Remove only empty IPC storage: failed process-tree reaping deliberately
# retains live namespaces. Never recursively remove them from an EXIT trap.
legion_ci_ipc_storage=""
cleanup_ci_storage() {
  local status=$?
  if [[ -n "${regen_log:-}" ]]; then rm -f "$regen_log"; fi
  if [[ -n "${regen_patch:-}" ]]; then rm -f "$regen_patch"; fi
  if [[ -n "$legion_ci_ipc_storage" ]]; then
    if ! rmdir "$legion_ci_ipc_storage"; then
      printf 'Preserving IPC run storage: %s\n' "$legion_ci_ipc_storage" >&2
    fi
  fi
  return "$status"
}
trap cleanup_ci_storage EXIT

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

# Dependency-independent deterministic checks run first, before installation,
# regeneration and compilation, so a defect fails in seconds instead of after the
# build. They need only Python, rustfmt and the committed tree; each keeps the
# fail-closed set -e semantics. Later checks run right after their prerequisites.
export PYTHONDONTWRITEBYTECODE=1
(cd engine && cargo fmt --all -- --check)
if [[ "${RUNNER_OS:-}" == "Linux" ]]; then
  python3 scripts/ci/audit-qualification-records.py --root "$GITHUB_WORKSPACE" --check
fi

pnpm install --frozen-lockfile

if [[ "$regenerate_workflow" != "true" ]]; then
  regen_log="$(mktemp)"
  regen_patch="$(mktemp)"
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
  exit 0
fi

# RUNNER_TEMP may have ACL-bearing ancestors. Provision short private IPC
# storage explicitly; native validation still rejects every nonempty ancestor
# ACL, symlink, foreign owner or unsafe mode. Keep artifacts in RUNNER_TEMP.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  legion_ci_ipc_storage="$(mktemp -d /private/tmp/li-ci.XXXXXXXX)"
  chmod 700 "$legion_ci_ipc_storage"
  export LEGION_CI_IPC_STORAGE="$legion_ci_ipc_storage"
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

# Lint gate (formerly the ci.yml lint job): clippy::correctness findings fail
# the build; other warnings are allowed. rustfmt drift is checked at the top.

# Preserve independent qualification evidence after a workspace failure;
# every command records its own status before the installer delivery barrier.
workspace_failures=0
if [[ "${RIGHT_GIT_RUST_CHANGED:-true}" == "true" ]]; then
  if (cd engine && cargo clippy --workspace --all-targets --locked --keep-going -- -A warnings -D clippy::correctness); then
    :
  else
    workspace_status=$?
    workspace_failures=$((workspace_failures + 1))
    printf '::error::Workspace clippy failed (exit %s).\n' "$workspace_status" >&2
  fi
  if (cd engine && cargo check --workspace --all-targets --locked); then
    :
  else
    workspace_status=$?
    workspace_failures=$((workspace_failures + 1))
    printf '::error::Workspace check failed (exit %s).\n' "$workspace_status" >&2
  fi
  if (cd engine && cargo test --locked --no-fail-fast); then
    :
  else
    workspace_status=$?
    workspace_failures=$((workspace_failures + 1))
    printf '::error::Workspace tests failed (exit %s).\n' "$workspace_status" >&2
  fi
fi

# Canonical checks above already built this exact legion-dev. Reuse it;
# qualification adds no target, dependency or build admission.
ci_target_root="$(cargo metadata --locked --no-deps --format-version 1 --manifest-path engine/Cargo.toml | node -e 'let input=""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => console.log(JSON.parse(input).target_directory.replace(/\\/g, "/")));')"
ci_binary_root="${ci_target_root}${CARGO_BUILD_TARGET:+/${CARGO_BUILD_TARGET}}/debug"
case "${RUNNER_OS:-}" in
  macOS) ci_dev_helper="${ci_binary_root}/legion-dev" ;;
  Windows) ci_dev_helper="${ci_binary_root}/legion-dev.exe" ;;
  *) echo "Unsupported native helper retention platform: ${RUNNER_OS:-unset}" >&2; exit 1 ;;
esac
if [[ ! -f "$ci_dev_helper" ]]; then
  echo "Compiled CI qualification owner helper missing: $ci_dev_helper" >&2
  exit 1
fi
audit_native_command() {
  "$ci_dev_helper" ci-qualification-child --sequence "${sequence:?qualification span missing}" -- "$@"
}
# Keep provisioning functions in this shell: their exports feed later controls.
# Native leaves inside composed test functions use audit_native_command too.
audit_qualification_dispatch() {
  if declare -F "$1" >/dev/null; then
    "$@"
  else
    audit_native_command "$@"
  fi
}

audit_qualification_failures=0
audit_qualification_sequence=0
audit_cargo_bin="$(command -v cargo)"
audit_runtime_app_qualification() {
  audit_native_command "$audit_cargo_bin" test --locked --manifest-path engine/Cargo.toml -p legion \
    --test runtime_app_accuracy real_runtime_app_accuracy -- --ignored --exact --nocapture --test-threads=1
}

run_audit_qualification() {
  audit_qualification_sequence=$((audit_qualification_sequence + 1))
  local sequence="$audit_qualification_sequence"
  python3 - "$sequence" "$@" <<'PY'
import json
import sys
print("AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps(
    {"sequence": int(sys.argv[1]), "argv": sys.argv[2:]},
    sort_keys=True, separators=(",", ":")))
PY
  local status=0
  if audit_qualification_dispatch "$@"; then
    status=0
  else
    status=$?
    audit_qualification_failures=$((audit_qualification_failures + 1))
    printf '::error::Audit qualification command failed (exit %s): %s\n' "$status" "$*" >&2
  fi
  printf 'AUDIT_QUALIFICATION_COMMAND_END %s %s\n' "$sequence" "$status"
  # Runner disk after each control: run39520170497 macOS died of ENOSPC mid-gate.
  printf 'AUDIT_QUALIFICATION_DISK %s %s\n' "$sequence" "$(df -k . 2>/dev/null | tail -1 | tr -s ' ')"
  # Continue independent controls, then refuse delivery below if any failed.
  return 0
}

printf 'AUDIT_QUALIFICATION_DISK 0 %s\n' "$(df -k . 2>/dev/null | tail -1 | tr -s ' ')"

if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  # Runtime app accuracy: the real runtime-app test target and its validator.
  export LEGION_RUNTIME_APP_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/runtime-app"
  mkdir -p "$LEGION_RUNTIME_APP_RECEIPTS"
  run_audit_qualification audit_runtime_app_qualification
  run_audit_qualification python3 scripts/ci/audit-runtime-app-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_RUNTIME_APP_RECEIPTS"
  unset LEGION_RUNTIME_APP_RECEIPTS
fi

# Assemble the exact CI candidate and smoke the installed native CLI.
export CARGO_INCREMENTAL=1
(cd engine && cargo build --locked --bins)
ci_dev_helper_dir="${RUNNER_TEMP}/legion-provider-qualification/native-helper"
ci_dev_helper_copy="${ci_dev_helper_dir}/$(basename "$ci_dev_helper")"
mkdir -p "$ci_dev_helper_dir"
python3 - "$ci_dev_helper" "$ci_dev_helper_copy" "$RUNNER_OS" "${RUNNER_ARCH:-unknown}" "$GITHUB_SHA" <<'PY'
import hashlib
import json
import shutil
import stat
import sys
from pathlib import Path

source, destination = Path(sys.argv[1]), Path(sys.argv[2])
platform_os, platform_arch, revision = sys.argv[3:]
if source.is_symlink() or not source.is_file():
    raise SystemExit(f"already-built legion-dev helper is missing or not a regular file: {source}")
shutil.copy2(source, destination)
source_bytes, retained_bytes = source.read_bytes(), destination.read_bytes()
source_sha = hashlib.sha256(source_bytes).hexdigest()
retained_sha = hashlib.sha256(retained_bytes).hexdigest()
if source_sha != retained_sha or len(source_bytes) != len(retained_bytes):
    raise SystemExit("retained legion-dev helper does not match built source bytes")
record = {
    "source": str(source),
    "sourceSHA": source_sha,
    "sourceRevision": revision,
    "platform": {"os": platform_os, "architecture": platform_arch},
    "SHA256": retained_sha,
    "bytes": len(retained_bytes),
    "mode": stat.S_IMODE(source.stat().st_mode),
}
(destination.parent / "legion-dev.json").write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
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
    run_audit_qualification python3 scripts/ci/audit-capsule-preflight.py \
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
  run_audit_qualification python3 "${GITHUB_WORKSPACE}/scripts/ci/audit-ember-bounded.py" \
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

# Emit fresh native proof before asserting retained closures; stale closures still block delivery.
run_audit_qualification python3 scripts/ci/audit-qualification-records.py --root "$GITHUB_WORKSPACE" --check

if (( workspace_failures != 0 || audit_qualification_failures != 0 )); then
  printf 'CI checks failed: %s workspace command(s), %s Audit qualification command(s); refusing installer delivery.\n' \
    "$workspace_failures" "$audit_qualification_failures" >&2
  exit 1
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
