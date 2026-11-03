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

# Capsule preflight, bounded Ember audit and the A/A behavior benchmark ran the assembled CLI
# through LEGION_PROVIDER_REGISTRY, a dev switch that was deleted with every debug-only path
# (Adrian: debug assertions gone). They return only when they run against a real installed home
# as end-to-end cases (Orthic-Labs/legion#118).

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
