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

python3 -m unittest discover -s scripts/ci/tests -p test_audit_cargo_geiger_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_qualification_records.py
python3 -m unittest discover -s scripts/ci/tests -p test_semgrep_raw_record_digest.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_compatibility_report_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_supply_chain_native_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_backend_source_facts.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_code_long_tail_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_extra_provider_receipt_contract.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_opengrep_artifact_contract.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_cargo_deny_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_node_outdated_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p 'test_*sdk_adapter.py'
python3 -m unittest discover -s scripts/ci/tests -p test_c_family_sdk_bootstrap.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_reasoning_runtime_registration.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_runtime_app_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_capsule_preflight.py
python3 -m unittest discover -s scripts/ci/tests -p test_audit_visual_provider_accuracy.py
python3 -m unittest discover -s scripts/ci/tests -p test_quality_test_interruption.py

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
  python3 scripts/ci/audit-qualification-records.py --root "$GITHUB_WORKSPACE" --check
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

# Format and lint gate (formerly the ci.yml lint job): rustfmt drift and
# clippy::correctness findings fail the build; other warnings are allowed.
(cd engine && cargo fmt --all -- --check)

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
audit_cargo_test() {
  if [[ -n "${LEGION_DOTNET_CHILD_OUTPUT:-}" ]]; then
    (cd engine && audit_native_command python3 "$GITHUB_WORKSPACE/scripts/ci/run-dotnet-sdk-qualification-child.py" \
      --output-root "$LEGION_DOTNET_CHILD_OUTPUT" -- "$audit_cargo_bin" test --locked -p legion-audit "$@")
  else
    (cd engine && audit_native_command "$audit_cargo_bin" test --locked -p legion-audit "$@")
  fi
}
audit_runtime_app_qualification() {
  audit_native_command "$audit_cargo_bin" test --locked --manifest-path engine/Cargo.toml -p legion \
    --test runtime_app_accuracy real_runtime_app_accuracy -- --ignored --exact --nocapture --test-threads=1
}
# Build admission belongs to managed CI. Runner consumes only this exact prebuilt target.
audit_compatibility_report_qualification() {
  local metadata="${RUNNER_TEMP}/legion-compatibility-report-build.jsonl"
  local output="${RUNNER_TEMP}/legion-provider-qualification/compatibility-report"
  (cd engine && audit_native_command "$audit_cargo_bin" test --locked -p legion-audit --test compatibility_report_accuracy \
    --no-run --message-format=json > "$metadata") &&
    audit_native_command python3 scripts/ci/audit-compatibility-report-accuracy.py --build-messages "$metadata" --output "$output"
}
audit_effects_test() { (cd engine && audit_native_command "$audit_cargo_bin" test --locked -p legion-effects "$@"); }
# Full JVM/v1 proof uses shared owner's native profile & lifecycle controls first.
# A failed native prerequisite stops JVM commands; no network relaxation occurs.
audit_jvm_qualification() {
  audit_effects_test --lib gradle_sandbox::tests::gradle_bind_only_native_confinement \
    -- --ignored --exact --nocapture --test-threads=1 &&
    audit_cargo_test --test real_jvm_sdk_accuracy real_jvm_sdk_accuracy \
      -- --ignored --exact --nocapture --test-threads=1
}
provision_jvm_sdk() {
  local output="${RUNNER_TEMP}/legion-jvm-sdk-tools"
  audit_native_command python3 scripts/ci/provision-jvm-sdk.py --root "$output" || return "$?"
  export LEGION_JVM_SDK_ENROLLMENT_JSON="${output}/enrollment.json"
}

# Provision source-pinned PHP/Ruby tools against existing observed managed runtimes.
provision_php_ruby_sdk() {
  local output="${RUNNER_TEMP}/legion-php-ruby-sdk-tools"
  audit_native_command python3 -I -S -B scripts/ci/audit-php-ruby-sdk-bootstrap.py \
    --repository-root "$GITHUB_WORKSPACE" --output-root "$output" || return "$?"
  test -f "$output/exports.sh" || return 1
  . "$output/exports.sh"
}

# Provisioning refusal counts against delivery without stopping independent lanes.
provision_js_sdk() {
  unset LEGION_JS_SDK_ENROLLMENT
  local output="${RUNNER_TEMP}/legion-js-sdk-tools"
  local node enrollment
  node="$(command -v node)" || return "$?"
  enrollment="$(audit_native_command python3 scripts/ci/audit-javascript-sdk-bootstrap.py \
    --repository-root "$GITHUB_WORKSPACE" \
    --output-root "$output" --node "$node")" || return "$?"
  if [[ "$enrollment" != "$output/enrollment.json" || ! -f "$enrollment" || -L "$enrollment" ]]; then
    printf 'JavaScript SDK bootstrap enrollment missing or malformed.\n' >&2
    return 1
  fi
  export LEGION_JS_SDK_ENROLLMENT="$enrollment"
}

# Returned provisioning failures count without stopping independent controls.
provision_license_checker() {
  unset LEGION_LICENSE_TOOL_ROOT audit_license_tool_dir audit_license_node_dir
  local tool="${RUNNER_TEMP}/legion-license-checker-tool"
  local node node_dir
  # Remove prior official-entry alias before accepting any new provision.
  audit_native_command rm -f "$tool/bin/license-checker" || return "$?"
  audit_native_command mkdir -p "$tool/bin" "$LEGION_LICENSE_RECEIPTS/provision" || return "$?"
  node="$(command -v node)" || return "$?"
  node_dir="$(audit_native_command dirname "$node")" || return "$?"
  audit_native_command curl --fail --location --retry 0 --max-time 120 \
    https://registry.npmjs.org/license-checker/-/license-checker-25.0.1.tgz \
    --output "$LEGION_LICENSE_RECEIPTS/provision/license-checker-25.0.1.tgz" || return "$?"
  audit_native_command python3 - "$LEGION_LICENSE_RECEIPTS/provision/license-checker-25.0.1.tgz" <<'LICENSE_ASSET' || return "$?"
import hashlib
from pathlib import Path
import sys
assert hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() == "e0200853f53ff27b2418fe0e3497d50a4bb2a0978abe0ef6b86c80d92fc47363"
LICENSE_ASSET
  printf '%s\n' '{"name":"legion-license-tool-provision","version":"1.0.0","private":true}' > "$tool/package.json" || return "$?"
  audit_native_command pnpm --dir "$tool" add --ignore-scripts --save-exact \
    "$LEGION_LICENSE_RECEIPTS/provision/license-checker-25.0.1.tgz" || return "$?"
  audit_native_command python3 - "$tool" <<'LICENSE_ALIAS' || return "$?"
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
entry = (root / "node_modules/license-checker/bin/license-checker").resolve(strict=True)
assert entry.is_relative_to(root) and entry.is_file()
# Alias genuine published executable, never pnpm's generated .bin shell shim.
(root / "bin/license-checker").symlink_to(entry)
LICENSE_ALIAS
  audit_license_tool_dir="$tool"
  audit_license_node_dir="$node_dir"
  export LEGION_LICENSE_TOOL_ROOT="$tool"
}

audit_tflint_qualification() {
  audit_effects_test --lib scoped_ipc_ci_storage_requires_private_canonical_owned_root -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_rejects_long_paths_symlinks_modes_and_foreign_tools -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_native_acl_controls_empty_allow_deny_and_lookup_failure -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_failed_version_probe_preserves_lifecycle_and_namespace -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_native_confinement -- --ignored --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_timeout_and_cancel_cleanup_after_reaping -- --ignored --nocapture --test-threads=1 &&
    audit_cargo_test --test tflint_accuracy real_scanner_accuracy_tflint -- --ignored --nocapture --test-threads=1
}
# Shared Python scanners use reviewed binary-wheel closures in private CI tools
# storage. Each consumer calls this through run_audit_qualification before its
# scanner selector; exports remain in this shell for actual SDK enrollment.
provision_python_qualification_tool() {
  export PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
  unset PYTHONPATH PYTHONHOME
  local tool="$1"
  case "$tool" in pip-audit|semgrep) ;; *) return 2 ;; esac
  local output="${RUNNER_TEMP}/legion-python-tools/${tool}"
  audit_native_command python3 -I -S -B scripts/ci/provision-python-qualification-tools.py \
    --tool "$tool" --repository-root "$GITHUB_WORKSPACE" --output-root "$output" || return "$?"
  export LEGION_PYTHON_TOOL_ENROLLMENT="${output}/enrollment.json"
  local launcher
  launcher="$(audit_native_command python3 -I -S -B - "$LEGION_PYTHON_TOOL_ENROLLMENT" <<'PYTHON_LAUNCHER'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text())["launcher"]["path"])
PYTHON_LAUNCHER
)" || return "$?"
  if [[ "$tool" == "pip-audit" ]]; then
    export LEGION_PIP_AUDIT_BIN="$launcher"
  else
    export LEGION_SEMGREP_BIN="$launcher"
  fi
}
provision_code_sdk_vulnerability_tool() {
  local output="${RUNNER_TEMP}/legion-govulncheck"
  audit_native_command python3 scripts/ci/audit-govulncheck-bootstrap.py \
    --repository-root "$GITHUB_WORKSPACE" --output-root "$output" \
    --go-root "$LEGION_GO_ROOT" --go-archive "$LEGION_GO_ARCHIVE" || return "$?"
  local values
  values="$(audit_native_command python3 - "$output/enrollment.json" <<'CODE_SDK_ENV'
import json
import sys
from pathlib import Path
names = ["LEGION_GOVULNCHECK_BIN", "LEGION_GOVULNCHECK_DB_ROOT", "LEGION_GOVULNCHECK_DB_ARCHIVE", "LEGION_GOVULNCHECK_ENROLLMENT_JSON", "GOMODCACHE"]
values = json.loads(Path(sys.argv[1]).read_bytes())["environment"]
if set(values) != set(names) or any(not isinstance(value, str) or not Path(value).is_absolute() or any(c in value for c in "\0\t\r\n") for value in values.values()):
    raise SystemExit("Exact code SDK bootstrap environment missing or malformed")
print("\t".join(values[name] for name in names))
CODE_SDK_ENV
)" || return "$?"
  IFS=$'\t' read -r LEGION_GOVULNCHECK_BIN LEGION_GOVULNCHECK_DB_ROOT \
    LEGION_GOVULNCHECK_DB_ARCHIVE LEGION_GOVULNCHECK_ENROLLMENT_JSON GOMODCACHE <<< "$values" || return "$?"
  export LEGION_GOVULNCHECK_BIN LEGION_GOVULNCHECK_DB_ROOT LEGION_GOVULNCHECK_DB_ARCHIVE \
    LEGION_GOVULNCHECK_ENROLLMENT_JSON GOMODCACHE
}
# Native tools are provisioned by managed macOS runner owner. Enroll observed
# installed LLVM/CMake dependency roots; missing native tools fail this lane.
provision_c_family_sdk() {
  [[ "${RUNNER_OS}" == "macOS" && "${CI}" == "true" ]] || return 2
  local llvm_root cmake_root sdk_root homebrew_prefix dependency prefix
  homebrew_prefix="$(audit_native_command brew --prefix)" || return "$?"
  llvm_root="$(audit_native_command brew --prefix llvm)" || return "$?"
  cmake_root="$(audit_native_command brew --prefix cmake)" || return "$?"
  sdk_root="$(audit_native_command xcrun --sdk macosx --show-sdk-path)" || return "$?"
  local roots=(--runtime-root "$llvm_root" --runtime-root "$cmake_root")
  local dependencies
  dependencies="$(audit_native_command brew deps --installed --union llvm cmake)" || return "$?"
  while IFS= read -r dependency; do
    [[ -n "$dependency" ]] || continue
    prefix="$(audit_native_command brew --prefix "$dependency")" || return "$?"
    roots+=(--runtime-root "$prefix")
  done <<< "$dependencies"
  export LEGION_C_FAMILY_ENROLLMENT_JSON="${RUNNER_TEMP}/legion-provider-qualification/code-c-family-toolchain/enrollment.json"
  audit_native_command python3 scripts/ci/audit-c-family-sdk-bootstrap.py \
    --cmake "$cmake_root/bin/cmake" --ctest "$cmake_root/bin/ctest" \
    --clang "$llvm_root/bin/clang" --clangxx "$llvm_root/bin/clang++" \
    --clang-tidy "$llvm_root/bin/clang-tidy" --make /usr/bin/make \
    "${roots[@]}" --homebrew-prefix "$homebrew_prefix" --sdk-root "$sdk_root" --out "$LEGION_C_FAMILY_ENROLLMENT_JSON"
}
provision_dotnet_code_sdk() {
  audit_native_command python3 scripts/ci/provision-dotnet-qualification-tools.py \
    --root "${RUNNER_TEMP}/legion-dotnet-code-sdk-tools"
}
provision_python_code_sdk() {
  local output="${RUNNER_TEMP}/legion-python-code-sdk-tools"
  audit_native_command python3 scripts/ci/audit-python-sdk-bootstrap.py \
    --repository-root "$GITHUB_WORKSPACE" --output-root "$output" || return "$?"
  local values
  values="$(audit_native_command python3 - "$output/enrollment.json" <<'PYTHON_CODE_SDK_ENV'
import json
import sys
from pathlib import Path
names = ["LEGION_PYTHON_SDK_ENROLLMENT_JSON", "LEGION_PYTHON_SDK_PYTHON", "LEGION_PYTHON_SDK_BIN_DIR"]
values = json.loads(Path(sys.argv[1]).read_bytes())["environment"]
if set(values) != set(names) or any(not isinstance(value, str) or not Path(value).is_absolute() or any(c in value for c in "\0\t\r\n") for value in values.values()):
    raise SystemExit("Exact Python SDK bootstrap environment missing or malformed")
print("\t".join(values[name] for name in names))
PYTHON_CODE_SDK_ENV
)" || return "$?"
  IFS=$'\t' read -r LEGION_PYTHON_SDK_ENROLLMENT_JSON LEGION_PYTHON_SDK_PYTHON \
    LEGION_PYTHON_SDK_BIN_DIR <<< "$values" || return "$?"
  export LEGION_PYTHON_SDK_ENROLLMENT_JSON LEGION_PYTHON_SDK_PYTHON LEGION_PYTHON_SDK_BIN_DIR
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
  # Continue independent controls, then refuse delivery below if any failed.
  return 0
}

# Measure provider output separately from selection/routing & final adjudication.
# Run explicitly on both native hosts even when change detection skips workspace
# tests. Each registered provider must emit a current source/corpus-bound record.
export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-provider-accuracy"
mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
run_audit_qualification audit_cargo_test \
  --test security_packs --test architecture_input_producer \
  --test code_provider_accuracy --test suite_provider_accuracy \
  --test legacy_file_accuracy --test artifact_provider_accuracy \
  file_only_provider_accuracy -- --nocapture --test-threads=1
run_audit_qualification python3 scripts/ci/audit-provider-accuracy.py \
  --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
unset LEGION_PROVIDER_BENCHMARK_DIR

# Package-owned report producer -> v1/v2 reader/render; v1-core semantics only.
# Runtime compatibility & production admission remain unavailable.
run_audit_qualification audit_compatibility_report_qualification
run_audit_qualification python3 scripts/ci/validate-compatibility-report-accuracy.py \
  --root "$GITHUB_WORKSPACE" \
  --record "${RUNNER_TEMP}/legion-provider-qualification/compatibility-report/controls/compatibility.core.json"

# BEGIN ownership native qualification.
# Owner supplies canonical executable & committed fixture identities; trust remains
# verified by actual owner calls, native controls & separate strict validator.
if [[ ! ${LEGION_OWNERSHIP_NATIVE_OWNER+x} && ! ${LEGION_OWNERSHIP_FIXTURE_IDENTITIES+x} ]]; then
  printf 'OWNERSHIP_NATIVE_UNAVAILABLE: owner executable & fixture identities are unset; no qualification enrolled\n'
elif [[ "${RUNNER_OS:-}" != "macOS" ]]; then
  printf '::error::Configured ownership native qualification requires macOS\n' >&2
  audit_qualification_failures=$((audit_qualification_failures + 1))
else
  ownership_accuracy_dir="${RUNNER_TEMP}/legion-provider-qualification/ownership-native"
  if python3 - "${LEGION_OWNERSHIP_NATIVE_OWNER-}" "${LEGION_OWNERSHIP_FIXTURE_IDENTITIES-}" \
      "$GITHUB_WORKSPACE" "$ownership_accuracy_dir" <<'OWNERSHIP_PREREQUISITES'
import os
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


try:
    for value in sys.argv[1:3]:
        require(bool(value), "ownership prerequisite is empty or partially configured")
        path = Path(value)
        require(path.is_absolute() and str(path) == value and path.resolve(strict=True) == path
                and path.is_file(), "ownership prerequisite must be an absolute canonical file")
    require(os.access(sys.argv[1], os.X_OK), "native ownership owner must be executable")
    source = Path(sys.argv[3]).resolve(strict=True)
    output = Path(sys.argv[4])
    resolved = output.resolve()
    require(output.is_absolute() and resolved != source and source not in resolved.parents,
            "ownership retained output must stay outside repository")
    require(not output.is_symlink() and (not output.exists() or (output.is_dir() and not any(output.iterdir()))),
            "ownership retained output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
except (ValueError, OSError) as error:
    print("::error::Ownership native prerequisites refused: " + str(error), file=sys.stderr)
    sys.exit(1)
OWNERSHIP_PREREQUISITES
  then
    export LEGION_OWNERSHIP_NATIVE_OWNER LEGION_OWNERSHIP_FIXTURE_IDENTITIES
    export LEGION_OWNERSHIP_ACCURACY_OUTPUT="$ownership_accuracy_dir/controls"
    run_audit_qualification audit_cargo_test \
      --test ownership_native_accuracy ownership_native_sdk_known_answers \
      -- --ignored --exact --nocapture --test-threads=1 \
      > "$ownership_accuracy_dir/harness.log" 2>&1
    cat "$ownership_accuracy_dir/harness.log"
    run_audit_qualification python3 scripts/ci/validate-ownership-native-accuracy.py \
      --root "$GITHUB_WORKSPACE" --receipts "$ownership_accuracy_dir" \
      > "$ownership_accuracy_dir/validator.log" 2>&1
    cat "$ownership_accuracy_dir/validator.log"
    unset LEGION_OWNERSHIP_ACCURACY_OUTPUT
  else
    audit_qualification_failures=$((audit_qualification_failures + 1))
  fi
fi
# END ownership native qualification.

# Existing explicit visual provider: real pinned shared Chrome & retained PNGs.
# This is separate from file-only controls; no model or system Chrome fallback.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  visual_accuracy_dir="${RUNNER_TEMP}/legion-provider-qualification/visual"
  visual_accuracy_tmp="${RUNNER_TEMP}/legion-visual-tmp"
  mkdir -p "$visual_accuracy_dir" "$visual_accuracy_tmp"
  export LEGION_PROVIDER_BENCHMARK_DIR="$visual_accuracy_dir"
  # Redirect without a pipeline: preserve run_audit_qualification's failure count
  # in this shell, then replay actual log bytes into authenticated CI job output.
  TMPDIR="$visual_accuracy_tmp" run_audit_qualification audit_cargo_test \
    --test visual_accuracy real_browser_accuracy_visual_regression \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$visual_accuracy_dir/harness.log" 2>&1
  cat "$visual_accuracy_dir/harness.log"
  run_audit_qualification python3 scripts/ci/audit-visual-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" \
    > "$visual_accuracy_dir/validator.log" 2>&1
  cat "$visual_accuracy_dir/validator.log"
  unset LEGION_PROVIDER_BENCHMARK_DIR
fi

# Full cargo-geiger runs nested Cargo & target build scripts only in disposable CI scratch.
# Upstream has no binary assets: build exact unchanged commit using pinned workspace toolchain.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  geiger_dir="${RUNNER_TEMP}/legion-cargo-geiger-0.13.0"
  geiger_receipts="${RUNNER_TEMP}/legion-provider-qualification/cargo-geiger"
  mkdir -p "$geiger_receipts"
  geiger_toolchain_bin="$(rustc --print sysroot)/bin"
  run_audit_qualification python3 scripts/ci/provision-cargo-geiger.py \
    --directory "$geiger_dir" --toolchain-bin "$geiger_toolchain_bin" \
    > "$geiger_receipts/provision.log" 2>&1
  cat "$geiger_receipts/provision.log"
  export LEGION_CARGO_GEIGER_BIN="$geiger_dir/tools/bin/cargo-geiger"
  export LEGION_CARGO_GEIGER_TOOLCHAIN_BIN="$geiger_toolchain_bin"
  export LEGION_CARGO_GEIGER_PROVISION="$geiger_dir/provision.json"
  export LEGION_CARGO_GEIGER_RECEIPTS="$geiger_receipts"
  run_audit_qualification audit_cargo_test --test cargo_geiger_accuracy real_cargo_geiger_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$geiger_receipts/harness.log" 2>&1
  cat "$geiger_receipts/harness.log"
  run_audit_qualification python3 scripts/ci/audit-cargo-geiger-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$geiger_receipts" \
    > "$geiger_receipts/validator.log" 2>&1
  cat "$geiger_receipts/validator.log"
  unset LEGION_CARGO_GEIGER_BIN LEGION_CARGO_GEIGER_TOOLCHAIN_BIN
  unset LEGION_CARGO_GEIGER_PROVISION LEGION_CARGO_GEIGER_RECEIPTS
fi

# Constructed native SDK accuracy for structural.ast-grep. The pinned upstream
# release is verified before extraction; this remains fixture-only evidence.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  case "$(uname -m)" in
    arm64) ast_grep_asset=app-aarch64-apple-darwin.zip; ast_grep_asset_sha=e18e13c27ed6c4b3ec4de00745b0755dee9dc26c035e226f4dd5d147dca99cc8 ;;
    x86_64) ast_grep_asset=app-x86_64-apple-darwin.zip; ast_grep_asset_sha=8438fe549da59da28518c45bdaab5b851aabafe8fb4f8dc05c261a7649b4eca6 ;;
    *) echo "unsupported ast-grep qualification host: $(uname -m)" >&2; exit 1 ;;
  esac
  ast_grep_dir="${RUNNER_TEMP}/legion-ast-grep-0.51.0"
  ast_grep_receipts="${RUNNER_TEMP}/legion-provider-qualification/ast-grep"
  mkdir -p "$ast_grep_dir" "$ast_grep_receipts"
  curl --fail --location "https://github.com/ast-grep/ast-grep/releases/download/0.51.0/$ast_grep_asset" -o "$ast_grep_dir/$ast_grep_asset"
  printf '%s  %s\n' "$ast_grep_asset_sha" "$ast_grep_dir/$ast_grep_asset" | shasum -a 256 --check
  unzip -q "$ast_grep_dir/$ast_grep_asset" -d "$ast_grep_dir/unpacked"
  ast_grep_bin="$(find "$ast_grep_dir/unpacked" -type f -name ast-grep -perm -111 -print)"
  test "$(printf '%s\n' "$ast_grep_bin" | wc -l | tr -d ' ')" -eq 1
  export LEGION_AST_GREP_BIN="$ast_grep_bin"
  export LEGION_AST_GREP_ASSET_SHA256="sha256:$ast_grep_asset_sha"
  export LEGION_AST_GREP_FIXTURES="$GITHUB_WORKSPACE/engine/crates/legion-audit/tests/fixtures/ast-grep"
  export LEGION_AST_GREP_RUN_DIR="$ast_grep_receipts/run"
  export LEGION_AST_GREP_RECORD="$ast_grep_receipts/ast-grep-provider-accuracy.json"
  mkdir -p "$LEGION_AST_GREP_RUN_DIR"
  run_audit_qualification audit_cargo_test --test ast_grep_accuracy real_ast_grep_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$ast_grep_receipts/harness.log" 2>&1
  cat "$ast_grep_receipts/harness.log"
  run_audit_qualification python3 scripts/ci/audit-ast-grep-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$ast_grep_receipts" \
    > "$ast_grep_receipts/validator.log" 2>&1
  cat "$ast_grep_receipts/validator.log"
  unset LEGION_AST_GREP_BIN LEGION_AST_GREP_ASSET_SHA256 LEGION_AST_GREP_FIXTURES
  unset LEGION_AST_GREP_RUN_DIR LEGION_AST_GREP_RECORD
fi

# Real cargo-machete 0.9.1 controls; constructed SDK admission only.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  case "$(uname -m)" in
    arm64)
      machete_target=aarch64-apple-darwin
      machete_asset_sha=72355383848acb154060e6fea2d5b7d58a825ed49fef157b46a6fe25180f8638
      machete_binary_sha=76ce4dc236df8204d8c110a4d1164a3abe8240fd622ab7016bf02f901d113167 ;;
    x86_64)
      machete_target=x86_64-apple-darwin
      machete_asset_sha=fd0c0dbcc9db0c1b8745fe9dc4f273d838b04391c6e487d1146957bf687a9703
      machete_binary_sha=e1cfbe4e076a040b6fa394f52e94a3895ff4078a1dd435ab5ed641f145a4815e ;;
    *) echo "unsupported cargo-machete qualification architecture" >&2; exit 1 ;;
  esac
  machete_tool_dir="${RUNNER_TEMP}/legion-cargo-machete-0.9.1"
  machete_receipts="${RUNNER_TEMP}/legion-provider-qualification/cargo-machete"
  machete_asset="cargo-machete-v0.9.1-${machete_target}.tar.gz"
  machete_member="cargo-machete-v0.9.1-${machete_target}/cargo-machete"
  mkdir -p "$machete_tool_dir/bin" "$machete_tool_dir/unpacked" "$machete_receipts"
  curl --fail --location "https://github.com/bnjbvr/cargo-machete/releases/download/v0.9.1/$machete_asset" -o "$machete_tool_dir/$machete_asset"
  printf '%s  %s\n' "$machete_asset_sha" "$machete_tool_dir/$machete_asset" | shasum -a 256 --check
  tar -xzf "$machete_tool_dir/$machete_asset" -C "$machete_tool_dir/unpacked" "$machete_member"
  printf '%s  %s\n' "$machete_binary_sha" "$machete_tool_dir/unpacked/$machete_member" | shasum -a 256 --check
  cp "$machete_tool_dir/unpacked/$machete_member" "$machete_tool_dir/bin/cargo-machete"
  chmod 755 "$machete_tool_dir/bin/cargo-machete"
  export LEGION_CARGO_MACHETE_TOOLCHAIN_BIN="$(rustc +1.98.0 --print sysroot)/bin"
  export LEGION_CARGO_MACHETE_BINARY_SHA256="sha256:$machete_binary_sha"
  export LEGION_CARGO_MACHETE_ASSET_SHA256="sha256:$machete_asset_sha"
  export LEGION_CARGO_MACHETE_SCRATCH="${RUNNER_TEMP}/legion-cargo-machete-fixtures"
  export LEGION_CARGO_MACHETE_RECEIPTS="$machete_receipts"
  mkdir -p "$LEGION_CARGO_MACHETE_SCRATCH"
  PATH="$machete_tool_dir/bin:$PATH" run_audit_qualification audit_cargo_test \
    --test real_cargo_machete_accuracy real_cargo_machete_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$machete_receipts/harness.log" 2>&1
  cat "$machete_receipts/harness.log"
  run_audit_qualification python3 scripts/ci/audit-cargo-machete-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$machete_receipts" \
    > "$machete_receipts/validator.log" 2>&1
  cat "$machete_receipts/validator.log"
  unset LEGION_CARGO_MACHETE_TOOLCHAIN_BIN LEGION_CARGO_MACHETE_BINARY_SHA256
  unset LEGION_CARGO_MACHETE_ASSET_SHA256 LEGION_CARGO_MACHETE_SCRATCH LEGION_CARGO_MACHETE_RECEIPTS
fi

# Genuine pinned Syft SBOM/license controls. CI execution provenance never
# substitutes for audited-target build provenance; target gap remains required.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  case "$(uname -m)" in
    arm64)
      supply_chain_asset=syft_1.55.0_darwin_arm64.tar.gz
      supply_chain_asset_sha=1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625 ;;
    x86_64)
      supply_chain_asset=syft_1.55.0_darwin_amd64.tar.gz
      supply_chain_asset_sha=e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003 ;;
    *) echo "unsupported supply-chain native qualification architecture" >&2; exit 1 ;;
  esac
  supply_chain_tool_dir="${RUNNER_TEMP}/legion-syft-1.55.0"
  export LEGION_SUPPLY_CHAIN_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/supply-chain-native"
  mkdir -p "$supply_chain_tool_dir" "$LEGION_SUPPLY_CHAIN_RECEIPTS"
  curl --fail --location "https://github.com/anchore/syft/releases/download/v1.55.0/$supply_chain_asset" -o "$supply_chain_tool_dir/$supply_chain_asset"
  printf '%s  %s\n' "$supply_chain_asset_sha" "$supply_chain_tool_dir/$supply_chain_asset" | shasum -a 256 --check
  tar -xzf "$supply_chain_tool_dir/$supply_chain_asset" -C "$supply_chain_tool_dir" syft
  export LEGION_SYFT_BINARY="$supply_chain_tool_dir/syft"
  export LEGION_SYFT_ARCHIVE="$supply_chain_tool_dir/$supply_chain_asset"
  run_audit_qualification audit_cargo_test --lib \
    native_providers::security::producer::supply_chain_qualification_tests::native_supply_chain_qualification \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_SUPPLY_CHAIN_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_SUPPLY_CHAIN_RECEIPTS/harness.log"
  run_audit_qualification python3 scripts/ci/audit-supply-chain-native-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_SUPPLY_CHAIN_RECEIPTS" \
    > "$LEGION_SUPPLY_CHAIN_RECEIPTS/validator.log" 2>&1
  cat "$LEGION_SUPPLY_CHAIN_RECEIPTS/validator.log"
  unset LEGION_SYFT_BINARY LEGION_SYFT_ARCHIVE LEGION_SUPPLY_CHAIN_RECEIPTS
fi

# Real cargo-outdated 0.19.0 controls; constructed SDK admission only.
if [[ "${RUNNER_OS:-}" == "macOS" ]]; then
  case "$(uname -m)" in
    arm64)
      outdated_target=aarch64-apple-darwin
      outdated_asset_sha=c3a3ca56a748d94fdaa1f208c641685d996ee1c4954cd4fbe358b7c06a2186a5
      outdated_binary_sha=22003be477d106e10c285d11e677b680859fc72d1c0035fe599b3755ede231a8 ;;
    x86_64)
      outdated_target=x86_64-apple-darwin
      outdated_asset_sha=945b64728ae9021be49a70346424da7634d889f181f2d33af64c7bf95265f6d3
      outdated_binary_sha=63a2f5ffe56c7c7ad0e21eba87e4dcf7ebd757bc376c16d534caaa2d82ac127b ;;
    *) echo "unsupported cargo-outdated qualification architecture" >&2; exit 1 ;;
  esac
  outdated_tool_dir="${RUNNER_TEMP}/legion-cargo-outdated-0.19.0"
  outdated_receipts="${RUNNER_TEMP}/legion-provider-qualification/rust-outdated"
  outdated_asset="cargo-outdated-0.19.0-${outdated_target}.tar.gz"
  outdated_member="cargo-outdated"
  mkdir -p "$outdated_tool_dir/bin" "$outdated_tool_dir/unpacked" "$outdated_receipts"
  curl --fail --location "https://github.com/kbknapp/cargo-outdated/releases/download/v0.19.0/$outdated_asset" -o "$outdated_tool_dir/$outdated_asset"
  printf '%s  %s\n' "$outdated_asset_sha" "$outdated_tool_dir/$outdated_asset" | shasum -a 256 --check
  tar -xzf "$outdated_tool_dir/$outdated_asset" -C "$outdated_tool_dir/unpacked" "$outdated_member"
  printf '%s  %s\n' "$outdated_binary_sha" "$outdated_tool_dir/unpacked/$outdated_member" | shasum -a 256 --check
  cp "$outdated_tool_dir/unpacked/$outdated_member" "$outdated_tool_dir/bin/cargo-outdated"
  chmod 755 "$outdated_tool_dir/bin/cargo-outdated"
  export LEGION_RUST_OUTDATED_TOOLCHAIN_BIN="$(rustc +1.98.0 --print sysroot)/bin"
  export LEGION_RUST_OUTDATED_BINARY_SHA256="sha256:$outdated_binary_sha"
  export LEGION_RUST_OUTDATED_ASSET_SHA256="sha256:$outdated_asset_sha"
  export LEGION_RUST_OUTDATED_SCRATCH="${RUNNER_TEMP}/legion-cargo-outdated-fixtures"
  export LEGION_RUST_OUTDATED_RECEIPTS="$outdated_receipts"
  mkdir -p "$LEGION_RUST_OUTDATED_SCRATCH"
  PATH="$outdated_tool_dir/bin:$PATH" run_audit_qualification audit_cargo_test \
    --test real_rust_outdated_accuracy real_rust_outdated_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$outdated_receipts/harness.log" 2>&1
  cat "$outdated_receipts/harness.log"
  run_audit_qualification python3 scripts/ci/audit-rust-outdated-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$outdated_receipts" \
    > "$outdated_receipts/validator.log" 2>&1
  cat "$outdated_receipts/validator.log"
  unset LEGION_RUST_OUTDATED_TOOLCHAIN_BIN LEGION_RUST_OUTDATED_BINARY_SHA256
  unset LEGION_RUST_OUTDATED_ASSET_SHA256 LEGION_RUST_OUTDATED_SCRATCH LEGION_RUST_OUTDATED_RECEIPTS
fi

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
  brew install gitleaks shellcheck zizmor kube-linter kubeconform actionlint hadolint swiftlint ruby@3.3 php@8.4 llvm cmake
  # Brakeman's published gem includes its Ruby parser; use provisioned Ruby's
  # default gem directory because native scanner execution scrubs GEM_HOME.
  export PATH="$(brew --prefix ruby@3.3)/bin:$PATH"
  gem install brakeman --version 8.1.0 --no-document
  LEGION_BRAKEMAN_GEM_ROOT="$(ruby -rrubygems -e 'print Gem::Specification.find_by_name("brakeman", "=8.1.0").full_gem_path')"
  export LEGION_BRAKEMAN_GEM_ROOT
  export PATH="$LEGION_BRAKEMAN_GEM_ROOT/bin:$PATH"
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
  # Official TFLint archive includes its Terraform ruleset; never --init.
  case "$(uname -m)" in
    arm64) tflint_asset=tflint_darwin_arm64.zip; tflint_sha=2496e9cb3d24992d553b45e7c87a0fdc9449ca975233876247a9bfeda857e6c0 ;;
    x86_64) tflint_asset=tflint_darwin_amd64.zip; tflint_sha=0f3a9fd17526014646a2dfc3f9122f7b4161abe3d6b0f0f03f9014483ddf4d19 ;;
    *) echo "Unsupported TFLint host architecture" >&2; exit 1 ;;
  esac
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/${tflint_asset}" \
    --output "$squawk_dir/tflint.zip"
  printf '%s  %s\n' "$tflint_sha" "$squawk_dir/tflint.zip" | shasum -a 256 --check
  unzip -q "$squawk_dir/tflint.zip" tflint -d "$squawk_dir"
  chmod +x "$squawk_dir/tflint"
  case "$(uname -m)" in
    arm64) trivy_asset=trivy_0.69.3_macOS-ARM64.tar.gz; trivy_sha=a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5 ;;
    x86_64) trivy_asset=trivy_0.69.3_macOS-64bit.tar.gz; trivy_sha=fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e ;;
    *) echo "Unsupported Trivy host architecture" >&2; exit 1 ;;
  esac
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/${trivy_asset}" \
    --output "$squawk_dir/trivy.tar.gz"
  printf '%s  %s\n' "$trivy_sha" "$squawk_dir/trivy.tar.gz" | shasum -a 256 --check
  tar -xzf "$squawk_dir/trivy.tar.gz" -C "$squawk_dir" trivy
  chmod +x "$squawk_dir/trivy"
  # Real Go scanner/toolchain archives stay isolated from host installations.
  case "$(uname -m)" in
    arm64)
      golangci_arch=arm64
      golangci_sha=d1e409481a8ca846c4bc97e781eb5cb1bd5c23353a0b3977a1cbda1b1b6447d5
      go_sha=020a1e8224811be75163e920bc77e0926a1390a6aeea19bdcf23f74b9d749f6d ;;
    x86_64)
      golangci_arch=amd64
      golangci_sha=767b899a28285e88ded2823d5dcc4bc5ef681173eb2d80f029a7b17ee4ece3b8
      go_sha=92e8b34bff3c89ab16404c595669ac8cb004cc2f676dcbd1f5b87a6b8def3b47 ;;
    *) echo "Unsupported Go scanner host architecture" >&2; exit 1 ;;
  esac
  export LEGION_GOLANGCI_LINT_ARCHIVE="$squawk_dir/golangci-lint-2.15.0-darwin-${golangci_arch}.tar.gz"
  export LEGION_GO_ARCHIVE="$squawk_dir/go1.26.7.darwin-${golangci_arch}.tar.gz"
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://github.com/golangci/golangci-lint/releases/download/v2.15.0/$(basename "$LEGION_GOLANGCI_LINT_ARCHIVE")" \
    --output "$LEGION_GOLANGCI_LINT_ARCHIVE"
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://go.dev/dl/$(basename "$LEGION_GO_ARCHIVE")" --output "$LEGION_GO_ARCHIVE"
  printf '%s  %s\n' "$golangci_sha" "$LEGION_GOLANGCI_LINT_ARCHIVE" "$go_sha" "$LEGION_GO_ARCHIVE" | shasum -a 256 --check
  mkdir -p "$RUNNER_TEMP/legion-go-toolchain"
  tar -xzf "$LEGION_GO_ARCHIVE" -C "$RUNNER_TEMP/legion-go-toolchain"
  tar -xzf "$LEGION_GOLANGCI_LINT_ARCHIVE" -C "$squawk_dir"
  export LEGION_GO_ROOT="$RUNNER_TEMP/legion-go-toolchain/go"
  export LEGION_GOLANGCI_LINT_BIN="$squawk_dir/golangci-lint-2.15.0-darwin-${golangci_arch}/golangci-lint"
  # Freeze an upstream Kubernetes schema for offline native validation.
  export LEGION_KUBECONFORM_SCHEMA_DIR="${RUNNER_TEMP}/legion-kubeconform-schemas"
  mkdir -p "$LEGION_KUBECONFORM_SCHEMA_DIR"
  curl --fail --location --connect-timeout 20 --max-time 120 \
    "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/074539312bcc717d5492d1448be088d7549c042b/v1.32.0-standalone-strict/pod-v1.json" \
    --output "$LEGION_KUBECONFORM_SCHEMA_DIR/pod-v1.json"
  printf '%s  %s\n' 4912d4d8c79fd1e31cc8553cceecbf4dea2111b652e8ba6b8e0fee7bb7880b66 \
    "$LEGION_KUBECONFORM_SCHEMA_DIR/pod-v1.json" | shasum -a 256 --check
  npm install -g knip jscpd typescript
  gitleaks version; knip --version; jscpd --version; tsc --version
  run_audit_qualification audit_cargo_test --test bench_recall \
    bench_recall_qualification_receipt -- --ignored --exact --nocapture --test-threads=1
  bench_receipts="${RUNNER_TEMP}/legion-provider-qualification/bench"
  mkdir -p "$bench_receipts"
  bench_source="$GITHUB_WORKSPACE/engine/crates/legion-audit/target/bench-receipts/bench_recall_receipt.json"
  if [[ -f "$bench_source" ]]; then
    cp "$bench_source" "$bench_receipts/bench_recall_receipt.json"
  fi
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$bench_receipts" --group bench
  export LEGION_REAL_SCANNER_SCRATCH="${RUNNER_TEMP}/legion-real-scanner-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-external-provider-accuracy"
  mkdir -p "$LEGION_REAL_SCANNER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test external_scanner_accuracy \
    real_scanner_accuracy_shellcheck -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-external-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-additional-scanner-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test additional_external_scanner_accuracy \
    real_scanner_accuracy -- --ignored --nocapture --test-threads=1
  export LEGION_REAL_GIT_SCRATCH="${RUNNER_TEMP}/legion-real-git-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-real-git-accuracy"
  mkdir -p "$LEGION_REAL_GIT_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test legacy_git_accuracy \
    real_legacy_git_accuracy -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-real-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" \
    --scanner-receipts "${RUNNER_TEMP}/legion-provider-qualification/legion-additional-scanner-accuracy" \
    --git-receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-squawk-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test more_external_scanner_accuracy \
    real_scanner_accuracy_squawk -- --ignored --nocapture --test-threads=1
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-tflint-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_tflint_qualification
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" --group tflint
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-kubeconform-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test kubeconform_accuracy \
    real_scanner_accuracy_kubeconform -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" --group kubeconform
  unset LEGION_KUBECONFORM_SCHEMA_DIR
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-golangci-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  audit_rustc_bin="$(command -v rustc)"
  PATH="$LEGION_GO_ROOT/bin:/usr/bin:/bin" RUSTC="$audit_rustc_bin" \
    run_audit_qualification audit_cargo_test --test golangci_accuracy \
      real_scanner_accuracy_golangci_lint -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" --group golangci
  # Actual PHP/Ruby SDK controls retain original selected-scope gaps.
  run_audit_qualification provision_php_ruby_sdk
  export LEGION_PHP_RUBY_CODE_COMMAND_SCRATCH="${RUNNER_TEMP}/legion-php-ruby-code-command-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/code-php-ruby-sdk"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_php_ruby_code_command_accuracy \
    real_php_ruby_code_command_accuracy -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-php-ruby-code-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  unset LEGION_PHP_RUBY_CODE_COMMAND_SCRATCH LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON \
    LEGION_PHP_RUBY_SDK_PHP LEGION_PHP_RUBY_SDK_RUBY LEGION_PHP_RUBY_SDK_BIN_DIR
  # Generic-source controls retain mandatory unsupported-language gaps in every native case.
  # Source facts only: exact original13 framework controls, no runtime/auth admission.
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/backend-source"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test backend_source_facts \
    backend_source_native_qualification -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-backend-source-facts.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/code-long-tail"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test code_long_tail_accuracy \
    code_long_tail_native_qualification -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-code-long-tail-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  # Official pinned distributions are enrolled before offline JVM execution.
  # Private owner/ACL-checked IPC storage also holds JVM cache & staged inputs.
  # Output is copied only after validation, preserving original absolute receipt paths.
  run_audit_qualification provision_jvm_sdk
  export LEGION_JVM_SDK_SCRATCH="${LEGION_CI_IPC_STORAGE}/jvm-sdk-fixtures"
  export LEGION_JVM_SDK_OUTPUT="${LEGION_CI_IPC_STORAGE}/legion-provider-qualification/code-jvm-sdk"
  export LEGION_JVM_CONFINEMENT_RECORD="${LEGION_CI_IPC_STORAGE}/jvm-confinement/confinement.json"
  mkdir -p "${LEGION_CI_IPC_STORAGE}/jvm-confinement" "${LEGION_CI_IPC_STORAGE}/legion-provider-qualification"
  run_audit_qualification audit_jvm_qualification
  run_audit_qualification python3 scripts/ci/audit-jvm-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_JVM_SDK_OUTPUT"
  if [[ -d "$LEGION_JVM_SDK_OUTPUT" ]]; then
    cp -R "$LEGION_JVM_SDK_OUTPUT" "${RUNNER_TEMP}/legion-provider-qualification/code-jvm-sdk"
  fi
  # Preserve partial native failures for authenticated CI inspection too.
  if [[ -d "${LEGION_CI_IPC_STORAGE}/jvm-confinement" ]]; then
    cp -R "${LEGION_CI_IPC_STORAGE}/jvm-confinement" "${RUNNER_TEMP}/legion-provider-qualification/jvm-confinement"
  fi
  unset LEGION_JVM_SDK_SCRATCH LEGION_JVM_SDK_OUTPUT LEGION_JVM_CONFINEMENT_RECORD LEGION_JVM_SDK_ENROLLMENT_JSON
  # Real CMake objects/link, clang-tidy/analyzer & normal/instrumented CTest.
  run_audit_qualification provision_c_family_sdk
  export LEGION_C_FAMILY_SCRATCH="${RUNNER_TEMP}/legion-provider-qualification/code-c-family"
  mkdir -p "$LEGION_C_FAMILY_SCRATCH"
  if [[ -f "${LEGION_C_FAMILY_ENROLLMENT_JSON:-/missing-c-family-enrollment}" ]]; then
    run_audit_qualification audit_cargo_test --test c_family_sdk_accuracy \
      c_family_sdk_accuracy -- --ignored --exact --nocapture --test-threads=1
  fi
  run_audit_qualification python3 scripts/ci/audit-c-family-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_C_FAMILY_SCRATCH"
  unset LEGION_C_FAMILY_SCRATCH LEGION_C_FAMILY_ENROLLMENT_JSON
  export LEGION_RUNTIME_APP_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/runtime-app"
  mkdir -p "$LEGION_RUNTIME_APP_RECEIPTS"
  run_audit_qualification audit_runtime_app_qualification
  run_audit_qualification python3 scripts/ci/audit-runtime-app-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_RUNTIME_APP_RECEIPTS"
  unset LEGION_RUNTIME_APP_RECEIPTS
  # Pin official Python wheels before network-denied SDK commands & retain original enrollment.
  run_audit_qualification provision_python_code_sdk
  export LEGION_PYTHON_CODE_COMMAND_SCRATCH="${RUNNER_TEMP}/legion-python-code-command-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/code-python-sdk"
  mkdir -p "$LEGION_PYTHON_CODE_COMMAND_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_python_code_command_accuracy \
    real_python_code_command_accuracy -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-python-code-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  unset LEGION_PYTHON_CODE_COMMAND_SCRATCH LEGION_PYTHON_SDK_ENROLLMENT_JSON \
    LEGION_PYTHON_SDK_PYTHON LEGION_PYTHON_SDK_BIN_DIR
  # Full installed input observations are independently rehashed by native harness.
  export LEGION_MOBILE_SDK_SCRATCH="${RUNNER_TEMP}/legion-mobile-sdk-fixtures"
  export LEGION_MOBILE_SDK_OUTPUT="${RUNNER_TEMP}/legion-provider-qualification/code-mobile/code_mobile.json"
  export LEGION_MOBILE_SDK_ENROLLMENT="${RUNNER_TEMP}/legion-provider-qualification/code-mobile/mobile-native-enrollment.json"
  export LEGION_MOBILE_SOURCE_ENROLLMENT="${RUNNER_TEMP}/legion-provider-qualification/code-mobile/mobile-source-enrollment.json"
  mkdir -p "$LEGION_MOBILE_SDK_SCRATCH"
  run_audit_qualification python3 -m unittest discover -s scripts/ci/tests -p test_audit_mobile_sdk_accuracy.py
  run_audit_qualification python3 scripts/ci/audit-mobile-native-enrollment.py \
    --root "$GITHUB_WORKSPACE" --receipts "${RUNNER_TEMP}/legion-provider-qualification/code-mobile"
  run_audit_qualification audit_cargo_test --lib \
    native_providers::code::tools::mobile_sdk::tests::native::native_mobile_sdk_controls \
    -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-mobile-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "${RUNNER_TEMP}/legion-provider-qualification/code-mobile"
  unset LEGION_MOBILE_SDK_SCRATCH LEGION_MOBILE_SDK_OUTPUT LEGION_MOBILE_SDK_ENROLLMENT LEGION_MOBILE_SOURCE_ENROLLMENT
  # Archive-only official JS tooling enrollment; no project install or scripts.
  run_audit_qualification provision_js_sdk
  if [[ -n "${LEGION_JS_SDK_ENROLLMENT:-}" ]]; then
    export LEGION_JS_SDK_SCRATCH="$RUNNER_TEMP/legion-js-sdk-fixtures"
    export LEGION_PROVIDER_BENCHMARK_DIR="$RUNNER_TEMP/legion-provider-qualification/javascript-sdk"
    mkdir -p "$LEGION_JS_SDK_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
    run_audit_qualification audit_cargo_test --test real_javascript_sdk_accuracy \
      real_javascript_sdk_accuracy -- --ignored --exact --nocapture --test-threads=1
    run_audit_qualification python3 scripts/ci/audit-javascript-sdk-accuracy.py \
      --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  else
    printf '::error::JavaScript SDK controls skipped: provisioning refused.\n' >&2
  fi
  unset LEGION_JS_SDK_ENROLLMENT LEGION_JS_SDK_SCRATCH
  # Acquire pinned SDK/package inputs before native network-denied project execution.
  run_audit_qualification provision_dotnet_code_sdk
  export LEGION_DOTNET_ENROLLMENT="${RUNNER_TEMP}/legion-dotnet-code-sdk-tools/enrollment.json"
  export LEGION_DOTNET_CHILD_OUTPUT="${RUNNER_TEMP}/legion-provider-qualification/code-dotnet-sdk"
  export LEGION_DOTNET_ACCURACY_OUTPUT="${LEGION_DOTNET_CHILD_OUTPUT}/code_dotnet.json"
  mkdir -p "$LEGION_DOTNET_CHILD_OUTPUT"
  run_audit_qualification audit_cargo_test --lib \
    native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls \
    -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-dotnet-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_DOTNET_CHILD_OUTPUT"
  unset LEGION_DOTNET_ENROLLMENT LEGION_DOTNET_CHILD_OUTPUT LEGION_DOTNET_ACCURACY_OUTPUT
  # Provision exact official vulnerability inputs before the network-denied SDK controls.
  run_audit_qualification provision_code_sdk_vulnerability_tool
  # Constructed code SDK diagnostics preserve full-provider gaps; never promote partial controls.
  export LEGION_CODE_COMMAND_SCRATCH="${RUNNER_TEMP}/legion-code-command-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/code-sdk"
  mkdir -p "$LEGION_CODE_COMMAND_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_code_command_accuracy \
    real_code_command_accuracy -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-code-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  unset LEGION_CODE_COMMAND_SCRATCH LEGION_GOVULNCHECK_BIN LEGION_GOVULNCHECK_DB_ROOT \
    LEGION_GOVULNCHECK_DB_ARCHIVE LEGION_GOVULNCHECK_ENROLLMENT_JSON GOMODCACHE
  unset LEGION_GO_ROOT LEGION_GO_ARCHIVE LEGION_GOLANGCI_LINT_BIN LEGION_GOLANGCI_LINT_ARCHIVE
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-trivy-iac-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test trivy_iac_accuracy \
    real_scanner_accuracy_trivy_iac -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" --group trivy-iac
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-brakeman-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test brakeman_accuracy \
    real_scanner_accuracy_brakeman -- --ignored --nocapture --test-threads=1
  unset LEGION_BRAKEMAN_GEM_ROOT
  export LEGION_REAL_LINTER_SCRATCH="${RUNNER_TEMP}/legion-real-linter-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/legion-real-linter-accuracy"
  mkdir -p "$LEGION_REAL_LINTER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_legacy_linter_accuracy \
    real_legacy_linter_accuracy -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-extra-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" \
    --squawk-receipts "${RUNNER_TEMP}/legion-provider-qualification/legion-squawk-accuracy" \
    --brakeman-receipts "${RUNNER_TEMP}/legion-provider-qualification/legion-brakeman-accuracy" \
    --linter-receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  # Official published JS entry + full installed closure, real native SDK controls.
  # Dependencies provision only here; sandboxed version/scan requests deny network.
  export LEGION_LICENSE_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/license-checker"
  run_audit_qualification provision_license_checker
  if [[ -n "${LEGION_LICENSE_TOOL_ROOT:-}" ]]; then
    PATH="$audit_license_tool_dir/bin:$audit_license_node_dir:$PATH" \
      run_audit_qualification audit_cargo_test --test license_checker_accuracy \
        real_license_checker_accuracy -- --ignored --exact --nocapture --test-threads=1 \
        > "$LEGION_LICENSE_RECEIPTS/harness.log" 2>&1
    cat "$LEGION_LICENSE_RECEIPTS/harness.log"
    run_audit_qualification python3 scripts/ci/audit-license-provider-accuracy.py \
      --root "$GITHUB_WORKSPACE" --receipts "$LEGION_LICENSE_RECEIPTS" \
      > "$LEGION_LICENSE_RECEIPTS/validator.log" 2>&1
    cat "$LEGION_LICENSE_RECEIPTS/validator.log"
  else
    printf '::error::License-checker controls skipped: provisioning refused.\n' >&2
  fi
  unset LEGION_LICENSE_RECEIPTS LEGION_LICENSE_TOOL_ROOT audit_license_tool_dir audit_license_node_dir
  # Real pinned native secret history controls; explicitly constructed admission.
  secrets_tool_root="${RUNNER_TEMP}/legion-secrets-history-tool"
  export LEGION_SECRET_QUALIFICATION_DIR="${RUNNER_TEMP}/legion-provider-qualification/secrets-history"
  mkdir -p "$secrets_tool_root" "$LEGION_SECRET_QUALIFICATION_DIR"
  case "$(uname -m)" in
    arm64) export LEGION_GITLEAKS_ARCHIVE_NAME="gitleaks_8.30.0_darwin_arm64.tar.gz"
      export LEGION_GITLEAKS_ARCHIVE_SHA256="sha256:b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7" ;;
    x86_64) export LEGION_GITLEAKS_ARCHIVE_NAME="gitleaks_8.30.0_darwin_x64.tar.gz"
      export LEGION_GITLEAKS_ARCHIVE_SHA256="sha256:ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5" ;;
    *) echo "Unsupported native Gitleaks qualification architecture" >&2; exit 1 ;;
  esac
  curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/${LEGION_GITLEAKS_ARCHIVE_NAME}" \
    --output "$secrets_tool_root/$LEGION_GITLEAKS_ARCHIVE_NAME"
  python3 - "$secrets_tool_root/$LEGION_GITLEAKS_ARCHIVE_NAME" "$LEGION_GITLEAKS_ARCHIVE_SHA256" <<'PY_PIN'
import hashlib, pathlib, sys
actual = "sha256:" + hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit("Native Gitleaks archive digest mismatch")
PY_PIN
  tar -xzf "$secrets_tool_root/$LEGION_GITLEAKS_ARCHIVE_NAME" -C "$secrets_tool_root" gitleaks
  export LEGION_GITLEAKS_BINARY="$secrets_tool_root/gitleaks"
  LEGION_GITLEAKS_SHA256="$(python3 - "$LEGION_GITLEAKS_BINARY" <<'PY_PIN'
import hashlib, pathlib, sys
print("sha256:" + hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY_PIN
)"
  export LEGION_GITLEAKS_SHA256
  run_audit_qualification audit_cargo_test --lib \
    native_providers::security::producer::history_qualification_tests::native_current_history_qualification \
    -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-secrets-history-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_SECRET_QUALIFICATION_DIR"
  unset LEGION_GITLEAKS_BINARY LEGION_GITLEAKS_SHA256 LEGION_GITLEAKS_ARCHIVE_NAME LEGION_GITLEAKS_ARCHIVE_SHA256 LEGION_SECRET_QUALIFICATION_DIR
  # Real existing build/lint SDK controls; no production owner-admission claim.
  export LEGION_QUALITY_TOOLCHAIN_BIN="$(rustc +1.98.0 --print sysroot)/bin"
  export LEGION_QUALITY_COMMAND_SCRATCH="${RUNNER_TEMP}/legion-quality-command-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/quality"
  mkdir -p "$LEGION_QUALITY_COMMAND_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_quality_command_accuracy \
    real_quality_command_accuracy -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-harness-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR" --group quality
  unset LEGION_QUALITY_TOOLCHAIN_BIN LEGION_QUALITY_COMMAND_SCRATCH
  # Real attested test qualification requires separately provisioned native owner pins.
  # Never replace absent trust/admission with a local fake broker or signing key.
  if [[ -n "${LEGION_ATTESTED_RUNS_ENROLLMENT:-}" ]]; then
    export LEGION_QUALITY_TEST_EVIDENCE="${RUNNER_TEMP}/legion-provider-qualification/quality-test-native"
    if python3 scripts/ci/provision-quality-test-native.py --root "$GITHUB_WORKSPACE"; then
      run_audit_qualification audit_cargo_test --test real_quality_test_accuracy \
        real_quality_test_accuracy -- --ignored --exact --nocapture --test-threads=1
      run_audit_qualification python3 scripts/ci/audit-quality-test-accuracy.py \
        "$LEGION_QUALITY_TEST_EVIDENCE/legacy_quality_test.json" \
        --repository-root "$GITHUB_WORKSPACE" --evidence-root "$LEGION_QUALITY_TEST_EVIDENCE" --mutation-checks
    else
      audit_qualification_failures=$((audit_qualification_failures + 1))
      printf '::error::Native test qualification owner prerequisites refused.\n' >&2
    fi
    unset LEGION_QUALITY_TEST_EVIDENCE
  else
    printf 'QUALITY_TEST_NATIVE_UNAVAILABLE managed-test-trust-not-configured; production-owner-admission-unavailable\n'
  fi
  # Constructed pip-audit SDK controls use shared hash-locked Python enrollment.
  run_audit_qualification provision_python_qualification_tool pip-audit
  export LEGION_PIP_AUDIT_SCRATCH="$RUNNER_TEMP/legion-pip-audit-work"
  export LEGION_PROVIDER_BENCHMARK_DIR="$RUNNER_TEMP/legion-provider-qualification/pip-audit"
  mkdir -p "$LEGION_PIP_AUDIT_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  PATH="$(dirname "${LEGION_PIP_AUDIT_BIN:-/missing/pip-audit}"):$PATH" \
    run_audit_qualification audit_cargo_test --test pip_audit_accuracy real_pip_audit_accuracy \
    -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-pip-audit-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  unset LEGION_PIP_AUDIT_SCRATCH LEGION_PROVIDER_BENCHMARK_DIR LEGION_PIP_AUDIT_BIN LEGION_PYTHON_TOOL_ENROLLMENT

  # Constructed Semgrep SDK controls use shared hash-locked Python enrollment.
  run_audit_qualification provision_python_qualification_tool semgrep
  export LEGION_SEMGREP_SCRATCH="${RUNNER_TEMP}/legion-semgrep-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/semgrep"
  mkdir -p "$LEGION_SEMGREP_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  PATH="$(dirname "$LEGION_SEMGREP_BIN"):$PATH" run_audit_qualification audit_cargo_test \
    --test semgrep_accuracy real_semgrep_accuracy \
    -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-semgrep-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"

  # Fixed official OpenGrep binary; constructed SDK/artifact cases only.
  audit_provision_opengrep() {
    local opengrep_asset opengrep_sha
    audit_native_command mkdir -p "$opengrep_tool_dir" || return $?
    case "$(audit_native_command uname -m)" in
      arm64) opengrep_asset=opengrep_osx_arm64; opengrep_sha=035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb ;;
      x86_64) opengrep_asset=opengrep_osx_x86; opengrep_sha=2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee ;;
      *) return 1 ;;
    esac
    audit_native_command curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/opengrep/opengrep/releases/download/v1.31.0/${opengrep_asset}" \
      --output "${opengrep_tool_dir}/opengrep" || return $?
    printf '%s  %s\n' "$opengrep_sha" "${opengrep_tool_dir}/opengrep" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command chmod 0755 "${opengrep_tool_dir}/opengrep"
  }
  opengrep_tool_dir="${RUNNER_TEMP}/legion-opengrep-native-v1.31.0"
  run_audit_qualification audit_provision_opengrep
  export LEGION_OPENGREP_SCRATCH="${RUNNER_TEMP}/legion-opengrep-fixtures"
  export LEGION_OPENGREP_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/opengrep"
  mkdir -p "$LEGION_OPENGREP_SCRATCH" "$LEGION_OPENGREP_RECEIPTS"
  PATH="${opengrep_tool_dir}:$PATH" run_audit_qualification audit_cargo_test \
    --test opengrep_accuracy real_sdk_artifact_accuracy_opengrep \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_OPENGREP_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_OPENGREP_RECEIPTS/harness.log"
  run_audit_qualification python3 scripts/ci/audit-opengrep-artifact-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_OPENGREP_RECEIPTS" \
    > "$LEGION_OPENGREP_RECEIPTS/validator.log" 2>&1
  cat "$LEGION_OPENGREP_RECEIPTS/validator.log"
  export LEGION_SECURITY_CONTROLS_SCRATCH="$RUNNER_TEMP/legion-security-controls-scanner-work"
  export LEGION_SECURITY_CONTROLS_RECEIPTS="$RUNNER_TEMP/legion-provider-qualification/security-controls-scanner"
  mkdir -p "$LEGION_SECURITY_CONTROLS_SCRATCH" "$LEGION_SECURITY_CONTROLS_RECEIPTS"
  PATH="${opengrep_tool_dir}:$PATH" run_audit_qualification audit_cargo_test \
    --test audit_security_controls_scanner_preflight real_security_controls_scanner_population \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_SECURITY_CONTROLS_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_SECURITY_CONTROLS_RECEIPTS/harness.log"
  unset LEGION_SECURITY_CONTROLS_SCRATCH LEGION_SECURITY_CONTROLS_RECEIPTS
  unset LEGION_OPENGREP_SCRATCH LEGION_OPENGREP_RECEIPTS
  # Official pinned OSV; one advisory offline SDK/artifact fixtures only.
  audit_provision_osv() {
    local osv_asset osv_sha
    audit_native_command mkdir -p "$osv_tool_dir" || return $?
    case "$(audit_native_command uname -m)" in
      arm64) osv_asset=osv-scanner_darwin_arm64; osv_sha=f1e1cc84b6e365b79b874cb9028a4f74ac64666094b542f1eb196b10f44b505e ;;
      x86_64) osv_asset=osv-scanner_darwin_amd64; osv_sha=5c2a2e2a686e34c0674e0a463aa626467df5d9fba0ed06870a2eb684dc434de3 ;;
      *) return 1 ;;
    esac
    audit_native_command curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/google/osv-scanner/releases/download/v2.2.2/${osv_asset}" \
      --output "${osv_tool_dir}/osv-scanner" || return $?
    printf '%s  %s\n' "$osv_sha" "${osv_tool_dir}/osv-scanner" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command chmod 0755 "${osv_tool_dir}/osv-scanner"
  }
  osv_tool_dir="${RUNNER_TEMP}/legion-osv-native-v2.2.2"
  run_audit_qualification audit_provision_osv
  export LEGION_OSV_BIN="${osv_tool_dir}/osv-scanner"
  export LEGION_OSV_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/osv"
  mkdir -p "$LEGION_OSV_RECEIPTS"
  run_audit_qualification audit_cargo_test \
    --test osv_accuracy real_sdk_artifact_accuracy_osv \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_OSV_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_OSV_RECEIPTS/harness.log"
  run_audit_qualification python3 scripts/ci/audit-osv-artifact-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_OSV_RECEIPTS" \
    > "$LEGION_OSV_RECEIPTS/validator.log" 2>&1
  cat "$LEGION_OSV_RECEIPTS/validator.log"
  unset LEGION_OSV_BIN LEGION_OSV_RECEIPTS
  # Pinned official cargo-audit; unchanged historical advisory subset, no freshness claim.
  audit_provision_cargo_audit() {
    local audit_target audit_sha audit_binary_sha
    case "$(audit_native_command uname -m)" in
      arm64) audit_target=aarch64-apple-darwin; audit_sha=ec7ca4263769593df4d909be85b94a6b79efa2897be5d2bb8ebd516e823175af; audit_binary_sha=33fbe81adca1b794f4ffe98574d59b0ebe6fcfdb310976fafed98a094c795111 ;;
      x86_64) audit_target=x86_64-apple-darwin; audit_sha=847831323de932155b226ab60ee4a180e13e5d007a019f0d4b7b4d89a6de2ab2; audit_binary_sha=1a63bb3ab4f99a0220a8e4d8a677692afe5901cb44a949b2473c545a02028326 ;;
      *) return 1 ;;
    esac
    audit_native_command mkdir -p "$cargo_audit_tool_dir" || return $?
    audit_native_command curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-${audit_target}-v0.22.2.tgz" \
      --output "$cargo_audit_tool_dir/tool.tgz" || return $?
    printf '%s  %s\n' "$audit_sha" "$cargo_audit_tool_dir/tool.tgz" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command tar -xzf "$cargo_audit_tool_dir/tool.tgz" -C "$cargo_audit_tool_dir" --strip-components=1 "cargo-audit-${audit_target}-v0.22.2/cargo-audit" || return $?
    printf '%s  %s\n' "$audit_binary_sha" "$cargo_audit_tool_dir/cargo-audit" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command chmod 0755 "$cargo_audit_tool_dir/cargo-audit"
  }
  cargo_audit_tool_dir="${RUNNER_TEMP}/legion-cargo-audit-native-v0.22.2"
  run_audit_qualification audit_provision_cargo_audit
  export LEGION_CARGO_AUDIT_BIN="$cargo_audit_tool_dir/cargo-audit"
  export LEGION_CARGO_AUDIT_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/cargo-audit"
  mkdir -p "$LEGION_CARGO_AUDIT_RECEIPTS"
  run_audit_qualification audit_cargo_test \
    --test cargo_audit_accuracy real_cargo_audit_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_CARGO_AUDIT_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_CARGO_AUDIT_RECEIPTS/harness.log"
  run_audit_qualification python3 scripts/ci/audit-cargo-audit-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_CARGO_AUDIT_RECEIPTS" \
    > "$LEGION_CARGO_AUDIT_RECEIPTS/validator.log" 2>&1
  cat "$LEGION_CARGO_AUDIT_RECEIPTS/validator.log"
  # Dedicated full Rust SDK controls reuse already provisioned pinned scanner & managed Rust.
  provision_rust_code_sdk() {
    local output="${RUNNER_TEMP}/legion-rust-code-sdk-tools"
    audit_native_command python3 scripts/ci/provision-rust-code-fixtures.py --root "$output" || return "$?"
    local values
    values="$(audit_native_command python3 - "$output/environment.json" <<'RUST_CODE_SDK_ENV'
import json
import sys
from pathlib import Path
names = ["CARGO_HOME", "LEGION_RUST_CODE_ENROLLMENT_JSON", "SDKROOT"]
values = json.loads(Path(sys.argv[1]).read_bytes())
if set(values) != set(names) or any(not isinstance(v, str) or not Path(v).is_absolute() or any(c in v for c in "\0\t\r\n") for v in values.values()):
    raise SystemExit("Exact Rust SDK environment export missing or malformed")
print("\t".join(values[name] for name in names))
RUST_CODE_SDK_ENV
)" || return "$?"
    IFS=$'\t' read -r rust_sdk_fixture_cargo_home LEGION_RUST_CODE_ENROLLMENT_JSON SDKROOT <<< "$values" || return "$?"
    export LEGION_RUST_CODE_ENROLLMENT_JSON SDKROOT
  }
  rust_sdk_previous_cargo_home="${CARGO_HOME-}"
  rust_sdk_previous_sdkroot="${SDKROOT-}"
  rust_sdk_had_cargo_home="${CARGO_HOME+x}"
  rust_sdk_had_sdkroot="${SDKROOT+x}"
  run_audit_qualification provision_rust_code_sdk
  export LEGION_QUALITY_TOOLCHAIN_BIN="$(rustc +1.98.0 --print sysroot)/bin"
  export LEGION_RUST_CODE_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/code-rust-sdk"
  mkdir -p "$LEGION_RUST_CODE_RECEIPTS"
  run_audit_qualification audit_cargo_test --test real_rust_code_accuracy \
    real_rust_code_accuracy -- --ignored --exact --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-rust-code-sdk-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_RUST_CODE_RECEIPTS"
  unset LEGION_QUALITY_TOOLCHAIN_BIN LEGION_RUST_CODE_RECEIPTS LEGION_RUST_CODE_ENROLLMENT_JSON rust_sdk_fixture_cargo_home
  if [[ "$rust_sdk_had_cargo_home" == x ]]; then export CARGO_HOME="$rust_sdk_previous_cargo_home"; else unset CARGO_HOME; fi
  if [[ "$rust_sdk_had_sdkroot" == x ]]; then export SDKROOT="$rust_sdk_previous_sdkroot"; else unset SDKROOT; fi
  unset rust_sdk_previous_cargo_home rust_sdk_previous_sdkroot rust_sdk_had_cargo_home rust_sdk_had_sdkroot
  unset LEGION_CARGO_AUDIT_BIN LEGION_CARGO_AUDIT_RECEIPTS
  audit_provision_cargo_deny() {
    local deny_arch deny_archive_sha deny_binary_sha
    audit_native_command mkdir -p "$cargo_deny_tool_dir" || return $?
    case "$(audit_native_command uname -m)" in
      arm64) deny_arch=aarch64; deny_archive_sha=fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3; deny_binary_sha=5f65c07c459c9514f0c97cc2e2fb6b120daef2d95aee31062cab4816cf027eb1 ;;
      x86_64) deny_arch=x86_64; deny_archive_sha=248da7f581724e470071990c088ffc55c811981715f4cbdb258621fb79f8b7a6; deny_binary_sha=325ae013000059dfa398557f7bc35659e1d73af6b0c39955dff633de164f9c1e ;;
      *) return 1 ;;
    esac
    audit_native_command curl --fail --location --retry 3 \
      "https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-${deny_arch}-apple-darwin.tar.gz" \
      --output "${cargo_deny_tool_dir}/release.tar.gz" || return $?
    printf '%s  %s\n' "$deny_archive_sha" "${cargo_deny_tool_dir}/release.tar.gz" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command tar -xzf "${cargo_deny_tool_dir}/release.tar.gz" --strip-components=1 -C "$cargo_deny_tool_dir" \
      "cargo-deny-0.20.2-${deny_arch}-apple-darwin/cargo-deny" || return $?
    printf '%s  %s\n' "$deny_binary_sha" "${cargo_deny_tool_dir}/cargo-deny" | audit_native_command shasum -a 256 -c - || return $?
    audit_native_command chmod 0755 "${cargo_deny_tool_dir}/cargo-deny"
  }
  cargo_deny_tool_dir="${RUNNER_TEMP}/legion-cargo-deny-native-0.20.2"
  run_audit_qualification audit_provision_cargo_deny
  export LEGION_CARGO_DENY_TOOLCHAIN_BIN="$(rustc --print sysroot)/bin"
  export LEGION_CARGO_DENY_BIN="${cargo_deny_tool_dir}/cargo-deny"
  export LEGION_CARGO_DENY_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/cargo-deny"
  mkdir -p "$LEGION_CARGO_DENY_RECEIPTS"
  run_audit_qualification audit_cargo_test --test cargo_deny_accuracy real_cargo_deny_accuracy \
    -- --ignored --exact --nocapture --test-threads=1 \
    > "$LEGION_CARGO_DENY_RECEIPTS/harness.log" 2>&1
  cat "$LEGION_CARGO_DENY_RECEIPTS/harness.log"
  run_audit_qualification python3 scripts/ci/audit-cargo-deny-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_CARGO_DENY_RECEIPTS" \
    > "$LEGION_CARGO_DENY_RECEIPTS/validator.log" 2>&1
  cat "$LEGION_CARGO_DENY_RECEIPTS/validator.log"
  unset LEGION_CARGO_DENY_BIN LEGION_CARGO_DENY_RECEIPTS LEGION_CARGO_DENY_TOOLCHAIN_BIN

  unset LEGION_REAL_LINTER_SCRATCH
  unset LEGION_REAL_GIT_SCRATCH
  unset LEGION_REAL_SCANNER_SCRATCH LEGION_PROVIDER_BENCHMARK_DIR
fi

# Apple bundle integrity (formerly apple-skills.yml): the workspace test run
# above already covers legion-apple, apple_skill_integrity, apple_cli,
# role_host_binding and canonical_mcp_schema; the enforce-phase native CLI
# surface check in the list above was the only step not already in this gate.

# Source-owned corpus checks never resolve a harness or authorize generation.
run_audit_qualification audit_cargo_test --test reasoning_runtime_qualification \
  reasoning_runtime_no_call_contract -- --exact --nocapture --test-threads=1
# The no-call harness atomically moves its actual Cargo CLI to fresh retained
# storage before executing it. No later build/copy may substitute tested bytes.
export LEGION_REASONING_NATIVE_RUNNER_DIR="${RUNNER_TEMP}/legion-provider-qualification/reasoning-native-runner"
run_audit_qualification "$audit_cargo_bin" test --locked --manifest-path engine/Cargo.toml -p legion \
  --test reasoning_runtime_qualification reasoning_runtime_production_no_call_contract \
  -- --exact --nocapture --test-threads=1
unset LEGION_REASONING_NATIVE_RUNNER_DIR

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
# Cargo may recreate its original CLI after the tested inode was moved. Verify
# the retained bytes again after that build, including any shared-inode aliases.
ci_reasoning_dir="${RUNNER_TEMP}/legion-provider-qualification/reasoning-native-runner"
python3 - "$ci_reasoning_dir" "$GITHUB_SHA" "$RUNNER_OS" "$RUNNER_ARCH" <<'REASONING_PY'
import hashlib
import json
import stat
import sys
from pathlib import Path
root = Path(sys.argv[1])
record = json.loads((root / "runner.json").read_bytes())
if record["schema"] != "legion-reasoning-native-runner/1" or record["sourceRevision"] != sys.argv[2] or record["platform"] != {"os":sys.argv[3],"architecture":sys.argv[4]}:
    raise SystemExit("retained no-call runner source/platform differs")
name = "legion.exe" if sys.argv[3] == "Windows" else "legion"
if record["binary"]["path"] != name or record["modelCalls"] != 0 or record["qualification"] is not False:
    raise SystemExit("retained no-call runner identity/claims differ")
retained = root / name
if retained.is_symlink() or not retained.is_file():
    raise SystemExit("retained tested CLI is not a regular file")
raw = retained.read_bytes()
if record["binary"] != {"path":name,"sha256":"sha256:"+hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"mode":stat.S_IMODE(retained.stat().st_mode)}:
    raise SystemExit("retained CLI differs from bytes exercised by production no-call proof")
REASONING_PY
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

# Node's bundled npm rewrites Windows command files to LF; qualification binds
# exact published npm package bytes, including CRLF files. Reprovision that same
# pinned npm version in shared Node prefix before taking immutable runtime hashes.
provision_node_outdated_npm() {
  local archive="$LEGION_NODE_OUTDATED_RECEIPTS/npm-10.9.8.tgz"
  local node_prefix
  node_prefix="$(python3 - <<'NPM_PREFIX'
from pathlib import Path
import shutil
node = Path(shutil.which("node")).resolve(strict=True)
npm = Path(shutil.which("npm")).resolve(strict=True)
prefix = node.parent.parent
assert npm == prefix / "lib/node_modules/npm/bin/npm-cli.js"
print(prefix)
NPM_PREFIX
)" || return
  curl --fail --location https://registry.npmjs.org/npm/-/npm-10.9.8.tgz \
    --output "$archive" || return
  printf '%s  %s\n' 3e68f9b5fcaf1a94ba0e37e6a565c920b2be6bd98998c50970385d6a692af780 "$archive" \
    | shasum -a 256 --check || return
  "$node_prefix/bin/node" "$node_prefix/lib/node_modules/npm/bin/npm-cli.js" install \
    --global --prefix "$node_prefix" --ignore-scripts --no-audit --no-fund --offline "$archive"
}
# npm completion controls use shared pinned CI Node/npm; audited fixtures are never installed.
if [[ "$(uname -s)" == "Darwin" ]]; then
  export LEGION_NODE_OUTDATED_RECEIPTS="${RUNNER_TEMP}/legion-provider-qualification/node-outdated"
  export LEGION_NODE_OUTDATED_PROVISION="$LEGION_NODE_OUTDATED_RECEIPTS/provision.json"
  mkdir -p "$LEGION_NODE_OUTDATED_RECEIPTS"
  if provision_node_outdated_npm &&
    python3 scripts/ci/provision-audit-node-outdated.py --root "$GITHUB_WORKSPACE" \
      --receipts "$LEGION_NODE_OUTDATED_RECEIPTS"; then
    while IFS= read -r audit_npm_runtime; do
      export "$audit_npm_runtime"
    done < "$LEGION_NODE_OUTDATED_RECEIPTS/runtime.env"
    run_audit_qualification audit_cargo_test --test node_outdated_accuracy real_node_outdated_accuracy \
      -- --ignored --exact --nocapture --test-threads=1 \
      > "$LEGION_NODE_OUTDATED_RECEIPTS/harness.log" 2>&1
    cat "$LEGION_NODE_OUTDATED_RECEIPTS/harness.log"
    run_audit_qualification python3 scripts/ci/audit-node-outdated-accuracy.py --root "$GITHUB_WORKSPACE" \
      --receipts "$LEGION_NODE_OUTDATED_RECEIPTS"
  else
    audit_node_status=$?
    audit_qualification_failures=$((audit_qualification_failures + 1))
    printf '::error::npm outdated runtime binding failed (exit %s).\n' "$audit_node_status" >&2
  fi
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

# Known-answer recall gate. The bench scores planted defects against
# negative controls and fails on any false positive, so a detector that
# flags everything cannot pass. It was lost when the skill became a
# product and the conformance suite has been dead at its ninth case since.
# Recall, provider-selection, and conformance gates now run as native Rust
# integration tests covered by `cargo test` above:
#   engine/crates/legion-audit/tests/bench_recall.rs
#   engine/crates/legion-audit/tests/provider_selection_benchmark.rs
#   engine/crates/legion-audit/tests/audit_conformance.rs
