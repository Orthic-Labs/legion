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

python3 -m unittest discover -s scripts/ci/tests -p test_audit_qualification_records.py
python3 scripts/ci/audit-qualification-records.py --root "$GITHUB_WORKSPACE" --check

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

audit_qualification_failures=0
audit_qualification_sequence=0
audit_cargo_bin="$(command -v cargo)"
audit_cargo_test() { (cd engine && "$audit_cargo_bin" test --locked -p legion-audit "$@"); }
audit_effects_test() { (cd engine && "$audit_cargo_bin" test --locked -p legion-effects "$@"); }
audit_tflint_qualification() {
  audit_effects_test --lib scoped_ipc_ci_storage_requires_private_canonical_owned_root -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_rejects_long_paths_symlinks_modes_and_foreign_tools -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_native_acl_controls_empty_allow_deny_and_lookup_failure -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_failed_version_probe_preserves_lifecycle_and_namespace -- --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_native_confinement -- --ignored --nocapture --test-threads=1 &&
    audit_effects_test --lib scoped_ipc_timeout_and_cancel_cleanup_after_reaping -- --ignored --nocapture --test-threads=1 &&
    audit_cargo_test --test tflint_accuracy real_scanner_accuracy_tflint -- --ignored --nocapture --test-threads=1
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
  if "$@"; then
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
export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-accuracy"
mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
run_audit_qualification audit_cargo_test \
  --test security_packs --test architecture_input_producer \
  --test code_provider_accuracy --test suite_provider_accuracy \
  --test legacy_file_accuracy --test artifact_provider_accuracy \
  file_only_provider_accuracy -- --nocapture --test-threads=1
run_audit_qualification python3 scripts/ci/audit-provider-accuracy.py \
  --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
unset LEGION_PROVIDER_BENCHMARK_DIR

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
  brew install gitleaks shellcheck zizmor kube-linter kubeconform actionlint hadolint swiftlint ruby@3.3
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
  export LEGION_REAL_SCANNER_SCRATCH="${RUNNER_TEMP}/legion-real-scanner-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-external-provider-accuracy"
  mkdir -p "$LEGION_REAL_SCANNER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test external_scanner_accuracy \
    real_scanner_accuracy_shellcheck -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-external-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" --receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-additional-scanner-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test additional_external_scanner_accuracy \
    real_scanner_accuracy -- --ignored --nocapture --test-threads=1
  export LEGION_REAL_GIT_SCRATCH="${RUNNER_TEMP}/legion-real-git-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-real-git-accuracy"
  mkdir -p "$LEGION_REAL_GIT_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test legacy_git_accuracy \
    real_legacy_git_accuracy -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-real-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" \
    --scanner-receipts "${RUNNER_TEMP}/legion-additional-scanner-accuracy" \
    --git-receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-squawk-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test more_external_scanner_accuracy \
    real_scanner_accuracy_squawk -- --ignored --nocapture --test-threads=1
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-tflint-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_tflint_qualification
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-kubeconform-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test kubeconform_accuracy \
    real_scanner_accuracy_kubeconform -- --ignored --nocapture --test-threads=1
  unset LEGION_KUBECONFORM_SCHEMA_DIR
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-golangci-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  audit_rustc_bin="$(command -v rustc)"
  PATH="$LEGION_GO_ROOT/bin:/usr/bin:/bin" RUSTC="$audit_rustc_bin" \
    run_audit_qualification audit_cargo_test --test golangci_accuracy \
      real_scanner_accuracy_golangci_lint -- --ignored --nocapture --test-threads=1
  unset LEGION_GO_ROOT LEGION_GO_ARCHIVE LEGION_GOLANGCI_LINT_BIN LEGION_GOLANGCI_LINT_ARCHIVE
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-trivy-iac-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test trivy_iac_accuracy \
    real_scanner_accuracy_trivy_iac -- --ignored --nocapture --test-threads=1
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-brakeman-accuracy"
  mkdir -p "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test brakeman_accuracy \
    real_scanner_accuracy_brakeman -- --ignored --nocapture --test-threads=1
  unset LEGION_BRAKEMAN_GEM_ROOT
  export LEGION_REAL_LINTER_SCRATCH="${RUNNER_TEMP}/legion-real-linter-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-real-linter-accuracy"
  mkdir -p "$LEGION_REAL_LINTER_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_legacy_linter_accuracy \
    real_legacy_linter_accuracy -- --ignored --nocapture --test-threads=1
  run_audit_qualification python3 scripts/ci/audit-extra-provider-accuracy.py \
    --root "$GITHUB_WORKSPACE" \
    --squawk-receipts "${RUNNER_TEMP}/legion-squawk-accuracy" \
    --brakeman-receipts "${RUNNER_TEMP}/legion-brakeman-accuracy" \
    --linter-receipts "$LEGION_PROVIDER_BENCHMARK_DIR"
  # Real existing build/lint SDK controls; no production owner-admission claim.
  export LEGION_QUALITY_TOOLCHAIN_BIN="$(rustc +1.98.0 --print sysroot)/bin"
  export LEGION_QUALITY_COMMAND_SCRATCH="${RUNNER_TEMP}/legion-quality-command-fixtures"
  export LEGION_PROVIDER_BENCHMARK_DIR="${RUNNER_TEMP}/legion-provider-qualification/quality"
  mkdir -p "$LEGION_QUALITY_COMMAND_SCRATCH" "$LEGION_PROVIDER_BENCHMARK_DIR"
  run_audit_qualification audit_cargo_test --test real_quality_command_accuracy \
    real_quality_command_accuracy -- --ignored --exact --nocapture --test-threads=1
  unset LEGION_QUALITY_TOOLCHAIN_BIN LEGION_QUALITY_COMMAND_SCRATCH
  # Fixed official OpenGrep binary; constructed SDK/artifact cases only.
  audit_provision_opengrep() {
    local opengrep_asset opengrep_sha
    mkdir -p "$opengrep_tool_dir" || return $?
    case "$(uname -m)" in
      arm64) opengrep_asset=opengrep_osx_arm64; opengrep_sha=035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb ;;
      x86_64) opengrep_asset=opengrep_osx_x86; opengrep_sha=2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee ;;
      *) return 1 ;;
    esac
    curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/opengrep/opengrep/releases/download/v1.31.0/${opengrep_asset}" \
      --output "${opengrep_tool_dir}/opengrep" || return $?
    printf '%s  %s\n' "$opengrep_sha" "${opengrep_tool_dir}/opengrep" | shasum -a 256 -c - || return $?
    chmod 0755 "${opengrep_tool_dir}/opengrep"
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
  unset LEGION_OPENGREP_SCRATCH LEGION_OPENGREP_RECEIPTS
  # Official pinned OSV; one advisory offline SDK/artifact fixtures only.
  audit_provision_osv() {
    local osv_asset osv_sha
    mkdir -p "$osv_tool_dir" || return $?
    case "$(uname -m)" in
      arm64) osv_asset=osv-scanner_darwin_arm64; osv_sha=f1e1cc84b6e365b79b874cb9028a4f74ac64666094b542f1eb196b10f44b505e ;;
      x86_64) osv_asset=osv-scanner_darwin_amd64; osv_sha=5c2a2e2a686e34c0674e0a463aa626467df5d9fba0ed06870a2eb684dc434de3 ;;
      *) return 1 ;;
    esac
    curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/google/osv-scanner/releases/download/v2.2.2/${osv_asset}" \
      --output "${osv_tool_dir}/osv-scanner" || return $?
    printf '%s  %s\n' "$osv_sha" "${osv_tool_dir}/osv-scanner" | shasum -a 256 -c - || return $?
    chmod 0755 "${osv_tool_dir}/osv-scanner"
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
