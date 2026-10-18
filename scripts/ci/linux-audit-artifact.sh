#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "linux-audit-artifact: $*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == "true" ]] || fail "must run in GitHub Actions"
[[ "${RUNNER_OS:-}" == "Linux" ]] || fail "requires a Linux GitHub runner"
[[ "$(uname -m)" == "x86_64" ]] || fail "requires an x86_64 runner"
[[ -z "${CARGO_BUILD_TARGET:-}" ]] || fail "requires native Linux compilation without CARGO_BUILD_TARGET"
[[ -n "${GITHUB_WORKSPACE:-}" && -d "$GITHUB_WORKSPACE" ]] || fail "GITHUB_WORKSPACE is missing"
[[ -n "${GITHUB_SHA:-}" ]] || fail "GITHUB_SHA is missing"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || fail "RUNNER_TEMP is missing"

if [[ ! -r /etc/os-release ]] || ! grep -q '^ID=ubuntu$' /etc/os-release || ! grep -q '^VERSION_ID="24.04"$' /etc/os-release; then
  fail "requires managed Ubuntu 24.04"
fi

cd "$GITHUB_WORKSPACE"
actual_sha="$(git rev-parse HEAD)"
[[ "$actual_sha" == "$GITHUB_SHA" ]] || fail "checkout HEAD $actual_sha does not match GITHUB_SHA $GITHUB_SHA"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || fail "source checkout is not clean"

toolchain_file="$GITHUB_WORKSPACE/engine/rust-toolchain.toml"
[[ -f "$toolchain_file" ]] || fail "engine/rust-toolchain.toml is missing"
grep -Eq '^channel[[:space:]]*=[[:space:]]*"1\.98\.0"$' "$toolchain_file" || fail "Rust toolchain manifest must pin 1.98.0"
rust_version="$(cd "$GITHUB_WORKSPACE/engine" && rustc --version)"
[[ "$rust_version" == "rustc 1.98.0 "* ]] || fail "active Rust is not pinned 1.98.0: $rust_version"

python3 - <<'PY'
import pathlib
import tomllib

expected = {
    "engine/bins/legion/Cargo.toml": ("legion", "legion"),
    "engine/bins/legion-hook/Cargo.toml": ("legion-hook", "legion-hook"),
    "engine/bins/legion-mcp/Cargo.toml": ("legion-mcp", "legion-mcp"),
    "engine/xtask/Cargo.toml": ("xtask", "xtask"),
}
for path, (package_name, binary_name) in expected.items():
    manifest = tomllib.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if manifest.get("package", {}).get("name") != package_name:
        raise SystemExit(f"{path}: expected package {package_name}")
    if not any(binary.get("name") == binary_name for binary in manifest.get("bin", [])):
        raise SystemExit(f"{path}: expected binary {binary_name}")
PY

# The managed workflow provisions pnpm before invoking this script. Cargo is
# intentionally run directly on the GitHub runner and remains lockfile-bound.
export CARGO_INCREMENTAL=1
export CARGO_PROFILE_DEV_DEBUG=0
(cd "$GITHUB_WORKSPACE/engine" && cargo build --locked \
  --bin legion --bin legion-hook --bin legion-mcp --bin xtask)

target_root="$(cd "$GITHUB_WORKSPACE/engine" && cargo metadata --locked --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
binary_root="$target_root/debug"
xtask="$binary_root/xtask"
[[ -x "$xtask" ]] || fail "debug xtask binary is missing or not executable"

artifact_root="$GITHUB_WORKSPACE/dist/linux-audit"
payload="$RUNNER_TEMP/legion-linux-audit-payload"
assembly_tmp="$RUNNER_TEMP/legion-linux-audit-modes.txt"
extraction_root="$RUNNER_TEMP/legion-linux-audit-extracted"
rm -rf "$artifact_root" "$assembly_tmp" "$extraction_root"
mkdir -p "$artifact_root"
"$xtask" assemble-native-release \
  --profile debug --platform linux --architecture x86_64 \
  --bin-dir "$binary_root" --out "$payload" --force
if ! timeout 5m "$xtask" native-installed-smoke "$payload" "$RUNNER_TEMP/legion-linux-audit-installed" \
  > "$artifact_root/assembly-smoke.log" 2>&1; then
  cat "$artifact_root/assembly-smoke.log" >&2
  fail "assembled payload native-installed-smoke failed or timed out"
fi

# Record content hashes and executable modes outside the sealed assembler
# output. The extracted copy must match both manifests before its smoke run.
if find "$payload" -type l -print -quit | grep -q .; then
  fail "assembled payload contains a symlink"
fi
(
  cd "$payload"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "$artifact_root/payload-files.sha256"
(
  cd "$payload"
  find . -type f -printf '%m %p\n' | LC_ALL=C sort
) > "$artifact_root/payload-modes.txt"

archive="$artifact_root/linux-audit-payload.tar.gz"
tar -czf "$archive" -C "$(dirname "$payload")" "$(basename "$payload")"
(
  cd "$artifact_root"
  sha256sum "$(basename "$archive")" > linux-audit-payload.sha256
  sha256sum -c linux-audit-payload.sha256
)

mkdir -p "$extraction_root"
tar -xzf "$archive" --no-same-owner --same-permissions -C "$extraction_root"
(
  cd "$extraction_root/$(basename "$payload")"
  sha256sum -c "$artifact_root/payload-files.sha256" >/dev/null
  find . -type f -printf '%m %p\n' | LC_ALL=C sort
) > "$assembly_tmp"
diff -u "$artifact_root/payload-modes.txt" "$assembly_tmp" || fail "archive extraction changed payload file modes"
if ! timeout 5m "$xtask" native-installed-smoke "$extraction_root/$(basename "$payload")" \
  "$RUNNER_TEMP/legion-linux-audit-extracted-installed" > "$artifact_root/archive-extraction-smoke.log" 2>&1; then
  cat "$artifact_root/archive-extraction-smoke.log" >&2
  fail "archive-extracted payload native-installed-smoke failed or timed out"
fi

GITHUB_SHA="$GITHUB_SHA" \
CHECKOUT_HEAD="$actual_sha" \
RUSTC_VERSION="$rust_version" \
MACHINE_ARCH="$(uname -m)" \
PAYLOAD_PATH="$payload" \
python3 - "$artifact_root/provenance.json" <<'PY'
import json
import os
import pathlib
import sys

provenance = {
    "schemaVersion": 1,
    "kind": "legion-linux-debug-audit-artifact",
    "source": {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "commit": os.environ["GITHUB_SHA"],
        "checkoutHead": os.environ["CHECKOUT_HEAD"],
        "clean": True,
    },
    "run": {
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "runId": os.environ.get("GITHUB_RUN_ID", ""),
        "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "runnerOs": os.environ["RUNNER_OS"],
        "runnerArchitecture": os.environ["MACHINE_ARCH"],
        "ubuntuVersion": "24.04",
        "rustc": os.environ["RUSTC_VERSION"],
        "cargoProfile": "debug",
    },
    "payload": {
        "path": os.path.basename(os.environ["PAYLOAD_PATH"]),
        "archive": "linux-audit-payload.tar.gz",
        "archiveSha256File": "linux-audit-payload.sha256",
        "fileChecksums": "payload-files.sha256",
        "fileModes": "payload-modes.txt",
        "assemblySmokeLog": "assembly-smoke.log",
        "archiveExtractionSmokeLog": "archive-extraction-smoke.log",
        "assemblySmoke": "passed",
        "archiveExtractionSmoke": "passed",
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
PY

echo "Linux debug audit payload ready: $artifact_root"
