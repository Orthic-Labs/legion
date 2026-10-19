#!/usr/bin/env python3
"""Observe installed managed macOS inputs. No install, process, trust or admission grant."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

CODE = "engine/crates/legion-audit/src/native_providers/code/"
HELPER = "scripts/ci/audit-mobile-native-enrollment.py"
VALIDATOR = "scripts/ci/audit-mobile-sdk-accuracy.py"
SOURCE_ROOTS = ["engine/crates/" + name + "/src" for name in
                ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HELPER, VALIDATOR,
                "scripts/ci/tests/test_audit_mobile_sdk_accuracy.py", "scripts/ci/audit-qualification-records.py",
                "scripts/ci/tests/test_audit_qualification_records.py", "scripts/ci/tests/test_python_code_sdk_adapter.py", "qualification/provider-accuracy/schema.json",
                "bench/provider-accuracy-plan.json", "src/registry/providers.json", ".github/workflows/ci.yml",
                "scripts/ci/right-git-ci.sh", ".rightgit.json", "package.json", "pnpm-lock.yaml"] + [
                    "engine/crates/" + name + "/Cargo.toml" for name in
                    ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]
MAX_NODES, MAX_BYTES = 500_000, 32 * 1024**3
OS_BOUNDARY = "Apple system dynamic runtime identified by enrolled macOS build; no system-library completeness claim"
SCOPE = "installed macOS Xcode toolchain + selected SDK + XCTest/runtime support + SwiftLint"


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def parsed(data):
    def pairs(rows):
        require(len(rows) == len(dict(rows)), "duplicate JSON field")
        return dict(rows)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def file_hash(path):
    hash_ = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            hash_.update(chunk)
    return "sha256:" + hash_.hexdigest()


def source_files(root):
    files = set(SOURCE_FILES)
    for name in SOURCE_ROOTS:
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink(), "source root absent/unsafe")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            relative = path.relative_to(root).as_posix()
            generated = re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative)
            if path.is_file() and not generated:
                files.add(relative)
    for name in files:
        path = root / name
        require(path.is_file() and not path.is_symlink(), "source closure file absent/unsafe: " + name)
    return sorted(files)


def registry_semantics(value):
    # Qualification is downstream registration metadata, never provider behavior.
    # Keep every provider, capability, selector & requiredForCleanClaim bit.
    value = parsed(encoded(value))
    require(isinstance(value.get("providers"), list), "provider registry missing")
    for provider in value["providers"]:
        benchmark = provider.get("benchmark")
        require(isinstance(benchmark, dict), "provider benchmark missing")
        for name in ("status", "qualificationDigest", "qualification"):
            benchmark.pop(name, None)
    return value


def source_digest(root, name):
    path = root / name
    return digest(encoded(registry_semantics(parsed(path.read_bytes())))) if name == "src/registry/providers.json" else file_hash(path)


def source_snapshot(root):
    files = {name: source_digest(root, name) for name in source_files(root)}
    return {"schema": "legion-mobile-source-enrollment/1", "root": str(root), "files": files, "digest": digest(encoded(files)), "registryRawDigest":file_hash(root / "src/registry/providers.json")}


def installed_roots(sdk, swiftlint):
    developer = next((parent for parent in sdk.parents if (parent / "Toolchains/XcodeDefault.xctoolchain").is_dir()), None)
    require(developer is not None, "full managed Xcode required")
    contents = developer.parent
    swiftlint = swiftlint.resolve(strict=True)
    swiftlint_root = swiftlint.parent.parent if "/Cellar/swiftlint/" in str(swiftlint) else swiftlint
    roots = {"toolchain": developer / "Toolchains/XcodeDefault.xctoolchain", "macosSdk": sdk,
             "macosTestRuntime": developer / "Platforms/MacOSX.platform/Developer/Library",
             "developerTools": developer / "usr", "developerLibrary": developer / "Library",
             "xcodeSharedFrameworks": contents / "SharedFrameworks", "xcodeVersion": contents / "version.plist",
             "swiftlintRuntime": swiftlint_root, "osBuild": Path("/System/Library/CoreServices/SystemVersion.plist"),
             "xcrun": Path("/usr/bin/xcrun"), "xcodeSelect": Path("/usr/bin/xcode-select"), "sandboxExec": Path("/usr/bin/sandbox-exec")}
    return dict(sorted((name, path.resolve(strict=True)) for name, path in roots.items()))


def capture(sdk, swiftlint, audited_root):
    roots = installed_roots(sdk, swiftlint)
    trees, total = {}, 0
    for name, root in roots.items():
        require(not root.is_relative_to(audited_root), "native root overlaps audited source")
        rows = {}
        def walk(path):
            nonlocal total
            require(len(rows) < MAX_NODES, "native node budget")
            metadata = path.lstat()
            relative = "" if path == root else path.relative_to(root).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                rows[relative] = {"kind": "symlink", "target": os.readlink(path)}
                target = path.resolve(strict=True)
                require(any(target.is_relative_to(value) for value in roots.values()) or any(
                    target.is_relative_to(prefix) for prefix in (Path("/System/Library"), Path("/usr/lib"), Path("/System/Volumes/Preboot"))), "unenrolled native symlink")
            elif stat.S_ISDIR(metadata.st_mode):
                rows[relative] = {"kind": "directory"}
                for child in sorted(path.iterdir()):
                    walk(child)
            else:
                require(stat.S_ISREG(metadata.st_mode), "special native input")
                total += metadata.st_size
                require(total <= MAX_BYTES, "native byte budget")
                rows[relative] = {"kind": "file", "bytes": metadata.st_size, "digest": file_hash(path)}
        walk(root)
        trees[name] = {"root": str(root), "files": rows, "digest": digest(encoded(rows))}
    return {"schema": "legion-mobile-native-enrollment/1", "host": {"os": "macos", "arch": {"arm64": "aarch64", "x86_64": "x86_64"}[platform.machine()]},
            "sdkRoot": str(sdk), "sdkSettingsRawBytes":list((sdk / "SDKSettings.json").read_bytes()), "swiftlintExecutable": str(swiftlint.resolve(strict=True)),
            "swiftlintInvocation": {"path":str(swiftlint), "canonicalPath":str(swiftlint.resolve(strict=True)), "linkTarget":os.readlink(swiftlint) if swiftlint.is_symlink() else None}, "roots": trees,
            "fileBytes": total, "osRuntimeBoundary": OS_BOUNDARY, "scope": SCOPE}


def prepare(root, retained):
    require(platform.system() == "Darwin", "managed macOS only")
    root = root.resolve(strict=True)
    require(retained.is_absolute(), "absolute retained root required")
    retained.mkdir(parents=True, exist_ok=True)
    retained = retained.resolve(strict=True)
    require(not retained.is_relative_to(root), "retained root overlaps repository")
    if os.environ.get("SDKROOT"):
        sdk = Path(os.environ["SDKROOT"]).resolve(strict=True)
    elif os.environ.get("DEVELOPER_DIR"):
        sdk = (Path(os.environ["DEVELOPER_DIR"]) / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk").resolve(strict=True)
    else:
        sdk = Path("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk").resolve(strict=True)
    settings = parsed((sdk / "SDKSettings.json").read_bytes())
    require(settings["CanonicalName"].startswith("macosx") and isinstance(settings["Version"], str), "macOS SDK identity required")
    swiftlint = next((Path(directory) / "swiftlint" for directory in os.environ.get("PATH", "").split(os.pathsep)
                      if (Path(directory) / "swiftlint").is_file() and os.access(Path(directory) / "swiftlint", os.X_OK)), None)
    require(swiftlint is not None and not swiftlint.resolve().is_relative_to(root), "managed SwiftLint absent/unsafe")
    for name, value in (("mobile-native-enrollment.json", capture(sdk, swiftlint, root)), ("mobile-source-enrollment.json", source_snapshot(root))):
        path = retained / name
        require(not path.exists() and not path.is_symlink(), "refuse reused prepared enrollment")
        data = encoded(value)
        with path.open("xb") as stream:
            stream.write(data)
        require(path.read_bytes() == data, "enrollment readback failed")
    return {"nativeEnrollment": str(retained / "mobile-native-enrollment.json"), "sourceEnrollment": str(retained / "mobile-source-enrollment.json"), "qualificationEligible": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    print("CODE_MOBILE_INPUTS_PREPARED " + encoded(prepare(args.root, args.receipts)).decode())


if __name__ == "__main__":
    main()
