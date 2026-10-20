#!/usr/bin/env python3
"""CI-only build of unchanged pinned upstream cargo-geiger; retains actual build output."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.request

COMMIT = "08543ac0b48ff6eec12c0a1f2478ef9c3259cd4d"
URL = "https://api.github.com/repos/geiger-rs/cargo-geiger/tarball/" + COMMIT
ARCHIVE = "sha256:4fbe170b23e5130aadb2ede5b169d027596dada6ad2aadf6422f50a858ce3e3b"
LOCK = "sha256:3f11d51a112555ed76faec9ab9d10cf9ae0f852582e6a3b12773aabf41f583c4"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def execute(argv, cwd, env):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=1200)
        code, stdout, stderr, timed_out = result.returncode, result.stdout, result.stderr, False
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
    return {"argv": argv, "cwd": str(cwd), "exitCode": code, "timedOut": timed_out, "timeoutSeconds": 1200,
            "stdout": stdout.decode("utf-8"), "stderr": stderr.decode("utf-8"),
            "stdoutDigest": digest(stdout), "stderrDigest": digest(stderr)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--toolchain-bin", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "macOS", "nested Cargo provisioning requires native macOS CI")
    base, toolchain = args.directory.resolve(), args.toolchain_bin.resolve()
    base.mkdir()  # Refuse reuse of an earlier provision result.
    env = dict(os.environ)
    env["PATH"] = str(toolchain) + os.pathsep + env["PATH"]
    env["RUSTC"] = str(toolchain / "rustc")
    versions = {name: execute([str(toolchain / name), "--version"], base, env) for name in ("cargo", "rustc")}
    require(all(row["exitCode"] == 0 and row["stdout"].startswith(name + " 1.98.0 ") for name, row in versions.items()), "pinned workspace Cargo/Rust unavailable")
    data = urllib.request.urlopen(URL, timeout=120).read()
    require(digest(data) == ARCHIVE, "pinned upstream source archive differs")
    archive = base / "upstream.tar.gz"
    archive.write_bytes(data)
    source = base / "source"
    source.mkdir()
    links = {}
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = PurePosixPath(member.name).parts
            require(len(parts) >= 1 and not PurePosixPath(member.name).is_absolute() and ".." not in parts, "unsafe archive path")
            relative = Path(*parts[1:])
            if not relative.parts:
                require(member.isdir(), "archive root is not a directory")
                continue
            target = source / relative
            if member.issym():
                require(relative.as_posix() == "cargo-geiger/README.md" and member.linkname == "../README.md", "unreviewed upstream symlink")
                links[relative.as_posix()] = member.linkname
                continue
            require(member.isdir() or member.isfile(), "archive hardlink/special file refused")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(member).read())
    require(links == {"cargo-geiger/README.md": "../README.md"}, "reviewed upstream link missing")
    for relative, link in links.items():
        target = source / relative
        require((target.parent / link).resolve().is_relative_to(source) and (target.parent / link).is_file(), "upstream link leaves source root")
        target.symlink_to(link)
    require(digest((source / "Cargo.lock").read_bytes()) == LOCK, "upstream lock differs")
    source_hashes = {p.relative_to(source).as_posix(): digest(p.read_bytes()) for p in source.rglob("*") if p.is_file() and not p.is_symlink()}
    # Inherited CI Cargo configuration owns build/cache output.
    argv = [str(toolchain / "cargo"), "install", "--debug", "--locked", "--path", str(source / "cargo-geiger"), "--root", str(base / "tools")]
    build = execute(argv, source, env)
    (base / "build.stdout.log").write_text(build["stdout"])
    (base / "build.stderr.log").write_text(build["stderr"])
    row = {"schema": "legion-cargo-geiger-ci-provision/1", "sourceCommit": COMMIT, "archiveUrl": URL, "archiveDigest": ARCHIVE,
           "archivePath": str(archive), "source": str(source), "sourceFiles": source_hashes, "sourceLinks": links, "lockDigest": LOCK,
           "toolchainBin": str(toolchain), "toolchainVersions": versions,
           "toolchainDigests": {name: digest((toolchain / name).read_bytes()) for name in versions}, "build": build}
    tool = base / "tools/bin/cargo-geiger"
    if build["exitCode"] == 0:
        row.update({"tool": str(tool.resolve()), "toolDigest": digest(tool.read_bytes())})
    (base / "provision.json").write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
    print(build["stdout"], end="")
    print(build["stderr"], end="", file=__import__("sys").stderr)
    require(build["exitCode"] == 0, "actual pinned upstream CI build failed; raw logs retained")
    print("CARGO_GEIGER_CI_PROVISION " + json.dumps(row, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
