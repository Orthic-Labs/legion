#!/usr/bin/env python3
"""Provision fixed official archives for managed macOS arm64 qualification.

Never executes downloaded tools, resolves project dependencies or runs wrappers.
Runtime uses only these already extracted distributions; bootstrap is forbidden.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import tarfile
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
LOCK = HERE / "audit-jvm-sdk-inputs.json"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def snapshot(root):
    root = root.resolve(strict=True)
    files = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(root), "toolchain symlink escapes root")
            files[relative] = "symlink:" + os.readlink(path)
        elif path.is_file():
            files[relative] = digest(path.read_bytes())
        else:
            require(path.is_dir(), "unsupported toolchain entry")
    require(files, "empty installed toolchain")
    return files


def extract(archive, destination):
    require(not destination.exists(), "extract destination already exists")
    destination.mkdir()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                path = PurePosixPath(item.filename)
                require(not path.is_absolute() and ".." not in path.parts, "unsafe ZIP member")
                mode = item.external_attr >> 16
                require(mode & 0o170000 != 0o120000, "ZIP symlink refused")
                target = destination / item.filename
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read(item))
                    target.chmod(0o755 if mode & 0o111 else 0o644)
    else:
        with tarfile.open(archive) as source:
            source.extractall(destination, filter="data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "lock targets macOS arm64")
    root = args.root.absolute()
    require(not root.exists() and (str(root).startswith("/Volumes/D/scratch/") or os.environ.get("GITHUB_ACTIONS") == "true"), "fresh external/managed CI root required")
    root.mkdir(parents=True)
    lock_bytes = LOCK.read_bytes()
    lock = json.loads(lock_bytes)
    require(lock["schema"] == "legion-jvm-sdk-inputs/1", "lock schema differs")
    enrollment = {"schema": "legion-jvm-sdk-enrollment/1", "lockDigest": digest(lock_bytes), "platform": lock["platform"], "versions": lock["versions"], "assets": {}, "toolchains": {}}
    for item in lock["assets"]:
        require(item["url"].startswith(("https://services.gradle.org/", "https://github.com/", "https://raw.githubusercontent.com/")), "unapproved official URL")
        archive = root / item["archive"]
        with urllib.request.urlopen(item["url"], timeout=120) as response, archive.open("xb") as output:
            shutil.copyfileobj(response, output)
        require(digest(archive.read_bytes()) == item["sha256"], "official archive checksum differs: " + item["id"])
        enrollment["assets"][item["id"]] = {**item, "path": str(archive)}
        if item["root"] is not None:
            directory = root / (item["id"] + "-extracted")
            extract(archive, directory)
            runtime = directory / item["root"]
            enrollment["toolchains"][item["id"]] = {"root": str(runtime.resolve(strict=True)), "files": snapshot(runtime)}
    (root / "enrollment.json").write_text(json.dumps(enrollment, sort_keys=True, separators=(",", ":")) + "\n")
    print(root / "enrollment.json")


if __name__ == "__main__":
    main()
