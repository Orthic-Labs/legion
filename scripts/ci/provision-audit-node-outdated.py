#!/usr/bin/env python3
"""Bind existing CI Node/npm runtime; read/hash only, no install or package commands."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

NODE = {"18e387c90ab8a8400183e8bdd396376e1e875b91b4c874b894dcade7b35bf572", "0b4f059915f3bf3c6cbb02422f4a529bfb21cbbec2d29851c9a5d833f78a04f6"}
FIXTURES = "engine/crates/legion-audit/tests/fixtures/node-outdated"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def snapshot(root):
    files = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = path.resolve(strict=True)
            assert target.is_relative_to(root)
            files[relative] = {"symlink": str(path.readlink()), "canonicalTarget": target.relative_to(root).as_posix()}
        elif path.is_file():
            data = path.read_bytes()
            files[relative] = {"digest": digest(data), "bytes": len(data)}
        else:
            assert path.is_dir()
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--receipts", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve(strict=True)
    receipts = Path(args.receipts).resolve(strict=True)
    node = Path(shutil.which("node")).resolve(strict=True)
    npm = Path(shutil.which("npm")).resolve(strict=True)
    assert digest(node.read_bytes()).removeprefix("sha256:") in NODE
    package = npm.parent.parent
    assert npm == package / "bin/npm-cli.js"
    # Both runtime paths must belong to shared installed Node prefix.
    assert node.parent.parent == package.parent.parent.parent
    manifest = json.loads((package / "package.json").read_bytes())
    assert manifest["name"] == "npm" and manifest["version"] == "10.9.8"
    source_pin = json.loads((root / FIXTURES / "npm-source-pin.json").read_bytes())
    assert source_pin["npmCliDigest"] == digest(npm.read_bytes())
    files = snapshot(package)
    for path, expected in source_pin["files"].items():
        assert files[path]["digest"] == expected, path
    record = {"schema": "legion-node-outdated-ci-provision/1", "nodeVersion": "22.23.2", "npmVersion": "10.9.8",
              "nodePath": str(node), "nodeDigest": digest(node.read_bytes()), "npmPath": str(npm), "npmCliDigest": digest(npm.read_bytes()),
              "npmRoot": str(package), "npmFiles": files, "npmFilesDigest": digest(encoded(files)), "npmSource": source_pin}
    target = receipts / "provision.json"
    target.write_text(json.dumps(record, indent=2) + "\n")
    # Shell receives only environment values, never commands.
    (receipts / "runtime.env").write_text("LEGION_NODE_OUTDATED_NODE=" + str(node) + "\nLEGION_NODE_OUTDATED_NPM=" + str(npm) + "\n")


if __name__ == "__main__":
    main()
