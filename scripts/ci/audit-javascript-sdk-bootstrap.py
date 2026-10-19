#!/usr/bin/env python3
"""Managed-CI-only archive enrollment; never run Node, pnpm, installers or scripts.

Archive package member bytes/modes & exact Node binary are source-pinned. The
native SDK harness, not this bootstrap, observes versions & execution results.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time
import urllib.request

LOCK = "scripts/ci/audit-javascript-sdk-inputs.json"
LOCK_SHA = "sha256:58ba385af748a5765ae510609ca4cd876aa97375875aabe4b5072c5a0f70d0dc"
MAX_BYTES = 512 * 1024 * 1024
MAX_NODES = 60000


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require(test, message):
    if not test:
        raise ValueError(message)


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON field")
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "input size/kind")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
    after = path.lstat()
    require(len(data) <= limit and len(data) == before.st_size == opened.st_size == after.st_size,
            "input grew/changed")
    require((before.st_dev, before.st_ino, before.st_mtime_ns) ==
            (opened.st_dev, opened.st_ino, opened.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_mtime_ns), "input identity changed")
    return data


def safe(value):
    path = PurePosixPath(value)
    require(value and "\\" not in value and not path.is_absolute()
            and all(p not in ("", ".", "..") for p in value.split("/")), "unsafe relative path")
    return path


def expected_tree(lock):
    files = {}
    for location, key in lock["locations"].items():
        safe(location)
        require(location.startswith("node_modules/"), "non-module location")
        for relative, descriptor in lock["packages"][key]["files"].items():
            safe(relative)
            target = location + "/" + relative
            require(target not in files, "overlapping package files")
            files[target] = descriptor
    links = {
        "node_modules/.bin/tsc": "../typescript/bin/tsc",
        "node_modules/.bin/eslint": "../eslint/bin/eslint.js",
        "node_modules/.bin/pnpm": "../pnpm/bin/pnpm.mjs",
    }
    directories = {"node_modules"}
    for name in set(files) | set(links):
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
    return {"files": files, "links": links, "directories": sorted(directories)}


def snapshot(root):
    root = root.resolve(strict=True)
    files, links = {}, {}
    directories = set()
    pending = [(root / "node_modules", 0)]
    total = nodes = 0
    while pending:
        path, depth = pending.pop()
        nodes += 1
        require(nodes <= MAX_NODES and depth <= 64, "runtime tree node/depth limit")
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raw = os.readlink(path)
            # Bootstrap creates only these relative official-bin links. No
            # external/intermediate alias chain is admitted by enrollment.
            require(relative in expected_tree_links() and raw == expected_tree_links()[relative], "unrecognized runtime alias")
            require(path.resolve(strict=True).is_relative_to(root), "runtime alias escaped")
            links[relative] = raw
        elif stat.S_ISDIR(info.st_mode):
            directories.add(relative)
            with os.scandir(path) as stream:
                children = []
                for entry in stream:
                    require(nodes + len(pending) + len(children) < MAX_NODES, "runtime tree node limit")
                    children.append(Path(entry.path))
            pending.extend((child, depth + 1) for child in sorted(children, reverse=True))
        else:
            data = read(path, MAX_BYTES - total)
            total += len(data)
            files[relative] = {"digest": digest(data), "bytes": len(data), "executable": bool(info.st_mode & 0o111)}
    return {"files": files, "links": links, "directories": sorted(directories)}


def expected_tree_links():
    return {"node_modules/.bin/tsc": "../typescript/bin/tsc",
            "node_modules/.bin/eslint": "../eslint/bin/eslint.js",
            "node_modules/.bin/pnpm": "../pnpm/bin/pnpm.mjs"}


def load_lock(repository_root):
    data = read(repository_root / LOCK, 4 * 1024 * 1024)
    require(digest(data) == LOCK_SHA, "input lock digest differs")
    lock = strict_json(data)
    require(lock["schema"] == "legion-javascript-sdk-inputs/1", "input schema")
    require(lock["roots"] == {"typescript": "5.9.3", "eslint": "9.39.1", "@typescript-eslint/parser": "8.46.2", "pnpm": "11.24.0", "@types/node": "22.19.0"}, "root tool pins differ")
    return lock


def verify_enrollment(repository_root, enrollment, live=False):
    """Pure data verification offline; live additionally rehashes actual inputs."""
    root = Path(repository_root)
    lock = load_lock(root)
    expected = expected_tree(lock)
    require(enrollment["schema"] == "legion-javascript-sdk-enrollment/1", "enrollment schema")
    require(enrollment["lockDigest"] == LOCK_SHA and enrollment["runtime"] == expected,
            "official package closure differs")
    require(enrollment["runtimeDigest"] == digest(encoded(expected)), "runtime digest differs")
    node = enrollment["node"]
    require(node["digest"] in lock["nodeDigests"] and node["pinnedVersion"] == lock["nodeVersion"], "Node source pin differs")
    require(set(enrollment["archives"]) == set(lock["packages"]), "archive denominator differs")
    for key, package in lock["packages"].items():
        archive = enrollment["archives"][key]
        require(archive["url"] == package["url"] and archive["digest"] == package["digest"]
                and archive["bytes"] == package["bytes"], "official archive source differs")
    tool_root = Path(enrollment["toolRoot"])
    require(tool_root.is_absolute() and Path(node["path"]).is_absolute(), "runtime paths must be absolute")
    for name, relative in {"tsc": "typescript/bin/tsc", "eslint": "eslint/bin/eslint.js", "pnpm": "pnpm/bin/pnpm.mjs"}.items():
        require(enrollment["tools"][name] == str(tool_root / "node_modules" / relative), "tool path differs")
    if live:
        require(tool_root.resolve(strict=True) == tool_root, "tool root alias")
        require(snapshot(tool_root) == expected, "runtime closure changed")
        require(digest(read(Path(node["path"]), MAX_BYTES)) == node["digest"], "Node runtime changed")
    return {"lockDigest": LOCK_SHA, "runtimeDigest": enrollment["runtimeDigest"],
            "nodeDigest": node["digest"], "packages": len(lock["packages"]), "files": len(expected["files"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_TEMP"), "managed CI only")
    repository = Path(args.repository_root).resolve(strict=True)
    output = Path(args.output_root)
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(output.is_absolute() and output.parent.resolve(strict=True).is_relative_to(temporary)
            and not output.exists(), "output must be new managed scratch")
    node = Path(args.node).resolve(strict=True)
    node_digest = digest(read(node, MAX_BYTES))
    lock = load_lock(repository)
    require(node_digest in lock["nodeDigests"], "Node is not exact pinned official runtime")
    output.mkdir()
    (output / "archives").mkdir()
    deadline = time.monotonic() + 300
    transferred = 0
    archives = {}
    for key, package in sorted(lock["packages"].items()):
        require(time.monotonic() < deadline, "bootstrap total deadline")
        url = package["url"]
        require(url.startswith("https://registry.npmjs.org/") and package["bytes"] < 64 * 1024 * 1024,
                "source origin/size")
        with urllib.request.urlopen(url, timeout=min(30, max(1, deadline - time.monotonic()))) as response:
            require(response.geturl() == url, "archive redirected")
            chunks = []
            received = 0
            while True:
                require(time.monotonic() < deadline, "bootstrap total deadline")
                chunk = response.read1(min(65536, package["bytes"] + 1 - received))
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
                require(received <= package["bytes"], "archive exceeds byte bound")
            data = b"".join(chunks)
        transferred += len(data)
        require(transferred <= 64 * 1024 * 1024 and len(data) == package["bytes"]
                and digest(data) == package["digest"], "archive bytes differ")
        archive_file = output / "archives" / (package["digest"].split(":", 1)[1] + ".tgz")
        archive_file.write_bytes(data)
        members = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                require(time.monotonic() < deadline, "bootstrap total deadline")
                path = safe(member.name.rstrip("/"))
                require(path.parts[0] == package["archivePrefix"], "archive prefix differs")
                if member.isdir():
                    continue
                require(member.isfile() and len(path.parts) > 1, "nonregular archive member")
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                require(relative in package["files"] and relative not in members, "archive file denominator differs")
                descriptor = package["files"][relative]
                require(member.size == descriptor["bytes"], "member size differs")
                stream = archive.extractfile(member)
                content = stream.read(descriptor["bytes"] + 1)
                require(len(content) == descriptor["bytes"] and digest(content) == descriptor["digest"]
                        and bool(member.mode & 0o111) == descriptor["executable"], "member bytes/mode differ")
                members[relative] = content
        require(set(members) == set(package["files"]), "archive files missing")
        for location, expected_key in lock["locations"].items():
            if expected_key != key:
                continue
            destination = output / safe(location)
            for relative, content in members.items():
                target = destination / safe(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                require(not target.exists() and not target.is_symlink(), "overlapping archive path")
                target.write_bytes(content)
                target.chmod(0o755 if package["files"][relative]["executable"] else 0o644)
        archives[key] = {"url": url, "digest": digest(data), "bytes": len(data), "path": str(archive_file)}
    for relative, target in expected_tree_links().items():
        link = output / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    record = {"schema": "legion-javascript-sdk-enrollment/1", "lockDigest": LOCK_SHA,
              "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "toolRoot": str(output), "runtime": snapshot(output), "archives": archives,
              "node": {"path": str(node), "digest": node_digest, "pinnedVersion": lock["nodeVersion"]},
              "tools": {"tsc": str(output / "node_modules/typescript/bin/tsc"),
                        "eslint": str(output / "node_modules/eslint/bin/eslint.js"),
                        "pnpm": str(output / "node_modules/pnpm/bin/pnpm.mjs")}}
    record["runtimeDigest"] = digest(encoded(record["runtime"]))
    verify_enrollment(repository, record, live=True)
    (output / "enrollment.json").write_bytes(encoded(record) + b"\n")
    print(str(output / "enrollment.json"))


if __name__ == "__main__":
    main()
