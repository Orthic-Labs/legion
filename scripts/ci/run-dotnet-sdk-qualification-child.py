#!/usr/bin/env python3
"""Retain one real native harness child; never synthesize provider observations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

SELECTOR = "native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Pinned .NET qualification requires native macOS arm64")
    expected = ["test", "--locked", "-p", "legion-audit", "--lib", SELECTOR, "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
    if len(command) != len(expected) + 1 or command[1:] != expected or not Path(command[0]).is_absolute():
        raise SystemExit("Exact native audit harness command required")
    root = args.output_root
    scratch = Path(os.environ["RUNNER_TEMP"])
    if os.environ.get("GITHUB_ACTIONS") != "true" or not root.is_absolute() or root.resolve() != root or scratch.resolve() != scratch or not root.is_relative_to(scratch):
        raise SystemExit("Canonical managed CI scratch root required")
    root.mkdir(parents=True, exist_ok=True)
    if any((root / name).exists() or (root / name).is_symlink() for name in ("child-execution.json", "child.stdout.log", "child.stderr.log", "code_dotnet.json")):
        raise SystemExit("Fresh retained child outputs required")
    with (root / "child.stdout.log").open("xb") as stdout, (root / "child.stderr.log").open("xb") as stderr:
        status = subprocess.run(command, stdout=stdout, stderr=stderr, check=False).returncode
    streams = {}
    for name, output in (("stdout", sys.stdout), ("stderr", sys.stderr)):
        raw = (root / ("child." + name + ".log")).read_bytes()
        streams[name] = {"file": "child." + name + ".log", "bytes": len(raw), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        output.buffer.write(raw)
        output.flush()
    result = {"schema": "legion-dotnet-code-command-child-execution/1", "productionQualification": False,
              "status": {"success": status == 0, "exitCode": status if status >= 0 else None, "signal": -status if status < 0 else None}, **streams}
    with (root / "child-execution.json").open("x") as file:
        json.dump(result, file, sort_keys=True, separators=(",", ":"))
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main())
