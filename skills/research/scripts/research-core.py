#!/usr/bin/env python3
"""Stable installed-skill launcher for shared Research runtime entrypoints."""

from pathlib import Path
import runpy
import sys


TARGETS = {
    "route-resolve": "router/route_resolve.py",
    "resource-guard": "resource_guard.py",
    "run": "run.py",
    "ledger": "ledger.py",
    "independence": "independence.py",
    "contradictions": "contradictions.py",
    "citecheck": "citecheck.py",
    "notebooklm": "providers/notebooklm.py",
    "meter": "meter.py",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        choices = "|".join(TARGETS)
        raise SystemExit(f"usage: research-core.py <{choices}> [args...]")
    command = sys.argv.pop(1)
    package_root = Path(__file__).resolve().parents[3]
    target = package_root / "src" / "lib" / "research-core" / TARGETS[command]
    sys.argv[0] = str(target)
    runpy.run_path(str(target), run_name="__main__")


if __name__ == "__main__":
    main()
