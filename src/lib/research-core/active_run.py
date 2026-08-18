#!/usr/bin/env python3
"""Durable workspace pointer for the Research run subject to hooks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import manifest
from common import atomic_write_json, utc_now


def pointer_path() -> Path:
    return manifest.default_run_root() / ".active-run.json"


def _executable(run: dict[str, Any]) -> bool:
    return run.get("status") not in {"failed", "done", "aborted"} and bool(run.get("route", {}).get("allowed_effects"))


def activate(run_id: str) -> dict[str, Any]:
    run = manifest.load_run(run_id)
    if not _executable(run):
        raise ValueError("Research run is not executable or route effects are not granted")
    value = {
        "pointer_version": 1,
        "run_id": run_id,
        "route_sha256": run["route_sha256"],
        "activated_at": utc_now(),
    }
    atomic_write_json(pointer_path(), value)
    manifest.record_event(run_id, "run.activated", {"pointer": str(pointer_path())})
    return value


def _pointed() -> str | None:
    path = pointer_path()
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        run_id = str(value["run_id"])
        run = manifest.load_run(run_id)
    except Exception:
        return None
    if value.get("route_sha256") != run.get("route_sha256") or not _executable(run):
        return None
    return run_id


def executable_runs() -> list[str]:
    root = manifest.default_run_root()
    candidates: list[str] = []
    if not root.is_dir():
        return candidates
    for path in sorted(root.glob("run-*/manifest.json")):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _executable(run) and run.get("run_id"):
            candidates.append(str(run["run_id"]))
    return candidates


def selection() -> dict[str, Any]:
    pointed = _pointed()
    if pointed:
        return {"run_id": pointed, "ambiguous": False, "candidates": [pointed], "source": "pointer"}
    candidates = executable_runs()
    if len(candidates) == 1:
        return {"run_id": candidates[0], "ambiguous": False, "candidates": candidates, "source": "single"}
    return {"run_id": None, "ambiguous": len(candidates) > 1, "candidates": candidates, "source": "none"}


def current() -> str | None:
    return selection()["run_id"]


def clear(run_id: str) -> bool:
    path = pointer_path()
    if not path.is_file():
        return False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if str(value.get("run_id")) != run_id:
        return False
    path.unlink(missing_ok=True)
    manifest.record_event(run_id, "run.deactivated", {"pointer": str(path)})
    return True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    activate_parser = sub.add_parser("activate")
    activate_parser.add_argument("run_id")
    clear_parser = sub.add_parser("clear")
    clear_parser.add_argument("run_id")
    sub.add_parser("current")
    args = parser.parse_args(argv)
    if args.command == "activate":
        print(json.dumps(activate(args.run_id), indent=2))
    elif args.command == "clear":
        print(json.dumps({"cleared": clear(args.run_id)}))
    else:
        print(json.dumps(selection(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
