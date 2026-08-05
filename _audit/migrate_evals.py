#!/usr/bin/env python3
"""Migrate legacy local skill eval manifests to schema_version 1."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run_evals


REPO_ROOT = Path("D:/Claude")


def convert_legacy_case(case: dict[str, Any], index: int, skill: str) -> dict[str, Any]:
    assertions = case.get("assertions") or case.get("expectations") or []
    normalized_assertions: list[dict[str, Any] | str] = []
    for assertion in assertions:
        if isinstance(assertion, dict):
            normalized_assertions.append(assertion)
        else:
            normalized_assertions.append(str(assertion))
    return {
        "id": str(case.get("id") or f"legacy-{index + 1}"),
        "prompt": str(case.get("prompt") or ""),
        "expected_skill": skill,
        "forbidden_skills": [],
        "expected_behavior": str(case.get("expected_output") or case.get("expected_behavior") or ""),
        "assertions": normalized_assertions,
        "severity": "error",
        "mode": "static",
    }


def migrate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" in manifest:
        return manifest

    skill = str(manifest.get("skill_name") or manifest.get("skill") or "")
    legacy_cases = manifest.get("evals") or []
    converted = [
        convert_legacy_case(case, index, skill)
        for index, case in enumerate(legacy_cases)
        if isinstance(case, dict)
    ]
    return {
        "schema_version": 1,
        "skill": skill,
        "should_trigger": converted,
        "should_not_trigger": [],
        "output_quality": converted,
        "safety": [],
        "pressure": [],
        "compatibility": [],
    }


def migrate_file(path: Path, write: bool) -> tuple[bool, str]:
    manifest, error = run_evals.load_json(path)
    if error or manifest is None:
        return False, error or "invalid JSON"
    migrated = migrate_manifest(manifest)
    if migrated == manifest:
        return False, "already current"
    if write:
        path.write_text(json.dumps(migrated, indent=2), encoding="utf-8")
    return True, "migrated" if write else "would migrate"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate local skill eval manifests.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Workspace root.")
    parser.add_argument("--write", action="store_true", help="Write migrated files. Default is dry-run.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    args = parser.parse_args(argv)

    root = Path(args.root)
    results = []
    for path in run_evals.eval_files(root):
        changed, status = migrate_file(path, write=args.write)
        results.append({"path": str(path), "changed": changed, "status": status})

    if args.json:
        print(json.dumps({"root": str(root), "results": results}, indent=2))
    else:
        for result in results:
            marker = "changed" if result["changed"] else "skip"
            print(f"[{marker}] {result['path']} - {result['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
