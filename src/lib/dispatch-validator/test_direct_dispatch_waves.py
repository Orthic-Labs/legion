#!/usr/bin/env python3
"""Focused adversarial checks for direct dispatch waves and one-touch ownership."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-dispatch.py"


def load_dispatch_validator():
    spec = importlib.util.spec_from_file_location("dispatch_validator", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def direct_wave_packet(root: Path) -> dict:
    prompt = root / "request.md"
    revision = git(root, "rev-parse", "HEAD")
    return {
        "schemaVersion": 1,
        "kind": "legion-authority-dispatch",
        "packetType": "direct",
        "repositoryRoot": str(root),
        "sourceRevision": revision,
        "promptArtifact": str(prompt),
        "promptDigest": "sha256:" + hashlib.sha256(prompt.read_bytes()).hexdigest(),
        "modelRouting": {
            "modelTier": "MID",
            "workerProfile": "parallel",
            "routingRationale": "earliest safe dependency waves",
        },
        "objective": "Implement one bounded vertical slice through disjoint lanes.",
        "authority": ["AGENTS.md", "plan.md"],
        "integrationOwner": "current orchestrator",
        "fileTouchPolicy": {
            "mode": "once-end-to-end",
            "plannedFiles": ["src/runtime.rs", "tests/runtime.rs", "docs/runtime.md"],
            "allowUnplannedFiles": False,
        },
        "dispatches": [
            {
                "id": "A",
                "dependsOn": [],
                "lanes": ["runtime", "tests"],
                "completionChecks": ["runtime and test lanes pass focused checks"],
            },
            {
                "id": "B",
                "dependsOn": ["A"],
                "lanes": ["docs"],
                "completionChecks": ["docs bind verified A behavior"],
            },
        ],
        "workers": [
            {
                "id": "runtime",
                "dispatch": "A",
                "executor": "worker",
                "allowlist": ["src/runtime.rs"],
                "read": ["plan.md"],
                "forbidden": [".git", "secrets"],
                "checks": ["run runtime-focused test"],
                "dependencies": [],
            },
            {
                "id": "tests",
                "dispatch": "A",
                "executor": "worker",
                "allowlist": ["tests/runtime.rs"],
                "read": ["src/runtime.rs", "plan.md"],
                "forbidden": [".git", "secrets"],
                "checks": ["run test-focused test"],
                "dependencies": [],
            },
            {
                "id": "docs",
                "dispatch": "B",
                "executor": "worker",
                "allowlist": ["docs/runtime.md"],
                "read": ["src/runtime.rs", "tests/runtime.rs"],
                "forbidden": [".git", "secrets"],
                "checks": ["verify documented identities against A output"],
                "dependencies": [],
            },
        ],
        "oracleAudit": {
            "required": True,
            "mode": "adversarial",
            "status": "required-before-execution",
            "checks": [
                "allowlist-completeness",
                "lane-disjointness",
                "dependency-validity",
                "maximum-safe-parallelization",
                "end-to-end-lane-closure",
            ],
        },
        "recovery": {
            "maxRetries": 1,
            "stopConditions": ["required private input is missing"],
            "returnFields": [
                "changedPaths",
                "checks",
                "blockers",
                "baselineRevision",
                "patchDigest",
            ],
        },
    }


def errors_for(validator, value: dict, path: Path) -> list[str]:
    errors, _ = validator.authority_packet_errors(value, path)
    return errors


def main() -> int:
    validator = load_dispatch_validator()
    with tempfile.TemporaryDirectory(prefix="dispatch-waves-") as directory:
        root = Path(directory)
        git(root, "init", "-q")
        git(root, "config", "user.email", "dispatch@example.test")
        git(root, "config", "user.name", "Dispatch Test")
        (root / "AGENTS.md").write_text("authority\n", encoding="utf-8")
        (root / "plan.md").write_text("plan\n", encoding="utf-8")
        (root / "request.md").write_text("request\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "fixture")
        path = root / "dispatch.json"
        value = direct_wave_packet(root)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        assert not errors_for(validator, value, path)

        duplicate = json.loads(json.dumps(value))
        duplicate["workers"][1]["allowlist"].append("src/runtime.rs")
        assert any("direct OWN collision" in error for error in errors_for(validator, duplicate, path))

        missing = json.loads(json.dumps(value))
        missing["fileTouchPolicy"]["plannedFiles"].append("src/unassigned.rs")
        assert any("planned files lack lane allowlist" in error for error in errors_for(validator, missing, path))

        wildcard = json.loads(json.dumps(value))
        wildcard["workers"][0]["allowlist"] = ["src/**"]
        assert any("allowlist forbids globs" in error for error in errors_for(validator, wildcard, path))

        late_root = json.loads(json.dumps(value))
        late_root["dispatches"][1]["dependsOn"] = []
        assert any("move its lanes into first eligible wave" in error for error in errors_for(validator, late_root, path))

        worker_dependency = json.loads(json.dumps(value))
        worker_dependency["workers"][2]["dependencies"] = ["runtime"]
        assert any("dependencies belong on dispatch wave" in error for error in errors_for(validator, worker_dependency, path))

        no_oracle = json.loads(json.dumps(value))
        del no_oracle["oracleAudit"]
        assert any("adversarial Oracle" in error for error in errors_for(validator, no_oracle, path))

    print("PASS: direct dispatch waves enforce exact one-touch allowlists and Oracle contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
