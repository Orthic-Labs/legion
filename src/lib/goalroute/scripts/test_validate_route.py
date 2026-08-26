#!/usr/bin/env python3
"""Adversarial tests for GoalRoute v2 validation."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-route.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("route_validator", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_route() -> dict:
    run_id = "11111111-2222-4333-8444-555555555555"
    evidence = "D:/workspace/evidence/route-design.json"
    return {
        "schema": "goal-route.v2",
        "route_id": "delivery-route-001",
        "purpose": "DELIVERY",
        "routine": False,
        "comparison_mode": "COMPARE",
        "state_a": {
            "description": "Current runner uses an unvalidated serial implementation path.",
            "evidence": [
                {
                    "locator": evidence,
                    "sha256": "a" * 64,
                    "check": "Read current runner and observed serial route at revision abc123.",
                }
            ],
        },
        "state_b": {
            "description": "Validated implementation reaches required output with all checks green.",
            "proof": [
                {
                    "command": "py -3.11 D:/workspace/tests/verify_goal.py",
                    "expected": "Exit 0 and result status equals VERIFIED_COMPLETE.",
                    "evidence_path": "D:/workspace/evidence/verified-complete.json",
                }
            ],
        },
        "constraints": {
            key: {
                "rule": rule,
                "evidence_locator": evidence,
            }
            for key, rule in {
                "authority": "Only requested workspace files may change.",
                "safety": "Preserve user changes and forbid destructive production mutation.",
                "scope": "Implement route contract and named consumer bindings only.",
                "quality": "All validators, adversarial tests and receipts must pass.",
                "cost": "Use local tools with zero paid external calls.",
            }.items()
        },
        "candidates": [
            {
                "id": "R_FAST",
                "constraint_status": "PASS",
                "constraint_evidence": "D:/workspace/evidence/r-fast.json",
                "steps": [
                    {
                        "id": "R_FAST/S1",
                        "operation": "Patch the nominally shortest implementation path.",
                        "depends_on": [],
                        "min_wall_ms": 300000,
                        "kind": "ADVANCE_B",
                        "b_state_delta": "Implementation patch exists for first half of route.",
                    },
                    {
                        "id": "R_FAST/S2",
                        "operation": "Run final verification on nominal fast path.",
                        "depends_on": ["R_FAST/S1"],
                        "min_wall_ms": 300000,
                        "kind": "ADVANCE_B",
                        "b_state_delta": "Final verification records pass or failure.",
                    },
                ],
                "probabilities_bps": {"retry": 0, "terminal_failure": 5000},
                "retry_cost_ms": 0,
                "rework_cost_ms": 1800000,
                "nominal_critical_path_ms": 600000,
                "expected_time_to_verified_b_ms": 1500000,
                "cost_units": 1,
                "risk_units": 8,
                "rework_units": 9,
                "status": "REJECTED",
                "dominance_reason": "R_SAFE has lower expected time after failure rework.",
                "evidence": ["D:/workspace/evidence/r-fast.json"],
            },
            {
                "id": "R_SAFE",
                "constraint_status": "PASS",
                "constraint_evidence": "D:/workspace/evidence/r-safe.json",
                "steps": [
                    {
                        "id": "R_SAFE/S1",
                        "operation": "Add contract test and implement validated route.",
                        "depends_on": [],
                        "min_wall_ms": 360000,
                        "kind": "ADVANCE_B",
                        "b_state_delta": "Contract test and implementation prove route mechanics.",
                    },
                    {
                        "id": "R_SAFE/S2",
                        "operation": "Run adversarial and integration verification.",
                        "depends_on": ["R_SAFE/S1"],
                        "min_wall_ms": 360000,
                        "kind": "ADVANCE_B",
                        "b_state_delta": "All acceptance checks produce durable evidence.",
                    },
                ],
                "probabilities_bps": {"retry": 0, "terminal_failure": 100},
                "retry_cost_ms": 0,
                "rework_cost_ms": 1800000,
                "nominal_critical_path_ms": 720000,
                "expected_time_to_verified_b_ms": 738000,
                "cost_units": 2,
                "risk_units": 1,
                "rework_units": 1,
                "status": "SELECTED",
                "dominance_reason": "Minimum expected time to verified B.",
                "evidence": ["D:/workspace/evidence/r-safe.json"],
            },
        ],
        "selected_route_id": "R_SAFE",
        "selected_critical_path": ["R_SAFE/S1", "R_SAFE/S2"],
        "parallel_lanes": [],
        "bottleneck": {
            "step_id": "R_SAFE/S1",
            "bound_ms": 360000,
            "resource": "contract implementation and focused verification",
        },
        "deleted_work": [
            {
                "item": "Nominal-only route ranking",
                "reason": "It cannot choose lowest expected time to verified success.",
            }
        ],
        "deferred_work": [
            {
                "item": "Downstream execution batch",
                "until": "GoalRoute receipt verification passes.",
            }
        ],
        "single_feasible_evidence": [],
        "invalidation": {
            "revision": 1,
            "semantic_correction": "NONE",
            "invalidates": [],
            "source_fingerprint_sha256": "b" * 64,
        },
        "alchemist": {
            "required": True,
            "run_id": run_id,
            "state_ref": f"alchemist://run/{run_id}/state",
            "checkpoint": "GOAL_ROUTE_V2",
            "reason": "Non-routine shared workflow change.",
        },
    }


def expect_error(module, name: str, mutate, expected: str) -> None:
    case = copy.deepcopy(valid_route())
    mutate(case)
    errors = module.validate_route(case)
    assert any(expected in error for error in errors), (name, expected, errors)


def main() -> int:
    module = load_validator()
    assert module.validate_route(valid_route()) == []
    legacy_route = valid_route()
    legacy_binding = legacy_route.pop("alchemist")
    legacy_binding["state_ref"] = legacy_binding["state_ref"].replace(
        "alchemist://", "forge://", 1
    )
    legacy_route["forge"] = legacy_binding
    assert module.validate_route(legacy_route) == []

    expect_error(
        module,
        "nominal winner trap",
        lambda route: (
            route.__setitem__("selected_route_id", "R_FAST"),
            route["candidates"][0].__setitem__("status", "SELECTED"),
            route["candidates"][1].__setitem__("status", "REJECTED"),
            route.__setitem__("selected_critical_path", ["R_FAST/S1", "R_FAST/S2"]),
            route.__setitem__(
                "bottleneck",
                {
                    "step_id": "R_FAST/S1",
                    "bound_ms": 300000,
                    "resource": "nominal path",
                },
            ),
        ),
        "slower expected time",
    )
    expect_error(
        module,
        "arithmetic lie",
        lambda route: route["candidates"][1].__setitem__(
            "expected_time_to_verified_b_ms", 720000
        ),
        "must equal computed 738000",
    )
    expect_error(
        module,
        "cycle",
        lambda route: route["candidates"][1]["steps"][0].__setitem__(
            "depends_on", ["R_SAFE/S2"]
        ),
        "contains cycle",
    )
    expect_error(
        module,
        "false parallelism",
        lambda route: route.__setitem__(
            "parallel_lanes",
            [
                {
                    "id": "L1",
                    "steps": ["R_SAFE/S1", "R_SAFE/S2"],
                    "reason": "Run together to save time.",
                }
            ],
        ),
        "falsely groups dependent steps",
    )
    expect_error(
        module,
        "non-advancing",
        lambda route: route["candidates"][1]["steps"][0].__setitem__(
            "b_state_delta", "done"
        ),
        "observable b_state_delta",
    )
    expect_error(
        module,
        "missing quality",
        lambda route: route["constraints"].pop("quality"),
        "constraints.quality",
    )
    expect_error(
        module,
        "local correction",
        lambda route: route["invalidation"].update(
            {"revision": 2, "semantic_correction": "NONE"}
        ),
        "RECOMPILED_FROM_ROOT",
    )
    expect_error(
        module,
        "missing Alchemist",
        lambda route: route["alchemist"].update(
            {"required": False, "reason": "Skip Alchemist for speed."}
        ),
        "non-routine route requires Alchemist",
    )
    expect_error(
        module,
        "singleton proof",
        lambda route: route.update(
            {
                "comparison_mode": "SINGLE_FEASIBLE",
                "candidates": [route["candidates"][1]],
                "single_feasible_evidence": [],
            }
        ),
        "infeasible-alternative evidence",
    )

    diagnostic = valid_route()
    diagnostic["purpose"] = "DIAGNOSTIC"
    diagnostic["state_b"]["description"] = (
        "Root cause reaches counterfactual proof level four with alternatives rejected."
    )
    assert module.validate_route(diagnostic) == []

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        route_path = root / "goal-route.json"
        receipt_path = root / "goal-route.receipt.json"
        route_path.write_text(
            json.dumps(valid_route(), indent=2) + "\n", encoding="utf-8"
        )
        written = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(route_path),
                "--write-receipt",
                str(receipt_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert written.returncode == 0, written.stdout + written.stderr
        verified = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(route_path),
                "--verify-receipt",
                str(receipt_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert verified.returncode == 0, verified.stdout + verified.stderr
        route_path.write_text(
            json.dumps({**valid_route(), "route_id": "mutated-route"}, indent=2),
            encoding="utf-8",
        )
        stale = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(route_path),
                "--verify-receipt",
                str(receipt_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert stale.returncode != 0 and "route_sha256 mismatch" in stale.stdout

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repo_a = root / "mac-checkout"
        repo_b = root / "windows-checkout"
        relative = Path("tasks/dispatches/portable.route.json")
        for repo in (repo_a, repo_b):
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / relative.parent).mkdir(parents=True)
            (repo / relative).write_text(
                json.dumps(valid_route(), indent=2) + "\n", encoding="utf-8"
            )
        receipt_a = repo_a / relative.with_suffix(".route.receipt.json")
        written = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(repo_a / relative),
                "--write-receipt",
                str(receipt_a),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert written.returncode == 0, written.stdout + written.stderr
        receipt_b = repo_b / relative.with_suffix(".route.receipt.json")
        shutil.copy2(receipt_a, receipt_b)
        relocated = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(repo_b / relative),
                "--verify-receipt",
                str(receipt_b),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert relocated.returncode == 0, relocated.stdout + relocated.stderr

    print(
        "PASS: GoalRoute v2 rejects nominal-speed traps, arithmetic lies, cycles, "
        "false parallelism, local correction, missing proof, unbound routes, and stale receipts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
