#!/usr/bin/env python3
"""Adversarial smoke tests for validate-tasklist.py."""

from __future__ import annotations

import shutil
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-tasklist.py"
ROUTE_VALIDATOR = ROOT.parents[1] / "lib" / "goalroute" / "scripts" / "validate-route.py"
EXAMPLE = ROOT / "examples" / "validated-tasklist.md"
ROUTE = ROOT / "examples" / "validated-tasklist.route.json"
ROUTE_RECEIPT = ROOT / "examples" / "validated-tasklist.route.receipt.json"
MINIMIZE = ROOT / "examples" / "validated-tasklist.minimize.json"
MINIMIZE_VALIDATOR = ROOT.parents[1] / "lib" / "minimize" / "minimize_gate.py"
TEMPLATE = ROOT / "assets" / "tasklist-template.md"
CASES = ROOT / "examples" / "cases"


def run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT.parents[2],
        text=True,
        capture_output=True,
        check=False,
    )


def require(condition: bool, message: str, result: subprocess.CompletedProcess[str] | None = None) -> None:
    if condition:
        return
    detail = "" if result is None else f"\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    raise AssertionError(message + detail)


def prepare(name: str) -> tuple[Path, Path]:
    folder = CASES / name
    folder.mkdir(parents=True, exist_ok=True)
    tasklist = folder / f"{name}.tasklist.md"
    route = folder / f"{name}.route.json"
    route_receipt = folder / f"{name}.route.receipt.json"
    text = EXAMPLE.read_text(encoding="utf-8")
    bindings = {
        "Canonical path": tasklist,
        "Goal route artifact": route,
        "Goal route receipt": route_receipt,
    }
    for label, value in bindings.items():
        text = re.sub(
            rf"(?m)^- \*\*{re.escape(label)}:\*\* .+$",
            f"- **{label}:** {str(value.resolve()).replace(chr(92), '/')}",
            text,
        )
    tasklist.write_text(text, encoding="utf-8")
    shutil.copy2(ROUTE, route)
    minimize = tasklist.with_suffix(".minimize.json")
    minimize_receipt = tasklist.with_suffix(".minimize.receipt.json")
    shutil.copy2(MINIMIZE, minimize)
    result = run(ROUTE_VALIDATOR, route, "--write-receipt", route_receipt)
    require(result.returncode == 0, "fixture GoalRoute must validate", result)
    result = run(MINIMIZE_VALIDATOR, "decision", "receipt", minimize, minimize_receipt)
    require(result.returncode == 0, "fixture Minimize decision must validate", result)
    return tasklist, route_receipt


def expect_failure(name: str, mutate) -> None:
    tasklist, _ = prepare(name)
    text = mutate(tasklist.read_text(encoding="utf-8"))
    tasklist.write_text(text, encoding="utf-8")
    result = run(VALIDATOR, tasklist)
    require(result.returncode != 0 and result.stdout.startswith("FAIL:"), f"{name} must fail", result)


def main() -> int:
    if CASES.exists():
        shutil.rmtree(CASES)
    CASES.mkdir(parents=True)
    try:
        result = run(VALIDATOR, TEMPLATE, "--template-self-check")
        require(result.returncode == 0, "template self-check must pass", result)

        valid, _ = prepare("valid")
        receipt = valid.with_suffix(".receipt.json")
        result = run(VALIDATOR, valid, "--write-receipt", receipt)
        require(result.returncode == 0 and result.stdout.startswith("PASS:"), "valid tasklist must pass", result)
        result = run(VALIDATOR, valid, "--verify-receipt", receipt)
        require(
            result.returncode == 0 and result.stdout.startswith("RECEIPT_PASS:"),
            "valid receipt must replay",
            result,
        )

        def omit_last(text: str) -> str:
            start = text.index("### Task 3")
            end = text.index("## 4. Recovery", start)
            return text[:start] + text[end:]

        expect_failure("missing-step", omit_last)
        expect_failure(
            "wrong-action",
            lambda text: text.replace(
                "ACTION:Validate tasklist structure against selected route DAG.",
                "ACTION:Write an unrelated checklist.",
            ),
        )
        expect_failure(
            "wrong-dependency",
            lambda text: text.replace("AFTER:R_RELIABLE/S1", "START", 1),
        )
        expect_failure(
            "weak-recovery",
            lambda text: text.replace(
                "TRY:repair exact reported structural defect; FALLBACK:run py_compile and template self-check independently; RECOMPILE_IF:selected route step set or dependency DAG changed",
                "TRY:retry once",
            ),
        )
        expect_failure(
            "temporary-evidence",
            lambda text: text.replace(
                "D:/Claude/.audit/tasklist-example/structure-check.txt",
                "D:/tmp/structure-check.txt",
            ),
        )
        expect_failure(
            "false-complete",
            lambda text: text.replace("- **Status:** PLANNED", "- **Status:** COMPLETE").replace(
                "STATUS=PLANNED", "STATUS=COMPLETE"
            ),
        )

        missing_minimize, _ = prepare("missing-minimize")
        missing_minimize.with_suffix(".minimize.receipt.json").unlink()
        result = run(VALIDATOR, missing_minimize)
        require(
            result.returncode != 0 and "Minimize authority" in result.stdout,
            "missing Minimize receipt must fail",
            result,
        )

        stale, _ = prepare("stale-receipt")
        stale_receipt = stale.with_suffix(".receipt.json")
        result = run(VALIDATOR, stale, "--write-receipt", stale_receipt)
        require(result.returncode == 0, "stale receipt setup must pass", result)
        stale.write_text(stale.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        result = run(VALIDATOR, stale, "--verify-receipt", stale_receipt)
        require(result.returncode != 0 and "receipt tasklist_sha256 mismatch" in result.stdout, "stale receipt must fail", result)
    finally:
        if CASES.exists():
            shutil.rmtree(CASES)
    print("PASS: tasklist validator adversarial suite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
