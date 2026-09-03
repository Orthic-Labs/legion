#!/usr/bin/env python3
"""Deterministic Minimize decision and commit receipt gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
POLICY = HERE / "POLICY.md"
RUNGS = ["NOT_BUILD", "REUSE", "STDLIB", "NATIVE", "INSTALLED_DEP", "ONE_LINE", "MIN_CUSTOM"]


class GateError(ValueError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_root(path: Path) -> Path | None:
    current = path.resolve()
    if not current.is_dir():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def canonical_locator(path: Path) -> str:
    resolved = path.resolve()
    root = repository_root(resolved)
    if root is None:
        return str(resolved)
    return resolved.relative_to(root).as_posix()


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{path} must contain one JSON object")
    return value


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_decision(value: dict, new_files: list[str], new_dependencies: list[str]) -> None:
    if value.get("schema") != "minimize-decision.v1":
        raise GateError("decision schema must be minimize-decision.v1")
    selected = value.get("selected_rung")
    if selected not in RUNGS:
        raise GateError(f"selected_rung must be one of: {', '.join(RUNGS)}")
    prior = value.get("prior_rungs")
    if not isinstance(prior, list):
        raise GateError("prior_rungs must be a list")
    required = RUNGS[: RUNGS.index(selected)]
    observed = [row.get("rung") for row in prior if isinstance(row, dict)]
    if observed != required:
        missing = next((rung for rung in required if rung not in observed), "ordered prior rung")
        raise GateError(f"missing or unordered prior rung: {missing}")
    for row in prior:
        if row.get("verdict") != "REJECTED" or not str(row.get("evidence", "")).strip():
            raise GateError(f"prior rung {row.get('rung')} needs REJECTED verdict and evidence")
    for key in ("decision_id", "state_a", "state_b"):
        if not str(value.get(key, "")).strip():
            raise GateError(f"{key} is required")
    allowed_files = set(value.get("allowed_new_files") or [])
    allowed_deps = set(value.get("allowed_new_dependencies") or [])
    denied_files = sorted(set(new_files) - allowed_files)
    denied_deps = sorted(set(new_dependencies) - allowed_deps)
    if denied_files:
        raise GateError(f"new file not allowed by decision: {', '.join(denied_files)}")
    if denied_deps:
        raise GateError(f"new dependency not allowed by decision: {', '.join(denied_deps)}")


def decision_receipt(source: Path) -> dict:
    value = load(source)
    validate_decision(value, [], [])
    return {
        "schema": "minimize-decision-receipt.v1",
        "decision": canonical_locator(source),
        "decision_sha256": digest(source),
        "policy_sha256": digest(POLICY),
        "validator_sha256": digest(Path(__file__)),
        "decision_id": value["decision_id"],
        "selected_rung": value["selected_rung"],
    }


def verify_decision(source: Path, receipt_path: Path) -> None:
    expected = decision_receipt(source)
    actual = load(receipt_path)
    for key in ("decision_sha256", "policy_sha256", "validator_sha256", "decision_id", "selected_rung"):
        if actual.get(key) != expected.get(key):
            raise GateError(f"stale decision receipt: {key} mismatch")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], text=True, capture_output=True, check=False)
    if result.returncode:
        raise GateError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def staged_tree() -> str:
    return git("write-tree")


def staged_files() -> list[str]:
    base = os.environ.get("MINIMIZE_BASE_REF")
    args = ["diff", "--cached"]
    if base:
        args.append(base)
    args.extend(["--name-only", "--diff-filter=ACMR"])
    output = git(*args)
    return [line for line in output.splitlines() if line]


def init_review(path: Path) -> None:
    write(
        path,
        {
            "schema": "minimize-commit-review.v1",
            "candidate_tree": staged_tree(),
            "scope_files": staged_files(),
            "selected_rung": "REUSE",
            "rung_checks": [{"rung": "NOT_BUILD", "verdict": "REJECTED", "evidence": "staged change is requested"}],
            "new_files": [],
            "new_dependencies": [],
            "findings": [],
            "verdict": "CLEAN",
        },
    )


def validate_review(path: Path) -> dict:
    value = load(path)
    if value.get("schema") != "minimize-commit-review.v1":
        raise GateError("review schema must be minimize-commit-review.v1")
    if value.get("candidate_tree") != staged_tree():
        raise GateError("stale review: candidate_tree mismatch")
    if sorted(value.get("scope_files") or []) != sorted(staged_files()):
        raise GateError("stale review: scope_files mismatch")
    if value.get("verdict") != "CLEAN":
        raise GateError("review verdict must be CLEAN")
    open_findings = [row for row in value.get("findings", []) if row.get("status") not in {"resolved", "waived"}]
    if open_findings:
        raise GateError("open finding blocks commit receipt")
    return value


def commit_receipt(review_path: Path) -> dict:
    review = validate_review(review_path)
    return {
        "schema": "minimize-commit-receipt.v1",
        "candidate_tree": review["candidate_tree"],
        "scope_files": review["scope_files"],
        "review": str(review_path.resolve()),
        "review_sha256": digest(review_path),
        "policy_sha256": digest(POLICY),
        "validator_sha256": digest(Path(__file__)),
        "verdict": "CLEAN",
    }


def verify_commit(receipt_path: Path) -> None:
    actual = load(receipt_path)
    if actual.get("schema") != "minimize-commit-receipt.v1":
        raise GateError("commit receipt schema mismatch")
    if actual.get("candidate_tree") != staged_tree():
        raise GateError("stale commit receipt: candidate_tree mismatch")
    if sorted(actual.get("scope_files") or []) != sorted(staged_files()):
        raise GateError("stale commit receipt: scope_files mismatch")
    review_path = Path(actual.get("review", ""))
    if not review_path.is_file() or actual.get("review_sha256") != digest(review_path):
        raise GateError("stale commit receipt: review mismatch")
    if actual.get("policy_sha256") != digest(POLICY):
        raise GateError("stale commit receipt: policy mismatch")
    if actual.get("validator_sha256") != digest(Path(__file__)):
        raise GateError("stale commit receipt: validator mismatch")
    validate_review(review_path)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    domains = root.add_subparsers(dest="domain", required=True)
    decision = domains.add_parser("decision")
    dcmd = decision.add_subparsers(dest="action", required=True)
    validate = dcmd.add_parser("validate")
    validate.add_argument("source", type=Path)
    validate.add_argument("--new-file", action="append", default=[])
    validate.add_argument("--new-dependency", action="append", default=[])
    receipt = dcmd.add_parser("receipt")
    receipt.add_argument("source", type=Path)
    receipt.add_argument("receipt", type=Path)
    verify = dcmd.add_parser("verify")
    verify.add_argument("source", type=Path)
    verify.add_argument("receipt", type=Path)

    commit = domains.add_parser("commit")
    ccmd = commit.add_subparsers(dest="action", required=True)
    init = ccmd.add_parser("init-review")
    init.add_argument("review", type=Path)
    cr = ccmd.add_parser("receipt")
    cr.add_argument("review", type=Path)
    cr.add_argument("receipt", type=Path)
    cv = ccmd.add_parser("verify")
    cv.add_argument("receipt", type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.domain == "decision" and args.action == "validate":
            validate_decision(load(args.source), args.new_file, args.new_dependency)
        elif args.domain == "decision" and args.action == "receipt":
            write(args.receipt, decision_receipt(args.source))
        elif args.domain == "decision" and args.action == "verify":
            verify_decision(args.source, args.receipt)
        elif args.domain == "commit" and args.action == "init-review":
            init_review(args.review)
        elif args.domain == "commit" and args.action == "receipt":
            write(args.receipt, commit_receipt(args.review))
        elif args.domain == "commit" and args.action == "verify":
            verify_commit(args.receipt)
        print("MINIMIZE PASS")
        return 0
    except GateError as exc:
        print(f"MINIMIZE FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
