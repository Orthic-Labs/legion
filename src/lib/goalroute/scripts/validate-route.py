#!/usr/bin/env python3
"""Validate GoalRoute v2 artifacts and bind exact bytes to a sidecar receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "goal-route.v2"
RECEIPT_SCHEMA = "goal-route.receipt.v2"
VALIDATOR_VERSION = "2.1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}|(?:^|\s)(?:TBD|TODO|PLACEHOLDER)(?:\s|$)", re.I)
VAGUE_RE = re.compile(
    r"^(?:current state|target state|done|complete|best route|fastest route|same as above)$",
    re.I,
)
LOCATOR_RE = re.compile(
    r"^(?:[A-Za-z]:[\\/]|/|(?:forge|https?)://|(?:\.\.?[\\/])?[\w.-]+[\\/])\S+"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validator_sha256() -> str:
    return sha256_bytes(Path(__file__).read_bytes())


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


def concrete(value: Any, minimum: int = 12) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return (
        len(text) >= minimum
        and not PLACEHOLDER_RE.search(text)
        and not VAGUE_RE.fullmatch(text)
    )


def locator(value: Any) -> bool:
    return (
        isinstance(value, str)
        and not PLACEHOLDER_RE.search(value)
        and bool(LOCATOR_RE.match(value.strip()))
    )


def nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def positive_int(value: Any) -> bool:
    return nonnegative_int(value) and value > 0


def candidate_graph(
    candidate: dict[str, Any], errors: list[str]
) -> tuple[dict[str, dict[str, Any]], int]:
    candidate_id = str(candidate.get("id", "?"))
    raw_steps = candidate.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        errors.append(f"candidate {candidate_id} requires non-empty steps")
        return {}, 0

    steps: dict[str, dict[str, Any]] = {}
    for index, raw_step in enumerate(raw_steps, start=1):
        if not isinstance(raw_step, dict):
            errors.append(f"candidate {candidate_id} step {index} must be object")
            continue
        step_id = raw_step.get("id")
        if not isinstance(step_id, str) or not re.fullmatch(
            rf"{re.escape(candidate_id)}/[A-Z][A-Z0-9_-]*", step_id, re.I
        ):
            errors.append(
                f"candidate {candidate_id} step {index} id must be {candidate_id}/<STEP>"
            )
            continue
        normalized = step_id.upper()
        if normalized in steps:
            errors.append(f"candidate {candidate_id} duplicate step {step_id}")
            continue
        steps[normalized] = raw_step
        if not concrete(raw_step.get("operation")):
            errors.append(f"step {step_id} requires exact operation")
        if not positive_int(raw_step.get("min_wall_ms")):
            errors.append(f"step {step_id} min_wall_ms must be positive integer")
        if raw_step.get("kind") not in {"ADVANCE_B", "SAFETY_DEPENDENCY"}:
            errors.append(f"step {step_id} kind must be ADVANCE_B or SAFETY_DEPENDENCY")
        if not concrete(raw_step.get("b_state_delta"), minimum=6):
            errors.append(f"step {step_id} requires observable b_state_delta")
        dependencies = raw_step.get("depends_on")
        if not isinstance(dependencies, list) or any(
            not isinstance(dep, str) for dep in dependencies
        ):
            errors.append(f"step {step_id} depends_on must be string array")

    if not steps:
        return {}, 0

    indegree = {step_id: 0 for step_id in steps}
    consumers: dict[str, list[str]] = {step_id: [] for step_id in steps}
    for step_id, step in steps.items():
        dependencies = step.get("depends_on", [])
        seen_dependencies: set[str] = set()
        for dependency in dependencies:
            normalized = dependency.upper()
            if normalized not in steps:
                errors.append(f"step {step_id} references unknown dependency {dependency}")
                continue
            if normalized == step_id:
                errors.append(f"step {step_id} depends on itself")
                continue
            if normalized in seen_dependencies:
                errors.append(f"step {step_id} repeats dependency {dependency}")
                continue
            seen_dependencies.add(normalized)
            indegree[step_id] += 1
            consumers[normalized].append(step_id)

    queue = sorted(step_id for step_id, degree in indegree.items() if degree == 0)
    order: list[str] = []
    while queue:
        step_id = queue.pop(0)
        order.append(step_id)
        for consumer in sorted(consumers[step_id]):
            indegree[consumer] -= 1
            if indegree[consumer] == 0:
                queue.append(consumer)
                queue.sort()
    if len(order) != len(steps):
        errors.append(f"candidate {candidate_id} dependency graph contains cycle")
        return steps, 0

    distance: dict[str, int] = {}
    for step_id in order:
        duration = int(steps[step_id].get("min_wall_ms") or 0)
        dependencies = [
            dependency.upper() for dependency in steps[step_id].get("depends_on", [])
            if dependency.upper() in steps
        ]
        distance[step_id] = duration + max(
            (distance[dependency] for dependency in dependencies), default=0
        )
    return steps, max(distance.values(), default=0)


def has_dependency_path(
    ancestor: str, descendant: str, steps: dict[str, dict[str, Any]]
) -> bool:
    stack = [descendant]
    visited: set[str] = set()
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        dependencies = [
            item.upper() for item in steps[current].get("depends_on", [])
            if item.upper() in steps
        ]
        if ancestor in dependencies:
            return True
        stack.extend(dependencies)
    return False


def expected_time_ms(candidate: dict[str, Any], nominal_ms: int) -> int:
    probabilities = candidate.get("probabilities_bps", {})
    retry = probabilities.get("retry", 0) if isinstance(probabilities, dict) else 0
    terminal = (
        probabilities.get("terminal_failure", 0)
        if isinstance(probabilities, dict)
        else 0
    )
    retry_cost = candidate.get("retry_cost_ms", 0)
    rework_cost = candidate.get("rework_cost_ms", 0)
    if not all(
        nonnegative_int(value)
        for value in (retry, terminal, retry_cost, rework_cost)
    ):
        return -1
    return (
        nominal_ms
        + math.ceil(retry * retry_cost / 10000)
        + math.ceil(terminal * rework_cost / 10000)
    )


def validate_route(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["route root must be JSON object"]
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must equal {SCHEMA}")
    if not concrete(data.get("route_id"), minimum=4):
        errors.append("route_id must be concrete")
    if data.get("purpose") not in {"DELIVERY", "DIAGNOSTIC"}:
        errors.append("purpose must be DELIVERY or DIAGNOSTIC")
    if not isinstance(data.get("routine"), bool):
        errors.append("routine must be boolean")
    comparison_mode = data.get("comparison_mode")
    if comparison_mode not in {"COMPARE", "SINGLE_FEASIBLE"}:
        errors.append("comparison_mode must be COMPARE or SINGLE_FEASIBLE")

    state_a = data.get("state_a")
    if not isinstance(state_a, dict) or not concrete(state_a.get("description")):
        errors.append("state_a requires concrete description")
    else:
        evidence = state_a.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append("state_a requires evidence")
        else:
            for index, item in enumerate(evidence, start=1):
                if not isinstance(item, dict):
                    errors.append(f"state_a evidence {index} must be object")
                    continue
                if not locator(item.get("locator")):
                    errors.append(f"state_a evidence {index} requires locator")
                if not SHA256_RE.fullmatch(str(item.get("sha256", ""))):
                    errors.append(f"state_a evidence {index} requires sha256")
                if not concrete(item.get("check")):
                    errors.append(f"state_a evidence {index} requires exact check")

    state_b = data.get("state_b")
    if not isinstance(state_b, dict) or not concrete(state_b.get("description")):
        errors.append("state_b requires concrete description")
    else:
        proofs = state_b.get("proof")
        if not isinstance(proofs, list) or not proofs:
            errors.append("state_b requires executable proof")
        else:
            for index, proof in enumerate(proofs, start=1):
                if not isinstance(proof, dict):
                    errors.append(f"state_b proof {index} must be object")
                    continue
                if not concrete(proof.get("command")):
                    errors.append(f"state_b proof {index} requires command")
                if not concrete(proof.get("expected"), minimum=6):
                    errors.append(f"state_b proof {index} requires expected result")
                if not locator(proof.get("evidence_path")):
                    errors.append(f"state_b proof {index} requires evidence_path")

    constraints = data.get("constraints")
    if not isinstance(constraints, dict):
        errors.append("constraints must be object")
    else:
        for key in ("authority", "safety", "scope", "quality", "cost"):
            constraint = constraints.get(key)
            if not isinstance(constraint, dict):
                errors.append(f"constraints.{key} must be object")
                continue
            if not concrete(constraint.get("rule")):
                errors.append(f"constraints.{key}.rule must be concrete")
            if not locator(constraint.get("evidence_locator")):
                errors.append(f"constraints.{key}.evidence_locator required")

    raw_candidates = data.get("candidates")
    if not isinstance(raw_candidates, list):
        errors.append("candidates must be array")
        raw_candidates = []
    if comparison_mode == "COMPARE" and not 2 <= len(raw_candidates) <= 3:
        errors.append("COMPARE requires 2-3 candidates")
    if comparison_mode == "SINGLE_FEASIBLE":
        if len(raw_candidates) != 1:
            errors.append("SINGLE_FEASIBLE requires exactly one candidate")
        singleton = data.get("single_feasible_evidence")
        if not isinstance(singleton, list) or not singleton or any(
            not locator(item) for item in singleton
        ):
            errors.append("SINGLE_FEASIBLE requires infeasible-alternative evidence")

    candidate_ids: set[str] = set()
    candidates: list[dict[str, Any]] = []
    graph_by_candidate: dict[str, dict[str, dict[str, Any]]] = {}
    for index, raw_candidate in enumerate(raw_candidates, start=1):
        if not isinstance(raw_candidate, dict):
            errors.append(f"candidate {index} must be object")
            continue
        candidate_id = raw_candidate.get("id")
        if not isinstance(candidate_id, str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_-]*", candidate_id, re.I
        ):
            errors.append(f"candidate {index} id invalid")
            continue
        normalized_id = candidate_id.upper()
        if normalized_id in candidate_ids:
            errors.append(f"duplicate candidate id {candidate_id}")
            continue
        candidate_ids.add(normalized_id)
        constraint_status = raw_candidate.get("constraint_status")
        if constraint_status not in {"PASS", "FAIL"}:
            errors.append(f"candidate {candidate_id} constraint_status must PASS or FAIL")
        if not locator(raw_candidate.get("constraint_evidence")):
            errors.append(f"candidate {candidate_id} requires constraint_evidence")

        steps, nominal = candidate_graph(raw_candidate, errors)
        graph_by_candidate[normalized_id] = steps
        if raw_candidate.get("nominal_critical_path_ms") != nominal:
            errors.append(
                f"candidate {candidate_id} nominal_critical_path_ms must equal computed {nominal}"
            )
        probabilities = raw_candidate.get("probabilities_bps")
        if not isinstance(probabilities, dict):
            errors.append(f"candidate {candidate_id} probabilities_bps must be object")
        else:
            retry = probabilities.get("retry")
            terminal = probabilities.get("terminal_failure")
            if not all(nonnegative_int(value) and value <= 10000 for value in (retry, terminal)):
                errors.append(f"candidate {candidate_id} probabilities must be 0..10000")
            elif retry + terminal > 10000:
                errors.append(f"candidate {candidate_id} retry + terminal probability exceeds 10000")
        for field in (
            "retry_cost_ms",
            "rework_cost_ms",
            "cost_units",
            "risk_units",
            "rework_units",
        ):
            if not nonnegative_int(raw_candidate.get(field)):
                errors.append(f"candidate {candidate_id} {field} must be nonnegative integer")
        computed_expected = expected_time_ms(raw_candidate, nominal)
        if raw_candidate.get("expected_time_to_verified_b_ms") != computed_expected:
            errors.append(
                f"candidate {candidate_id} expected_time_to_verified_b_ms must equal computed {computed_expected}"
            )
        status = raw_candidate.get("status")
        if status not in {"SELECTED", "REJECTED"}:
            errors.append(f"candidate {candidate_id} status must SELECTED or REJECTED")
        if status == "SELECTED" and constraint_status != "PASS":
            errors.append(f"selected candidate {candidate_id} must pass constraints")
        if status == "REJECTED" and constraint_status == "PASS" and not concrete(
            raw_candidate.get("dominance_reason")
        ):
            errors.append(f"passing rejected candidate {candidate_id} requires dominance_reason")
        evidence = raw_candidate.get("evidence")
        if not isinstance(evidence, list) or not evidence or any(
            not locator(item) for item in evidence
        ):
            errors.append(f"candidate {candidate_id} requires evidence locators")
        raw_candidate["_computed_nominal"] = nominal
        raw_candidate["_computed_expected"] = computed_expected
        candidates.append(raw_candidate)

    selected = [candidate for candidate in candidates if candidate.get("status") == "SELECTED"]
    if len(selected) != 1:
        errors.append("exactly one candidate must be SELECTED")
    selected_candidate = selected[0] if len(selected) == 1 else None
    selected_id = str(data.get("selected_route_id", "")).upper()
    if selected_candidate and selected_id != str(selected_candidate.get("id", "")).upper():
        errors.append("selected_route_id must match SELECTED candidate")
    if selected_candidate:
        winner_expected = selected_candidate.get("_computed_expected", -1)
        for candidate in candidates:
            if candidate is selected_candidate or candidate.get("constraint_status") != "PASS":
                continue
            candidate_expected = candidate.get("_computed_expected", -1)
            if candidate_expected < winner_expected:
                errors.append(
                    f"selected route {selected_candidate['id']} has slower expected time than {candidate['id']}"
                )
            if (
                candidate_expected == winner_expected
                and all(
                    candidate.get(field, 0) <= selected_candidate.get(field, 0)
                    for field in ("cost_units", "risk_units", "rework_units")
                )
                and any(
                    candidate.get(field, 0) < selected_candidate.get(field, 0)
                    for field in ("cost_units", "risk_units", "rework_units")
                )
            ):
                errors.append(
                    f"selected route {selected_candidate['id']} is dominated at equal expected time by {candidate['id']}"
                )

        winner_id = str(selected_candidate.get("id", "")).upper()
        steps = graph_by_candidate.get(winner_id, {})
        critical_path = data.get("selected_critical_path")
        if not isinstance(critical_path, list) or not critical_path:
            errors.append("selected_critical_path must be non-empty array")
        else:
            normalized_path = [
                item.upper() if isinstance(item, str) else "" for item in critical_path
            ]
            if any(item not in steps for item in normalized_path):
                errors.append("selected_critical_path contains non-selected/unknown step")
            else:
                for previous, current in zip(normalized_path, normalized_path[1:]):
                    dependencies = [
                        item.upper() for item in steps[current].get("depends_on", [])
                    ]
                    if previous not in dependencies:
                        errors.append(
                            "selected_critical_path must follow direct dependency edges"
                        )
                        break
                path_total = sum(
                    int(steps[item].get("min_wall_ms", 0)) for item in normalized_path
                )
                if path_total != selected_candidate.get("_computed_nominal"):
                    errors.append(
                        "selected_critical_path total must equal computed nominal critical path"
                    )

        lanes = data.get("parallel_lanes")
        if not isinstance(lanes, list):
            errors.append("parallel_lanes must be array")
        else:
            lane_steps_seen: set[str] = set()
            for index, lane in enumerate(lanes, start=1):
                if not isinstance(lane, dict):
                    errors.append(f"parallel lane {index} must be object")
                    continue
                items = lane.get("steps")
                if not concrete(lane.get("id"), minimum=2) or not concrete(
                    lane.get("reason"), minimum=6
                ):
                    errors.append(f"parallel lane {index} requires id and reason")
                if not isinstance(items, list) or len(items) < 2:
                    errors.append(f"parallel lane {index} requires at least two steps")
                    continue
                normalized_items = [
                    item.upper() if isinstance(item, str) else "" for item in items
                ]
                if any(item not in steps for item in normalized_items):
                    errors.append(f"parallel lane {index} contains unknown/non-selected step")
                    continue
                for item in normalized_items:
                    if item in lane_steps_seen:
                        errors.append(f"parallel step {item} appears in multiple lanes")
                    lane_steps_seen.add(item)
                for left_index, left in enumerate(normalized_items):
                    for right in normalized_items[left_index + 1 :]:
                        if has_dependency_path(left, right, steps) or has_dependency_path(
                            right, left, steps
                        ):
                            errors.append(
                                f"parallel lane {index} falsely groups dependent steps {left} and {right}"
                            )

        bottleneck = data.get("bottleneck")
        if not isinstance(bottleneck, dict):
            errors.append("bottleneck must be object")
        else:
            bottleneck_id = str(bottleneck.get("step_id", "")).upper()
            if bottleneck_id not in steps:
                errors.append("bottleneck step must belong to selected route")
            elif bottleneck.get("bound_ms") != steps[bottleneck_id].get("min_wall_ms"):
                errors.append("bottleneck bound_ms must equal selected step min_wall_ms")
            if not concrete(bottleneck.get("resource"), minimum=4):
                errors.append("bottleneck requires resource/dependency")

    for field, second in (("deleted_work", "reason"), ("deferred_work", "until")):
        items = data.get(field)
        if not isinstance(items, list):
            errors.append(f"{field} must be array")
            continue
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict) or not concrete(item.get("item"), minimum=4):
                errors.append(f"{field} item {index} requires concrete item")
            elif not concrete(item.get(second), minimum=6):
                errors.append(f"{field} item {index} requires {second}")

    invalidation = data.get("invalidation")
    if not isinstance(invalidation, dict):
        errors.append("invalidation must be object")
    else:
        revision = invalidation.get("revision")
        correction = invalidation.get("semantic_correction")
        if not positive_int(revision):
            errors.append("invalidation.revision must be positive integer")
        if correction not in {"NONE", "RECOMPILED_FROM_ROOT"}:
            errors.append("semantic_correction must be NONE or RECOMPILED_FROM_ROOT")
        if not SHA256_RE.fullmatch(
            str(invalidation.get("source_fingerprint_sha256", ""))
        ):
            errors.append("invalidation requires source_fingerprint_sha256")
        invalidates = invalidation.get("invalidates")
        if not isinstance(invalidates, list):
            errors.append("invalidation.invalidates must be array")
        if positive_int(revision) and revision > 1:
            if correction != "RECOMPILED_FROM_ROOT":
                errors.append("revision > 1 requires RECOMPILED_FROM_ROOT")
            if not invalidates:
                errors.append("recompiled route must name invalidated route")

    forge = data.get("forge")
    if not isinstance(forge, dict) or not isinstance(forge.get("required"), bool):
        errors.append("forge must declare required boolean")
    else:
        required = forge.get("required")
        if data.get("routine") is False and required is not True:
            errors.append("non-routine route requires Forge")
        if required:
            run_id = str(forge.get("run_id", ""))
            try:
                uuid.UUID(run_id)
            except ValueError:
                errors.append("forge.run_id must be UUID")
            expected_ref = f"forge://run/{run_id}/state"
            if forge.get("state_ref") != expected_ref:
                errors.append("forge.state_ref must match run_id")
            if forge.get("checkpoint") != "GOAL_ROUTE_V2":
                errors.append("forge.checkpoint must equal GOAL_ROUTE_V2")
        elif not concrete(forge.get("reason"), minimum=8):
            errors.append("routine route without Forge requires reason")

    return errors


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_receipt(route_path: Path, receipt_path: Path, raw: bytes) -> list[str]:
    errors: list[str] = []
    try:
        receipt = load_json(receipt_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"receipt unreadable: {exc}"]
    expected = {
        "schema": RECEIPT_SCHEMA,
        "route_path": canonical_locator(route_path),
        "route_sha256": sha256_bytes(raw),
        "validator_version": VALIDATOR_VERSION,
        "validator_sha256": validator_sha256(),
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"receipt {key} mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("route", type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write-receipt", type=Path)
    action.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args()

    route_path = args.route.resolve()
    try:
        raw = route_path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: route unreadable: {exc}")
        return 2

    errors = validate_route(data)
    if args.verify_receipt:
        errors.extend(validate_receipt(route_path, args.verify_receipt.resolve(), raw))
    if errors:
        print(f"FAIL: {len(errors)} route defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1

    selected_id = data["selected_route_id"]
    selected = next(
        candidate for candidate in data["candidates"] if candidate["id"] == selected_id
    )
    digest = sha256_bytes(raw)
    if args.write_receipt:
        receipt_path = args.write_receipt.resolve()
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "route_path": canonical_locator(route_path),
            "route_sha256": digest,
            "validator_version": VALIDATOR_VERSION,
            "validator_sha256": validator_sha256(),
            "selected_route_id": selected_id,
            "expected_time_to_verified_b_ms": selected[
                "expected_time_to_verified_b_ms"
            ],
            "route_revision": data["invalidation"]["revision"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    prefix = "RECEIPT_PASS" if args.verify_receipt else "PASS"
    print(
        f"{prefix}: schema={SCHEMA} selected={selected_id} "
        f"expected_ms={selected['expected_time_to_verified_b_ms']} sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
