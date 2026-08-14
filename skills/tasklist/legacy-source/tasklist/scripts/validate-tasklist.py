#!/usr/bin/env python3
"""Validate a durable same-agent tasklist against its GoalRoute authority."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "tasklist.receipt.v1"
VERSION = "1.0.0"
REQUIRED_HEADINGS = [
    "## 0. Control",
    "## 1. Goal Contract",
    "## 2. GoalRoute Binding",
    "## 3. Execution Tasks",
    "## 4. Recovery & TRUE_BLOCKER",
    "## 5. Progress & Change Control",
    "## 6. Completion Contract",
]
TASK_RE = re.compile(r"(?m)^### Task (\d+) — (.+)$")
ABS_RE = re.compile(r"^(?:[A-Za-z]:[/\\]|/)")
PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")
# Elapsed-clock span counted from minute 0 ("minute 3-20"), never a duration and never a
# low/high range. Trailing parenthetical guidance from the template is tolerated and ignored.
TIME_SPAN_RE = re.compile(r"^minute\s+(\d+)-(\d+)\s*(?:\(.*\))?$")
# One named activity and its minutes, e.g. "compile=6".
BASIS_PART_RE = re.compile(r"^([A-Za-z][A-Za-z _-]*)=(\d+(?:\.\d+)?)$")
# Labels that hide work rather than describe it. Banning them is the point of the basis field.
BANNED_BASIS_LABELS = frozenset(
    {"overhead", "buffer", "contingency", "misc", "miscellaneous", "padding", "slack", "other"}
)
# Labels counted as code generation, checked against lines / rate.
CODE_BASIS_LABELS = frozenset({"code", "coding", "codegen", "write", "implement", "implementation"})


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_goalroute():
    path = Path(__file__).resolve().parents[3] / "lib" / "goalroute" / "scripts" / "validate-route.py"
    spec = importlib.util.spec_from_file_location("goalroute_validator", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load GoalRoute validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def load_minimize():
    path = Path(__file__).resolve().parents[3] / "lib" / "minimize" / "minimize_gate.py"
    spec = importlib.util.spec_from_file_location("minimize_validator", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load Minimize validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def field(text: str, label: str) -> str:
    match = re.search(rf"(?m)^- \*\*{re.escape(label)}:\*\* (.+)$", text)
    return match.group(1).strip() if match else ""


def marker(value: str, prefix: str) -> str:
    return value[len(prefix) :].strip() if value.startswith(prefix) else ""


def permanent_path(value: str) -> bool:
    if not ABS_RE.match(value):
        return False
    lowered = value.replace("\\", "/").lower()
    forbidden = ("/temp/", "/tmp/", "/scratch/", "/.cache/", "/review-run/")
    return not any(part in lowered for part in forbidden)


def concrete(value: str, minimum: int = 8) -> bool:
    return len(value.strip()) >= minimum and not PLACEHOLDER_RE.search(value)


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_tasks(text: str) -> list[dict[str, str]]:
    matches = list(TASK_RE.finditer(text))
    tasks: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else text.find("\n## 4.", match.end())
        if end < 0:
            end = len(text)
        block = text[match.start() : end]
        tasks.append(
            {
                "number": match.group(1),
                "name": match.group(2).strip(),
                "status": field(block, "Task status"),
                "step": marker(field(block, "Route step"), "ROUTE_STEP:"),
                "action": marker(field(block, "Action"), "ACTION:"),
                "depends": field(block, "Depends on"),
                "delta": marker(field(block, "Advances target"), "ADVANCES_STATE_B:"),
                "check": marker(field(block, "Done check"), "CHECK:"),
                "expected": marker(field(block, "Expected result"), "EXPECTED:"),
                "evidence": field(block, "Evidence path"),
                "failure": field(block, "On failure"),
                "time_span": field(block, "Time span"),
                "basis": field(block, "Basis"),
                "parallelizable": field(block, "Parallelizable"),
            }
        )
    return tasks


def validate(tasklist_path: Path, text: str) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    context: dict[str, Any] = {}

    for heading in REQUIRED_HEADINGS:
        if heading not in text:
            errors.append(f"missing heading: {heading}")
    if PLACEHOLDER_RE.search(text):
        errors.append("tasklist contains unresolved template placeholders")

    minimize_path = tasklist_path.with_suffix(".minimize.json")
    minimize_receipt = tasklist_path.with_suffix(".minimize.receipt.json")
    try:
        minimize, minimize_validator_path = load_minimize()
        minimize.verify_decision(minimize_path, minimize_receipt)
        context["minimize_artifact"] = str(minimize_path)
        context["minimize_receipt"] = str(minimize_receipt)
        context["minimize_validator"] = str(minimize_validator_path)
    except (OSError, ValueError, RuntimeError) as exc:
        errors.append(f"Minimize authority missing, invalid, or stale: {exc}")

    canonical = field(text, "Canonical path")
    if not permanent_path(canonical):
        errors.append("Canonical path must be absolute and permanent")
    elif Path(canonical).resolve() != tasklist_path.resolve():
        errors.append("Canonical path does not match tasklist file")

    purpose = field(text, "Purpose")
    if purpose not in {"EXECUTE_HERE", "GOAL_RECORD"}:
        errors.append("Purpose must be EXECUTE_HERE or GOAL_RECORD")
    overall = field(text, "Status")
    if overall not in {"PLANNED", "IN_PROGRESS", "COMPLETE", "TRUE_BLOCKER"}:
        errors.append("Status is invalid")
    revision = marker(field(text, "Tasklist revision"), "TASKLIST_REVISION:")
    if not revision.isdigit() or int(revision or 0) < 1:
        errors.append("Tasklist revision must be a positive integer")
    for label in ("Tasklist ID", "Owner", "Scope boundary", "Authority", "Non-goals", "Hard constraints"):
        if not concrete(field(text, label)):
            errors.append(f"{label} must be concrete")

    route_path_value = field(text, "Goal route artifact")
    receipt_path_value = field(text, "Goal route receipt")
    if not permanent_path(route_path_value):
        errors.append("Goal route artifact must be absolute and permanent")
    if not permanent_path(receipt_path_value):
        errors.append("Goal route receipt must be absolute and permanent")
    route_path = Path(route_path_value).resolve() if route_path_value else Path()
    route_receipt_path = Path(receipt_path_value).resolve() if receipt_path_value else Path()
    if route_path_value and route_path.parent != tasklist_path.parent:
        errors.append("Goal route artifact must be a sibling of tasklist")
    if receipt_path_value and route_receipt_path.parent != tasklist_path.parent:
        errors.append("Goal route receipt must be a sibling of tasklist")

    route: dict[str, Any] = {}
    route_raw = b""
    goalroute = None
    goalroute_validator_path = Path()
    try:
        goalroute, goalroute_validator_path = load_goalroute()
        route_raw = route_path.read_bytes()
        route = json.loads(route_raw.decode("utf-8"))
        errors.extend(f"route: {item}" for item in goalroute.validate_route(route))
        errors.extend(
            f"route receipt: {item}"
            for item in goalroute.validate_receipt(route_path, route_receipt_path, route_raw)
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
        errors.append(f"GoalRoute authority unreadable: {exc}")

    if route:
        selected_id = route.get("selected_route_id", "")
        selected = next(
            (candidate for candidate in route.get("candidates", []) if candidate.get("id") == selected_id),
            {},
        )
        expected_ms = selected.get("expected_time_to_verified_b_ms")
        route_revision = route.get("invalidation", {}).get("revision")
        mirrors = [
            ("Goal route schema", field(text, "Goal route schema"), "goal-route.v2"),
            ("Selected route", marker(field(text, "Selected route"), "SELECTED_ROUTE:"), selected_id),
            (
                "Expected time to verified B",
                marker(field(text, "Expected time to verified B"), "EXPECTED_TIME_TO_VERIFIED_B_MS:"),
                str(expected_ms),
            ),
            ("Route revision", marker(field(text, "Route revision"), "ROUTE_REVISION:"), str(route_revision)),
            ("Critical path", marker(field(text, "Critical path"), "CRITICAL_PATH:"), ">".join(route.get("selected_critical_path", []))),
            ("Parallel lanes", marker(field(text, "Parallel lanes"), "PARALLEL_LANES_JSON:"), compact(route.get("parallel_lanes", []))),
            ("Deleted work", marker(field(text, "Deleted work"), "DELETED_WORK_JSON:"), compact(route.get("deleted_work", []))),
            ("Deferred work", marker(field(text, "Deferred work"), "DEFERRED_WORK_JSON:"), compact(route.get("deferred_work", []))),
        ]
        for label, actual, expected in mirrors:
            if actual != expected:
                errors.append(f"{label} does not mirror GoalRoute")

        state_a = marker(field(text, "State A"), "STATE_A:")
        state_b = marker(field(text, "State B"), "STATE_B:")
        if state_a != route.get("state_a", {}).get("description"):
            errors.append("State A does not mirror GoalRoute")
        if state_b != route.get("state_b", {}).get("description"):
            errors.append("State B does not mirror GoalRoute")

        tasks = parse_tasks(text)
        steps = selected.get("steps", [])
        if [task["number"] for task in tasks] != [str(i) for i in range(1, len(tasks) + 1)]:
            errors.append("Task numbers must be contiguous from 1")
        if len(tasks) != len(steps):
            errors.append("task count must equal selected route step count")
        seen: set[str] = set()
        per_task_spans: list[dict[str, Any]] = []
        span_by_step: dict[str, tuple[int, int]] = {}
        parallel_by_step: dict[str, bool] = {}
        parallelizable_count = 0
        code_basis_minutes = 0.0
        for index, step in enumerate(steps):
            if index >= len(tasks):
                break
            task = tasks[index]
            step_id = str(step.get("id", ""))
            if task["step"] != step_id:
                errors.append(f"Task {index + 1} route step mismatch")
            if task["action"] != step.get("operation"):
                errors.append(f"Task {index + 1} action does not match route operation")
            if task["delta"] != step.get("b_state_delta"):
                errors.append(f"Task {index + 1} target delta does not match route")
            dependencies = step.get("depends_on", [])
            expected_depends = "START" if not dependencies else "AFTER:" + ",".join(dependencies)
            if task["depends"] != expected_depends:
                errors.append(f"Task {index + 1} dependency contract mismatch")
            if any(dep not in seen for dep in dependencies):
                errors.append(f"Task {index + 1} is not topologically ordered")
            seen.add(step_id)
            if task["status"] not in {"TODO", "IN_PROGRESS", "DONE", "TRUE_BLOCKER"}:
                errors.append(f"Task {index + 1} status invalid")
            if not concrete(task["check"]) or not concrete(task["expected"]):
                errors.append(f"Task {index + 1} needs exact check and expected result")
            if not permanent_path(task["evidence"]):
                errors.append(f"Task {index + 1} evidence path must be absolute and permanent")
            failure = task["failure"]
            if not all(token in failure for token in ("TRY:", "FALLBACK:", "RECOMPILE_IF:")):
                errors.append(f"Task {index + 1} failure branch is incomplete")

            span_match = TIME_SPAN_RE.match(task["time_span"].strip())
            if not span_match:
                errors.append(
                    f"Task {index + 1} time span must be an elapsed-clock span from minute 0, "
                    'formatted as "minute START-END" (not a duration, not a low/high range)'
                )
            else:
                span_start, span_end = int(span_match.group(1)), int(span_match.group(2))
                if span_end <= span_start:
                    errors.append(f"Task {index + 1} time span must end after it starts")
                per_task_spans.append(
                    {"task_number": task["number"], "start": span_start, "end": span_end}
                )
                span_by_step[step_id] = (span_start, span_end)
            # Every minute in a span must be attributed to a named activity. Without this, one
            # opaque bucket absorbs inspection, compile, test and remote-validation time, and the
            # step total becomes unfalsifiable -- the exact place padding survives review.
            basis_parts = [
                part.strip()
                for part in task["basis"].split(",")
                if part.strip()
            ]
            if not basis_parts:
                errors.append(f"Task {index + 1} must name what its minutes are spent on")
            basis_total = 0.0
            for part in basis_parts:
                part_match = BASIS_PART_RE.match(part)
                if not part_match:
                    errors.append(
                        f"Task {index + 1} basis part {part!r} must be formatted as label=minutes"
                    )
                    continue
                label = part_match.group(1).strip().lower()
                minutes = float(part_match.group(2))
                if label in BANNED_BASIS_LABELS:
                    errors.append(
                        f"Task {index + 1} basis label {label!r} is a generic bucket; "
                        "name the actual activity (inspect, compile, test, deploy, smoke, report)"
                    )
                basis_total += minutes
                if label in CODE_BASIS_LABELS:
                    code_basis_minutes += minutes
            if span_match and basis_parts:
                span_length = int(span_match.group(2)) - int(span_match.group(1))
                if abs(basis_total - span_length) > 0.5:
                    errors.append(
                        f"Task {index + 1} named minutes sum to {basis_total:g} but its span is "
                        f"{span_length} minutes long"
                    )

            parallel_flag = task["parallelizable"].strip().lower()
            if parallel_flag not in {"yes", "no"}:
                errors.append(f"Task {index + 1} parallelizable must be yes or no")
            else:
                parallel_by_step[step_id] = parallel_flag == "yes"
                if parallel_flag == "yes":
                    parallelizable_count += 1

        statuses = [task["status"] for task in tasks]
        if overall == "PLANNED" and any(status != "TODO" for status in statuses):
            errors.append("PLANNED requires every task TODO")
        if overall == "COMPLETE" and any(status != "DONE" for status in statuses):
            errors.append("COMPLETE requires every task DONE")
        if overall == "TRUE_BLOCKER" and "TRUE_BLOCKER" not in statuses:
            errors.append("TRUE_BLOCKER status requires blocked task")

        terminal = field(text, "Terminal record")
        done_count = statuses.count("DONE")
        expected_next = next((task["step"] for task in tasks if task["status"] != "DONE"), "NONE")
        expected_terminal = f"STATUS={overall}; DONE={done_count}/{len(tasks)}; NEXT={expected_next}"
        if terminal != expected_terminal:
            errors.append("Terminal record does not match task states")

        proof = route.get("state_b", {}).get("proof", [{}])[0]
        success = field(text, "Success proof")
        success_match = re.fullmatch(r"PROOF_COMMAND:(.*); EXPECTED:(.*); EVIDENCE:(.*)", success)
        if not success_match:
            errors.append("Success proof format invalid")
        else:
            actual = tuple(part.strip() for part in success_match.groups())
            expected = (proof.get("command", ""), proof.get("expected", ""), proof.get("evidence_path", ""))
            if actual != expected:
                errors.append("Success proof does not mirror GoalRoute")

        # Scope inputs are mandatory and the total must be reproducible from them. An estimate
        # asserted from feel cannot survive this: to claim more minutes you must claim more lines,
        # and the line claim is itself checkable against the real diff afterward.
        files_touched_raw = marker(field(text, "Files touched"), "FILES_TOUCHED:")
        lines_changed_raw = marker(field(text, "Lines changed"), "LINES_CHANGED:")
        rate_raw = marker(field(text, "Rate"), "LINES_PER_MINUTE:")

        if not files_touched_raw.isdigit() or int(files_touched_raw) < 1:
            errors.append("Files touched must be a positive integer")
        if not lines_changed_raw.isdigit() or int(lines_changed_raw) < 1:
            errors.append("Lines changed must be a positive integer")
        try:
            rate = float(rate_raw)
        except ValueError:
            rate = 0.0
        if rate <= 0:
            errors.append("Lines per minute must be a positive number")
        elif rate < 10:
            # Measured reality: an agent emits tens of lines per minute. A low rate is how a plan
            # smuggles inspection and verification time into "typing" and inflates the total.
            errors.append(
                f"Lines per minute ({rate}) is implausibly slow for code generation; "
                "bill inspection, compile, and test time as named parts instead"
            )
        # The declared code-generation minutes must actually follow from lines and rate, so the
        # line estimate cannot be decorative.
        if lines_changed_raw.isdigit() and rate > 0:
            expected_code_minutes = int(lines_changed_raw) / rate
            if code_basis_minutes and abs(code_basis_minutes - expected_code_minutes) > max(
                2.0, 0.5 * expected_code_minutes
            ):
                errors.append(
                    f"Declared code minutes ({code_basis_minutes:g}) do not follow from "
                    f"{lines_changed_raw} lines / {rate} per minute (~{expected_code_minutes:.0f})"
                )

        total_minutes_raw = marker(field(text, "Total minutes"), "TOTAL_MINUTES:")
        if not total_minutes_raw.isdigit() or int(total_minutes_raw) < 1:
            errors.append("Total minutes must be a positive integer")
        else:
            total_minutes = int(total_minutes_raw)
            spans = sorted(span_by_step.values())
            if spans:
                # Spans are positions on one shared clock, so the plan's wall time is simply the
                # last minute any step is still running -- parallel lanes overlap rather than sum.
                if spans[0][0] != 0:
                    errors.append(f"First step must start at minute 0, found {spans[0][0]}")
                finish = max(end for _, end in spans)
                if total_minutes != finish:
                    errors.append(
                        f"Total minutes ({total_minutes}) must equal the last minute any step "
                        f"is still running ({finish})"
                    )
                # A gap means the declared total covers time no step accounts for -- padding.
                covered_to = 0
                for start, end in spans:
                    if start > covered_to:
                        errors.append(
                            f"Clock gap: nothing runs between minute {covered_to} and {start}"
                        )
                        break
                    covered_to = max(covered_to, end)
                # Overlap is the definition of parallel here, so the flag must match the clock
                # rather than being asserted independently of it.
                for step_id, (start, end) in span_by_step.items():
                    overlaps = any(
                        other_id != step_id and start < other_end and other_start < end
                        for other_id, (other_start, other_end) in span_by_step.items()
                    )
                    if parallel_by_step.get(step_id) is True and not overlaps:
                        errors.append(
                            f"Step {step_id} is flagged parallelizable but its span overlaps no other step"
                        )
                    if parallel_by_step.get(step_id) is False and overlaps:
                        errors.append(
                            f"Step {step_id} is flagged serial but its span overlaps another step"
                        )

        context = {
            "route_path": route_path,
            "route_raw": route_raw,
            "route_receipt_path": route_receipt_path,
            "goalroute_validator_path": goalroute_validator_path,
            "selected_route_id": selected_id,
            "expected_ms": expected_ms,
            "route_revision": route_revision,
            "task_count": len(tasks),
            "total_minutes": int(total_minutes_raw) if total_minutes_raw.isdigit() else None,
            "per_task_minute_spans": per_task_spans,
            "parallelizable_task_count": parallelizable_count,
            # Recorded so a later pass can score the claimed scope against the real diff, not just
            # the claimed minutes against the clock.
            "files_touched": int(files_touched_raw) if files_touched_raw.isdigit() else None,
            "lines_changed": int(lines_changed_raw) if lines_changed_raw.isdigit() else None,
            "lines_per_minute": rate if rate > 0 else None,
            "code_minutes": code_basis_minutes or None,
        }

    if overall == "TRUE_BLOCKER":
        blocked = field(text, "Blocked artifact path")
        if not permanent_path(blocked) or not Path(blocked).exists():
            errors.append("TRUE_BLOCKER requires existing permanent blocked artifact")
    if field(text, "TRUE_BLOCKER allowed only if") != (
        "RECOVERY_EXHAUSTED; INDEPENDENT_WORK_COMPLETE; NO_FEASIBLE_ROUTE; ONE_MISSING_EXTERNAL_INPUT"
    ):
        errors.append("TRUE_BLOCKER contract changed")

    final_evidence = field(text, "Final evidence path")
    if not permanent_path(final_evidence):
        errors.append("Final evidence path must be absolute and permanent")
    if not concrete(field(text, "Final verification")) or not concrete(field(text, "Final expected result")):
        errors.append("Final verification contract must be concrete")
    return errors, context


def receipt_errors(tasklist_path: Path, raw: bytes, receipt_path: Path, context: dict[str, Any]) -> list[str]:
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"tasklist receipt unreadable: {exc}"]
    expected = {
        "schema": SCHEMA,
        "tasklist_path": str(tasklist_path.resolve()),
        "tasklist_sha256": digest(raw),
        "validator_version": VERSION,
        "validator_sha256": digest(Path(__file__).read_bytes()),
        "route_path": str(context["route_path"]),
        "route_sha256": digest(context["route_raw"]),
        "route_receipt_path": str(context["route_receipt_path"]),
        "route_receipt_sha256": digest(context["route_receipt_path"].read_bytes()),
        "total_minutes": context["total_minutes"],
        "per_task_minute_spans": context["per_task_minute_spans"],
        "parallelizable_task_count": context["parallelizable_task_count"],
    }
    return [f"receipt {key} mismatch" for key, value in expected.items() if receipt.get(key) != value]


def template_check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = [f"missing heading: {heading}" for heading in REQUIRED_HEADINGS if heading not in text]
    for token in (
        "{{TASKLIST_ID}}",
        "{{ROUTE_ID_AND_STEP}}",
        "TRY:",
        "FALLBACK:",
        "RECOMPILE_IF:",
        "TOTAL_MINUTES:",
        "FILES_TOUCHED:",
        "LINES_CHANGED:",
        "LINES_PER_MINUTE:",
        "minute {{START_OFFSET}}-{{END_OFFSET}}",
        "**Basis:**",
        "Parallelizable",
    ):
        if token not in text:
            errors.append(f"template missing token: {token}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tasklist", type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write-receipt", type=Path)
    action.add_argument("--verify-receipt", type=Path)
    action.add_argument("--template-self-check", action="store_true")
    args = parser.parse_args()
    path = args.tasklist.resolve()
    if args.template_self_check:
        errors = template_check(path)
        if errors:
            print(f"FAIL: {len(errors)} template defect(s)")
            for error in errors:
                print(f"- {error}")
            return 1
        print("PASS: tasklist template")
        return 0
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"FAIL: tasklist unreadable: {exc}")
        return 2
    errors, context = validate(path, text)
    if args.verify_receipt and context:
        errors.extend(receipt_errors(path, raw, args.verify_receipt.resolve(), context))
    if errors:
        print(f"FAIL: {len(errors)} tasklist defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    if args.write_receipt:
        receipt_path = args.write_receipt.resolve()
        if receipt_path.parent != path.parent or not permanent_path(str(receipt_path)):
            print("FAIL: tasklist receipt must be permanent sibling")
            return 1
        receipt = {
            "schema": SCHEMA,
            "tasklist_path": str(path),
            "tasklist_sha256": digest(raw),
            "validator_version": VERSION,
            "validator_sha256": digest(Path(__file__).read_bytes()),
            "route_path": str(context["route_path"]),
            "route_sha256": digest(context["route_raw"]),
            "route_receipt_path": str(context["route_receipt_path"]),
            "route_receipt_sha256": digest(context["route_receipt_path"].read_bytes()),
            "selected_route_id": context["selected_route_id"],
            "expected_time_to_verified_b_ms": context["expected_ms"],
            "route_revision": context["route_revision"],
            "task_count": context["task_count"],
            "total_minutes": context["total_minutes"],
            "per_task_minute_spans": context["per_task_minute_spans"],
            "parallelizable_task_count": context["parallelizable_task_count"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    prefix = "RECEIPT_PASS" if args.verify_receipt else "PASS"
    print(
        f"{prefix}: tasklist={path.name} selected={context['selected_route_id']} "
        f"tasks={context['task_count']} sha256={digest(raw)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
