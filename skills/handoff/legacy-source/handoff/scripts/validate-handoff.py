#!/usr/bin/env python3
"""Fail-closed validator for zero-memory cold-chat handoffs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


FORBIDDEN_STORAGE_PARTS = {
    "temp", "tmp", ".tmp", "temporary", "cache", ".cache", "review-run",
    "review-runs", ".review-runs", ".council-runs", "scratch",
}


def clean_path_value(value: str) -> str:
    return value.strip().strip("`").strip('"').strip("'")


def normalized_path(value: str | Path, platform_name: str | None = None) -> str:
    raw = clean_path_value(str(value)).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", raw):
        normalized = raw.rstrip("/")
    else:
        normalized = str(Path(raw).expanduser().resolve()).replace("\\", "/").rstrip("/")
    return normalized.casefold() if (platform_name or os.name) == "nt" else normalized


def is_absolute_path(value: str) -> bool:
    raw = clean_path_value(value).replace("\\", "/")
    return bool(re.match(r"^[A-Za-z]:/", raw) or raw.startswith("/"))


def storage_errors(
    text: str,
    artifact: Path,
    write_receipt: Path | None,
    verify_receipt: Path | None,
) -> list[str]:
    errors: list[str] = []
    declared_artifact = clean_path_value(label_value(text, "**Packet path:**") or "")
    declared_receipt = clean_path_value(label_value(text, "**Receipt path:**") or "")
    actual_artifact = artifact.resolve()
    receipt_arg = write_receipt or verify_receipt

    if not artifact.is_absolute():
        errors.append("validator requires absolute handoff file path")
    if not is_absolute_path(declared_artifact):
        errors.append("declared handoff packet path must be absolute")
    elif normalized_path(declared_artifact) != normalized_path(actual_artifact):
        errors.append("declared handoff packet path does not match validated file")

    artifact_parts = set(normalized_path(actual_artifact).split("/"))
    if artifact_parts & FORBIDDEN_STORAGE_PARTS or any(
        part.startswith(".validator-") for part in artifact_parts
    ):
        errors.append("canonical handoff cannot use temporary/cache/review-run storage")
    if actual_artifact.suffix.lower() != ".md":
        errors.append("canonical handoff must be Markdown")

    if receipt_arg is None:
        errors.append("validation must write or verify sidecar receipt")
        return errors
    if not receipt_arg.is_absolute():
        errors.append("validator requires absolute receipt path")
    if not is_absolute_path(declared_receipt):
        errors.append("declared receipt path must be absolute")
    elif normalized_path(declared_receipt) != normalized_path(receipt_arg.resolve()):
        errors.append("declared receipt path does not match validator receipt argument")
    if normalized_path(receipt_arg.parent) != normalized_path(actual_artifact.parent):
        errors.append("handoff receipt must be adjacent to canonical packet")
    expected_receipt = f"{actual_artifact.stem}.receipt.json"
    if receipt_arg.name != expected_receipt:
        errors.append(f"handoff receipt must be named {expected_receipt}")
    receipt_parts = set(normalized_path(receipt_arg.resolve()).split("/"))
    if receipt_parts & FORBIDDEN_STORAGE_PARTS or any(
        part.startswith(".validator-") for part in receipt_parts
    ):
        errors.append("handoff receipt cannot use temporary/cache/review-run storage")
    return errors


HEADINGS = [
    "# COLD-START HANDOFF:",
    "## 0. Handoff Control",
    "## 1. Intent & Mission",
    "## 2. Current State",
    "## 3. Environment & Active Work",
    "## 4. Decisions, Invariants & User Corrections",
    "## 5. Artifacts & Evidence",
    "## 6. Failures, Dead Ends & Attempts",
    "## 7. Learnings, Gotchas & Landmines",
    "## 8. Open Loops & Context Gaps",
    "## 9. Safety, Authority & Boundaries",
    "## 10. Exact Resume Sequence",
    "## 11. State Verification & Invalidation",
    "## 12. First Output & Readback Contract",
    "## 13. Ready-to-Paste First Message",
    "## 14. Context Gap Report",
    "## 15. Handoff Author Gate",
]

LABELS = [
    "**Handoff ID:**", "**Created:**", "**Source task / chat:**", "**Target:**",
    "**Author:**", "**Receiver role:**", "**Proceed mode:**", "**Readiness:**",
    "**Handoff reason:**", "**Source evidence mode:**",
    "**Transcript evidence path:**", "**Source prefix receipt:**",
    "**Packet path:**", "**Receipt path:**",
    "**Original user intent verbatim:**", "**Underlying goal:**",
    "**Current objective:**", "**Definition of success:**", "**Out of scope:**",
    "**First responsibility:**", "**Must not do first:**", "**Phase:**",
    "**Completed:**", "**In progress:**", "**Blocked:**", "**Not started:**",
    "**Last action:**", "**Last observed result:**", "**Active goal / plan:**",
    "**Current hypothesis:**", "**Work type:**", "**Workspace / repo:**",
    "**Branch / version:**", "**Baseline revision:**", "**Dirty state:**",
    "**OS / shell:**", "**Tools / dependencies:**", "**Services / processes:**",
    "**Agents / tasks / threads:**", "**Scheduled work:**",
    "**Credentials / access:**", "**May do:**", "**Do not change:**",
    "**Do not run:**", "**Irreversible / production actions:**",
    "**Spend / external effects:**", "**Secrets handling:**",
    "**Reserved decisions:**", "**Verification command:**", "**Expected state:**",
    "**Invalidated by:**", "**Refresh action:**", "**Validator command:**",
    "**Receiver receipt check:**", "**First deliverable after readback:**",
    "**Gap report format:**", "**Gap summary:**", "**Safe-to-proceed scope:**",
    "**Fatal recovery owner:**", "**Exact recovery sequence:**",
]

STEP_LABELS = [
    "**Owner:**", "**Working directory / system:**", "**Exact action:**",
    "**Expected result:**", "**Evidence path:**", "**Timeout / retry:**",
    "**If failure:**", "**Depends on:**",
]

STEP_RE = re.compile(r"(?m)^### Resume Step\s+\d+\s+—\s+.+$")
PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\s`|]+")
ACTION_RE = re.compile(
    r"\b(run|read|search|inspect|verify|capture|compare|resume|execute|open|"
    r"check|record|load|query|test)\b", re.I
)
PLACEHOLDER_RE = re.compile(r"\{\{[^{}\n]+\}\}")
GENERIC = {"", "value", "example", "placeholder", "fixture-value", "todo", "tbd", "n/a", "none"}
ENUM_VALUES = {
    "READY", "READY_WITH_GAPS", "NOT_READY", "IMMEDIATE", "READBACK_ONLY",
    "REVIEW_ONLY", "DECISION", "CODE", "DOCUMENT", "RESEARCH", "OPERATIONS",
    "MIXED", "LOCKED", "ACTIVE_ASSUMPTION", "REVISIT_ON", "FATAL", "HIGH",
    "MEDIUM", "LOW", "NONE",
}
BANNED = {
    "old-chat dependency": r"\b(as discussed|see above|previous chat|you already know|prior[- ](?:thread|chat|conversation) context|earlier[- ](?:thread|chat|conversation)|inherited context|remembered state|implicit credentials?|(?:old|earlier|prior)[- ](?:messages?|session|history))\b",
    "orphan continuation": r"\b(continue where we left off|just continue|usual constraints apply)\b",
    "weak gap handling": r"\b(ask me if anything is unclear|catch up on)\b",
    "unfinished marker": r"\b(TODO|TBD|TK)\b",
}
SECRET_PATTERNS = {
    "OpenAI-like key": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "Slack token": r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "literal secret assignment": r"(?i)\b(password|api[_-]?key|secret|token)\s*[:=]\s*[`\"']?[A-Za-z0-9+/=_-]{12,}",
    "authorization header": r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}",
    "bearer credential": r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
}


def label_value(text: str, label: str) -> str | None:
    match = re.search(rf"(?m)^-\s+{re.escape(label)}\s*(.*)$", text)
    return match.group(1).strip() if match else None


def concrete(value: str) -> bool:
    raw = value.strip().strip("`")
    if raw in ENUM_VALUES:
        return True
    normalized = raw.lower()
    return len(normalized) >= 8 and normalized not in GENERIC


def fenced_after(text: str, label: str) -> str | None:
    match = re.search(
        rf"{re.escape(label)}\s*\n+\s*```[^\n]*\n(.*?)\n```", text, re.S
    )
    return match.group(1).strip() if match else None


def table_rows(text: str, start: str, end: str) -> list[list[str]]:
    left = text.find(start)
    right = text.find(end, left + len(start))
    if left < 0 or right < 0:
        return []
    rows: list[list[str]] = []
    for line in text[left:right].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def table_errors(name: str, rows: list[list[str]], width: int, template: bool) -> list[str]:
    if len(rows) < 2:
        return [f"{name} requires at least one data row"]
    errors: list[str] = []
    for row_index, row in enumerate(rows[1:], start=1):
        if len(row) != width:
            errors.append(f"{name} row {row_index} must contain {width} cells")
            continue
        if not template:
            for cell_index, cell in enumerate(row, start=1):
                if not concrete(cell):
                    errors.append(f"{name} row {row_index} cell {cell_index} is too vague")
    return errors


def ordered_errors(text: str) -> list[str]:
    errors: list[str] = []
    cursor = -1
    for heading in HEADINGS:
        index = text.find(heading)
        if index < 0:
            errors.append(f"missing heading: {heading}")
        elif index <= cursor:
            errors.append(f"heading out of order: {heading}")
        else:
            cursor = index
    return errors


def resume_errors(text: str, template: bool) -> list[str]:
    matches = list(STEP_RE.finditer(text))
    if len(matches) < 3:
        return ["resume sequence requires at least 3 steps"]
    errors: list[str] = []
    section_end = text.find("## 11. State Verification & Invalidation")
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else section_end
        block = text[match.start():end]
        name = match.group(0)
        for label in STEP_LABELS:
            if label not in block:
                errors.append(f"{name} missing label: {label}")
        action = fenced_after(block, "**Exact action:**")
        if action is None:
            errors.append(f"{name} lacks fenced exact action")
        if template:
            continue
        for label in STEP_LABELS:
            if label == "**Exact action:**":
                continue
            value = label_value(block, label) or ""
            if not concrete(value):
                errors.append(f"{name} has non-concrete value: {label}")
        if action is None or not concrete(action) or not ACTION_RE.search(action):
            errors.append(f"{name} exact action is not executable/actionable")
        for label in ("**Working directory / system:**", "**Evidence path:**"):
            if not PATH_RE.search(label_value(block, label) or ""):
                errors.append(f"{name} {label} lacks explicit path")
        if not re.search(r"\d+", label_value(block, "**Timeout / retry:**") or ""):
            errors.append(f"{name} timeout/retry lacks numeric bound")
    return errors


def validate(text: str, template: bool = False) -> list[str]:
    errors = ordered_errors(text)
    for label in LABELS:
        value = label_value(text, label)
        if value is None:
            errors.append(f"missing label: {label}")
        elif not value and label not in {
            "**Verification command:**",
            "**Validator command:**",
            "**Receiver receipt check:**",
        }:
            errors.append(f"empty value: {label}")
        elif not template and value.strip().strip("`").lower() in GENERIC:
            errors.append(f"generic filler value: {label}")

    errors.extend(resume_errors(text, template))
    tables = [
        ("decision log", "## 4. Decisions, Invariants & User Corrections", "## 5. Artifacts & Evidence", 5),
        ("artifact map", "## 5. Artifacts & Evidence", "## 6. Failures, Dead Ends & Attempts", 6),
        ("failure map", "## 6. Failures, Dead Ends & Attempts", "## 7. Learnings, Gotchas & Landmines", 7),
        ("gotcha map", "## 7. Learnings, Gotchas & Landmines", "## 8. Open Loops & Context Gaps", 4),
        ("gap map", "## 8. Open Loops & Context Gaps", "## 9. Safety, Authority & Boundaries", 6),
    ]
    parsed: dict[str, list[list[str]]] = {}
    for name, start, end, width in tables:
        rows = table_rows(text, start, end)
        parsed[name] = rows
        errors.extend(table_errors(name, rows, width, template))

    if not template:
        readiness = (label_value(text, "**Readiness:**") or "").strip("`")
        if readiness not in {"READY", "READY_WITH_GAPS", "NOT_READY"}:
            errors.append("Readiness must be READY, READY_WITH_GAPS, or NOT_READY")
        proceed = (label_value(text, "**Proceed mode:**") or "").strip("`")
        if proceed not in {"IMMEDIATE", "READBACK_ONLY", "REVIEW_ONLY", "DECISION"}:
            errors.append("invalid Proceed mode")
        work_type = (label_value(text, "**Work type:**") or "").strip("`")
        if work_type not in {"CODE", "DOCUMENT", "RESEARCH", "OPERATIONS", "MIXED"}:
            errors.append("invalid Work type")
        source_mode = (
            label_value(text, "**Source evidence mode:**") or ""
        ).strip("`")
        evidence_path = label_value(text, "**Transcript evidence path:**") or ""
        source_receipt = label_value(text, "**Source prefix receipt:**") or ""
        if source_mode not in {"TRANSCRIPT_INGEST", "LIVE_CONTEXT"}:
            errors.append(
                "Source evidence mode must be TRANSCRIPT_INGEST or LIVE_CONTEXT"
            )
        if source_mode == "TRANSCRIPT_INGEST":
            if not PATH_RE.search(evidence_path):
                errors.append(
                    "TRANSCRIPT_INGEST requires absolute compiled evidence path"
                )
            for token in (
                "PLATFORM:",
                "SESSION_ID:",
                "CUTOFF_BYTES:",
                "SHA256:",
                "PARSER_VERSION:",
            ):
                if token not in source_receipt.upper():
                    errors.append(
                        f"TRANSCRIPT_INGEST source prefix receipt missing {token}"
                    )
            if not re.search(r"\bSHA256:[0-9a-f]{64}\b", source_receipt, re.I):
                errors.append(
                    "TRANSCRIPT_INGEST source prefix receipt requires 64-hex SHA256"
                )
            if not re.search(r"\bCUTOFF_BYTES:[1-9]\d*\b", source_receipt, re.I):
                errors.append(
                    "TRANSCRIPT_INGEST source prefix receipt requires positive cutoff"
                )
        else:
            if not re.match(r"^NOT_APPLICABLE:\s*\S", evidence_path, re.I):
                errors.append(
                    "LIVE_CONTEXT transcript evidence path requires NOT_APPLICABLE reason"
                )
            if not re.match(r"^NOT_APPLICABLE:\s*\S", source_receipt, re.I):
                errors.append(
                    "LIVE_CONTEXT source prefix receipt requires NOT_APPLICABLE reason"
                )
        severities = []
        for row in parsed.get("gap map", [])[1:]:
            if len(row) == 6:
                severity = row[1].strip("`")
                severities.append(severity)
                if severity not in {"FATAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
                    errors.append(f"invalid gap severity: {severity}")
        if readiness == "READY" and any(level in {"FATAL", "HIGH"} for level in severities):
            errors.append("READY cannot contain FATAL or HIGH gap")
        if readiness == "NOT_READY" and "FATAL" not in severities:
            errors.append("NOT_READY requires FATAL gap")
        if readiness == "READY_WITH_GAPS" and all(level == "NONE" for level in severities):
            errors.append("READY_WITH_GAPS requires declared gap")
        if readiness == "READY_WITH_GAPS" and "FATAL" in severities:
            errors.append("READY_WITH_GAPS cannot contain FATAL gap; use NOT_READY")

        verification = fenced_after(text, "**Verification command:**")
        if verification is None or not concrete(verification) or not ACTION_RE.search(verification):
            errors.append("state verification lacks executable fenced command/action")
        validator_command = fenced_after(text, "**Validator command:**") or ""
        receiver_command = fenced_after(text, "**Receiver receipt check:**") or ""
        declared_packet = clean_path_value(label_value(text, "**Packet path:**") or "")
        declared_receipt = clean_path_value(label_value(text, "**Receipt path:**") or "")
        for label, command, flag in (
            ("Validator command", validator_command, "--write-receipt"),
            ("Receiver receipt check", receiver_command, "--verify-receipt"),
        ):
            normalized_command = normalized_path(command)
            if (
                "validate-handoff.py" not in command
                or flag not in command
                or normalized_path(declared_packet) not in normalized_command
                or normalized_path(declared_receipt) not in normalized_command
            ):
                errors.append(
                    f"{label} must execute validate-handoff.py with bound paths and {flag}"
                )
        for label in ("**Packet path:**", "**Receipt path:**", "**Workspace / repo:**"):
            if not PATH_RE.search(label_value(text, label) or ""):
                errors.append(f"{label} lacks explicit path")
        first_message = text[text.find("## 13. Ready-to-Paste First Message"):text.find("## 14. Context Gap Report")]
        if "READBACK" not in first_message or "Proceed mode" not in first_message:
            errors.append("first message must require READBACK + Proceed mode")

    author = text[text.find("## 15. Handoff Author Gate"):]
    if not template:
        if PLACEHOLDER_RE.search(text):
            errors.append("unfilled placeholder remains")
        if "- [ ]" in author:
            errors.append("handoff author gate contains unchecked item")
        if author.count("- [x]") < 18:
            errors.append("handoff author gate requires 18 checked items")

    for name, pattern in BANNED.items():
        match = re.search(pattern, text, re.I)
        if match:
            errors.append(f"{name}: forbidden phrase '{match.group(0)}'")
    if not template:
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, text):
                errors.append(f"possible secret detected: {name}")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handoff", type=Path)
    parser.add_argument("--template-self-check", action="store_true")
    receipt_group = parser.add_mutually_exclusive_group()
    receipt_group.add_argument("--write-receipt", type=Path)
    receipt_group.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args()

    if not args.handoff.is_file():
        print(f"FAIL: handoff file not found: {args.handoff}", file=sys.stderr)
        return 2
    if (
        not args.template_self_check
        and args.write_receipt is None
        and args.verify_receipt is None
    ):
        print("FAIL: exactly one receipt mode is required")
        return 1

    raw_bytes = args.handoff.read_bytes()
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"FAIL: handoff is not valid UTF-8: {exc}")
        return 1
    errors = validate(text, template=args.template_self_check)
    if not args.template_self_check:
        errors.extend(
            storage_errors(
                text, args.handoff, args.write_receipt, args.verify_receipt
            )
        )
    if errors:
        print(f"FAIL: {len(errors)} handoff defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1

    digest = hashlib.sha256(raw_bytes).hexdigest()
    if args.verify_receipt:
        if not args.verify_receipt.is_file():
            print(f"FAIL: receipt file not found: {args.verify_receipt}")
            return 2
        try:
            receipt = json.loads(args.verify_receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL: invalid receipt: {exc}")
            return 1
        if receipt.get("sha256") != digest:
            print("FAIL: handoff bytes do not match receipt")
            return 1
        if receipt.get("artifact_name") != args.handoff.name:
            print("FAIL: handoff filename does not match receipt")
            return 1
        if normalized_path(receipt.get("artifact_path", "")) != normalized_path(
            args.handoff.resolve()
        ):
            print("FAIL: handoff path does not match receipt")
            return 1
        print(f"RECEIPT_PASS: sha256={digest}")
    if args.write_receipt:
        receipt = {
            "schema_version": 1,
            "artifact_name": args.handoff.name,
            "artifact_path": str(args.handoff.resolve()),
            "sha256": digest,
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "validator": "handoff/validate-handoff.py",
        }
        args.write_receipt.parent.mkdir(parents=True, exist_ok=True)
        args.write_receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: handoff is cold-start complete (sha256={digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
