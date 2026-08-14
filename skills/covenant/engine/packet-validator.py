#!/usr/bin/env python3
"""Fail-closed validator for packet-only external review briefs (Covenant-owned)."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


HEADINGS = [
    "# EXTERNAL REVIEW PACKET",
    "## 0. Packet Control",
    "## 1. Problem in Plain Language",
    "## 2. User Intent",
    "### Exact request",
    "### Desired outcome",
    "### Definition of success",
    "## 3. What Went Wrong",
    "## 4. Current System & State",
    "## 5. Constraints & Invariants",
    "## 6. Existing Attempts & Inputs",
    "## 7. Evidence Bundle",
    "## 8. Known Unknowns",
    "## 9. Questions for Reviewer",
    "## 10. Response Contract",
]
LABELS = [
    "**Created:**",
    "**Mode:**",
    "**Audience:**",
    "**Packet path:**",
    "**Requested response:**",
]
CANONICAL_MODE = "PACKET_ONLY — DO_NOT_RUN_COVENANT"
PLACEHOLDER_RE = re.compile(r"\{\{[^{}\n]+\}\}")
ABSOLUTE_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\n|]+")
FORBIDDEN_STORAGE = {
    "temp", "tmp", ".tmp", "temporary", "cache", ".cache", "review-run",
    "review-runs", ".review-runs", ".covenant-runs", "scratch",
}
BANNED = (
    "as discussed",
    "see previous chat",
    "continue where we left off",
    "you already know",
    "prior-thread context",
    "prior chat context",
    "earlier conversation",
    "inherited context",
    "remembered state",
    "implicit credentials",
    "old messages",
    "earlier messages",
    "prior session",
    "old session",
)
SECRET_PATTERNS = {
    "literal secret": r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[`\"']?[A-Za-z0-9+/=_-]{12,}",
    "authorization header": r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}",
    "bearer credential": r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "OpenAI-like key": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "Slack token": r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
}


def label_value(text: str, label: str) -> str | None:
    match = re.search(rf"(?m)^-\s*{re.escape(label)}\s*(.*)$", text)
    return match.group(1).strip() if match else None


def normalized(value: str | Path, platform_name: str | None = None) -> str:
    raw = str(value).strip().strip("`\"'").replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", raw):
        result = raw.rstrip("/")
    else:
        result = str(Path(raw).expanduser().resolve()).replace("\\", "/").rstrip("/")
    return result.casefold() if (platform_name or os.name) == "nt" else result


def table_rows(text: str, start: str, end: str) -> list[list[str]]:
    a, b = text.find(start), text.find(end)
    if a < 0 or b < 0:
        return []
    rows = []
    for line in text[a:b].splitlines():
        if line.startswith("|") and not re.match(r"^\|[\s:|-]+\|$", line):
            rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows


def validate(text: str, path: Path, inline: bool, template: bool = False) -> list[str]:
    errors: list[str] = []
    cursor = -1
    for heading in HEADINGS:
        position = text.find(heading, cursor + 1)
        if position < 0:
            errors.append(f"missing or out-of-order heading: {heading}")
        else:
            cursor = position

    for label in LABELS:
        value = label_value(text, label)
        if value is None:
            errors.append(f"missing label: {label}")
        elif not value:
            errors.append(f"empty label: {label}")

    if template:
        return sorted(set(errors))

    if PLACEHOLDER_RE.search(text):
        errors.append("unfilled placeholder remains")
    if label_value(text, "**Mode:**") != CANONICAL_MODE:
        errors.append(f"Mode must be {CANONICAL_MODE}")

    declared = label_value(text, "**Packet path:**") or ""
    if inline:
        if declared.strip("`").upper() != "INLINE":
            errors.append("inline packet must declare Packet path INLINE")
    else:
        if not path.is_absolute():
            errors.append("durable packet validator requires absolute file path")
        if not ABSOLUTE_RE.search(declared):
            errors.append("durable packet must declare absolute Packet path")
        elif normalized(declared) != normalized(path.resolve()):
            errors.append("declared Packet path does not match validated file")
        path_parts = set(normalized(path.resolve()).split("/"))
        if path_parts & FORBIDDEN_STORAGE or any(
            part.startswith(".validator-") for part in path_parts
        ):
            errors.append("durable packet cannot use temporary/cache/review-run storage")
        if path.suffix.lower() != ".md":
            errors.append("durable packet must be Markdown")

    exact_start = text.find("### Exact request")
    exact_end = text.find("### Desired outcome", exact_start)
    exact_block = text[exact_start:exact_end]
    if not re.search(r"(?m)^>\s+\S.{15,}$", exact_block):
        errors.append("Exact request must include substantive verbatim quote")

    for name, start, end, width in (
        ("failure", "## 3. What Went Wrong", "## 4. Current System & State", 3),
        ("attempt", "## 6. Existing Attempts & Inputs", "## 7. Evidence Bundle", 3),
    ):
        rows = table_rows(text, start, end)
        if len(rows) < 2:
            errors.append(f"{name} table requires data row")
        for index, row in enumerate(rows[1:], 1):
            if len(row) != width or any(len(cell) < 6 for cell in row):
                errors.append(f"{name} table row {index} is incomplete")

    evidence_start = text.find("## 7. Evidence Bundle")
    evidence_end = text.find("## 8. Known Unknowns", evidence_start)
    evidence = text[evidence_start:evidence_end]
    fenced = re.search(r"```(?:text)?\s*\n(.+?)\n```", evidence, re.S)
    if not fenced or len(fenced.group(1).strip()) < 60:
        errors.append("Evidence Bundle requires substantive embedded evidence")

    for phrase in BANNED:
        if phrase in text.casefold():
            errors.append(f"old-context dependency: {phrase}")
    for name, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            errors.append(f"possible secret detected: {name}")
    if "READY_TO_IMPLEMENT" not in text or "REVISE_PACKET" not in text:
        errors.append("response contract lacks required verdict values")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--inline", action="store_true")
    parser.add_argument("--template-self-check", action="store_true")
    args = parser.parse_args()
    if not args.packet.is_file():
        print(f"FAIL: packet file not found: {args.packet}", file=sys.stderr)
        return 2
    text = args.packet.read_text(encoding="utf-8")
    errors = validate(text, args.packet, args.inline, args.template_self_check)
    if errors:
        print(f"FAIL: {len(errors)} packet defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS: external-review packet is zero-context complete & packet-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
