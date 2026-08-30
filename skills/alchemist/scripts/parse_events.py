#!/usr/bin/env python3
"""Parse `codex exec --json` events for the Alchemist skill.

Modes:
  --stream    read JSONL on stdin; assistant text to stdout, activity to stderr.
  --summary   read a saved JSONL event log and print a structured run summary.

Also importable: viewer.py reuses classify() so the live view and the CLI summary
can never disagree about what an event means.

Codex event schemas have shifted across releases, so field lookup is defensive:
probe several shapes rather than assume one.
"""

from __future__ import annotations

import argparse
import json
import sys

TEXT_KEYS = ("text", "content", "message", "delta")


def first_text(obj) -> str:
    """Best-effort extraction of human-readable text from a nested event."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return "".join(p for p in (first_text(o) for o in obj) if p)
    if isinstance(obj, dict):
        for key in TEXT_KEYS:
            if key in obj:
                found = first_text(obj[key])
                if found:
                    return found
    return ""


def classify(event: dict) -> tuple[str, str]:
    """Return (kind, detail). kind is a coarse bucket the UI colours by."""
    payload = event.get("item") if isinstance(event.get("item"), dict) else event
    if payload is event and isinstance(event.get("msg"), dict):
        payload = event["msg"]
    kind = (
        payload.get("type")
        or event.get("type")
        or event.get("event")
        or (event.get("msg") or {}).get("type")
        or "unknown"
    )
    lowered = str(kind).lower()

    if "reason" in lowered:
        return "reasoning", first_text(payload)[:400]
    if "command" in lowered or "exec" in lowered or "shell" in lowered:
        cmd = payload.get("command") or payload.get("cmd") or first_text(payload)
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        return "command", str(cmd)[:400]
    if "patch" in lowered or "diff" in lowered or "apply" in lowered:
        return "patch", first_text(payload)[:400]
    if "error" in lowered or event.get("error"):
        return "error", first_text(event.get("error") or payload)[:400]
    if "message" in lowered or "agent" in lowered or "assistant" in lowered:
        return "assistant", first_text(payload)
    if "token" in lowered or "usage" in lowered:
        return "usage", json.dumps(payload)[:200]
    return str(kind), first_text(payload)[:400]


def iter_events(stream):
    for line in stream:
        # Windows PowerShell prefixes a UTF-8 BOM on the first line it writes,
        # and the exact behaviour varies by PowerShell version and redirection.
        # A BOM here is not corruption, so strip it rather than discarding a
        # real agent event as unparseable — dropping it loses worker output.
        line = line.lstrip("﻿").strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            print(f"[non-json] {line[:160]}", file=sys.stderr)


def run_stream() -> int:
    for event in iter_events(sys.stdin):
        kind, detail = classify(event)
        if kind == "assistant" and detail:
            print(detail, flush=True)
        else:
            print(f"  · {kind}: {detail.replace(chr(10), ' ')[:160]}", file=sys.stderr, flush=True)
    return 0


def run_summary(path: str) -> int:
    counts: dict[str, int] = {}
    commands: list[str] = []
    patches = 0
    errors: list[str] = []
    assistant: list[str] = []

    with open(path, encoding="utf-8", errors="replace") as handle:
        for event in iter_events(handle):
            kind, detail = classify(event)
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "command":
                commands.append(detail)
            elif kind == "patch":
                patches += 1
            elif kind == "error":
                errors.append(detail)
            elif kind == "assistant" and detail:
                assistant.append(detail)

    print("=== alchemist run summary ===")
    print(f"events: {sum(counts.values())}  ({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))})")
    print(f"commands run by worker: {len(commands)}")
    for cmd in commands[:20]:
        print(f"   $ {cmd}")
    if len(commands) > 20:
        print(f"   … {len(commands) - 20} more")
    print(f"patch/apply events: {patches}")
    if errors:
        print(f"ERRORS ({len(errors)}):")
        for err in errors[:10]:
            print(f"   ! {err}")
    else:
        print("errors: none")
    if assistant:
        print("--- final worker message (tail) ---")
        print("".join(assistant)[-1200:])
    print()
    print("NOTE: this summarizes what the worker CLAIMS. The host must still read")
    print("      the real git diff and re-run the verification commands itself.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--stream", action="store_true", help="live-parse JSONL from stdin")
    group.add_argument("--summary", metavar="EVENT_LOG", help="summarize a saved event log")
    args = ap.parse_args()
    return run_stream() if args.stream else run_summary(args.summary)


if __name__ == "__main__":
    sys.exit(main())
