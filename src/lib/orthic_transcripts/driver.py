#!/usr/bin/env python3
"""Thin CLI driver invoked by tools/lib/orthic_transcripts/index.mjs.

Reads a JSON payload from stdin, dispatches to the requested operation, and
prints a single JSON-encoded response on stdout. Stays hermetic and process-
isolated so the JS shim never has to import Python code directly.

Subcommands:
    parse <options.json>          — invoke the parser and return JSON.
    resolve-session <options.json>— exact-match session resolver.
    parser-digest                 — return the parser implementation digest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running as a script from anywhere — the package directory is one
# level up from this file.
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from orthic_transcripts import (  # noqa: E402  (path injection above)
    PARSER_DIGEST,
    parse,
    resolve_session,
)


def _read_payload() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON on stdin: {exc}")
    return value if isinstance(value, dict) else {}


def _emit(value) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit("usage: driver.py <parse|resolve-session|parser-digest>")
    subcommand = argv[1]
    if subcommand == "parse":
        _emit(parse(**_read_payload()))
        return 0
    if subcommand == "resolve-session":
        _emit(resolve_session(**_read_payload()))
        return 0
    if subcommand == "parser-digest":
        _emit({"parserDigest": PARSER_DIGEST})
        return 0
    raise SystemExit(f"unknown subcommand: {subcommand}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))