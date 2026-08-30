#!/usr/bin/env python3
"""Structural, contamination, and high-risk semantic checks for Atom reports."""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys


HEADERS = {
    "inventory": ["Platform", "Domain", "Atom", "Definition / boundary", "Source evidence"],
    "stage2": ["Scope", "Domain", "Atom", "Repository mechanisms", "Best observed", "Best combined", "Rationale / tradeoffs", "Source evidence"],
    "final": ["Scope", "Domain", "Atom", "Best observed", "Recommended implementation", "Why / tradeoffs", "Source evidence", "Confidence"],
}

FORBIDDEN_EVIDENCE = (
    ".cache/", ".right-release/", ".fingerprint/", "node_modules/", "target/debug/",
    "target/release/", "deriveddata/", "heardright-recording-lifecycle-review/",
)

BOILERPLATE = (
    "combine observed strengths without assuming parity",
    "combine strongest observed mechanism with explicit state",
    "strongest dedicated source match; recovery/persistence depth remains qualified",
    "state/persistence/fallback: unclear unless separately evidenced",
    "keep boundary explicit, observable, and testable",
)

# Each tuple is an AND of token groups; each group is satisfied by any listed
# token. Remove every literal occurrence of atom label before matching so
# quoted forms such as ``For “Atom”, ...`` cannot satisfy their own gate.
SEMANTIC_SIGNATURES = {
    "pill motion & relocation": (
        ("drag", "snap", "relocat", "move", "position", "anchor"),
        ("screen", "display", "coordinate", "geometry", "position", "anchor"),
    ),
    "spoken send parser": (
        ("parse", "parser", "phrase", "utterance", "intent", "command"),
        ("send", "submit"),
    ),
    "post-insert submit": (
        ("enter", "return", "submit"),
        ("insert", "delivery"),
        ("confirm", "verif", "evidence", "success"),
    ),
    "target snapshot & revalidation": (
        ("target", "focus"),
        ("revalid", "identity", "same target", "snapshot"),
    ),
    "clipboard transaction": (
        ("clipboard",),
        ("snapshot", "preserve", "save"),
        ("restore",),
    ),
    "background model download": (
        ("download", "transfer"),
        ("model", "artifact"),
        ("background", "resume", "resumable", "checkpoint"),
        ("validat", "checksum", "signature", "atomic"),
    ),
    "watchconnectivity bridge": (
        ("wcsession", "watchconnectivity", "watch session"),
        ("message", "applicationcontext", "userinfo", "file transfer", "payload"),
        ("reachab", "ack", "retry", "queue", "dedup"),
    ),
    "watchconnectivity relay": (
        ("wcsession", "watchconnectivity", "watch session"),
        ("message", "applicationcontext", "userinfo", "file transfer", "payload"),
        ("ack", "retry", "queue", "dedup", "idempot"),
    ),
    "forward queue retry": (
        ("queue",),
        ("retry", "backoff"),
        ("idempot", "dedup", "stable id", "operation id"),
    ),
    "device registration": (
        ("device", "identity"),
        ("register", "pair", "token", "credential"),
    ),
    "ime microphone key": (
        ("ime", "keyboard", "input method"),
        ("microphone", "mic"),
        ("start", "stop", "toggle", "capture"),
    ),
    "action_recognize_speech": (
        ("action_recognize_speech", "recognition intent", "recognizer intent"),
        ("result", "caller", "activity result"),
    ),
    "vad/silence endpointing": (
        ("vad", "voice activity", "speech"),
        ("silence", "endpoint"),
    ),
    "verified update install": (
        ("signature", "signed", "checksum", "hash", "verif"),
        ("artifact", "package", "bundle", "release", "update"),
        ("install", "replace", "activate", "relaunch"),
        ("rollback", "last-good", "prior working", "resume"),
    ),
}


def parse_table(path: pathlib.Path, expected_header: list[str]) -> list[tuple[int, list[str]]]:
    rows: list[tuple[int, list[str]]] = []
    in_table = False
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.startswith("|"):
            continue
        cells = [cell.strip() for cell in raw.strip().strip("|").split("|")]
        if cells == expected_header:
            in_table = True
            continue
        if in_table and all(cell and set(cell) <= {"-", ":"} for cell in cells):
            continue
        if in_table:
            if len(cells) != len(expected_header):
                raise ValueError(f"line {line_number}: expected {len(expected_header)} cells, got {len(cells)}")
            rows.append((line_number, cells))
    if not in_table:
        raise ValueError(f"missing table header: {' | '.join(expected_header)}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--mode", choices=HEADERS, required=True)
    parser.add_argument("--expected-rows", type=int)
    parser.add_argument("--max-repeat", type=int, default=8)
    parser.add_argument("--manifest", type=pathlib.Path)
    args = parser.parse_args()

    errors: list[str] = []
    try:
        rows = parse_table(args.report, HEADERS[args.mode])
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1

    header = HEADERS[args.mode]
    index = {name: position for position, name in enumerate(header)}
    repo_roots: dict[str, pathlib.Path] = {}
    scope_repos: dict[str, list[str]] = {}
    if args.manifest is not None:
        try:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            repo_roots = {name: pathlib.Path(value).resolve() for name, value in manifest["repo_roots"].items()}
            scope_repos = {name: list(value) for name, value in manifest["scope_repos"].items()}
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            print(f"FAIL: invalid manifest: {exc}")
            return 1
    if args.expected_rows is not None and len(rows) != args.expected_rows:
        errors.append(f"expected {args.expected_rows} rows, found {len(rows)}")

    scope_name = "Scope" if "Scope" in index else "Platform"
    seen: dict[tuple[str, str, str], int] = {}
    for line_number, cells in rows:
        key = (cells[index[scope_name]], cells[index["Domain"]], cells[index["Atom"]])
        if key in seen:
            errors.append(f"line {line_number}: duplicate atom tuple; first at line {seen[key]}")
        else:
            seen[key] = line_number

        evidence = cells[index["Source evidence"]].lower()
        for token in FORBIDDEN_EVIDENCE:
            if token in evidence:
                errors.append(f"line {line_number}: forbidden evidence path `{token}`")

        joined = " ".join(cells).lower()
        for phrase in BOILERPLATE:
            if phrase in joined:
                errors.append(f"line {line_number}: prohibited boilerplate `{phrase}`")

        recommendation_name = "Best combined" if "Best combined" in index else "Recommended implementation" if "Recommended implementation" in index else None
        atom_key = cells[index["Atom"]].strip().lower()
        signature = SEMANTIC_SIGNATURES.get(atom_key)
        if recommendation_name is not None and signature is not None:
            body = cells[index[recommendation_name]].strip().lower()
            prefix = f"{atom_key}:"
            if body.startswith(prefix):
                body = body[len(prefix):].strip()
            body = body.replace(atom_key, "")
            missing = [group for group in signature if not any(token in body for token in group)]
            if missing:
                expected = " + ".join("/".join(group) for group in missing)
                errors.append(
                    f"line {line_number}: `{cells[index['Atom']]}` recommendation lacks semantic signature: {expected}"
                )

        if args.mode == "stage2" and scope_repos:
            scope = cells[index["Scope"]]
            expected_repos = scope_repos.get(scope)
            if expected_repos is None:
                errors.append(f"line {line_number}: scope `{scope}` missing from manifest")
                continue

            mechanism_entries = cells[index["Repository mechanisms"]].split("<br>")
            for repo in expected_repos:
                matches = [entry for entry in mechanism_entries if entry.startswith(f"{repo}:")]
                if len(matches) != 1:
                    errors.append(f"line {line_number}: expected exactly one `{repo}:` mechanism entry, found {len(matches)}")
                    continue
                entry = matches[0]
                if ": Observed " in entry:
                    cited = re.findall(r"`([^`]+)`", entry)
                    if not cited:
                        errors.append(f"line {line_number}: `{repo}` Observed entry lacks backticked production path/symbol")
                    if repo not in cells[index["Source evidence"]]:
                        errors.append(f"line {line_number}: `{repo}` Observed entry missing source-evidence entry")

            evidence_cell = cells[index["Source evidence"]]
            for repo, cited in re.findall(r"(?:^|;\s*)([^:;]+):\s*`([^`]+)`", evidence_cell):
                repo = repo.strip()
                root = repo_roots.get(repo)
                if root is None:
                    errors.append(f"line {line_number}: evidence repository `{repo}` missing from manifest roots")
                    continue
                relative = cited.split("#", 1)[0]
                candidate = (root / relative).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    errors.append(f"line {line_number}: evidence path escapes `{repo}` root: {relative}")
                    continue
                if not candidate.is_file():
                    errors.append(f"line {line_number}: missing evidence file for `{repo}`: {relative}")

    repeat_columns = [name for name in ("Best observed", "Best combined", "Recommended implementation", "Rationale / tradeoffs", "Why / tradeoffs") if name in index]
    sentinels = {"not found", "unclear", "n/a", "no proven winner"}
    for name in repeat_columns:
        counter = collections.Counter(cells[index[name]].strip() for _, cells in rows)
        for value, count in counter.items():
            if not value or value.lower() in sentinels:
                continue
            if count > args.max_repeat:
                sample = value[:100].replace("\n", " ")
                errors.append(f"column `{name}` repeats {count} times: {sample!r}")

    if errors:
        print(f"FAIL: {len(errors)} issue(s)")
        for issue in errors:
            print(f"- {issue}")
        return 1

    print(f"PASS: {args.report} ({len(rows)} rows, mode={args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
