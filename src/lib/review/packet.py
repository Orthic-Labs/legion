"""Jury packet contract — structural lint + skeleton.

Closes the sender-bias hole: when an agent ships a thing to /jury for review,
the engine refuses to run if the packet lacks the required fields. Every
/jury-<kind> review has named success criteria, non-goals, constraints with
file:line evidence, ≥2 alternatives considered OR an explicit sole_viable
justification, ≥3 author-disclosed weaknesses, the user's actual intention
(distinct from the chosen mechanism), and a disclosure of what was NOT
included.

This is a pure-Python structural validator; no network calls, no model
calls. The engine (`engine.py`) calls `validate_packet` at the top of
`Engine.run`; failures raise `PacketValidationError` and the run aborts.

Authoring convenience: `render_packet_skeleton(kind)` returns a pre-filled
markdown skeleton with the right section names for that kind. The caller
fills it in, then `jury.py` or `auto-jury.mjs` writes it as either a
fenced-markdown ````packet` block inside an existing input.md or as a
standalone packet file (.yaml or .md). The validator accepts both shapes.

Fable review (2026-07-14):
  "Make jury.py refuse an input that lacks required sections, exactly
   like the manifest schema work. ARTIFACT (verbatim) · SUCCESS CRITERIA ·
   NON-GOALS · CONSTRAINTS with file:line evidence · ALTERNATIVES CONSIDERED
   (≥2, or 'sole viable + why the others are dominated') · KNOWN WEAKNESSES
   (author must disclose ≥3 — your own 'critique, don't validate' rule
   turned into an input field) · OMISSIONS."

the operator addition (2026-07-14):
  USER_INTENTION is its own field, separate from the proposal. "I want a
  lighter pill" is the user's *want*; "change pill to native Win32" is
  the *mechanism*. Jurors judge against the want, not the mechanism.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union


# ---------- Required sections ----------

PACKET_REQUIRED_SECTIONS: tuple[str, ...] = (
    "ARTIFACT",
    "SUCCESS_CRITERIA",
    "NON_GOALS",
    "CONSTRAINTS",
    "ALTERNATIVES_CONSIDERED",
    "KNOWN_WEAKNESSES",
    "USER_INTENTION",
    "OMISSIONS",
)

# Sections whose absence is a hard error vs a soft warning.
SECTION_RULES: dict[str, str] = {
    "ARTIFACT": "error",                # non-empty
    "SUCCESS_CRITERIA": "error",        # ≥1 bullet
    "NON_GOALS": "error",               # ≥1 bullet
    "CONSTRAINTS": "warn",              # each must be file:line-cite OR ": " rationale
    "ALTERNATIVES_CONSIDERED": "error", # ≥2 entries OR sole_viable marker
    "KNOWN_WEAKNESSES": "error",        # ≥3 bullets
    "USER_INTENTION": "warn",           # non-empty; soft because raw input may lack framing
    "OMISSIONS": "warn",                # missing is fine but should be explicit
}

# ---------- Fence regex (named for clarity in error messages) ----------

PACKET_FENCE_RE = re.compile(
    r"```packet\s*\n(?P<body>.*?)\n```",
    re.DOTALL,
)


@dataclass(frozen=True)
class PacketValidation:
    """Result of `validate_packet`. ok=True only if no errors."""
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sections: dict[str, str] = field(default_factory=dict)  # parsed body per section

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "section_count": len(self.sections),
            "sections_seen": sorted(self.sections.keys()),
        }


class PacketValidationError(ValueError):
    """Raised when `validate_packet(..., strict=True)` finds errors.

    Engine.py raises this from `Engine.run` when a hard-validation packet
    fails; the run aborts before any model is contacted.
    """


# ---------- Parsing the fence body ----------

def _parse_fence_body(body: str) -> dict[str, str]:
    """Parse a ``packet`` fence body into {SECTION_NAME: text}.

    Inside the fence, sections are introduced by a single line of the form
    `SECTION_NAME:` (no leading whitespace). Everything until the next
    section header (or EOF) is the section's body. Inline-marker logic
    (`[P0]`, `[P1]`, `[P2]`, `sole_viable:`) lives in the validators.
    """
    sections: dict[str, str] = {}
    current: Optional[str] = None
    buf: list[str] = []

    for raw_line in body.splitlines():
        line = raw_line.rstrip()
        # A new section header looks like "UPPER_CASE_NAME:" — at least 1 char
        # before the colon, no leading whitespace.
        match = re.match(r"^([A-Z][A-Z0-9_]*)\s*:\s*(.*)$", line)
        if match and not line.startswith((" ", "\t")):
            name = match.group(1)
            tail = match.group(2)
            if current is not None:
                sections[current] = "\n".join(buf).strip("\n")
            current = name
            buf = [tail] if tail else []
            continue
        if current is not None:
            buf.append(raw_line)

    if current is not None:
        sections[current] = "\n".join(buf).strip("\n")

    return sections


def extract_packet(text: str) -> Optional[dict[str, str]]:
    """Return parsed packet sections if `text` carries a ``packet`` fence, else None.

    Returns the *first* ``packet`` fence in the text. The renderer in
    auto-jury.mjs guarantees exactly one fence per file.
    """
    match = PACKET_FENCE_RE.search(text)
    if not match:
        return None
    return _parse_fence_body(match.group("body"))


# ---------- Per-section validators ----------

_CITE_RE = re.compile(r"^file:\S+:\d+\b|^[A-Za-z][^:]*:[^:]+|^:[^:]+")

_BLOCKER_RE = re.compile(r"^\s*[-*]\s+")

# Marker line in ALTERNATIVES_CONSIDERED that lets an author declare "I
# genuinely considered only one option, the others are dominated."
# Matches `sole_viable:` whether it's bare on a line or after a bullet (`- sole_viable:`).
_ALT_SOLE_VIABLE_RE = re.compile(
    r"(?:^|\s-\s*|\b)sole_viable\s*:", re.IGNORECASE
)


def _bullet_count(text: str) -> int:
    """Count list bullets. Strips code fences so fenced code doesn't count."""
    cleaned = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    return sum(1 for line in cleaned.splitlines() if _BLOCKER_RE.match(line))


def _validate_artifact(name: str, text: str) -> tuple[list[str], list[str]]:
    if text.strip():
        return [], []
    return [f"{name}: section is empty"], []


def _validate_bulleted_min(name: str, text: str, *, minimum: int) -> tuple[list[str], list[str]]:
    n = _bullet_count(text)
    if n < minimum:
        return [f"{name}: needs ≥{minimum} bullets, found {n}"], []
    return [], []


def _validate_constraints(name: str, text: str) -> tuple[list[str], list[str]]:
    """Each non-empty line should be `file:path:line - cite` or `<topic>: <justification>`.

    Bad cites warn, never error — a free-form justification starting with
    `topic:` is acceptable for non-code constraints. Bullet lines (with a
    leading `-` or `*`) ARE checked — bullets can carry the cite.
    """
    warnings: list[str] = []
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Strip bullet prefix if present, then check the cite
        content = _BLOCKER_RE.sub("", stripped).strip()
        if not content:
            continue
        if not _CITE_RE.match(content):
            warnings.append(
                f"{name} line {i}: no file:line cite or `topic:` justification — "
                f"consider `file:tools/foo.py:42 — short cite`"
            )
    return [], warnings


def _validate_alternatives(name: str, text: str) -> tuple[list[str], list[str]]:
    """≥2 alternatives OR a sole_viable marker.

    The sole_viable marker is an escape hatch for the rare case where one
    option is genuinely the only sensible answer. Still warn so the
    reviewer can challenge the dominance claim.
    """
    if _ALT_SOLE_VIABLE_RE.search(text):
        msg = text.strip().splitlines()[0]
        return [], [
            f"{name}: declared sole_viable — reviewer should challenge the dominance claim"
        ]
    n = _bullet_count(text)
    if n < 2:
        return [f"{name}: needs ≥2 alternatives OR a `sole_viable:` marker, found {n}"], []
    return [], []


def _validate_user_intention(name: str, text: str) -> tuple[list[str], list[str]]:
    """USER_INTENTION is soft but should distinguish *want* from *mechanism*.

    Heuristic: if the text is empty, warn. If it mentions both "want" (or
    equivalent: goal, outcome, lighter, faster, ...) AND
    "mechanism" (or equivalent: implementation, approach, library,
    framework, ...), it's clearly framed; otherwise warn that the line may
    be ambiguous.
    """
    warnings: list[str] = []
    if not text.strip():
        warnings.append(f"{name}: missing — without it jurors may confuse the want with the mechanism")
        return [], warnings

    lower = text.lower()
    want_markers = sum(1 for m in ("want", "need", "goal", "outcome", "lighter", "faster", "simpler") if m in lower)
    mechanism_markers = sum(1 for m in ("implementation", "mechanism", "approach", "library", "framework", "swap", "switch") if m in lower)

    if want_markers == 0:
        warnings.append(f"{name}: no 'want' phrasing — state the user's underlying intent, not the proposal")
    # mechanism_markers == 0 is fine — sometimes the packet IS the intention
    return [], warnings


def _validate_omissions(name: str, text: str) -> tuple[list[str], list[str]]:
    """OMISSIONS: missing or empty is a warn. Empty list IS acceptable —
    the author considered and disclosed nothing else."""
    if text.strip() or "nothing" in text.lower():
        return [], []
    return [], [
        f"{name}: missing — say either what's omitted or `nothing` for explicit disclosure"
    ]


# ---------- Top-level validate ----------

_VALIDATORS = {
    "ARTIFACT": _validate_artifact,
    "SUCCESS_CRITERIA": lambda n, t: _validate_bulleted_min(n, t, minimum=1),
    "NON_GOALS": lambda n, t: _validate_bulleted_min(n, t, minimum=1),
    "CONSTRAINTS": _validate_constraints,
    "ALTERNATIVES_CONSIDERED": _validate_alternatives,
    "KNOWN_WEAKNESSES": lambda n, t: _validate_bulleted_min(n, t, minimum=3),
    "USER_INTENTION": _validate_user_intention,
    "OMISSIONS": _validate_omissions,
}


NO_PACKET_FENCE = "no_packet_fence"


def is_legacy_no_packet(validation: "PacketValidation") -> bool:
    """True when the input carried NO packet fence at all.

    This is the marked legacy path — a disclosure, not a hard failure.
    Hard-fail (D1, locked 2026-07-14) applies only when a packet IS
    provided and fails validation; punishing fence-less legacy callers
    would break every pre-contract invocation (jury.py --input, auto-jury
    without context.packet) in one release.
    """
    return validation.errors == [NO_PACKET_FENCE]


def validate_packet(text: str, *, kind: Optional[str] = None) -> PacketValidation:
    """Validate the ``packet`` fence (if any) inside `text`.

    Returns a `PacketValidation`. `ok=True` means no errors (warnings
    allowed).

    If `text` has no ``packet`` fence, returns `PacketValidation(ok=False,
    errors=["no_packet_fence"])`. The engine treats that as a structural
    skip unless the caller explicitly opts into packet enforcement.
    """
    sections = extract_packet(text)
    if sections is None:
        return PacketValidation(ok=False, errors=[NO_PACKET_FENCE])

    errors: list[str] = []
    warnings: list[str] = []

    # Missing required sections are errors (or warns for soft ones).
    for required in PACKET_REQUIRED_SECTIONS:
        if required not in sections:
            sev = SECTION_RULES.get(required, "error")
            msg = f"missing section: {required}"
            if sev == "error":
                errors.append(msg)
            else:
                warnings.append(msg)

    # Per-section validators for what IS present. Each returns
    # (errors, warnings) — already normalized.
    for name, body in sections.items():
        if name not in _VALIDATORS:
            continue
        section_errors, section_warnings = _VALIDATORS[name](name, body)
        errors.extend(section_errors)
        warnings.extend(section_warnings)

    return PacketValidation(
        ok=not errors, errors=errors, warnings=warnings, sections=sections
    )


# ---------- Skeleton ----------

SKELETON_TEMPLATE = """\
```packet
ARTIFACT: <verbatim text or path to the artifact being reviewed>

SUCCESS_CRITERIA:
  - <one observable signal that proves the artifact achieved its goal>

NON_GOALS:
  - <one thing this work is NOT trying to do>

CONSTRAINTS:
  - file:<repo-relative path>:<line> — <why this constraint binds>
  - : <non-code constraint with topic and justification>

ALTERNATIVES_CONSIDERED:
  - <alternative A> — <why rejected or `sole_viable: ...`>
  - <alternative B> — <why rejected>

KNOWN_WEAKNESSES:
  - <author-disclosed weakness #1 — critique, don't validate>
  - <author-disclosed weakness #2>
  - <author-disclosed weakness #3>

USER_INTENTION:
  - Want: <what the user actually wants, separate from the chosen mechanism>
  - Mechanism: <the proposed way to deliver the want, one of several>

OMISSIONS:
  - <what this packet does NOT include that a reviewer might expect>
  - or: "nothing" if you considered and disclosed everything relevant
```
"""


def render_packet_skeleton(kind: Optional[str] = None) -> str:
    """Return an empty ``packet`` skeleton. `kind` is for future kind-specific
    hints (e.g. `plan` expects an ADR block section) — for v1 the skeleton
    is uniform across kinds.

    Author fills it in, then either embeds it in their input.md or passes
    it as a standalone file to jury.py / auto-jury.mjs.
    """
    return SKELETON_TEMPLATE


# ---------- Standalone CLI ----------

def _read_input(p: Union[str, Path]) -> str:
    p = Path(p)
    if p.is_file():
        return p.read_text(encoding="utf-8")
    # Otherwise treat as a packet body itself (a yaml-ish block)
    return p.read_text(encoding="utf-8") if p.exists() else p


def main(argv: Optional[list[str]] = None) -> int:
    """CLI: `python -m jury.packet <input_file> [--strict]`."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Validate a jury packet")
    parser.add_argument("input", help="path to packet/markdown input")
    parser.add_argument("--kind", default=None, help="kind hint for skeleton")
    parser.add_argument("--strict", action="store_true", help="raise on errors")
    parser.add_argument("--skeleton", action="store_true", help="print skeleton and exit")
    args = parser.parse_args(argv)

    if args.skeleton:
        sys.stdout.write(render_packet_skeleton(args.kind))
        return 0

    text = Path(args.input).read_text(encoding="utf-8")
    validation = validate_packet(text, kind=args.kind)

    sys.stdout.write(json.dumps(validation.to_dict(), indent=2, ensure_ascii=False) + "\n")
    if validation.errors:
        sys.stderr.write(f"\nERRORS ({len(validation.errors)}):\n")
        for e in validation.errors:
            sys.stderr.write(f"  - {e}\n")
    if validation.warnings:
        sys.stderr.write(f"\nWARNINGS ({len(validation.warnings)}):\n")
        for w in validation.warnings:
            sys.stderr.write(f"  - {w}\n")

    if args.strict and not validation.ok:
        raise PacketValidationError(f"packet invalid: {validation.errors}")

    return 0 if validation.ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
