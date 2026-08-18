"""Tests for jury.packet — packet contract linter.

Run: py -3.11 -m pytest src/lib/review/tests/test_packet.py -v
Or:  py -3.11 src/lib/review/tests/test_packet.py
"""
from __future__ import annotations

import sys
# Force UTF-8 stdout/stderr (Windows console defaults to cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

from pathlib import Path

# Allow running this file directly with `py -3.11 test_packet.py`
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from review.packet import (  # noqa: E402
    PACKET_REQUIRED_SECTIONS,
    PacketValidationError,
    extract_packet,
    render_packet_skeleton,
    validate_packet,
)


# ---------- Test fixtures ----------

GOOD_PACKET = """\
Some preamble text the author wrote above the fence.

```packet
ARTIFACT: src/capture.rs

SUCCESS_CRITERIA:
  - capture loop handles 1k events/sec without drop
  - mean latency under 50ms

NON_GOALS:
  - not touching the renderer
  - not adding new dependencies

CONSTRAINTS:
  - file:src/capture.rs:42 — must not break existing wiring
  - : TS is in Rust, not Python — Rust-only changes

ALTERNATIVES_CONSIDERED:
  - rewrite in tokio — overkill for current load
  - keep status quo — fails the latency goal

KNOWN_WEAKNESSES:
  - ignores backpressure on full buffer
  - lacks structured shutdown
  - no metric for dropped frames

USER_INTENTION:
  - Want: lighter, less-hungry capture loop on Windows
  - Mechanism: native Win32 hook — one of several

OMISSIONS:
  - did not benchmark on macOS
```

Trailing text is allowed.
"""


EMPTY_BODY = """\
```packet
ARTIFACT:

SUCCESS_CRITERIA:

NON_GOALS:

CONSTRAINTS:

ALTERNATIVES_CONSIDERED:

KNOWN_WEAKNESSES:

USER_INTENTION:

OMISSIONS:
```
"""


NO_FENCE = "Just prose, no fence at all."


BAD_NO_FENCE_YET_ALSO_FINE_FALLBACK = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - works

NON_GOALS:
  - no GUI

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - sole_viable: only one option exists; the alternatives are dominated because the codebase restricts changes to Rust files (CONSTRAINTS)

KNOWN_WEAKNESSES:
  - bug 1
  - bug 2
  - bug 3

USER_INTENTION:
  - Want: thing

OMISSIONS:
  - nothing
```
"""


MISSING_USER_INTENTION = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

OMISSIONS:
  - nothing
```
"""


MISSING_OMISSIONS = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x
```
"""


KWN_TOO_FEW = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
"""


ALT_TOO_FEW = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
"""


BAD_CONSTRAINTS = """\
```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - this is fine because we say so

ALTERNATIVES_CONSIDERED:
  - alt A
  - alt B

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
"""


# ---------- Tests ----------

def test_good_packet_passes() -> None:
    v = validate_packet(GOOD_PACKET)
    assert v.ok, f"expected ok=True, got errors={v.errors}, warnings={v.warnings}"
    assert not v.errors
    # USER_INTENTION is good (has Want + Mechanism) and OMISSIONS is present
    # so no warnings
    assert not v.warnings


def test_no_fence_fails() -> None:
    v = validate_packet(NO_FENCE)
    assert not v.ok
    assert "no_packet_fence" in v.errors


def test_empty_body_fails() -> None:
    v = validate_packet(EMPTY_BODY)
    # every section is present but empty → per-section validators fire
    assert not v.ok
    # many errors expected
    assert len(v.errors) >= 5


def test_sole_viable_marker_accepted() -> None:
    v = validate_packet(BAD_NO_FENCE_YET_ALSO_FINE_FALLBACK)
    assert v.ok, f"errors={v.errors} warnings={v.warnings}"
    # sole_viable generates one warning (reviewer should challenge)
    assert any("sole_viable" in w for w in v.warnings)


def test_missing_user_intention_warns_not_errors() -> None:
    v = validate_packet(MISSING_USER_INTENTION)
    # no error (it's a soft warning)
    assert v.ok
    assert any("USER_INTENTION" in w for w in v.warnings)


def test_missing_omissions_warns() -> None:
    v = validate_packet(MISSING_OMISSIONS)
    assert v.ok
    assert any("OMISSIONS" in w for w in v.warnings)


def test_known_weaknesses_too_few_errors() -> None:
    v = validate_packet(KWN_TOO_FEW)
    assert not v.ok
    assert any("KNOWN_WEAKNESSES" in e for e in v.errors)


def test_alternatives_too_few_errors() -> None:
    v = validate_packet(ALT_TOO_FEW)
    assert not v.ok
    assert any("ALTERNATIVES_CONSIDERED" in e for e in v.errors)


def test_bad_constraint_warns_not_errors() -> None:
    v = validate_packet(BAD_CONSTRAINTS)
    assert v.ok  # warn-only
    assert any("CONSTRAINTS" in w for w in v.warnings)


def test_extract_packet_returns_dict() -> None:
    sections = extract_packet(GOOD_PACKET)
    assert sections is not None
    assert "ARTIFACT" in sections
    assert sections["ARTIFACT"] == "src/capture.rs"
    assert "UNKNOWN" not in sections


def test_packet_required_sections_match() -> None:
    # sanity: locked set
    expected = (
        "ARTIFACT", "SUCCESS_CRITERIA", "NON_GOALS", "CONSTRAINTS",
        "ALTERNATIVES_CONSIDERED", "KNOWN_WEAKNESSES", "USER_INTENTION", "OMISSIONS",
    )
    assert PACKET_REQUIRED_SECTIONS == expected


def test_render_skeleton_includes_all_sections() -> None:
    text = render_packet_skeleton("plan")
    for section in PACKET_REQUIRED_SECTIONS:
        assert section in text, f"section {section} missing from skeleton"


def test_strict_mode_raises_on_errors() -> None:
    # packet.py's main() with --strict raises PacketValidationError when
    # errors exist. Smoke that path via direct invocation.
    import io
    import contextlib
    v = validate_packet(EMPTY_BODY)
    assert not v.ok
    # The CLI converts non-ok into a raise under --strict; confirm by calling main()
    from review.packet import main
    # Write EMPTY_BODY to a temp file and invoke main(['--strict', path])
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(EMPTY_BODY)
        tmp = f.name
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                raised = False
                try:
                    main(["--strict", tmp])
                except PacketValidationError:
                    raised = True
                assert raised, "--strict did not raise on empty body"
    finally:
        Path(tmp).unlink(missing_ok=True)


# ---------- Runner ----------

if __name__ == "__main__":
    tests = [
        test_good_packet_passes,
        test_no_fence_fails,
        test_empty_body_fails,
        test_sole_viable_marker_accepted,
        test_missing_user_intention_warns_not_errors,
        test_missing_omissions_warns,
        test_known_weaknesses_too_few_errors,
        test_alternatives_too_few_errors,
        test_bad_constraint_warns_not_errors,
        test_extract_packet_returns_dict,
        test_packet_required_sections_match,
        test_render_skeleton_includes_all_sections,
        test_strict_mode_raises_on_errors,
    ]
    failures: list[str] = []
    for t in tests:
        try:
            t()
        except Exception as e:
            failures.append(f"{t.__name__}: {e}")
    if failures:
        print(f"FAIL ({len(failures)}/{len(tests)}):")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)
    else:
        print(f"PASS {len(tests)}/{len(tests)}")
