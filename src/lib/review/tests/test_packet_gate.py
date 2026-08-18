"""Regression tests for the legacy/no-fence vs invalid-packet distinction.

The original 4e39225 wiring raised PacketValidationError on `no_packet_fence`
too, which crashed every fence-less legacy invocation (jury.py --input,
auto-jury without context.packet) while its own comment promised a soft
marker. These tests pin the contract:

  - no fence          -> legacy marked path, never a hard failure
  - fence but invalid -> hard failure material (engine raises when enforcing)
  - fence and valid   -> ok
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packet import (  # noqa: E402
    NO_PACKET_FENCE,
    is_legacy_no_packet,
    validate_packet,
)

VALID_PACKET = """```packet
ARTIFACT: the plan text
SUCCESS_CRITERIA:
  - pill idle CPU under 1%
NON_GOALS:
  - no visual redesign
CONSTRAINTS:
  - file:sampleapp/src/pill.rs:10 — current implementation
ALTERNATIVES_CONSIDERED:
  - native Win32 layered window
  - keep WebView, strip animations
KNOWN_WEAKNESSES:
  - Win32 path untested on ARM
  - larger maintenance surface
  - per-monitor DPI handling unknown
USER_INTENTION: user wants a lighter pill; Win32 is one mechanism, not the goal
OMISSIONS: nothing
```"""


def test_no_fence_is_legacy_marker_not_failure_material():
    validation = validate_packet("just some raw review input, no fence")
    assert validation.errors == [NO_PACKET_FENCE]
    assert is_legacy_no_packet(validation) is True


def test_invalid_packet_is_failure_material_not_legacy():
    text = "```packet\nARTIFACT: x\n```"  # missing required sections
    validation = validate_packet(text)
    assert validation.errors and NO_PACKET_FENCE not in validation.errors
    assert is_legacy_no_packet(validation) is False


def test_valid_packet_is_neither():
    validation = validate_packet(VALID_PACKET)
    assert validation.ok, validation.errors
    assert is_legacy_no_packet(validation) is False
