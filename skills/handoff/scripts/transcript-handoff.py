#!/usr/bin/env python3
"""Packaged Handoff transcript compiler entrypoint."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE_LIB = PACKAGE_ROOT / "src" / "lib"
if str(_PACKAGE_LIB) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_LIB))
_SPEC = spec_from_file_location(
    "legion_transcript_handoff", _PACKAGE_LIB / "handoff/transcript_handoff.py"
)
assert _SPEC and _SPEC.loader
_ENGINE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _ENGINE
_SPEC.loader.exec_module(_ENGINE)


def __getattr__(name: str):
    return getattr(_ENGINE, name)


if __name__ == "__main__":
    raise SystemExit(_ENGINE.main())
