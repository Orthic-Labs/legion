#!/usr/bin/env python3
"""CLI compatibility wrapper for :mod:`transcript_handoff`."""

from pathlib import Path
import sys

_PACKAGE_LIB = Path(__file__).resolve().parents[1]
if str(_PACKAGE_LIB) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_LIB))

from transcript_handoff import main


if __name__ == "__main__":
    raise SystemExit(main())
