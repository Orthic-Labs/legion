"""Selftest entry point — run via `python3 -m orthic_transcripts.selftest`.

Re-exports the unittest TestCase from ``tests/test_orthic_transcripts.py``
and runs it under ``unittest.main``. The package directory layout is

    tools/lib/orthic_transcripts/
        __init__.py
        host_adapters.py
        driver.py
        selftest.py            <-- this file
        index.mjs
        tests/
            __init__.py
            test_orthic_transcripts.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Discover every test module under tests/ so adding new files picks them up.
_LOADER = unittest.TestLoader()
_SUITE = _LOADER.discover(start_dir=str(_HERE / "tests"), pattern="test_*.py")


def main() -> int:
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(_SUITE)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())