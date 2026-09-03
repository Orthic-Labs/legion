#!/usr/bin/env python3
"""Compatibility entrypoint delegating Coder jobs to shared Pi worker engine."""
from pathlib import Path
import runpy
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]

_BUNDLE = Path(__file__).resolve().parents[1] / "engine"


def _engine(bundled: str, repository: str) -> Path:
    """Prefer the engine shipped inside this bundle.

    An installed plugin root contains the skill and nothing above it, so the
    repository path exists only during development. Resolving the bundled copy
    first is what lets this wrapper run from an installed product at all.
    """
    candidate = _BUNDLE / bundled
    return candidate if candidate.is_file() else PACKAGE_ROOT / repository

sys.path.insert(0, str(PACKAGE_ROOT / "src" / "lib"))
runpy.run_path(str(_engine("api-worker.py", "src/lib/coder-api-worker/api-worker.py")), run_name="__main__")
