#!/usr/bin/env python3
"""Compatibility entrypoint delegating both Tasklist packet generations."""
from pathlib import Path
import runpy
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
BUNDLE = Path(__file__).resolve().parents[1] / "engine"
LEGACY_FLAGS = {"--template-self-check", "--write-receipt", "--verify-receipt"}
packet = next((arg for arg in sys.argv[1:] if not arg.startswith("-")), "")
legacy = bool(LEGACY_FLAGS.intersection(sys.argv[1:])) or packet.lower().endswith(".md")


def engine(bundled: str, repository: str) -> Path:
    """Prefer the engine shipped inside this bundle.

    An installed plugin root contains the skill and nothing above it, so the
    repository path exists only during development. Resolving the bundled copy
    first is what lets these wrappers run from an installed product at all.
    """
    candidate = BUNDLE / bundled
    return candidate if candidate.is_file() else PACKAGE_ROOT / repository


target = (
    engine("validate-tasklist-legacy.py", "src/lib/tasklist-validator/validate-tasklist.py")
    if legacy
    else engine("validate-tasklist.py", "src/lib/dispatch-validator/validate-tasklist.py")
)
runpy.run_path(str(target), run_name="__main__")
