#!/usr/bin/env python3
"""Compatibility entrypoint for canonical dispatch validator."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
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

_SPEC = spec_from_file_location(
    "legion_dispatch_validator", _engine("validate-dispatch.py", "src/lib/dispatch-validator/validate-dispatch.py")
)
assert _SPEC and _SPEC.loader
_ENGINE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _ENGINE
_SPEC.loader.exec_module(_ENGINE)


def __getattr__(name: str):
    return getattr(_ENGINE, name)


if __name__ == "__main__":
    raise SystemExit(_ENGINE.main())
