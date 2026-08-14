#!/usr/bin/env python3
"""Compatibility entrypoint for canonical dispatch validator."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_SPEC = spec_from_file_location(
    "legion_dispatch_validator", PACKAGE_ROOT / "lib/dispatch-validator/validate-dispatch.py"
)
assert _SPEC and _SPEC.loader
_ENGINE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _ENGINE
_SPEC.loader.exec_module(_ENGINE)


def __getattr__(name: str):
    return getattr(_ENGINE, name)


if __name__ == "__main__":
    raise SystemExit(_ENGINE.main())
