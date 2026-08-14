#!/usr/bin/env python3
"""Focused checks for Covenant packet validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-external-review-packet.py"
TEMPLATE = HERE.parents[0] / "assets" / "external-review-packet-template.md"


def load_validator():
    spec = importlib.util.spec_from_file_location("covenant_packet_validator", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    validator = load_validator()
    canonical = TEMPLATE.read_text(encoding="utf-8")
    assert validator.validate(canonical, TEMPLATE, False, True) == []
    errors = validator.validate(canonical.replace(validator.CANONICAL, "RUN_COVENANT", 1), TEMPLATE, False, True)
    assert any("Mode must be" in error for error in errors)
    print("PASS: canonical marker & no-run rejection (2/2)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
