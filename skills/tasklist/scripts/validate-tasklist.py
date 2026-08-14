#!/usr/bin/env python3
"""Compatibility entrypoint delegating both Tasklist packet generations."""
from pathlib import Path
import runpy
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
LEGACY_FLAGS = {"--template-self-check", "--write-receipt", "--verify-receipt"}
packet = next((arg for arg in sys.argv[1:] if not arg.startswith("-")), "")
legacy = bool(LEGACY_FLAGS.intersection(sys.argv[1:])) or packet.lower().endswith(".md")
engine = "lib/tasklist-validator/validate-tasklist.py" if legacy else "lib/dispatch-validator/validate-tasklist.py"
runpy.run_path(str(PACKAGE_ROOT / engine), run_name="__main__")
