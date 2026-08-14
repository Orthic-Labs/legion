#!/usr/bin/env python3
"""Compatibility entrypoint delegating Tasklist validation to shared engine."""
from pathlib import Path
import runpy

WORKSPACE = Path(__file__).resolve().parents[6]
runpy.run_path(str(WORKSPACE / "tools/lib/dispatch-validator/validate-tasklist.py"), run_name="__main__")
