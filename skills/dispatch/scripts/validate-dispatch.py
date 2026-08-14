#!/usr/bin/env python3
"""Compatibility entrypoint for canonical dispatch validator."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[5]
runpy.run_path(str(ROOT / "lib" / "dispatch-validator" / "validate-dispatch.py"), run_name="__main__")
