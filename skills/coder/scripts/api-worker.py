#!/usr/bin/env python3
"""Compatibility entrypoint delegating Coder jobs to shared Pi worker engine."""
from pathlib import Path
import runpy
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PACKAGE_ROOT / "src" / "lib"))
runpy.run_path(str(PACKAGE_ROOT / "src/lib/coder-api-worker/api-worker.py"), run_name="__main__")
