#!/usr/bin/env python3
"""Compatibility entrypoint delegating Coder jobs to shared API worker engine."""
from pathlib import Path
import runpy

WORKSPACE = Path(__file__).resolve().parents[6]
runpy.run_path(str(WORKSPACE / "tools/lib/coder-api-worker/api-worker.py"), run_name="__main__")
