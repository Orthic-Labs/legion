"""Shared fixtures for review engine tests.

`tmp` existed only as an untracked conftest on the source machine when
4e39225 shipped — a clean checkout collected 6 fixture errors. Keep it a
thin alias of pytest's tmp_path so tests stay portable.
"""
from pathlib import Path

import pytest


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    return tmp_path
