"""Provider scheduling must serialize only providers that require it."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import _execution_units  # noqa: E402


def test_parallel_safe_seats_split_while_unsafe_seats_batch():
    jurors = [
        {"id": "g1", "provider": "groq"},
        {"id": "g2", "provider": "groq"},
        {"id": "n1", "provider": "nim"},
        {"id": "n2", "provider": "nim"},
    ]
    providers = {
        "groq": {"parallel_safe": True},
        "nim": {"parallel_safe": False},
    }

    units = _execution_units(jurors, providers)
    ids = [[seat["id"] for seat in unit] for unit in units]

    assert ["g1"] in ids
    assert ["g2"] in ids
    assert ["n1", "n2"] in ids
