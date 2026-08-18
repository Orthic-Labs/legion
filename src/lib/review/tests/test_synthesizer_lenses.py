"""Lens headline answers must be visible once, without duplicate sections."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from synthesizer import render  # noqa: E402


def test_lens_headline_is_rendered_exactly_once():
    unique = "UNIQUE_COUNTEREXAMPLE_7429"
    result = {
        "skill": "jury-plan",
        "flags": {},
        "packet_validation": {"ok": True, "errors": [], "warnings": []},
        "jurors": [{
            "juror_id": "red",
            "provider": "nim",
            "model": "example/model",
            "lens": "red_team",
            "verdict": "NEEDS-REVISION",
            "score": 5,
            "parsed_ok": True,
            "answers": {"strongest_known_counterexample": unique},
            "blockers": [],
        }],
        "escalation": [],
        "synthesis": {
            "majority_verdict": "NEEDS-REVISION",
            "majority_count": "1/1",
            "avg_score": 5,
            "split": False,
            "any_degraded": False,
            "any_error": False,
        },
    }

    assert render(result).count(unique) == 1
