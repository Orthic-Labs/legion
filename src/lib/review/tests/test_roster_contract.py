"""Current live roster and one-skill exposure contract."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from health_check import enumerate_models


ROOT = Path(__file__).resolve().parents[3]
MODELS = ROOT / "tools" / "review" / "models.yaml"


def _models(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "model" and isinstance(child, str):
                yield child
            yield from _models(child)
    elif isinstance(value, list):
        for child in value:
            yield from _models(child)


def test_roster_has_current_models_and_no_retired_seats():
    config = yaml.safe_load(MODELS.read_text(encoding="utf-8"))
    models = set(_models(config))

    assert {
        "deepseek-ai/deepseek-v4-flash",
        "qwen/qwen3.6-27b",
        "zai-glm-4.7",
        "MiniMax-M2.7",
        "MiniMax-M3",
    } <= models
    assert models.isdisjoint({
        "moonshotai/kimi-k2.6",
        "deepseek-ai/deepseek-v4-pro",
        "meta-llama/llama-4-scout-17b-16e-instruct",
        "llama-3.3-70b-versatile",
        "qwen/qwen3-32b",
    })
    assert len(config["panels"]["advisory"]["jurors"]) == 3


def test_only_council_skill_is_exposed():
    assert (ROOT / "tools" / "skills" / "council" / "SKILL.md").is_file()
    assert not (ROOT / "tools" / "skills" / "jury" / "SKILL.md").exists()


def test_health_check_includes_advisory_panel_primaries():
    config = yaml.safe_load(MODELS.read_text(encoding="utf-8"))
    usage = enumerate_models(config)
    assert usage[("nim", "mistralai/mistral-small-4-119b-2603")]["primary_seats"]
    assert any(
        seat.startswith("panel:advisory:")
        for seat in usage[("nim", "mistralai/mistral-small-4-119b-2603")]["primary_seats"]
    )
