import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from config import load_models_config, ConfigError


def _write(tmp_path, config: dict) -> Path:
    p = tmp_path / "models.yaml"
    p.write_text(yaml.safe_dump(config), encoding="utf-8")
    return p


def _minimal() -> dict:
    return {
        "providers": {"groq": {"type": "openai_compat"}},
        "skills": {
            "jury-x": {
                "jurors": [
                    {"id": "a", "provider": "groq", "model": "m1"},
                    {"id": "b", "provider": "groq", "model": "m2"},
                ]
            }
        },
    }


def test_live_config_validates():
    # Regression anchor: the shipped models.yaml must always pass.
    cfg = load_models_config()
    assert "providers" in cfg and "skills" in cfg


def test_minimal_ok(tmp_path):
    cfg = load_models_config(_write(tmp_path, _minimal()))
    assert cfg["skills"]["jury-x"]["jurors"][0]["id"] == "a"


def test_seat_missing_provider(tmp_path):
    c = _minimal()
    del c["skills"]["jury-x"]["jurors"][0]["provider"]
    with pytest.raises(ConfigError) as e:
        load_models_config(_write(tmp_path, c))
    assert "provider" in str(e.value)


def test_unknown_juror_key_rejected(tmp_path):
    c = _minimal()
    c["skills"]["jury-x"]["jurors"][0]["povider"] = "typo"
    with pytest.raises(ConfigError):
        load_models_config(_write(tmp_path, c))


def test_duplicate_juror_id(tmp_path):
    c = _minimal()
    c["skills"]["jury-x"]["jurors"][1]["id"] = "a"
    with pytest.raises(ConfigError) as e:
        load_models_config(_write(tmp_path, c))
    assert "duplicate" in str(e.value)


def test_fallback_missing_model(tmp_path):
    c = _minimal()
    c["skills"]["jury-x"]["jurors"][0]["fallbacks"] = [{"provider": "groq"}]
    with pytest.raises(ConfigError):
        load_models_config(_write(tmp_path, c))


def test_provider_missing_type(tmp_path):
    c = _minimal()
    del c["providers"]["groq"]["type"]
    with pytest.raises(ConfigError):
        load_models_config(_write(tmp_path, c))
