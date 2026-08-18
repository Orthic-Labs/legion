"""Single loader for models.yaml — schema-validated at load time.

Both Engine and health_check.py load through here so a malformed seat config
fails fast (naming the offending path) instead of collapsing to fallbacks or
crashing at call time.
"""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "models.schema.json"


class ConfigError(ValueError):
    """models.yaml failed schema or consistency validation."""


def _collect_lineups(config: dict):
    """Yield (label, jurors_list) for every seat lineup in the config.

    Anchors (_*_jurors) are expanded by yaml.safe_load, so a shared lineup is a
    distinct list object per referencing site — we key uniqueness per lineup,
    which is what the runtime actually dispatches.
    """
    for panel_name, panel in (config.get("panels") or {}).items():
        yield f"panels.{panel_name}", panel.get("jurors") or []
    for skill_name, skill in (config.get("skills") or {}).items():
        yield f"skills.{skill_name}", skill.get("jurors") or []


def _check_unique_ids(config: dict) -> None:
    for label, jurors in _collect_lineups(config):
        seen = set()
        for j in jurors:
            jid = j.get("id")
            if jid in seen:
                raise ConfigError(f"{label}: duplicate juror id {jid!r} in one lineup")
            seen.add(jid)


def load_models_config(path: str | Path = None) -> dict:
    cfg_path = Path(path or ROOT / "models.yaml")
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ConfigError(f"{cfg_path}: top-level YAML is not a mapping")

    import json
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    error = jsonschema.exceptions.best_match(validator.iter_errors(config))
    if error is not None:
        loc = "/".join(str(p) for p in error.absolute_path) or "<root>"
        raise ConfigError(f"{cfg_path}: schema error at {loc}: {error.message}")

    _check_unique_ids(config)
    return config
