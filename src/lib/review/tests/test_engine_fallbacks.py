"""Malformed primary output must fall through to the configured backup."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import Engine, _accounting  # noqa: E402
from providers.base import JurorResult  # noqa: E402


class _Cache:
    def make_key(self, **kwargs):
        return json.dumps(kwargs, sort_keys=True)

    def get(self, key):
        return None

    def set(self, key, value):
        pass

    def set_error(self, key, value):
        pass


class _Provider:
    def __init__(self, response: str):
        self.response = response

    def call(self, *args, **kwargs):
        return self.response


class _MetadataProvider(_Provider):
    def __init__(self, response: str, usage: dict):
        super().__init__(response)
        self.usage = usage

    def call_with_metadata(self, *args, **kwargs):
        return {
            "text": self.response,
            "model": "reported-model",
            "finish_reason": "stop",
            "usage": self.usage,
        }


def test_parse_failure_uses_fallback():
    engine = object.__new__(Engine)
    engine.config = {
        "providers": {
            "bad": {"max_output_tokens": 2048},
            "good": {"max_output_tokens": 2048},
        }
    }
    engine.providers = {
        "bad": _Provider('{"verdict":"SHIP"'),
        "good": _Provider(
            '{"verdict":"SHIP","score":9,"top_concern":"none",'
            '"scores":{},"answers":{},"blockers":[]}'
        ),
    }
    engine.cache = _Cache()
    engine.prompt_version = 1
    engine.lenses = {}

    result = engine._run_juror(
        {
            "id": "seat",
            "provider": "bad",
            "model": "bad-model",
            "fallbacks": [{"provider": "good", "model": "good-model"}],
        },
        "system",
        "user",
        no_cache=True,
    )

    assert result.parsed_ok is True
    assert result.provider == "good"
    assert result.fallback_used is True
    assert result.call_count == 2
    assert result.usage_complete is False


def test_provider_usage_and_fallback_calls_are_preserved():
    engine = object.__new__(Engine)
    engine.config = {
        "providers": {
            "bad": {"max_output_tokens": 2048},
            "good": {"max_output_tokens": 2048},
        }
    }
    engine.providers = {
        "bad": _MetadataProvider('{"verdict":"SHIP"', {
            "prompt_tokens": 5,
            "completion_tokens": 2,
            "total_tokens": 7,
        }),
        "good": _MetadataProvider(
            '{"verdict":"SHIP","score":9,"top_concern":"none",'
            '"scores":{},"answers":{},"blockers":[]}',
            {"input_tokens": 8, "output_tokens": 3},
        ),
    }
    engine.cache = _Cache()
    engine.prompt_version = 1
    engine.lenses = {}

    result = engine._run_juror(
        {
            "id": "seat",
            "provider": "bad",
            "model": "bad-model",
            "fallbacks": [{"provider": "good", "model": "good-model"}],
        },
        "system",
        "user",
        no_cache=True,
    )

    assert result.call_count == 2
    assert result.usage_complete is True
    assert result.usage == {
        "input_tokens": 13,
        "output_tokens": 5,
        "total_tokens": 18,
    }


def test_panel_accounting_sums_calls_tokens_and_completeness():
    summary = _accounting([
        JurorResult(
            juror_id="a", provider="p", model="m", call_count=2,
            usage={"input_tokens": 13, "output_tokens": 5, "total_tokens": 18},
        ),
        JurorResult(
            juror_id="b", provider="p", model="m", call_count=1,
            usage={}, usage_complete=False,
        ),
        JurorResult(
            juror_id="c", provider="p", model="m", cache_hit=True,
        ),
    ])

    assert summary == {
        "calls": 3,
        "usage": {"input_tokens": 13, "output_tokens": 5, "total_tokens": 18},
        "usage_complete": False,
        "cache_hits": 1,
    }
