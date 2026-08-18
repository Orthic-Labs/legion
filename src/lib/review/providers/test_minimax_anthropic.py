"""MiniMax Anthropic provider metadata contract tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

JURY_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(JURY_DIR))

from providers.minimax_anthropic import MiniMaxAnthropicProvider


class _Response:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_call_with_metadata_preserves_stop_reason_and_usage(monkeypatch):
    monkeypatch.setenv("MINIMAX_TEST_KEY", "test-only")
    seen = {}

    def fake_urlopen(request, timeout):
        seen.update(json.loads(request.data.decode("utf-8")))
        return _Response({
            "model": "MiniMax-M3",
            "content": [{"type": "text", "text": "[]"}],
            "stop_reason": "max_tokens",
            "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 34},
        })

    monkeypatch.setattr(
        "providers.minimax_anthropic.urllib.request.urlopen", fake_urlopen,
    )
    provider = MiniMaxAnthropicProvider(
        "test",
        {"keys": ["MINIMAX_TEST_KEY"], "base_url": "https://example.invalid"},
    )

    response = provider.call_with_metadata(
        "MiniMax-M3", "system", "user", max_tokens=64, temperature=0.0
    )

    assert response == {
        "text": "[]",
        "model": "MiniMax-M3",
        "stop_reason": "max_tokens",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 34},
    }
    assert seen["temperature"] == 0.0
    assert provider.call("MiniMax-M3", "system", "user", max_tokens=64) == "[]"
