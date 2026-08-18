"""Per-model transport settings override provider defaults."""
from __future__ import annotations

import json

from providers.openai_compat import OpenAICompatProvider


class _Response:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_per_model_stream_override():
    provider = OpenAICompatProvider(
        "nim",
        {
            "base_url": "https://example.invalid/v1",
            "keys": ["TEST_KEY"],
            "stream": True,
            "model_stream": {
                "deepseek-ai/deepseek-v4-flash": False,
                "z-ai/glm-5.2": True,
            },
        },
    )

    assert provider._stream_for("deepseek-ai/deepseek-v4-flash") is False
    assert provider._stream_for("z-ai/glm-5.2") is True
    assert provider._stream_for("other") is True


def test_call_with_metadata_preserves_nonstream_usage(monkeypatch):
    monkeypatch.setenv("OPENAI_COMPAT_TEST_KEY", "test-only")

    def fake_urlopen(request, timeout):
        return _Response({
            "model": "test-model-revision",
            "choices": [{
                "message": {"content": "{\"verdict\":\"SHIP\"}"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "total_tokens": 18,
            },
        })

    monkeypatch.setattr(
        "providers.openai_compat.urllib.request.urlopen", fake_urlopen,
    )
    provider = OpenAICompatProvider(
        "test",
        {
            "base_url": "https://example.invalid/v1",
            "keys": ["OPENAI_COMPAT_TEST_KEY"],
        },
    )

    response = provider.call_with_metadata("test-model", "system", "user")

    assert response == {
        "text": '{"verdict":"SHIP"}',
        "model": "test-model-revision",
        "finish_reason": "stop",
        "usage": {
            "prompt_tokens": 11,
            "completion_tokens": 7,
            "total_tokens": 18,
        },
    }
    assert provider.call("test-model", "system", "user") == '{"verdict":"SHIP"}'
