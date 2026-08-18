"""MiniMax Anthropic-compatible provider.

Used for MiniMax-M3 direct calls through api.minimax.io/anthropic rather than
the NIM-hosted OpenAI-compatible route.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

from .base import ProviderError


def _env_value(name: str) -> str | None:
    value = os.environ.get(name)
    if value:
        return value

    # Long-running Windows agent sessions may not inherit a newly-added User env
    # var. Read the User environment registry as a fallback without printing it.
    if sys.platform.startswith("win"):
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value, _ = winreg.QueryValueEx(key, name)
                if value:
                    return str(value)
        except Exception:
            pass
    return None


class MiniMaxAnthropicProvider:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.base_url = config.get("base_url", "https://api.minimax.io/anthropic/v1").rstrip("/")
        self.key_env_names: list[str] = config.get("keys", ["MINIMAX_API_KEY"])
        timeout_s = int(config.get("timeout_s", 180))
        self.timeout_s: int | None = None if timeout_s <= 0 else timeout_s
        self.min_gap_ms = int(config.get("min_gap_ms", 0))
        self.retry_codes_as_quota = set(config.get("retry_codes_as_quota", [429, 503, 504]))
        self.model_extra_body = config.get("model_extra_body") or {}
        self._last_call = 0.0

    def _key(self) -> str:
        for env_name in self.key_env_names:
            value = _env_value(env_name)
            if value:
                return value
        raise ProviderError(f"{self.name}: no API keys set")

    @staticmethod
    def _content_from_response(data: dict) -> str:
        parts: list[str] = []
        for block in data.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if text:
                    parts.append(text)
        return "".join(parts)

    def call(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        images: list | None = None,
        temperature: float = 0.2,
    ) -> str:
        return self.call_with_metadata(
            model,
            system,
            user,
            max_tokens=max_tokens,
            images=images,
            temperature=temperature,
        )["text"]

    def call_with_metadata(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        images: list | None = None,
        temperature: float = 0.2,
    ) -> dict:
        """Return text plus stop/usage metadata without changing ``call``."""
        if self.min_gap_ms > 0:
            wait = (self._last_call + self.min_gap_ms / 1000.0) - time.time()
            if wait > 0:
                time.sleep(wait)

        content: list[dict] = []
        for img in images or []:
            content.append({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": img.get("mime", "image/png"),
                    "data": img["b64"],
                },
            })
        content.append({"type": "text", "text": user})

        payload = {
            "model": model,
            "system": system,
            "messages": [{"role": "user", "content": content}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        payload.update(self.model_extra_body.get(model, {}))

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/messages",
            data=body,
            headers={
                "x-api-key": self._key(),
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "jury/0.1 (https://github.com/operator)",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                self._last_call = time.time()
                data = json.loads(resp.read().decode("utf-8"))
                content_text = self._content_from_response(data)
                if not content_text.strip():
                    stop_reason = data.get("stop_reason", "unknown")
                    raise ProviderError(f"{self.name}/{model} empty content (stop_reason={stop_reason})")
                return {
                    "text": content_text,
                    "model": data.get("model") or model,
                    "stop_reason": data.get("stop_reason"),
                    "stop_sequence": data.get("stop_sequence"),
                    "usage": data.get("usage") or {},
                }
        except urllib.error.HTTPError as e:
            self._last_call = time.time()
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:300]
            except Exception:
                pass
            raise ProviderError(
                f"{self.name}/{model} HTTP {e.code}: {body_text}",
                status=e.code,
                is_quota=e.code in self.retry_codes_as_quota,
            )
        except urllib.error.URLError as e:
            self._last_call = time.time()
            raise ProviderError(f"{self.name}/{model} URL error: {e}", is_quota=True)
        except (TimeoutError, socket.timeout) as e:
            self._last_call = time.time()
            raise ProviderError(f"{self.name}/{model} timeout: {e}", is_quota=True)
        except Exception as e:
            self._last_call = time.time()
            raise ProviderError(f"{self.name}/{model} error: {e}")
