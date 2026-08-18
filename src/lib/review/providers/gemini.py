"""Google Gemini API provider (REST, free tier)."""
from __future__ import annotations
import json
import os
import urllib.request
import urllib.error

from .base import ProviderError


class GeminiAPIProvider:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.base_url = config["base_url"].rstrip("/")
        self.key_env_names: list = config.get("keys", ["GEMINI_API_KEY"])
        self.timeout_s = int(config.get("timeout_s", 30))

    def _resolve_key(self) -> str:
        for env_name in self.key_env_names:
            val = os.environ.get(env_name)
            if val:
                return val
        raise ProviderError(f"{self.name}: no key in env {self.key_env_names}")

    def call(self, model: str, system: str, user: str, max_tokens: int = 2048, images: list | None = None) -> str:
        key = self._resolve_key()
        # Build content parts. Gemini accepts inline_data parts for images.
        parts: list[dict] = [{"text": user}]
        for img in (images or []):
            parts.append({
                "inline_data": {
                    "mime_type": img.get("mime", "image/png"),
                    "data":       img["b64"],
                },
            })
        # Gemini puts system instruction in a separate field
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": parts}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.2,
            },
        }
        url = f"{self.base_url}/models/{model}:generateContent?key={key}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "jury/0.1 (https://github.com/operator)",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # extract text
                cands = data.get("candidates", [])
                if not cands:
                    raise ProviderError(f"gemini/{model}: empty candidates")
                parts = cands[0].get("content", {}).get("parts", [])
                texts = [p.get("text", "") for p in parts if "text" in p]
                return "".join(texts)
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:200]
            except Exception:
                pass
            is_quota = e.code in (429, 503)
            raise ProviderError(
                f"gemini/{model} HTTP {e.code}: {body_text}",
                status=e.code, is_quota=is_quota,
            )
        except urllib.error.URLError as e:
            raise ProviderError(f"gemini/{model} URL error: {e}", is_quota=True)
