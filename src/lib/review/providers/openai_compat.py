"""OpenAI-compatible provider — used for NIM, Groq, Cerebras."""
from __future__ import annotations
import json
import os
import socket
import threading
import time
import urllib.request
import urllib.error
from contextlib import nullcontext

from .base import ProviderError

ROTATION_FAILOVER = "failover_only"
ROTATION_ROUND_ROBIN = "round_robin"


class OpenAICompatProvider:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.base_url = config["base_url"].rstrip("/")
        self.key_env_names: list = config.get("keys", [])
        self.timeout_s = int(config.get("timeout_s", 30))
        self.model_timeout_s = {
            model: int(timeout_s)
            for model, timeout_s in (config.get("model_timeout_s") or {}).items()
        }
        self.model_extra_body = config.get("model_extra_body") or {}
        self.model_stream = {
            model: bool(enabled)
            for model, enabled in (config.get("model_stream") or {}).items()
        }
        self.min_gap_ms = int(config.get("min_gap_ms", 0))
        self.retry_codes_as_quota = set(config.get("retry_codes_as_quota", [429]))
        self.flag_degraded = bool(config.get("flag_degraded", False))
        self.rotation = config.get("rotation", ROTATION_FAILOVER)
        # Stream responses (SSE). NIM reasoning models (deepseek-v4, etc.) HANG on
        # non-streaming buffered reads — they think server-side then dump, and a
        # non-stream urlopen times out waiting. Streaming reads tokens as they come.
        self.stream = bool(config.get("stream", False))
        self.parallel_safe = bool(config.get("parallel_safe", False))
        # per-key serialization lock + last-call timestamp
        self._key_locks = {k: threading.Lock() for k in self.key_env_names}
        self._key_last_call_ms = {k: 0.0 for k in self.key_env_names}
        # round-robin cursor (atomic increment, wraps mod key count)
        self._rr_index = 0
        self._rr_lock = threading.Lock()

    def _stream_for(self, model: str) -> bool:
        return self.model_stream.get(model, self.stream)

    def _all_keys(self) -> list[tuple[str, str]]:
        """Return [(env_name, value)] for all keys that are set."""
        out = []
        for env_name in self.key_env_names:
            val = os.environ.get(env_name)
            if val:
                out.append((env_name, val))
        return out

    def _ordered_keys(self) -> list[tuple[str, str]]:
        """
        Return keys in call order based on rotation strategy.
        - failover_only: always key1 first, key2 only on quota signal
        - round_robin:   rotate start position on every call, still fall through on quota
        """
        keys = self._all_keys()
        if not keys:
            return keys
        if self.rotation == ROTATION_ROUND_ROBIN and len(keys) > 1:
            with self._rr_lock:
                start = self._rr_index % len(keys)
                self._rr_index += 1
            # rotate the list so we start at 'start', wrap around
            return keys[start:] + keys[:start]
        return keys  # failover: always key1 first

    def call(self, model: str, system: str, user: str, max_tokens: int = 2048, images: list | None = None) -> str:
        return self.call_with_metadata(
            model, system, user, max_tokens=max_tokens, images=images,
        )["text"]

    def call_with_metadata(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        images: list | None = None,
    ) -> dict:
        """Return text plus provider-reported model, finish, and usage data."""
        keys = self._ordered_keys()
        if not keys:
            raise ProviderError(f"{self.name}: no API keys set")

        last_err = None
        for env_name, key in keys:
            try:
                return self._call_with_key(env_name, key, model, system, user, max_tokens, images or [])
            except ProviderError as e:
                last_err = e
                if e.is_quota:
                    continue   # try next key
                raise          # non-quota: fail fast
        raise last_err or ProviderError(f"{self.name}: all keys exhausted")

    @staticmethod
    def _read_stream(resp) -> dict:
        """Accumulate SSE text and terminal metadata without estimating usage."""
        parts = []
        usage: dict = {}
        response_model = None
        finish_reason = None
        for raw in resp:
            line = raw.decode("utf-8", "ignore").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
                if event.get("usage"):
                    usage = event["usage"]
                if event.get("model"):
                    response_model = event["model"]
                choices = event.get("choices") or []
                if not choices:
                    continue
                choice = choices[0]
                delta = choice.get("delta") or {}
                piece = delta.get("content")
                if piece:
                    parts.append(piece)
                if choice.get("finish_reason") is not None:
                    finish_reason = choice["finish_reason"]
            except Exception:
                continue
        return {
            "text": "".join(parts),
            "model": response_model,
            "finish_reason": finish_reason or "stream",
            "usage": usage,
        }

    def _call_with_key(self, env_name: str, key: str, model: str, system: str, user: str, max_tokens: int, images: list) -> dict:
        lock = nullcontext() if self.parallel_safe and self.min_gap_ms <= 0 else self._key_locks[env_name]
        with lock:
            if self.min_gap_ms > 0:
                last = self._key_last_call_ms[env_name]
                wait = (last + self.min_gap_ms / 1000.0) - time.time()
                if wait > 0:
                    time.sleep(wait)

            # Build user content. With images, switch to OpenAI multipart format.
            # IMAGE-FIRST: VLMs attend to images far better when they precede the
            # text. Appending the image after a long rubric starved attention —
            # models replied "no image" or over-passed. Image(s) first, text last.
            if images:
                content = []
                for img in images:
                    mime = img.get("mime", "image/png")
                    b64  = img["b64"]
                    content.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{b64}"},
                    })
                content.append({"type": "text", "text": user})
                user_message = {"role": "user", "content": content}
            else:
                user_message = {"role": "user", "content": user}

            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    user_message,
                ],
                "max_tokens": max_tokens,
                "temperature": 0.2,
            }
            payload.update(self.model_extra_body.get(model, {}))
            stream = self._stream_for(model)
            if stream:
                payload["stream"] = True
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=body,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                    "User-Agent": "jury/0.1 (https://github.com/operator)",
                    "Accept": "text/event-stream" if stream else "application/json",
                },
                method="POST",
            )
            timeout_s = self.timeout_s if images else self.model_timeout_s.get(model, self.timeout_s)
            try:
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    self._key_last_call_ms[env_name] = time.time()
                    if stream:
                        metadata = self._read_stream(resp)
                        content = metadata["text"]
                        finish_reason = metadata["finish_reason"]
                    else:
                        data = json.loads(resp.read().decode("utf-8"))
                        choice = data["choices"][0]
                        message = choice.get("message") or {}
                        content = message.get("content")
                        finish_reason = choice.get("finish_reason", "unknown")
                        metadata = {
                            "text": content,
                            "model": data.get("model") or model,
                            "finish_reason": finish_reason,
                            "usage": data.get("usage") or {},
                        }
                    if content is None or (isinstance(content, str) and not content.strip()):
                        raise ProviderError(
                            f"{self.name}/{model} empty content (finish_reason={finish_reason})"
                        )
                    metadata["text"] = content
                    metadata["model"] = metadata.get("model") or model
                    return metadata
            except urllib.error.HTTPError as e:
                self._key_last_call_ms[env_name] = time.time()
                is_quota = e.code in self.retry_codes_as_quota
                body_text = ""
                try:
                    body_text = e.read().decode("utf-8")[:200]
                except Exception:
                    pass
                raise ProviderError(
                    f"{self.name}/{model} HTTP {e.code}: {body_text}",
                    status=e.code, is_quota=is_quota,
                )
            except urllib.error.URLError as e:
                self._key_last_call_ms[env_name] = time.time()
                raise ProviderError(f"{self.name}/{model} URL error: {e}", is_quota=True)
            except (TimeoutError, socket.timeout) as e:
                self._key_last_call_ms[env_name] = time.time()
                raise ProviderError(f"{self.name}/{model} timeout: {e}", is_quota=True)
            except Exception as e:
                self._key_last_call_ms[env_name] = time.time()
                raise ProviderError(f"{self.name}/{model} error: {e}")
