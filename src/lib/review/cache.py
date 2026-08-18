"""Content-hash cache for juror responses.

Hash includes: rubric content + normalized input + model + provider + prompt_version.
Failed responses stored under .errors/ so retries don't poison the cache.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Optional


class Cache:
    def __init__(self, cache_dir: str | Path):
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.errors_dir = self.dir / ".errors"
        self.errors_dir.mkdir(exist_ok=True)

    @staticmethod
    def make_key(rubric: str, user_input: str, provider: str, model: str, prompt_version: int) -> str:
        h = hashlib.sha256()
        h.update(rubric.encode("utf-8"))
        h.update(b"\x00")
        h.update(user_input.strip().encode("utf-8"))
        h.update(b"\x00")
        h.update(provider.encode("utf-8"))
        h.update(b"\x00")
        h.update(model.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(prompt_version).encode("utf-8"))
        return h.hexdigest()[:32]

    def get(self, key: str) -> Optional[dict]:
        p = self.dir / f"{key}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None

    def set(self, key: str, value: dict) -> None:
        p = self.dir / f"{key}.json"
        p.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    def set_error(self, key: str, value: dict) -> None:
        p = self.errors_dir / f"{key}.json"
        p.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
