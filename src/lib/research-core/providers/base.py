#!/usr/bin/env python3
"""Provider contracts and common source-envelope rules."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

WORKSPACE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WORKSPACE / 'tools' / 'lib'))
from membrane_data import fence as membrane_fence  # noqa: E402


@dataclass(frozen=True)
class SearchHit:
    id: str
    url: str
    title: str
    publisher: str
    snippet: str
    suggested_by: str
    seed_chain: tuple[str, ...]
    provider: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['seed_chain'] = list(self.seed_chain)
        data['evidence_status'] = 'lead'
        return data


@dataclass(frozen=True)
class OpenedSource:
    url: str
    title: str
    publisher: str
    retrieved_at: str
    content: str
    content_sha256: str
    instruction_policy: str
    provider: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['instructionPolicy'] = data.pop('instruction_policy')
        return data


@dataclass(frozen=True)
class LocatedPassage:
    url: str
    locator: str
    text: str
    is_paraphrase: bool
    provider: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Provider(Protocol):
    name: str
    def search(self, query: str, *, limit: int, seed_chain: list[str]) -> list[SearchHit]: ...
    def open(self, url: str) -> OpenedSource: ...
    def find(self, opened: OpenedSource, pattern: str) -> LocatedPassage | None: ...


def publisher_from_url(url: str) -> str:
    host = urlparse(url).netloc.lower().split('@')[-1].split(':')[0]
    return host.removeprefix('www.') or 'local-corpus'


def seed_id(query: str) -> str:
    return 'seed:query:' + hashlib.sha256(query.encode('utf-8')).hexdigest()[:16]


def stable_hit_id(provider: str, url: str) -> str:
    return f"hit:{provider}:" + hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]


def data_only_envelope(body: str, *, source_url: str) -> tuple[str, str]:
    return membrane_fence(body, source=source_url)


def locate_text(body: str, pattern: str, *, context_chars: int = 300) -> tuple[str, str] | None:
    if not pattern.strip():
        return None
    match = re.search(re.escape(pattern.strip()), body, re.I)
    if not match:
        tokens = [re.escape(t) for t in re.findall(r'[A-Za-z0-9][A-Za-z0-9._%-]{2,}', pattern)[:8]]
        if not tokens:
            return None
        match = re.search(r'.{0,80}'.join(tokens), body, re.I | re.S)
        if not match:
            return None
    start = max(0, match.start() - context_chars)
    end = min(len(body), match.end() + context_chars)
    return f'chars:{start}-{end}', body[start:end].strip()


def command_json(command: list[str], payload: dict[str, Any], *, timeout_s: int = 90) -> dict[str, Any]:
    proc = subprocess.run(command, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout_s, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"provider command failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError('provider command did not return JSON') from exc
    if not isinstance(value, dict):
        raise RuntimeError('provider command returned non-object JSON')
    return value


def today() -> str:
    return dt.date.today().isoformat()
