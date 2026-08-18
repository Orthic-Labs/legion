#!/usr/bin/env python3
"""Command-backed provider for browser and legal-authority integrations."""
from __future__ import annotations

import os
import shlex

from base import LocatedPassage, OpenedSource, SearchHit, command_json, data_only_envelope, publisher_from_url, seed_id, stable_hit_id, today


class CommandBridgeProvider:
    external_ops: frozenset[str] = frozenset({'search', 'open', 'find'})
    def __init__(self, name: str, env_var: str):
        self.name = name
        raw = os.environ.get(env_var, '').strip()
        if not raw:
            raise RuntimeError(f'{env_var} is not configured')
        self.command = shlex.split(raw)

    def search(self, query: str, *, limit: int = 10, seed_chain: list[str] | None = None) -> list[SearchHit]:
        seed = seed_id(query)
        chain = tuple(seed_chain or ()) + (seed,)
        data = command_json(self.command, {'op': 'search', 'query': query, 'limit': limit})
        hits = []
        for row in data.get('results', [])[:limit]:
            url = str(row['url'])
            hits.append(SearchHit(id=stable_hit_id(self.name, url), url=url, title=str(row.get('title') or url), publisher=str(row.get('publisher') or publisher_from_url(url)), snippet=str(row.get('snippet') or ''), suggested_by=seed, seed_chain=chain, provider=self.name, metadata=dict(row.get('metadata') or {})))
        return hits

    def open(self, url: str) -> OpenedSource:
        data = command_json(self.command, {'op': 'open', 'url': url})
        body = str(data.get('content') or data.get('body') or '')
        if not body:
            raise RuntimeError('provider open returned an empty body')
        envelope, digest = data_only_envelope(body, source_url=url)
        return OpenedSource(url=url, title=str(data.get('title') or url), publisher=str(data.get('publisher') or publisher_from_url(url)), retrieved_at=str(data.get('retrieved_at') or today()), content=envelope, content_sha256=digest, instruction_policy='data_only', provider=self.name, metadata=dict(data.get('metadata') or {}))

    def find(self, opened: OpenedSource, pattern: str) -> LocatedPassage | None:
        data = command_json(self.command, {'op': 'find', 'url': opened.url, 'pattern': pattern})
        if data.get('found') is False:
            return None
        text = str(data.get('text') or data.get('quote_or_paraphrase') or '')
        if not text:
            return None
        return LocatedPassage(url=opened.url, locator=str(data.get('locator') or 'provider-locator'), text=text, is_paraphrase=bool(data.get('is_paraphrase', False)), provider=self.name, metadata=dict(data.get('metadata') or {}))
