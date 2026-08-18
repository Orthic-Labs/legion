#!/usr/bin/env python3
"""Live scholarly provider using Crossref metadata and DOI landing pages."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from base import LocatedPassage, OpenedSource, SearchHit, data_only_envelope, locate_text, publisher_from_url, seed_id, stable_hit_id, today

USER_AGENT = 'ResearchCore/2.0' + (f" (mailto:{os.environ['RESEARCH_CONTACT_EMAIL']})" if os.environ.get('RESEARCH_CONTACT_EMAIL') else '')


def _get_json(url: str, timeout: int = 30) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode('utf-8'))


def _get_text(url: str, timeout: int = 45) -> tuple[str, str]:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xhtml+xml,text/plain'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode(response.headers.get_content_charset() or 'utf-8', errors='replace')
        return body, response.geturl()


class ScholarlyProvider:
    external_ops: frozenset[str] = frozenset({'search', 'open'})
    name = 'scholarly'

    def search(self, query: str, *, limit: int = 10, seed_chain: list[str] | None = None) -> list[SearchHit]:
        seed = seed_id(query)
        chain = tuple(seed_chain or ()) + (seed,)
        url = 'https://api.crossref.org/works?' + urllib.parse.urlencode({'query': query, 'rows': max(1, min(limit, 20)), 'select': 'DOI,title,publisher,URL,author,published,relation,type'})
        data = _get_json(url)
        hits = []
        for item in data.get('message', {}).get('items', []):
            doi = str(item.get('DOI') or '').strip()
            target = str(item.get('URL') or (f'https://doi.org/{doi}' if doi else ''))
            if not target:
                continue
            title = ' '.join(item.get('title') or []) or target
            hits.append(SearchHit(id=stable_hit_id(self.name, target), url=target, title=title, publisher=str(item.get('publisher') or publisher_from_url(target)), snippet='', suggested_by=seed, seed_chain=chain, provider=self.name, metadata={'doi': doi or None, 'type': item.get('type'), 'relation': item.get('relation') or {}}))
        return hits

    def open(self, url: str) -> OpenedSource:
        body, final_url = _get_text(url)
        envelope, digest = data_only_envelope(body, source_url=final_url)
        return OpenedSource(final_url, final_url, publisher_from_url(final_url), today(), envelope, digest, 'data_only', self.name, {'requested_url': url})

    def find(self, opened: OpenedSource, pattern: str) -> LocatedPassage | None:
        body = json.loads(opened.content)['content']
        found = locate_text(body, pattern)
        if not found:
            return None
        locator, text = found
        return LocatedPassage(opened.url, locator, text, False, self.name, {})
