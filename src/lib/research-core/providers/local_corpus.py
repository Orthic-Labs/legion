#!/usr/bin/env python3
"""Deterministic local-corpus search/open/find provider."""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse

from base import LocatedPassage, OpenedSource, SearchHit, data_only_envelope, locate_text, seed_id, stable_hit_id, today

SUPPORTED = {'.md', '.txt', '.json', '.jsonl', '.csv', '.html', '.htm'}
TOKEN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._%-]{1,}')


class LocalCorpusProvider:
    external_ops: frozenset[str] = frozenset()
    name = 'local-corpus'

    def __init__(self, root: Path):
        self.root = root.resolve()
        if not self.root.is_dir():
            raise FileNotFoundError(f'local corpus does not exist: {self.root}')

    def _files(self) -> list[Path]:
        return sorted(p for p in self.root.rglob('*') if p.is_file() and p.suffix.lower() in SUPPORTED)

    def search(self, query: str, *, limit: int = 10, seed_chain: list[str] | None = None) -> list[SearchHit]:
        terms = [t.lower() for t in TOKEN_RE.findall(query)]
        seed = seed_id(query)
        chain = tuple(seed_chain or ()) + (seed,)
        files = self._files()
        if not files:
            return []
        docs = []
        df = Counter()
        for path in files:
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            counts = Counter(t.lower() for t in TOKEN_RE.findall(text))
            docs.append((path, text, counts))
            for term in set(counts):
                df[term] += 1
        n = max(1, len(docs))
        scored = []
        for path, text, counts in docs:
            score = 0.0
            for term in terms:
                tf = counts.get(term, 0)
                if tf:
                    score += (1 + math.log(tf)) * math.log((n + 1) / (1 + df[term]) + 1)
            if score <= 0:
                continue
            first = min((text.lower().find(term) for term in terms if term in text.lower()), default=0)
            snippet = text[max(0, first - 100): first + 300].replace('\n', ' ').strip()
            url = path.as_uri()
            scored.append((score, SearchHit(id=stable_hit_id(self.name, url), url=url, title=path.stem, publisher='local-corpus', snippet=snippet, suggested_by=seed, seed_chain=chain, provider=self.name, metadata={'path': str(path.relative_to(self.root)), 'score': round(score, 6)})))
        scored.sort(key=lambda item: (-item[0], item[1].url))
        return [hit for _, hit in scored[:limit]]

    def _path(self, url: str) -> Path:
        parsed = urlparse(url)
        if parsed.scheme != 'file':
            raise ValueError('local-corpus only opens file:// URLs')
        raw_path = unquote(parsed.path)
        if os.name == 'nt' and re.match(r'^/[A-Za-z]:', raw_path):
            raw_path = raw_path[1:]
        path = Path(raw_path).resolve()
        if self.root != path and self.root not in path.parents:
            raise ValueError('local-corpus path escapes corpus root')
        return path

    def open(self, url: str) -> OpenedSource:
        path = self._path(url)
        body = path.read_text(encoding='utf-8', errors='replace')
        envelope, digest = data_only_envelope(body, source_url=url)
        return OpenedSource(url=url, title=path.stem, publisher='local-corpus', retrieved_at=today(), content=envelope, content_sha256=digest, instruction_policy='data_only', provider=self.name, metadata={'path': str(path.relative_to(self.root))})

    def find(self, opened: OpenedSource, pattern: str) -> LocatedPassage | None:
        import json
        body = json.loads(opened.content)['content']
        found = locate_text(body, pattern)
        if not found:
            return None
        locator, text = found
        return LocatedPassage(opened.url, locator, text, False, self.name, {})
