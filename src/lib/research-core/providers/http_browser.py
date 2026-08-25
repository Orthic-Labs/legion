#!/usr/bin/env python3
"""Zero-configuration public-web provider for Research Core."""
from __future__ import annotations

import html
import ipaddress
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

from base import LocatedPassage, OpenedSource, SearchHit, data_only_envelope, locate_text, publisher_from_url, seed_id, stable_hit_id, today

USER_AGENT = 'LegionResearch/1.0 (+https://github.com/orthic-labs/legion)'
MAX_BODY_BYTES = 5 * 1024 * 1024


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag in {'script', 'style', 'noscript', 'svg'}:
            self.skip_depth += 1
        if tag == 'title':
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {'script', 'style', 'noscript', 'svg'} and self.skip_depth:
            self.skip_depth -= 1
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        value = re.sub(r'\s+', ' ', data).strip()
        if not value:
            return
        self.parts.append(value)
        if self.in_title:
            self.title_parts.append(value)


def _public_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('browser provider accepts only http(s) URLs')
    host = parsed.hostname.lower()
    if host == 'localhost' or host.endswith('.local'):
        raise ValueError('browser provider refuses local hosts')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError('browser provider refuses non-public addresses')
    return url


def _request(url: str, *, accept: str, timeout: int = 45) -> tuple[bytes, str, str]:
    request = urllib.request.Request(_public_url(url), headers={
        'User-Agent': USER_AGENT,
        'Accept': accept,
        'Accept-Encoding': 'identity',
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            raise RuntimeError(f'provider response exceeds {MAX_BODY_BYTES} bytes')
        return body, response.geturl(), response.headers.get_content_type()


def _document_text(raw: bytes, content_type: str) -> tuple[str, str]:
    decoded = raw.decode('utf-8', errors='replace')
    if content_type not in {'text/html', 'application/xhtml+xml'} and '<html' not in decoded[:1000].lower():
        return decoded, ''
    parser = _VisibleText()
    parser.feed(decoded)
    return '\n'.join(parser.parts), ' '.join(parser.title_parts)


def _rss_hits(raw: bytes, *, provider: str, query: str, limit: int, seed_chain: list[str] | None) -> list[SearchHit]:
    root = ET.fromstring(raw)
    seed = seed_id(query)
    chain = tuple(seed_chain or ()) + (seed,)
    hits: list[SearchHit] = []
    for item in root.findall('.//item'):
        url = (item.findtext('link') or '').strip()
        if not url:
            continue
        try:
            _public_url(url)
        except ValueError:
            continue
        title = html.unescape((item.findtext('title') or url).strip())
        snippet = re.sub(r'<[^>]+>', ' ', item.findtext('description') or '')
        hits.append(SearchHit(
            id=stable_hit_id(provider, url), url=url, title=title,
            publisher=publisher_from_url(url), snippet=html.unescape(re.sub(r'\s+', ' ', snippet).strip()),
            suggested_by=seed, seed_chain=chain, provider=provider, metadata={'search_engine': 'bing-rss'},
        ))
        if len(hits) >= limit:
            break
    return hits


class HttpBrowserProvider:
    external_ops: frozenset[str] = frozenset({'search', 'open'})
    name = 'browser'

    def search(self, query: str, *, limit: int = 10, seed_chain: list[str] | None = None) -> list[SearchHit]:
        query = query.strip()
        parsed = urllib.parse.urlparse(query)
        if parsed.scheme in {'http', 'https'} and parsed.netloc and not re.search(r'\s', query):
            url = _public_url(query)
            seed = seed_id(query)
            return [SearchHit(
                id=stable_hit_id(self.name, url), url=url, title=url,
                publisher=publisher_from_url(url), snippet='', suggested_by=seed,
                seed_chain=tuple(seed_chain or ()) + (seed,), provider=self.name,
                metadata={'discovery': 'direct-url'},
            )]
        endpoint = 'https://www.bing.com/search?' + urllib.parse.urlencode({'q': query, 'format': 'rss', 'count': max(1, min(limit, 50))})
        raw, _, _ = _request(endpoint, accept='application/rss+xml,application/xml,text/xml')
        return _rss_hits(raw, provider=self.name, query=query, limit=limit, seed_chain=seed_chain)

    def open(self, url: str) -> OpenedSource:
        raw, final_url, content_type = _request(url, accept='text/html,application/xhtml+xml,text/plain,application/json')
        body, title = _document_text(raw, content_type)
        envelope, digest = data_only_envelope(body, source_url=final_url)
        return OpenedSource(
            url=final_url, title=title or final_url, publisher=publisher_from_url(final_url),
            retrieved_at=today(), content=envelope, content_sha256=digest,
            instruction_policy='data_only', provider=self.name,
            metadata={'requested_url': url, 'content_type': content_type},
        )

    def find(self, opened: OpenedSource, pattern: str) -> LocatedPassage | None:
        found = locate_text(opened.content, pattern)
        if not found:
            return None
        locator, text = found
        return LocatedPassage(opened.url, locator, text, False, self.name, {})
