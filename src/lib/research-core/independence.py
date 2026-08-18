#!/usr/bin/env python3
"""Automatic source-independence clustering.

Clusters duplicate URLs, redirect/origin copies, identical or near-identical bodies,
shared DOI/study origins, explicit wire origins, and common wire-service copies.
Consensus counts unique cluster IDs, never raw source rows or fractional weights.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TRACKING = re.compile(r'^(utm_|fbclid$|gclid$|ref$|source$)', re.I)
WIRE_MARKERS = (
    'pr newswire', 'prnewswire', 'business wire', 'globe newswire', 'associated press',
    '(ap)', '(reuters)', 'accesswire', 'newsfile corp',
)
WORD_RE = re.compile(r'[a-z0-9]{3,}')


def canonical_url(url: str) -> str:
    if not url:
        return ''
    p = urlparse(url.strip())
    host = (p.hostname or '').lower().removeprefix('www.')
    path = re.sub(r'/+', '/', p.path).rstrip('/') or '/'
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)))
    scheme = 'file' if p.scheme == 'file' else 'https'
    return urlunparse((scheme, host, path, '', query, ''))


def _body_text(record: dict) -> str:
    return str(record.get('body_plain') or record.get('body') or record.get('quote_or_paraphrase') or '')


def _shingles(text: str, n: int = 5) -> set[str]:
    words = WORD_RE.findall(text.lower())
    return {' '.join(words[i:i+n]) for i in range(max(0, len(words) - n + 1))}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _wire_signature(record: dict) -> str | None:
    head = _body_text(record)[:2000].lower()
    marker = next((m for m in WIRE_MARKERS if m in head), None)
    if not marker:
        return None
    title_tokens = WORD_RE.findall(str(record.get('title') or '').lower())[:8]
    head_tokens = WORD_RE.findall(head)[:12]
    return f"{marker}|{' '.join(title_tokens or head_tokens)}"


class UnionFind:
    def __init__(self, ids: list[str]):
        self.parent = {item: item for item in ids}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            parent = self.parent[item]
            self.parent[item] = root
            item = parent
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            keep, drop = sorted((ra, rb))
            self.parent[drop] = keep


def cluster(evidence: list[dict], *, near_duplicate_threshold: float = 0.82) -> dict:
    ids = [str(e['id']) for e in evidence]
    uf = UnionFind(ids)
    by_id = {str(e['id']): e for e in evidence}
    reasons: dict[tuple[str, str], set[str]] = defaultdict(set)

    def merge(a: str, b: str, reason: str) -> None:
        if a == b or a not in by_id or b not in by_id:
            return
        uf.union(a, b)
        reasons[tuple(sorted((a, b)))].add(reason)

    indexes: dict[str, dict[str, list[str]]] = {
        'url': defaultdict(list), 'origin': defaultdict(list), 'doi': defaultdict(list),
        'body_hash': defaultdict(list), 'wire': defaultdict(list),
    }
    for record in evidence:
        eid = str(record['id'])
        indexes['url'][canonical_url(str(record.get('url') or ''))].append(eid)
        origin = canonical_url(str(record.get('origin_url') or record.get('resolved_from') or ''))
        if origin:
            indexes['origin'][origin].append(eid)
        doi = str(record.get('doi') or '').lower().removeprefix('https://doi.org/').strip()
        if doi:
            indexes['doi'][doi].append(eid)
        body_hash = str(record.get('content_sha256') or record.get('body_sha256') or '')
        if not body_hash and _body_text(record):
            body_hash = hashlib.sha256(_body_text(record).encode('utf-8')).hexdigest()
        if body_hash:
            indexes['body_hash'][body_hash].append(eid)
        sig = _wire_signature(record)
        if sig:
            indexes['wire'][sig].append(eid)
        explicit = record.get('wire_origin_id')
        if explicit:
            merge(eid, str(explicit), 'explicit-origin')

    for kind, groups in indexes.items():
        for key, members in groups.items():
            if not key or len(members) < 2:
                continue
            for member in members[1:]:
                merge(members[0], member, kind)

    shingles = {eid: _shingles(_body_text(record)) for eid, record in by_id.items()}
    for i, a in enumerate(ids):
        if len(shingles[a]) < 8:
            continue
        for b in ids[i + 1:]:
            if uf.find(a) == uf.find(b) or len(shingles[b]) < 8:
                continue
            score = _jaccard(shingles[a], shingles[b])
            if score >= near_duplicate_threshold:
                merge(a, b, f'near-body:{score:.3f}')

    groups: dict[str, list[str]] = defaultdict(list)
    for eid in ids:
        groups[uf.find(eid)].append(eid)

    cluster_rows = []
    id_to_cluster: dict[str, str] = {}
    for members in sorted((sorted(v) for v in groups.values()), key=lambda m: m[0]):
        digest = hashlib.sha256('|'.join(members).encode('utf-8')).hexdigest()[:12]
        cid = f'ind:{digest}'
        for eid in members:
            id_to_cluster[eid] = cid
        reason_set: set[str] = set()
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                reason_set.update(reasons.get(tuple(sorted((a, b))), set()))
        cluster_rows.append({'cluster_id': cid, 'members': members, 'reasons': sorted(reason_set)})

    updated = []
    for record in evidence:
        copy = dict(record)
        copy['independence_cluster'] = id_to_cluster[str(record['id'])]
        updated.append(copy)
    return {'evidence': updated, 'clusters': cluster_rows, 'unique_voices': len(cluster_rows)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    rows = [json.loads(line) for line in Path(args.evidence).read_text(encoding='utf-8').splitlines() if line.strip()]
    result = cluster(rows)
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
