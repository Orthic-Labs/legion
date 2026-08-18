#!/usr/bin/env python3
"""Citation-to-sentence binding and source-support verification."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

CITE_RE = re.compile(r'\[\+\s*([A-Za-z0-9_.:-]+)\s*\]')
NUMBER_RE = re.compile(r'[-+]?\d[\d,]*(?:\.\d+)?%?')
WORD_RE = re.compile(r'[A-Za-z0-9]{3,}')


def _norm_words(text: str) -> list[str]:
    stop = {'the', 'and', 'that', 'with', 'from', 'this', 'have', 'were', 'been', 'into', 'than', 'for'}
    return [w.lower() for w in WORD_RE.findall(text) if w.lower() not in stop]


def _sentences(markdown: str) -> list[dict[str, Any]]:
    rows = []
    section = ''
    idx = 0
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if line.startswith('#'):
            section = line.lstrip('#').strip().lower()
            continue
        if not line or section in {'sources', 'references'} or line.startswith('_as of'):
            continue
        is_bullet = bool(re.match(r'^[-*]\s+', line))
        text = re.sub(r'^[-*]\s+', '', line)
        if is_bullet:
            chunks = [text]
        else:
            raw_chunks = re.split(r'(?<=[.!?])\s+(?=[A-Z\[])', text)
            chunks = []
            for chunk in raw_chunks:
                if chunks and re.fullmatch(r'(?:\[+?[^\]]+\]|\[(?:confidence|status):[^\]]+\]\s*)+', chunk.strip(), re.I):
                    chunks[-1] += ' ' + chunk.strip()
                else:
                    chunks.append(chunk)
        for chunk in chunks:
            if chunk.strip():
                rows.append({'index': idx, 'text': chunk.strip()})
                idx += 1
    return rows


def _support_blob(ev: dict[str, Any]) -> str:
    return ' '.join(str(ev.get(key) or '') for key in (
        'quote_or_paraphrase', 'evidence_text', 'body_plain', 'title', 'locator'
    ))


def _verdict(sentence: str, ev: dict[str, Any]) -> tuple[str, str]:
    clean = CITE_RE.sub('', sentence)
    clean = re.sub(r'\[(?:confidence|status):[^\]]+\]', '', clean, flags=re.I)
    clean = re.sub(r'^\[[A-Z][A-Z-]*\]\s*', '', clean)
    numbers = [n.replace(',', '') for n in NUMBER_RE.findall(clean)]
    blob = _support_blob(ev)
    blob_numbers = blob.replace(',', '')
    if numbers and not all(number in blob_numbers for number in numbers):
        return 'unsupported', f"sentence numbers {numbers} are not all present in evidence"
    words = _norm_words(clean)
    evidence_words = set(_norm_words(blob))
    if not words:
        return 'supported', 'citation-only or metadata sentence'
    content_words = [w for w in words if not w.isdigit()]
    overlap = len(set(content_words) & evidence_words) / max(1, len(set(content_words)))
    if overlap >= 0.55 or (numbers and overlap >= 0.25):
        return 'supported', f'lexical overlap={overlap:.2f}'
    if overlap >= 0.30:
        return 'partially-supported', f'lexical overlap={overlap:.2f}'
    return 'unsupported', f'lexical overlap={overlap:.2f}'


def check(markdown: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(e['id']): e for e in evidence}
    pairs = []
    unbound = []
    dangling = []
    unsupported = []
    for row in _sentences(markdown):
        ids = CITE_RE.findall(row['text'])
        factual = bool(NUMBER_RE.search(row['text']) or re.search(r'\b(is|are|was|were|has|have|causes?|reduces?|increases?|requires?|prohibits?)\b', row['text'], re.I))
        if not ids:
            if factual:
                unbound.append(row)
            continue
        for eid in ids:
            if eid not in by_id:
                item = {**row, 'evidence_id': eid, 'verdict': 'dangling'}
                pairs.append(item)
                dangling.append(item)
                continue
            verdict, reason = _verdict(row['text'], by_id[eid])
            item = {**row, 'evidence_id': eid, 'verdict': verdict, 'reason': reason}
            pairs.append(item)
            if verdict in {'unsupported', 'partially-supported'}:
                unsupported.append(item)
    return {
        'ok': not unbound and not dangling and not unsupported,
        'summary': {
            'pairs': len(pairs), 'unbound': len(unbound), 'dangling': len(dangling),
            'unsupported_or_partial': len(unsupported),
        },
        'pairs': pairs,
        'unbound': unbound,
        'dangling': dangling,
        'unsupported': unsupported,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--draft', required=True)
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    evidence = [json.loads(x) for x in Path(args.evidence).read_text(encoding='utf-8').splitlines() if x.strip()]
    result = check(Path(args.draft).read_text(encoding='utf-8'), evidence)
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
