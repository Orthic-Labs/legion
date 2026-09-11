#!/usr/bin/env python3
"""Build an AEO question inventory from first-party query evidence plus optional supplied questions."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

QUESTION_RE = re.compile(r'^(who|what|when|where|why|how|can|could|does|do|did|is|are|should|which|will|would)\b', re.I)


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get('rows'), list):
        return payload['rows']
    raise ValueError('input must be a list or object with rows[]')


def intent(q: str) -> str:
    s = q.lower().strip()
    if any(x in s for x in ('price', 'pricing', 'cost', 'buy', 'book', 'download', 'signup', 'sign up')):
        return 'transactional'
    if any(x in s for x in ('best ', ' vs ', ' versus ', 'alternative', 'compare', 'review')):
        return 'commercial'
    if s.startswith(('where ', 'login ', 'website ')):
        return 'navigational'
    return 'informational'


def build(payload: Any, extras: list[str] | None = None) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for row in rows(payload):
        q = str(row.get('query') or '').strip()
        if not q or not (QUESTION_RE.match(q) or q.endswith('?')):
            continue
        key = q.lower().rstrip('?').strip()
        cur = found.setdefault(key, {
            'question': q.rstrip('?') + '?',
            'intent': intent(q),
            'source': 'gsc',
            'clicks': 0.0,
            'impressions': 0.0,
            'best_position': None,
            'intended_page': None,
            'answer_present': None,
            'extractable': None,
            'source_evidence_present': None,
            'traditional_visibility': 'observed',
            'generative_visibility': 'not_tested',
        })
        cur['clicks'] += float(row.get('clicks') or 0)
        cur['impressions'] += float(row.get('impressions') or 0)
        if row.get('position') not in (None, ''):
            pos = float(row['position'])
            cur['best_position'] = pos if cur['best_position'] is None else min(cur['best_position'], pos)
        if row.get('page') and not cur.get('intended_page'):
            cur['intended_page'] = row.get('page')
    for q in extras or []:
        q = q.strip()
        if not q:
            continue
        key = q.lower().rstrip('?').strip()
        found.setdefault(key, {
            'question': q.rstrip('?') + '?',
            'intent': intent(q),
            'source': 'supplied',
            'clicks': None,
            'impressions': None,
            'best_position': None,
            'intended_page': None,
            'answer_present': None,
            'extractable': None,
            'source_evidence_present': None,
            'traditional_visibility': 'not_tested',
            'generative_visibility': 'not_tested',
        })
    return sorted(found.values(), key=lambda x: (-(x['impressions'] or 0), x['question'].lower()))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='GSC normalized JSON')
    ap.add_argument('--questions', help='optional newline-delimited real customer/support questions')
    ap.add_argument('--out')
    args = ap.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding='utf-8'))
    extras = Path(args.questions).read_text(encoding='utf-8').splitlines() if args.questions else []
    inventory = build(payload, extras)
    result = {
        'questions': inventory,
        'count': len(inventory),
        'contract': 'question -> intent -> intended page -> answer present -> extractable -> evidence -> traditional visibility -> generative visibility',
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
