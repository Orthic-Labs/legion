#!/usr/bin/env python3
"""Fail closed when unstable official SEO/platform sources are overdue for review."""
from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = SEO_ROOT / 'config' / 'official-sources.json'


def load() -> dict[str, Any]:
    return json.loads(REGISTER.read_text(encoding='utf-8'))


def assess(as_of: date | None = None) -> dict[str, Any]:
    as_of = as_of or date.today()
    due, current, invalid = [], [], []
    for src in load().get('sources', []):
        try:
            checked = datetime.strptime(src['checked_at'], '%Y-%m-%d').date()
            interval = int(src['review_interval_days'])
        except Exception as exc:
            invalid.append({'id': src.get('id'), 'error': str(exc)})
            continue
        next_review = checked + timedelta(days=interval)
        row = {
            'id': src['id'], 'authority': src['authority'], 'url': src['url'],
            'checked_at': src['checked_at'], 'next_review': next_review.isoformat(),
            'applies_to': src.get('applies_to', []),
        }
        (due if as_of > next_review else current).append(row)
    return {
        'status': 'fail' if due or invalid else 'pass',
        'as_of': as_of.isoformat(),
        'due': due,
        'invalid': invalid,
        'current_count': len(current),
        'trigger_rule': load().get('trigger_rule'),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--as-of', help='YYYY-MM-DD; defaults to today')
    args = ap.parse_args()
    as_of = datetime.strptime(args.as_of, '%Y-%m-%d').date() if args.as_of else None
    result = assess(as_of)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
