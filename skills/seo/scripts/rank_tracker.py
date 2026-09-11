#!/usr/bin/env python3
"""Provider-neutral longitudinal rank observation store.

This tool ingests observations; it does not scrape a SERP. Provider adapters remain responsible
for collection and cost/terms. Project market/language/device are part of every observation.
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def state_dir(root: str | Path) -> Path:
    return Path(root).resolve() / '.legion' / 'seo' / 'rank-tracking'


def read_input(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == '.csv':
        with path.open(newline='', encoding='utf-8-sig') as fh:
            return list(csv.DictReader(fh))
    payload = json.loads(path.read_text(encoding='utf-8'))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get('rows'), list):
        return payload['rows']
    if isinstance(payload, dict) and isinstance(payload.get('observations'), list):
        return payload['observations']
    raise ValueError('expected list or object with rows[]/observations[]')


def normalize(row: dict[str, Any], defaults: dict[str, str]) -> dict[str, Any]:
    keyword = str(row.get('keyword') or row.get('query') or '').strip()
    if not keyword:
        raise ValueError('rank observation missing keyword/query')
    position_raw = row.get('position')
    position = float(position_raw) if position_raw not in (None, '') else None
    return {
        'keyword': keyword,
        'market': str(row.get('market') or defaults.get('market') or '').strip(),
        'language': str(row.get('language') or defaults.get('language') or '').strip(),
        'device': str(row.get('device') or defaults.get('device') or 'desktop').strip(),
        'intended_page': row.get('intended_page') or row.get('target_url'),
        'observed_url': row.get('observed_url') or row.get('url') or row.get('page'),
        'organic_position': position,
        'serp_features': row.get('serp_features') or [],
        'provider': str(row.get('provider') or defaults.get('provider') or 'unknown'),
        'collected_at': str(row.get('collected_at') or defaults.get('collected_at') or now()),
    }


def ingest(root: str | Path, observations: list[dict[str, Any]], defaults: dict[str, str]) -> Path:
    out_dir = state_dir(root)
    out_dir.mkdir(parents=True, exist_ok=True)
    normalized = [normalize(row, defaults) for row in observations]
    stamp = defaults.get('snapshot') or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = out_dir / f'{stamp}.json'
    path.write_text(json.dumps({'created_at': now(), 'observations': normalized}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return path


def snapshots(root: str | Path) -> list[Path]:
    d = state_dir(root)
    return sorted(d.glob('*.json')) if d.exists() else []


def compare(root: str | Path) -> dict[str, Any]:
    snaps = snapshots(root)
    if len(snaps) < 2:
        return {'status': 'not_testable', 'reason': 'at least two rank snapshots are required', 'snapshots': len(snaps)}
    prev = json.loads(snaps[-2].read_text(encoding='utf-8')).get('observations', [])
    curr = json.loads(snaps[-1].read_text(encoding='utf-8')).get('observations', [])
    key = lambda x: (x.get('keyword'), x.get('market'), x.get('language'), x.get('device'))
    pmap = {key(x): x for x in prev}
    changes = []
    for cur in curr:
        old = pmap.get(key(cur))
        if not old:
            changes.append({'type': 'new_keyword_observation', 'current': cur})
            continue
        old_pos, new_pos = old.get('organic_position'), cur.get('organic_position')
        delta = None if old_pos is None or new_pos is None else round(old_pos - new_pos, 3)
        ownership_changed = bool(old.get('observed_url') and cur.get('observed_url') and old.get('observed_url') != cur.get('observed_url'))
        intended_mismatch = bool(cur.get('intended_page') and cur.get('observed_url') and cur.get('intended_page') != cur.get('observed_url'))
        changes.append({
            'keyword': cur['keyword'], 'market': cur['market'], 'language': cur['language'], 'device': cur['device'],
            'previous_position': old_pos, 'current_position': new_pos, 'position_improvement': delta,
            'previous_url': old.get('observed_url'), 'current_url': cur.get('observed_url'),
            'ownership_changed': ownership_changed, 'intended_page_mismatch': intended_mismatch,
        })
    return {
        'status': 'ok',
        'previous_snapshot': snaps[-2].name,
        'current_snapshot': snaps[-1].name,
        'changes': changes,
        'ownership_changes': sum(1 for x in changes if x.get('ownership_changed')),
        'intended_page_mismatches': sum(1 for x in changes if x.get('intended_page_mismatch')),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    sub = ap.add_subparsers(dest='command', required=True)
    p_ing = sub.add_parser('ingest')
    p_ing.add_argument('input')
    p_ing.add_argument('--market', required=True)
    p_ing.add_argument('--language', required=True)
    p_ing.add_argument('--device', default='desktop')
    p_ing.add_argument('--provider', required=True)
    p_ing.add_argument('--snapshot')
    sub.add_parser('compare')
    args = ap.parse_args()
    if args.command == 'ingest':
        path = ingest(args.root, read_input(Path(args.input)), {
            'market': args.market, 'language': args.language, 'device': args.device,
            'provider': args.provider, 'snapshot': args.snapshot or '',
        })
        out = {'status': 'ok', 'path': str(path)}
    else:
        out = compare(args.root)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out.get('status') in ('ok', 'not_testable') else 1


if __name__ == '__main__':
    raise SystemExit(main())
