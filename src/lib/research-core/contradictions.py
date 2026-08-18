#!/usr/bin/env python3
"""Derive contradiction and consensus views from atomic claims."""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

NUMBER_RE = re.compile(r'[-+]?\d[\d,]*(?:\.\d+)?%?')


def _target(claim: dict[str, Any]) -> str:
    explicit = str(claim.get('stance_target') or claim.get('metric') or '').strip().lower()
    if explicit:
        return explicit
    text = re.sub(r'\[[^\]]+\]', ' ', str(claim.get('text') or '').lower())
    words = [w for w in re.findall(r'[a-z0-9]{3,}', text) if w not in {'this', 'that', 'with', 'from', 'than', 'into', 'does', 'have'}]
    return ' '.join(words[:8])


def _scope(claim: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    raw = claim.get('scope') or {}
    return tuple(sorted((str(k), str(v)) for k, v in raw.items() if v not in (None, '')))


def _stance(claim: dict[str, Any]) -> str:
    return str(claim.get('stance') or '').lower()


def _numbers(claim: dict[str, Any]) -> tuple[str, ...]:
    return tuple(NUMBER_RE.findall(str(claim.get('text') or '')))


def derive(claims: list[dict], evidence: list[dict]) -> dict:
    evidence_by_id = {e['id']: e for e in evidence}
    groups: dict[tuple[str, tuple[tuple[str, str], ...]], list[dict]] = defaultdict(list)
    for claim in claims:
        groups[(_target(claim), _scope(claim))].append(claim)

    contradictions = []
    consensus = []
    for (target, scope), rows in groups.items():
        if not target or len(rows) < 2:
            continue
        sides: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            stance = _stance(row)
            if stance:
                sides[stance].append(row)
        number_sets = {_numbers(row) for row in rows if _numbers(row)}
        genuine_stance_conflict = bool(sides.get('supports') and sides.get('refutes'))
        numeric_conflict = len(number_sets) > 1
        if genuine_stance_conflict or numeric_conflict:
            contradictions.append({
                'target': target,
                'scope': dict(scope),
                'claim_ids': [r['id'] for r in rows],
                'kind': 'stance' if genuine_stance_conflict else 'numeric',
                'positions': {k: [r['id'] for r in v] for k, v in sorted(sides.items())},
                'numeric_values': [list(v) for v in sorted(number_sets)],
                'resolution_status': 'unresolved',
                'decision_relevance': max((r.get('decision_relevance', 'medium') for r in rows), default='medium'),
            })
            continue

        clusters: set[str] = set()
        for row in rows:
            for sid in row.get('source_ids', []):
                ev = evidence_by_id.get(sid)
                if ev:
                    clusters.add(str(ev.get('independence_cluster') or sid))
        if len(clusters) >= 2 and all(r.get('status', 'supported') == 'supported' for r in rows):
            consensus.append({
                'target': target,
                'scope': dict(scope),
                'claim_ids': [r['id'] for r in rows],
                'independent_voices': len(clusters),
                'status': 'corroborated',
            })
    return {'contradictions': contradictions, 'consensus': consensus}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--claims', required=True)
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    claims = [json.loads(x) for x in Path(args.claims).read_text(encoding='utf-8').splitlines() if x.strip()]
    evidence = [json.loads(x) for x in Path(args.evidence).read_text(encoding='utf-8').splitlines() if x.strip()]
    result = derive(claims, evidence)
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
