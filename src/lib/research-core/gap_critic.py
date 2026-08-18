#!/usr/bin/env python3
"""Evidence-aware overturn review plus targeted blocking-gap queries.

Every claim records what could overturn it. Only an actual evidence deficiency blocks a
verified run; the mere possibility of future supersession is an overturn condition, not a
permanent gap.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

MULTI = {'comparative', 'causal', 'prevalence', 'benchmark', 'effect-size', 'adverse-event', 'dosing'}


def _iso_age_days(value: Any) -> int | None:
    try:
        return (dt.date.today() - dt.date.fromisoformat(str(value))).days
    except (TypeError, ValueError):
        return None


def review(claims: list[dict[str, Any]], evidence: list[dict[str, Any]], contradictions: dict[str, Any] | None = None) -> dict[str, Any]:
    by_id = {e['id']: e for e in evidence}
    contested_ids = {
        cid for row in (contradictions or {}).get('contradictions', []) for cid in row.get('claim_ids', [])
    }
    rows, targeted_queries = [], []
    for claim in claims:
        sources = [by_id[sid] for sid in claim.get('source_ids', []) if sid in by_id]
        clusters = {s.get('independence_cluster') or s['id'] for s in sources}
        primary = [s for s in sources if s.get('is_primary') or s.get('authority_role')]
        gaps: list[str] = []
        overturners: list[str] = []
        ctype = claim['claim_type']
        if not primary and ctype not in {'inference', 'recommendation'}:
            gaps.append('no proposition-fit primary source')
        if ctype in MULTI:
            overturners.append('methodologically sound independent evidence with a materially different result')
            if len(clusters) < 2:
                gaps.append('fewer than two independent evidence clusters')
        if claim['id'] in contested_ids or claim.get('status') in {'contested', 'unresolved'}:
            gaps.append('claim is contradicted or unresolved')
            overturners.append('resolution of the recorded contradiction against this position')
        if ctype in {'price', 'feature'}:
            overturners.append('a newer official vendor page or version-specific record')
            age = _iso_age_days(claim.get('as_of'))
            if age is None or age > 45:
                gaps.append('volatile vendor claim is not current within 45 days')
        if ctype in {'legal', 'case-law'}:
            overturners.append('a binding higher-court authority, amendment, repeal, or negative treatment')
            if any(not s.get('current_as_of') for s in primary):
                gaps.append('legal authority currentness is unverified')
        if ctype in {'effect-size', 'adverse-event', 'dosing'}:
            overturners.append('a larger, better-controlled, or more patient-applicable primary study')
            if any(not s.get('applicability') for s in primary):
                gaps.append('patient/population applicability is unrecorded')
        if not overturners:
            overturners.append('new proposition-fit primary evidence that contradicts the claim')
        query = _query(claim, gaps) if gaps else None
        if query:
            targeted_queries.append({'claim_id': claim['id'], 'query': query})
        rows.append({
            'claim_id': claim['id'],
            'text': claim['text'],
            'gaps': gaps,
            'what_would_overturn_it': overturners,
            'targeted_query': query,
            'status': 'gap-fetch-required' if gaps else 'complete',
        })
    blocking = [row for row in rows if row['gaps']]
    return {
        'findings': rows,
        'blocking_findings': blocking,
        'targeted_queries': targeted_queries,
        'complete': not blocking,
    }


def _query(claim: dict[str, Any], gaps: list[str]) -> str:
    target = claim.get('stance_target') or claim['text']
    as_of = claim.get('as_of') or dt.date.today().isoformat()
    if claim['claim_type'] in {'legal', 'case-law'}:
        return f'current binding authority negative treatment amendment {target} as of {as_of}'
    if claim['claim_type'] in {'effect-size', 'adverse-event', 'dosing'}:
        return f'primary randomized trial replication applicability adverse events {target}'
    if claim['claim_type'] in {'price', 'feature'}:
        return f'official current {target} {as_of}'
    return f'independent proposition-fit primary evidence contradicting {target}'


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--claims', required=True)
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--contradictions')
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    claims = [json.loads(x) for x in Path(args.claims).read_text(encoding='utf-8').splitlines() if x.strip()]
    evidence = [json.loads(x) for x in Path(args.evidence).read_text(encoding='utf-8').splitlines() if x.strip()]
    contradictions = json.loads(Path(args.contradictions).read_text(encoding='utf-8')) if args.contradictions else None
    result = review(claims, evidence, contradictions)
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
