#!/usr/bin/env python3
"""Classify GSC query ownership and cannibalization without naive keyword overlap.

Input JSON may be either a list of rows or an object with ``rows``. Rows need ``query``
and ``page`` plus any of clicks/impressions/position/date. Multiple dates/snapshots improve
switching detection. The output preserves evidence; it does not decide redirects by itself.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from statistics import mean
from typing import Any


@dataclass
class UrlEvidence:
    url: str
    clicks: float
    impressions: float
    avg_position: float | None
    observed_periods: int


@dataclass
class QueryOwnership:
    query: str
    urls: list[UrlEvidence]
    dominant_url: str | None
    dominant_share: float | None
    stability: str
    classification: str
    reason: str


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get('rows'), list):
        return payload['rows']
    raise ValueError('input must be a list or an object containing rows[]')


def _metric(row: dict[str, Any]) -> float:
    clicks = float(row.get('clicks') or 0)
    impressions = float(row.get('impressions') or 0)
    return clicks if clicks > 0 else impressions


def classify(rows: list[dict[str, Any]]) -> list[QueryOwnership]:
    by_query: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        q = str(row.get('query') or '').strip()
        page = str(row.get('page') or '').strip()
        if q and page:
            by_query[q].append(row)

    output: list[QueryOwnership] = []
    for query, qrows in sorted(by_query.items()):
        by_url: dict[str, list[dict[str, Any]]] = defaultdict(list)
        periods: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for row in qrows:
            url = str(row['page'])
            by_url[url].append(row)
            period = str(row.get('date') or row.get('period') or 'single')
            periods[period][url] += _metric(row)

        evidence: list[UrlEvidence] = []
        totals: dict[str, float] = {}
        for url, urows in by_url.items():
            clicks = sum(float(r.get('clicks') or 0) for r in urows)
            impressions = sum(float(r.get('impressions') or 0) for r in urows)
            positions = [float(r['position']) for r in urows if r.get('position') not in (None, '')]
            totals[url] = clicks if clicks > 0 else impressions
            evidence.append(UrlEvidence(
                url=url, clicks=clicks, impressions=impressions,
                avg_position=round(mean(positions), 3) if positions else None,
                observed_periods=len({str(r.get('date') or r.get('period') or 'single') for r in urows}),
            ))

        evidence.sort(key=lambda x: (totals.get(x.url, 0), x.impressions), reverse=True)
        total_metric = sum(totals.values())
        dominant = evidence[0].url if evidence else None
        share = (totals[dominant] / total_metric) if dominant and total_metric > 0 else None

        period_winners = []
        for _, scores in sorted(periods.items()):
            if scores:
                period_winners.append(max(scores, key=scores.get))
        winner_changes = sum(1 for i in range(1, len(period_winners)) if period_winners[i] != period_winners[i-1])
        unique_winners = len(set(period_winners))

        if len(evidence) == 1:
            stability, kind, reason = 'high', 'stable owner', 'only one observed URL owns the query'
        elif len(period_winners) >= 2 and unique_winners > 1 and winner_changes > 0:
            stability, kind, reason = 'low', 'ownership switching', 'dominant URL changes across observed periods'
        elif share is not None and share >= 0.80:
            stability, kind, reason = 'high', 'benign overlap', 'one URL owns at least 80% of observed demand while secondary URLs are minor'
        elif share is not None and share >= 0.60:
            stability, kind, reason = 'medium', 'ambiguous ownership', 'one URL leads but ownership is not decisive'
        else:
            stability, kind, reason = 'low', 'probable duplicate target', 'multiple URLs split query demand with no strong owner'

        output.append(QueryOwnership(
            query=query, urls=evidence, dominant_url=dominant,
            dominant_share=round(share, 4) if share is not None else None,
            stability=stability, classification=kind, reason=reason,
        ))
    return output


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--out')
    args = ap.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding='utf-8'))
    items = classify(_rows(payload))
    result = {
        'query_count': len(items),
        'ownership': [asdict(item) for item in items],
        'limitations': ['Classification is first-party evidence triage, not automatic redirect/consolidation authority. Intent and page-family evidence are required for remediation.'],
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
