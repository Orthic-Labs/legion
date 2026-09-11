#!/usr/bin/env python3
"""Calculate SEO audit evidence coverage without hiding unknowns in a weighted score.

Input is a JSON list (or {controls: [...]}) with each row containing at minimum
``id`` and ``status``. N/A is excluded only with an explicit rationale. Not-testable
remains in the applicable denominator and therefore reduces evidence coverage.
Critical gates are reported separately and may not be averaged away.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

STATUSES = {'pass', 'partial', 'fail', 'na', 'not_testable'}


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get('controls'), list):
        return payload['controls']
    raise ValueError('input must be list or object with controls[]')


def calculate(controls: list[dict[str, Any]]) -> dict[str, Any]:
    errors = []
    counts = Counter()
    applicable = 0
    tested = 0
    critical_failures = []
    critical_unknown = []
    partials = []
    for i, control in enumerate(controls):
        cid = str(control.get('id') or f'row-{i}')
        status = str(control.get('status') or '').lower()
        if status not in STATUSES:
            errors.append(f'{cid}: invalid status {status!r}')
            continue
        counts[status] += 1
        if status == 'na':
            if not str(control.get('rationale') or '').strip():
                errors.append(f'{cid}: N/A requires rationale')
            continue
        applicable += 1
        if status in {'pass', 'partial', 'fail'}:
            tested += 1
        if status == 'partial':
            if not control.get('tested_scope') or not control.get('untested_scope'):
                errors.append(f'{cid}: Partial requires tested_scope and untested_scope')
            partials.append(cid)
        if status == 'not_testable' and not str(control.get('reason') or '').strip():
            errors.append(f'{cid}: not_testable requires reason')
        if control.get('critical'):
            if status == 'fail':
                critical_failures.append(cid)
            elif status in {'partial', 'not_testable'}:
                critical_unknown.append(cid)
    coverage = tested / applicable if applicable else 1.0
    gate = 'fail' if critical_failures else ('partial' if critical_unknown or errors else 'pass')
    return {
        'status': 'fail' if errors else gate,
        'counts': dict(counts),
        'total_controls': len(controls),
        'applicable_controls': applicable,
        'tested_controls': tested,
        'evidence_coverage': round(coverage, 4),
        'critical_gate': gate,
        'critical_failures': critical_failures,
        'critical_unknown': critical_unknown,
        'partial_controls': partials,
        'validation_errors': errors,
        'scoring_note': 'N/A excluded with rationale; not_testable remains in denominator; critical gates are separate from any optional score.',
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--out')
    args = ap.parse_args()
    result = calculate(rows(json.loads(Path(args.input).read_text(encoding='utf-8'))))
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
