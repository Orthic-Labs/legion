#!/usr/bin/env python3
"""Deterministic adaptive stopping for Research acquisition.

Stopping is evaluated from persisted coverage, evidence gain, and hook-metered budget.
The model cannot silently widen the run or decide that an arbitrary source count is enough.
"""
from __future__ import annotations

import argparse
import json
from typing import Any


def decide(
    *,
    required_questions: list[str],
    answered_questions: list[str],
    consecutive_no_gain: int,
    external_requests_used: int,
    external_requests_budget: int,
    blocking_gaps: list[str] | None = None,
) -> dict[str, Any]:
    required = set(required_questions)
    answered = set(answered_questions)
    unanswered = sorted(required - answered)
    gaps = sorted(set(blocking_gaps or []))
    budget_exhausted = external_requests_used >= external_requests_budget

    if budget_exhausted:
        return {
            'action': 'stop',
            'reason': 'budget-exhausted',
            'complete': not unanswered and not gaps,
            'unanswered': unanswered,
            'blocking_gaps': gaps,
        }
    if not unanswered and not gaps:
        return {
            'action': 'stop',
            'reason': 'coverage-complete',
            'complete': True,
            'unanswered': [],
            'blocking_gaps': [],
        }
    if consecutive_no_gain >= 2:
        return {
            'action': 'stop',
            'reason': 'no-material-gain',
            'complete': False,
            'unanswered': unanswered,
            'blocking_gaps': gaps,
        }
    return {
        'action': 'continue',
        'reason': 'targeted-gap-search',
        'complete': False,
        'unanswered': unanswered,
        'blocking_gaps': gaps,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    args = parser.parse_args(argv)
    payload = json.loads(open(args.input, encoding='utf-8').read())
    result = decide(**payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
