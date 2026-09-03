#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'stopping.py'
spec = importlib.util.spec_from_file_location('research_stopping', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
stopping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stopping)


def main() -> int:
    complete = stopping.decide(
        required_questions=['price'], answered_questions=['price'], consecutive_no_gain=0,
        external_requests_used=2, external_requests_budget=12, blocking_gaps=[],
    )
    assert complete == {
        'action': 'stop', 'reason': 'coverage-complete', 'complete': True,
        'unanswered': [], 'blocking_gaps': [],
    }

    search = stopping.decide(
        required_questions=['price', 'privacy'], answered_questions=['price'], consecutive_no_gain=1,
        external_requests_used=3, external_requests_budget=12, blocking_gaps=['privacy authority'],
    )
    assert search['action'] == 'continue' and search['reason'] == 'targeted-gap-search'

    stagnant = stopping.decide(
        required_questions=['price', 'privacy'], answered_questions=['price'], consecutive_no_gain=2,
        external_requests_used=4, external_requests_budget=12, blocking_gaps=['privacy authority'],
    )
    assert stagnant['action'] == 'stop' and stagnant['reason'] == 'no-material-gain'
    assert not stagnant['complete']

    exhausted = stopping.decide(
        required_questions=['price'], answered_questions=[], consecutive_no_gain=0,
        external_requests_used=12, external_requests_budget=12, blocking_gaps=[],
    )
    assert exhausted['action'] == 'stop' and exhausted['reason'] == 'budget-exhausted'
    assert not exhausted['complete']

    print('OK: Research stopping is coverage-, gain-, and budget-driven')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
