#!/usr/bin/env python3
from __future__ import annotations

import importlib
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
CORE = WORKSPACE / 'src' / 'lib' / 'research-core'
sys.path.insert(0, str(CORE))

domain_verify = importlib.import_module('domain_verify')


def main() -> int:
    route = {
        'domain': 'legal',
        'subject': {'country': 'IN', 'area': 'civil', 'issue': 'precedent support'},
        'forbidden_resources': [],
    }
    claim = {
        'id': 'cl1',
        'claim_type': 'case-law',
        'source_ids': ['ev1'],
    }
    incomplete = {
        'id': 'ev1',
        'authority_type': 'judgment',
        'forum': 'High Court',
        'current_as_of': '2026-08-05',
    }
    result = domain_verify.verify(route, [incomplete], [claim])
    assert not result['ok'], result

    complete = {
        **incomplete,
        'precedential_status': 'binding',
        'negative_treatment': 'none found',
    }
    result = domain_verify.verify(route, [complete], [claim])
    assert result['ok'], result

    print('OK: legal case-law evidence requires forum, precedential status, negative treatment, and current-as-of')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
