#!/usr/bin/env python3
from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
CORE = WORKSPACE / 'src' / 'lib' / 'research-core'
sys.path.insert(0, str(CORE))
sys.path.insert(0, str(CORE / 'router'))
sys.path.insert(0, str(CORE / 'providers'))

ledger = importlib.import_module('ledger')
runmod = importlib.import_module('run')


def _valid_evidence(**overrides):
    row = {
        'id': 'ev1',
        'url': 'file:///tmp/source.md',
        'title': 'Source',
        'publisher': 'local-corpus',
        'retrieved_at': '2026-08-05',
        'locator': 'chars:0-42',
        'quote_or_paraphrase': 'Vendor X costs $29 per month.',
        'suggested_by': 'seed:query:1',
        'seed_chain': ['seed:query:1'],
        'is_primary': True,
        'authority_role': 'vendor-official',
        'instructionPolicy': 'data_only',
    }
    row.update(overrides)
    return row


def main() -> int:
    missing_policy = _valid_evidence()
    del missing_policy['instructionPolicy']
    assert ledger.validate_evidence([missing_policy])[0]['verdict'] == 'block'

    snippet = _valid_evidence(source_type='search-snippet')
    assert ledger.validate_evidence([snippet])[0]['verdict'] == 'block'

    no_passage = _valid_evidence(quote_or_paraphrase='')
    verdict = ledger.validate_evidence([no_passage])[0]
    assert verdict['verdict'] == 'block'
    assert 'missing opened passage text' in verdict['reasons']

    with tempfile.TemporaryDirectory() as tmp:
        os.environ['RESEARCH_RUN_ROOT'] = tmp
        init = runmod.init_run('Verify Vendor X pricing', {'provider': 'local-corpus'})
        run_id = init['run']['run_id']

        try:
            runmod.record_evidence(run_id, _valid_evidence())
        except RuntimeError as exc:
            assert 'route effects have not been granted' in str(exc)
        else:
            raise AssertionError('record_evidence succeeded before route effects were granted')

        assert runmod.grant(run_id)['ready']
        try:
            runmod.acquire(run_id, 'Vendor X pricing', provider_name='browser', corpus=None, pattern='pricing', limit=1)
        except PermissionError as exc:
            assert 'not authorized by frozen route provider' in str(exc)
        else:
            raise AssertionError('acquire accepted provider override outside frozen route')

        del os.environ['RESEARCH_RUN_ROOT']

    print('OK: Research route effects and evidence admission are frozen-route bound')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
