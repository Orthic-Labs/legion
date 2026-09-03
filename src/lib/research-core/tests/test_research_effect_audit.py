#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'effect_audit.py'
spec = importlib.util.spec_from_file_location('research_effect_audit', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
effect_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(effect_audit)


def main() -> int:
    manifest = {
        'usage': {'external_requests': 2, 'workers_started': 1, 'workers_active': 0},
        'budget': {'external_requests': 12, 'workers': 1},
    }
    events = [
        {'type': 'budget.consumed', 'effect': 'external_request', 'units': 1},
        {'type': 'budget.consumed', 'effect': 'external_request', 'units': 1},
        {'type': 'budget.consumed', 'effect': 'worker', 'worker_event': 'start', 'units': 1},
        {'type': 'budget.consumed', 'effect': 'worker', 'worker_event': 'finish', 'units': 1},
    ]
    assert effect_audit.audit(manifest, events)['ok']

    tampered = {**manifest, 'usage': {**manifest['usage'], 'external_requests': 1}}
    result = effect_audit.audit(tampered, events)
    assert not result['ok'] and 'external_requests' in result['mismatches']

    malformed = effect_audit.audit(manifest, events + [
        {'type': 'budget.consumed', 'effect': 'worker', 'worker_event': 'finish', 'units': 1},
    ])
    assert not malformed['ok'] and malformed['malformed']

    print('OK: hook effect receipts reconcile with manifest usage and budgets')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
