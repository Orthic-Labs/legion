#!/usr/bin/env python3
"""Reconcile hook-metered effect receipts with the frozen run manifest."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def audit(manifest_doc: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    external = 0
    workers_started = 0
    workers_active = 0
    refusals = 0
    malformed = []

    for index, event in enumerate(events):
        if event.get('type') == 'budget.refused':
            refusals += 1
            continue
        if event.get('type') != 'budget.consumed':
            continue
        effect = event.get('effect')
        units = event.get('units', 1)
        if not isinstance(units, int) or units <= 0:
            malformed.append(f'event {index}: invalid units')
            continue
        if effect == 'external_request':
            external += units
        elif effect == 'worker':
            worker_event = event.get('worker_event')
            if worker_event == 'start':
                workers_started += units
                workers_active += units
            elif worker_event == 'finish':
                workers_active -= units
                if workers_active < 0:
                    malformed.append(f'event {index}: worker finish without active worker')
            else:
                malformed.append(f'event {index}: invalid worker_event')
        else:
            malformed.append(f'event {index}: unknown metered effect {effect!r}')

    usage = manifest_doc.get('usage', {})
    expected = {
        'external_requests': external,
        'workers_started': workers_started,
        'workers_active': workers_active,
    }
    mismatches = {
        key: {'manifest': usage.get(key), 'events': value}
        for key, value in expected.items() if usage.get(key) != value
    }
    budget = manifest_doc.get('budget', {})
    over_budget = {
        'external_requests': external > int(budget.get('external_requests', 0)),
        'workers_active': workers_active > int(budget.get('workers', 0)),
    }
    ok = not malformed and not mismatches and not any(over_budget.values())
    return {
        'ok': ok,
        'reason': 'ok' if ok else 'meter receipts do not reconcile with manifest usage',
        'event_usage': expected,
        'manifest_usage': usage,
        'mismatches': mismatches,
        'over_budget': over_budget,
        'refusals': refusals,
        'malformed': malformed,
    }
