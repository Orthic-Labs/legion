from __future__ import annotations

import sys
from pathlib import Path

CORE = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE))
sys.path.insert(0, str(CORE / 'providers'))

import effects
import meter
import patch_guard
import run
import resource_guard
from providers import search_open_find


def test_non_research_tools_have_no_effect_classification():
    assert not effects.is_external('Read')
    assert not effects.is_worker('Read')


def test_run_and_provider_use_core_meter(monkeypatch):
    calls: list[tuple[str, str, str | None]] = []

    def consume(workspace, run_id, effect, *, units=1, worker_event=None):
        calls.append((run_id, effect, worker_event))
        return {'ok': True}

    monkeypatch.setattr(meter, 'consume', consume)
    assert run.meter_worker('run-direct', 'start')['ok']
    search_open_find.meter('run-provider', 'external_request')
    assert calls == [('run-direct', 'worker', 'start'), ('run-provider', 'external_request', None)]


def test_resource_guard_and_patch_receipt_remain_internal(tmp_path):
    source = tmp_path / 'source.md'
    source.write_text('sourced draft\n', encoding='utf-8')
    verdict = resource_guard.authorize({'forbidden_resources': ['private/**']}, source, tmp_path)
    assert verdict['ok']
    receipt = patch_guard.issue_receipt(source, 'run-parity', key_path=tmp_path / 'key')
    assert receipt['issued_by'] == 'research-core.patch-guard'
    assert receipt['signature'].startswith('hmac-sha256:')
