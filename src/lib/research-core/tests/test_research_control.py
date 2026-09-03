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

control = importlib.import_module('control')
manifest = importlib.import_module('manifest')
route_resolve = importlib.import_module('route_resolve')


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['RESEARCH_RUN_ROOT'] = tmp
        route = route_resolve.resolve('Quickly research Vendor X pricing')
        run = manifest.create_run('Quickly research Vendor X pricing', route, budget={'external_requests': 12, 'workers': 1})
        run_id = run['run_id']

        decision = control.decide_stop(run_id, {
            'required_questions': ['price'],
            'answered_questions': ['price'],
            'consecutive_no_gain': 0,
            'blocking_gaps': [],
        })
        assert decision['reason'] == 'coverage-complete'
        assert (manifest.run_dir(run_id) / 'stopping.json').is_file()

        plan = control.init_shards(run_id, [
            {'key': 'pricing', 'payload': {'query': 'price'}},
            {'key': 'privacy', 'payload': {'query': 'privacy'}},
        ])
        first, second = [row['id'] for row in plan['shards']]
        control.checkpoint_shard(run_id, first, 'running')
        control.checkpoint_shard(run_id, first, 'done', {'evidence': 'pricing.jsonl'})
        control.checkpoint_shard(run_id, second, 'failed')
        assert [row['id'] for row in control.resume_shards(run_id)] == [second]
        assert (manifest.run_dir(run_id) / 'shards.json').is_file()
        del os.environ['RESEARCH_RUN_ROOT']

    print('OK: stopping and shard resume state persist in the run manifest/event substrate')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
