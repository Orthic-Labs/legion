#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'shards.py'
spec = importlib.util.spec_from_file_location('research_shards', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


def main() -> int:
    plan = shards.plan('run-1', [
        {'key': 'pricing', 'payload': {'query': 'price'}},
        {'key': 'privacy', 'payload': {'query': 'privacy'}},
    ])
    assert [row['id'] for row in plan['shards']] == [
        shards.shard_id('run-1', 'pricing'), shards.shard_id('run-1', 'privacy')
    ]
    first = plan['shards'][0]['id']
    second = plan['shards'][1]['id']
    shards.checkpoint(plan, first, 'running')
    shards.checkpoint(plan, first, 'done', artifacts={'evidence': 'pricing.jsonl'})
    shards.checkpoint(plan, second, 'running')
    shards.checkpoint(plan, second, 'failed')
    assert [row['id'] for row in shards.resumable(plan)] == [second]
    assert plan['shards'][0]['attempts'] == 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        one = root / 'one.jsonl'
        two = root / 'two.jsonl'
        out = root / 'merged.jsonl'
        one.write_text(json.dumps({'id': 'b', 'value': 2}) + '\n', encoding='utf-8')
        two.write_text(json.dumps({'id': 'a', 'value': 1}) + '\n', encoding='utf-8')
        receipt = shards.merge_jsonl([one, two], out)
        assert receipt['rows'] == 2
        assert [json.loads(line)['id'] for line in out.read_text(encoding='utf-8').splitlines()] == ['a', 'b']
        two.write_text(json.dumps({'id': 'b', 'value': 3}) + '\n', encoding='utf-8')
        try:
            shards.merge_jsonl([one, two], out)
        except ValueError as exc:
            assert 'duplicate id' in str(exc)
        else:
            raise AssertionError('duplicate shard rows were not rejected')

    print('OK: shards are deterministic, resumable, and merge without duplicate ledger ids')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
