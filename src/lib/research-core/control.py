#!/usr/bin/env python3
"""Durable acquisition control: adaptive stopping and resumable shards."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import manifest  # noqa: E402
import shards  # noqa: E402
import stopping  # noqa: E402
from common import atomic_write_json  # noqa: E402


def decide_stop(run_id: str, payload: dict) -> dict:
    run = manifest.load_run(run_id)
    payload = dict(payload)
    payload['external_requests_used'] = run['usage']['external_requests']
    payload['external_requests_budget'] = run['budget']['external_requests']
    decision = stopping.decide(**payload)
    path = manifest.run_dir(run_id) / 'stopping.json'
    atomic_write_json(path, decision)
    manifest.attach_artifact(run_id, 'stopping-decision', str(path))
    manifest.record_event(run_id, 'stopping.decided', decision)
    if decision['action'] == 'stop':
        manifest.set_stage(
            run_id,
            'acquire',
            'done' if decision['complete'] else 'blocked',
            detail=None if decision['complete'] else decision['reason'],
        )
    return decision


def init_shards(run_id: str, work_items: list[dict]) -> dict:
    plan = shards.plan(run_id, work_items)
    path = manifest.run_dir(run_id) / 'shards.json'
    atomic_write_json(path, plan)
    manifest.attach_artifact(run_id, 'shard-plan', str(path))
    manifest.record_event(run_id, 'shards.planned', {'count': len(plan['shards'])})
    return plan


def checkpoint_shard(run_id: str, shard_id: str, status: str, artifacts: dict | None = None) -> dict:
    path = manifest.run_dir(run_id) / 'shards.json'
    plan = json.loads(path.read_text(encoding='utf-8'))
    shards.checkpoint(plan, shard_id, status, artifacts=artifacts)
    atomic_write_json(path, plan)
    manifest.record_event(run_id, 'shard.checkpoint', {'shard_id': shard_id, 'status': status, 'artifacts': artifacts or {}})
    return plan


def resume_shards(run_id: str) -> list[dict]:
    path = manifest.run_dir(run_id) / 'shards.json'
    plan = json.loads(path.read_text(encoding='utf-8'))
    rows = shards.resumable(plan)
    manifest.record_event(run_id, 'shards.resumed', {'shard_ids': [row['id'] for row in rows]})
    return rows


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('stop')
    p.add_argument('--run-id', required=True)
    p.add_argument('--input', required=True)
    p = sub.add_parser('shard-init')
    p.add_argument('--run-id', required=True)
    p.add_argument('--input', required=True)
    p = sub.add_parser('shard-checkpoint')
    p.add_argument('--run-id', required=True)
    p.add_argument('--shard-id', required=True)
    p.add_argument('--status', required=True)
    p.add_argument('--artifacts')
    p = sub.add_parser('shard-resume')
    p.add_argument('--run-id', required=True)
    args = parser.parse_args(argv)

    if args.cmd == 'stop':
        result = decide_stop(args.run_id, json.loads(Path(args.input).read_text(encoding='utf-8')))
    elif args.cmd == 'shard-init':
        result = init_shards(args.run_id, json.loads(Path(args.input).read_text(encoding='utf-8')))
    elif args.cmd == 'shard-checkpoint':
        artifacts = json.loads(Path(args.artifacts).read_text(encoding='utf-8')) if args.artifacts else None
        result = checkpoint_shard(args.run_id, args.shard_id, args.status, artifacts)
    else:
        result = resume_shards(args.run_id)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
