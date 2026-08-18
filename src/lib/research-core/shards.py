#!/usr/bin/env python3
"""Deterministic shard planning, checkpointing, resume, and ledger merge."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

VALID_STATES = {'pending', 'running', 'done', 'failed'}


def shard_id(run_id: str, key: str) -> str:
    digest = hashlib.sha256(f'{run_id}\0{key}'.encode('utf-8')).hexdigest()[:12]
    return f'shard-{digest}'


def plan(run_id: str, work_items: list[dict[str, Any]]) -> dict[str, Any]:
    seen = set()
    shards = []
    for item in work_items:
        key = str(item.get('key') or '').strip()
        if not key or key in seen:
            raise ValueError(f'missing or duplicate shard key: {key!r}')
        seen.add(key)
        shards.append({
            'id': shard_id(run_id, key),
            'key': key,
            'payload': item.get('payload') or {},
            'status': 'pending',
            'attempts': 0,
            'artifacts': {},
        })
    return {'schema_version': 1, 'run_id': run_id, 'shards': shards}


def checkpoint(plan_doc: dict[str, Any], shard: str, status: str, *, artifacts: dict[str, str] | None = None) -> dict[str, Any]:
    if status not in VALID_STATES:
        raise ValueError(f'invalid shard status: {status}')
    rows = [row for row in plan_doc['shards'] if row['id'] == shard]
    if len(rows) != 1:
        raise KeyError(f'unknown shard: {shard}')
    row = rows[0]
    if status == 'running':
        row['attempts'] += 1
    row['status'] = status
    if artifacts:
        row['artifacts'].update(artifacts)
    return plan_doc


def resumable(plan_doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in plan_doc['shards'] if row['status'] in {'pending', 'failed'}]


def merge_jsonl(paths: list[Path], output: Path, *, id_field: str = 'id') -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    seen: dict[str, Path] = {}
    for path in paths:
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            key = str(row.get(id_field) or '')
            if not key:
                raise ValueError(f'{path}:{number}: missing {id_field}')
            if key in seen:
                raise ValueError(f'duplicate {id_field} {key!r} in {seen[key]} and {path}')
            seen[key] = path
            rows.append(row)
    rows.sort(key=lambda row: str(row[id_field]))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
    return {
        'rows': len(rows),
        'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
        'output': str(output),
    }
