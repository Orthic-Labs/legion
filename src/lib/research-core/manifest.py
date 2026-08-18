#!/usr/bin/env python3
"""Durable Research run state, exact resume, approvals, events, and receipts."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import append_jsonl, atomic_write_json, file_lock, read_json, sha256_text, utc_now  # noqa: E402

MANIFEST_VERSION = 2
DEFAULT_STAGES = (
    'route', 'acquire', 'normalize', 'challenge', 'synthesize',
    'citecheck', 'retraction', 'patch', 'ship',
)
STAGE_STATUSES = {'pending', 'running', 'done', 'skipped', 'blocked', 'failed'}
RUN_STATUSES = {'running', 'blocked', 'failed', 'done', 'aborted'}


def default_run_root() -> Path:
    override = os.environ.get('RESEARCH_RUN_ROOT')
    return Path(override).expanduser().resolve() if override else HERE / 'runs'


def new_run_id(query: str) -> str:
    return f"run-{utc_now()[:10]}-{sha256_text(query)[:8]}-{secrets.token_hex(3)}"


def run_dir(run_id: str, root: Path | None = None) -> Path:
    if not run_id or '/' in run_id or '\\' in run_id or run_id.startswith('.'):
        raise ValueError(f'invalid run id: {run_id!r}')
    return (root or default_run_root()) / run_id


def _paths(run_id: str, root: Path | None = None) -> tuple[Path, Path, Path]:
    directory = run_dir(run_id, root)
    return directory / 'manifest.json', directory / 'events.jsonl', directory / 'receipt.json'


def create_run(query: str, route: dict[str, Any], *, budget: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    rid = new_run_id(query)
    mpath, epath, _ = _paths(rid, root)
    directory = mpath.parent
    directory.mkdir(parents=True, exist_ok=False)
    query_text = query.rstrip() + '\n'
    (directory / 'query.md').write_text(query_text, encoding='utf-8', newline='\n')
    now = utc_now()
    manifest = {
        'manifest_version': MANIFEST_VERSION,
        'run_id': rid,
        'query_sha256': sha256_text(query_text),
        'route': route,
        'route_sha256': sha256_text(json.dumps(route, sort_keys=True, separators=(',', ':'))),
        'status': 'running',
        'blocked_on': [],
        'created_at': now,
        'updated_at': now,
        'budget': {
            'external_requests': int(budget.get('external_requests', 12)),
            'workers': int(budget.get('workers', 1)),
        },
        'usage': {'external_requests': 0, 'workers_started': 0, 'workers_active': 0},
        'approvals': {},
        'stages': {name: {'status': 'pending'} for name in DEFAULT_STAGES},
        'artifacts': {},
        'failures': [],
    }
    manifest['stages']['route'] = {'status': 'done', 'started_at': now, 'finished_at': now}
    atomic_write_json(mpath, manifest)
    append_jsonl(epath, {'at': now, 'type': 'run.created', 'run_id': rid, 'query_sha256': manifest['query_sha256']})
    return manifest


def load_run(run_id: str, root: Path | None = None) -> dict[str, Any]:
    mpath, _, _ = _paths(run_id, root)
    manifest = read_json(mpath)
    if manifest.get('manifest_version') != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version: {manifest.get('manifest_version')!r}")
    return manifest


def save_run(manifest: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    rid = manifest['run_id']
    mpath, _, _ = _paths(rid, root)
    manifest['updated_at'] = utc_now()
    atomic_write_json(mpath, manifest)
    return manifest


def mutate_run(run_id: str, fn, root: Path | None = None) -> dict[str, Any]:
    mpath, _, _ = _paths(run_id, root)
    with file_lock(mpath):
        manifest = load_run(run_id, root)
        fn(manifest)
        return save_run(manifest, root)


def record_event(run_id: str, event_type: str, payload: dict[str, Any] | None = None, root: Path | None = None) -> None:
    _, epath, _ = _paths(run_id, root)
    with file_lock(epath):
        append_jsonl(epath, {'at': utc_now(), 'type': event_type, 'run_id': run_id, **(payload or {})})


def approve(run_id: str, gate: str, approval_text: str, *, actor: str = 'user', root: Path | None = None) -> dict[str, Any]:
    if not gate or not approval_text.strip():
        raise ValueError('gate and non-empty approval text are required')

    def apply(m: dict[str, Any]) -> None:
        m['approvals'][gate] = {
            'actor': actor,
            'text': approval_text.strip(),
            'approved_at': utc_now(),
        }
        m['blocked_on'] = [x for x in m.get('blocked_on', []) if x != gate]
        if m['status'] == 'blocked' and not m['blocked_on']:
            m['status'] = 'running'

    out = mutate_run(run_id, apply, root)
    record_event(run_id, 'gate.approved', {'gate': gate, 'actor': actor}, root)
    return out


def set_stage(run_id: str, stage: str, status: str, *, detail: str | None = None, root: Path | None = None) -> dict[str, Any]:
    if status not in STAGE_STATUSES:
        raise ValueError(f'invalid stage status: {status}')

    def apply(m: dict[str, Any]) -> None:
        if stage not in m['stages']:
            m['stages'][stage] = {'status': 'pending'}
        entry = m['stages'][stage]
        entry['status'] = status
        if status == 'running' and 'started_at' not in entry:
            entry['started_at'] = utc_now()
        if status in {'done', 'skipped', 'blocked', 'failed'}:
            entry['finished_at'] = utc_now()
        if detail:
            entry['detail'] = detail
        if status == 'blocked':
            m['status'] = 'blocked'
            if detail and detail not in m['blocked_on']:
                m['blocked_on'].append(detail)
        elif status == 'failed':
            m['status'] = 'failed'
            m['failures'].append({'stage': stage, 'detail': detail or 'failed', 'at': utc_now()})

    out = mutate_run(run_id, apply, root)
    record_event(run_id, 'stage.changed', {'stage': stage, 'status': status, 'detail': detail}, root)
    return out


def attach_artifact(run_id: str, name: str, path: str, *, sha256: str | None = None, root: Path | None = None) -> dict[str, Any]:
    def apply(m: dict[str, Any]) -> None:
        m['artifacts'][name] = {'path': path, 'sha256': sha256, 'recorded_at': utc_now()}
    out = mutate_run(run_id, apply, root)
    record_event(run_id, 'artifact.recorded', {'name': name, 'path': path, 'sha256': sha256}, root)
    return out


def resume_position(manifest: dict[str, Any]) -> dict[str, Any]:
    ordered = list(DEFAULT_STAGES) + [s for s in manifest['stages'] if s not in DEFAULT_STAGES]
    remaining = [s for s in ordered if manifest['stages'][s]['status'] not in {'done', 'skipped'}]
    return {
        'next_stage': remaining[0] if remaining else None,
        'remaining': remaining,
        'blocked_on': list(manifest.get('blocked_on', [])),
    }


def finalize(run_id: str, *, verdict: str, checks: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    if verdict not in {'ship', 'block', 'degraded'}:
        raise ValueError('verdict must be ship, block, or degraded')
    mpath, epath, rpath = _paths(run_id, root)
    with file_lock(mpath):
        manifest = load_run(run_id, root)
        manifest['status'] = 'done' if verdict in {'ship', 'degraded'} else 'blocked'
        manifest['updated_at'] = utc_now()
        if verdict == 'block' and 'ship-gate' not in manifest['blocked_on']:
            manifest['blocked_on'].append('ship-gate')
        atomic_write_json(mpath, manifest)
        receipt = {
            'receipt_version': 1,
            'run_id': run_id,
            'query_sha256': manifest['query_sha256'],
            'route_sha256': manifest['route_sha256'],
            'verdict': verdict,
            'checks': checks,
            'usage': manifest['usage'],
            'budget': manifest['budget'],
            'approvals': manifest['approvals'],
            'artifacts': manifest['artifacts'],
            'events_path': str(epath),
            'issued_at': utc_now(),
        }
        atomic_write_json(rpath, receipt)
    record_event(run_id, 'run.finalized', {'verdict': verdict}, root)
    return receipt


def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', default=None)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('init')
    p.add_argument('--query', required=True)
    p.add_argument('--route', required=True)
    p.add_argument('--external-requests', type=int, default=12)
    p.add_argument('--workers', type=int, default=1)

    p = sub.add_parser('status')
    p.add_argument('--run-id', required=True)

    p = sub.add_parser('approve')
    p.add_argument('--run-id', required=True)
    p.add_argument('--gate', required=True)
    p.add_argument('--text', required=True)

    p = sub.add_parser('stage')
    p.add_argument('--run-id', required=True)
    p.add_argument('--stage', required=True)
    p.add_argument('--status', required=True)
    p.add_argument('--detail')

    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else None
    if args.cmd == 'init':
        route = json.loads(Path(args.route).read_text(encoding='utf-8'))
        result = create_run(args.query, route, budget={'external_requests': args.external_requests, 'workers': args.workers}, root=root)
    elif args.cmd == 'status':
        result = load_run(args.run_id, root)
        result['resume'] = resume_position(result)
    elif args.cmd == 'approve':
        result = approve(args.run_id, args.gate, args.text, root=root)
    else:
        result = set_stage(args.run_id, args.stage, args.status, detail=args.detail, root=root)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(_cli(sys.argv[1:]))
