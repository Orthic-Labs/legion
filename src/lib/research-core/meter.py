#!/usr/bin/env python3
"""Research-internal meter for external requests & worker lifecycles."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def _load_manifest_module(workspace: Path):
    core = workspace / 'src' / 'lib' / 'research-core'
    sys.path.insert(0, str(core))
    path = core / 'manifest.py'
    name = 'research_manifest_' + __import__('hashlib').sha256(str(path).encode()).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load Research manifest module: {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def consume(workspace: Path, run_id: str, effect: str, *, units: int = 1, worker_event: str | None = None) -> dict:
    manifest_mod = _load_manifest_module(workspace)
    root = manifest_mod.default_run_root()

    def apply(m: dict) -> None:
        usage = m['usage']
        budget = m['budget']
        if effect == 'external_request':
            proposed = usage['external_requests'] + units
            if proposed > budget['external_requests']:
                raise RuntimeError(f"research budget exceeded: external_requests {proposed} > {budget['external_requests']}")
            usage['external_requests'] = proposed
        elif effect == 'worker':
            if worker_event == 'start':
                proposed = usage['workers_active'] + units
                if proposed > budget['workers']:
                    raise RuntimeError(f"research budget exceeded: workers_active {proposed} > {budget['workers']}")
                usage['workers_active'] = proposed
                usage['workers_started'] += units
            elif worker_event == 'finish':
                usage['workers_active'] = max(0, usage['workers_active'] - units)
            else:
                raise ValueError('worker effect requires worker_event=start|finish')
        else:
            raise ValueError(f'unknown metered effect: {effect}')

    try:
        updated = manifest_mod.mutate_run(run_id, apply, root)
    except RuntimeError as exc:
        manifest_mod.set_stage(run_id, 'acquire', 'blocked', detail='budget', root=root)
        manifest_mod.record_event(run_id, 'budget.refused', {'effect': effect, 'units': units, 'reason': str(exc)}, root)
        return {'ok': False, 'reason': str(exc)}
    manifest_mod.record_event(run_id, 'budget.consumed', {'effect': effect, 'units': units, 'worker_event': worker_event}, root)
    return {'ok': True, 'usage': updated['usage'], 'budget': updated['budget']}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--workspace', required=True)
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--effect', choices=['external_request', 'worker'], required=True)
    ap.add_argument('--units', type=int, default=1)
    ap.add_argument('--worker-event', choices=['start', 'finish'])
    args = ap.parse_args(argv)
    result = consume(Path(args.workspace).resolve(), args.run_id, args.effect, units=args.units, worker_event=args.worker_event)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
