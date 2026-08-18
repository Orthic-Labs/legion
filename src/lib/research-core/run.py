#!/usr/bin/env python3
"""Research Core run orchestrator.

This CLI makes the runbook executable without hiding model work inside prose. It owns
route freezing, approval resumption, provider calls, manifests, verification gates,
and the final receipt. Synthesis itself may be performed by the host agent, but it must
write evidence.jsonl, claims.jsonl, and draft.md into the run directory before verify.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'router'))
sys.path.insert(0, str(HERE / 'providers'))

import manifest  # noqa: E402
import ledger  # noqa: E402
import citecheck  # noqa: E402
import contradictions  # noqa: E402
import gap_critic  # noqa: E402
import domain_verify  # noqa: E402
import retraction  # noqa: E402
import patcher  # noqa: E402
import draft_integrity  # noqa: E402
import effect_audit  # noqa: E402
import meter as research_meter  # noqa: E402
import patch_guard  # noqa: E402
import query as query_contract  # noqa: E402
from common import append_jsonl  # noqa: E402
from router.route_resolve import gate_verdicts, grant_effects, resolve  # type: ignore  # noqa: E402
from providers.search_open_find import provider as get_provider, meter  # type: ignore  # noqa: E402


def _run_dir(run_id: str) -> Path:
    return manifest.run_dir(run_id)


def _write_json(path: Path, value: Any) -> None:
    from common import atomic_write_json
    atomic_write_json(path, value)


def _check_effects(route: dict[str, Any], *effects: str) -> None:
    allowed = set(route.get('allowed_effects') or [])
    missing = [effect for effect in effects if effect not in allowed]
    if missing:
        raise PermissionError(f'frozen route does not grant effects: {missing}')


def _require_granted(run_id: str, *effects: str) -> dict[str, Any]:
    run = manifest.load_run(run_id)
    route = run.get('route', {})
    if not route.get('allowed_effects'):
        raise RuntimeError('route effects have not been granted')
    _check_effects(route, *effects)
    return run


def _default_search_provider(route: dict[str, Any]) -> str:
    if route['provider'] == 'domain-default':
        if route['domain'] in {'medical', 'scientific'}:
            return 'scholarly'
        if route['domain'] == 'legal':
            return 'legal-authority'
        return 'browser'
    return route['provider']


def _resolve_acquire_provider(route: dict[str, Any], requested: str | None) -> str:
    selected = requested or route['provider']
    default = _default_search_provider(route)
    allowed = {route['provider'], default}
    if route['provider'] == 'domain-default':
        allowed.add('domain-default')
    if selected == 'domain-default':
        selected = default
    if selected not in allowed:
        raise PermissionError(
            f"provider {selected!r} is not authorized by frozen route provider {route['provider']!r}"
        )
    if selected == 'notebooklm':
        raise PermissionError(
            'NotebookLM does not expose search/open/find; answers remain leads until '
            'their underlying sources are opened through an authorized provider'
        )
    return selected


def init_run(intent: str, context: dict[str, Any]) -> dict[str, Any]:
    route = resolve(intent, context=context)
    scale_budgets = {
        'focused': {'external_requests': 12, 'workers': 1},
        'broad': {'external_requests': 30, 'workers': 4},
    }
    if route['scale'] == 'dossier':
        budget = context.get('budget') or {}
        if not budget.get('external_requests') or budget.get('workers') is None:
            raise ValueError('dossier routes require context.budget.external_requests and context.budget.workers')
    else:
        budget = scale_budgets[route['scale']]
    run = manifest.create_run(intent, route, budget=budget)
    directory = _run_dir(run['run_id'])
    query_contract.persist(directory, intent, context.get('wrapper_contract'))
    _write_json(directory / 'route.json', route)
    return {'run': run, 'route': route, 'gate_verdicts': gate_verdicts(route)}


def grant(run_id: str) -> dict[str, Any]:
    run = manifest.load_run(run_id)
    route = run['route']
    granted, verdicts = grant_effects(route, run.get('approvals'))
    if not granted['allowed_effects']:
        pending = [v['gate'] for v in verdicts if v['verdict'] != 'ok']
        manifest.set_stage(run_id, 'route', 'blocked', detail=','.join(pending) or 'route-gate')
        return {'ready': False, 'route': granted, 'gate_verdicts': verdicts, 'pending': pending}

    def apply(m: dict[str, Any]) -> None:
        m['route'] = granted
        m['route_sha256'] = hashlib.sha256(json.dumps(granted, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        m['stages']['route']['status'] = 'done'
        m['blocked_on'] = []
        m['status'] = 'running'
    manifest.mutate_run(run_id, apply)
    _write_json(_run_dir(run_id) / 'route.json', granted)
    manifest.record_event(run_id, 'route.effects-granted', {'effects': granted['allowed_effects']})
    return {'ready': True, 'route': granted, 'gate_verdicts': verdicts}


def meter_worker(run_id: str, event: str, *, units: int = 1) -> dict[str, Any]:
    return research_meter.consume(WORKSPACE, run_id, 'worker', units=units, worker_event=event)


def acquire(run_id: str, query: str, *, provider_name: str | None, corpus: str | None, pattern: str | None, limit: int) -> dict[str, Any]:
    run = _require_granted(run_id, 'search', 'extract')
    route = run['route']
    name = _resolve_acquire_provider(route, provider_name)
    impl = get_provider(name, corpus=corpus)
    if name == 'local-corpus':
        _check_effects(route, 'read-local')
    external_ops = set(getattr(impl, 'external_ops', ()))
    if 'open' in external_ops:
        _check_effects(route, 'fetch')
    manifest.set_stage(run_id, 'acquire', 'running')
    if 'search' in external_ops:
        meter(run_id, 'external_request')
    hits = impl.search(query, limit=limit, seed_chain=[])
    rows = []
    for hit in hits:
        if 'open' in external_ops:
            meter(run_id, 'external_request')
        opened = impl.open(hit.url)
        if 'find' in external_ops:
            meter(run_id, 'external_request')
        located = impl.find(opened, pattern or query)
        rows.append({
            'hit': hit.to_dict(),
            'opened': opened.to_dict(),
            'located': located.to_dict() if located else None,
        })
    _write_json(_run_dir(run_id) / 'acquisition.json', rows)
    manifest.attach_artifact(run_id, 'acquisition', str(_run_dir(run_id) / 'acquisition.json'))
    manifest.set_stage(run_id, 'acquire', 'done')
    return {'provider': name, 'results': rows}


def record_evidence(run_id: str, row: dict[str, Any]) -> dict[str, Any]:
    _require_granted(run_id, 'extract')
    directory = _run_dir(run_id)
    path = directory / 'evidence.jsonl'
    existing = ledger.parse_jsonl(path) if path.exists() else []
    if any(str(item.get('id')) == str(row.get('id')) for item in existing):
        raise ValueError(f"duplicate evidence id: {row.get('id')!r}")
    verdict = ledger.validate_evidence([row])[0]
    if verdict['verdict'] != 'ok':
        raise ValueError(f"evidence record blocked: {verdict['reasons']}")
    append_jsonl(path, row)
    manifest.attach_artifact(run_id, 'evidence-ledger', str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return row


def record_claim(run_id: str, row: dict[str, Any]) -> dict[str, Any]:
    _require_granted(run_id, 'synthesize')
    directory = _run_dir(run_id)
    path = directory / 'claims.jsonl'
    existing = ledger.parse_jsonl(path) if path.exists() else []
    if any(str(item.get('id')) == str(row.get('id')) for item in existing):
        raise ValueError(f"duplicate claim id: {row.get('id')!r}")
    evidence = ledger.parse_jsonl(directory / 'evidence.jsonl') if (directory / 'evidence.jsonl').exists() else []
    result = ledger.check(evidence, existing + [row])
    blocks = [v for v in result['verdicts'] if v.get('id') == row.get('id') and v.get('verdict') == 'block']
    if blocks:
        raise ValueError(f"claim record blocked: {blocks}")
    normalized = next(item for item in result['claims'] if str(item.get('id')) == str(row.get('id')))
    append_jsonl(path, normalized)
    manifest.attach_artifact(run_id, 'claim-ledger', str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return normalized


def render_draft(run_id: str, *, title: str = 'Research brief') -> dict[str, Any]:
    _require_granted(run_id, 'synthesize', 'write-output')
    directory = _run_dir(run_id)
    evidence = ledger.parse_jsonl(directory / 'evidence.jsonl')
    claims = ledger.parse_jsonl(directory / 'claims.jsonl')
    draft = ledger.render(evidence, claims, title=title)
    path = directory / 'draft.md'
    path.write_text(draft, encoding='utf-8', newline='\n')
    manifest.set_stage(run_id, 'synthesize', 'done')
    manifest.attach_artifact(run_id, 'sourced-draft', str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def issue_patch_receipt(run_id: str, *, key_file: str | None = None) -> dict[str, Any]:
    _require_granted(run_id, 'patch-sourced-draft')
    directory = _run_dir(run_id)
    draft = directory / 'draft.md'
    if not draft.exists():
        raise FileNotFoundError('draft.md does not exist')
    receipt = patch_guard.issue_receipt(draft, run_id, key_path=Path(key_file) if key_file else None)
    path = directory / 'patch-receipt.json'
    _write_json(path, receipt)
    manifest.attach_artifact(run_id, 'patch-receipt', str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return receipt


def apply_draft_patch(run_id: str, diff_path: str, *, key_file: str | None = None) -> dict[str, Any]:
    _require_granted(run_id, 'patch-sourced-draft')
    directory = _run_dir(run_id)
    source = directory / 'draft.md'
    receipt_path = directory / 'patch-receipt.json'
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    source_bytes = source.read_bytes()
    ok, reason = patcher.validate_correction_receipt(
        receipt, source_bytes=source_bytes, key_path=Path(key_file) if key_file else None,
    )
    if not ok:
        raise ValueError(reason)
    diff = Path(diff_path).read_text(encoding='utf-8')
    result = patcher.apply_patch(
        source_bytes.decode('utf-8'), diff,
        max_hunks=int(receipt.get('max_hunks', patcher.DEFAULT_MAX_HUNKS)),
        max_hunk_bytes=int(receipt.get('max_hunk_bytes', patcher.DEFAULT_MAX_HUNK_BYTES)),
    )
    if not result['ok']:
        manifest.set_stage(run_id, 'patch', 'failed', detail=str(result.get('reason')))
        return result
    source.write_text(result['output'], encoding='utf-8', newline='\n')
    saved_diff = directory / 'applied.patch'
    saved_diff.write_text(diff, encoding='utf-8', newline='\n')
    manifest.set_stage(run_id, 'patch', 'done')
    manifest.attach_artifact(run_id, 'patch-diff', str(saved_diff), sha256=hashlib.sha256(saved_diff.read_bytes()).hexdigest())
    manifest.attach_artifact(run_id, 'patched-draft', str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    return {k: v for k, v in result.items() if k != 'output'}


def _dois(evidence: list[dict[str, Any]]) -> list[str]:
    return [str(e['doi']) for e in evidence if e.get('doi')]


def _effect_integrity(run_id: str, directory: Path) -> dict[str, Any]:
    return effect_audit.audit(manifest.load_run(run_id), effect_audit.read_events(directory / 'events.jsonl'))


def verify(run_id: str, *, allow_unknown_retractions: bool = False) -> dict[str, Any]:
    run = _require_granted(run_id)
    directory = _run_dir(run_id)
    route = run['route']
    evidence_path = directory / 'evidence.jsonl'
    claims_path = directory / 'claims.jsonl'
    draft_path = directory / 'draft.md'
    for path in (evidence_path, claims_path, draft_path):
        if not path.exists():
            raise FileNotFoundError(f'missing required run artifact: {path.name}')
    evidence = ledger.parse_jsonl(evidence_path)
    claims = ledger.parse_jsonl(claims_path)

    manifest.set_stage(run_id, 'normalize', 'running')
    ledger_result = ledger.check(evidence, claims)
    _write_json(directory / 'ledger-check.json', ledger_result)
    if not ledger_result['overall_ok']:
        manifest.set_stage(run_id, 'normalize', 'failed', detail='ledger-block')
        return {'ok': False, 'stage': 'ledger', 'ledger': ledger_result}
    evidence, claims = ledger_result['evidence'], ledger_result['claims']
    evidence_path.write_text(''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in evidence), encoding='utf-8')
    claims_path.write_text(''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in claims), encoding='utf-8')
    manifest.set_stage(run_id, 'normalize', 'done')

    manifest.set_stage(run_id, 'challenge', 'running')
    views = contradictions.derive(claims, evidence)
    _write_json(directory / 'contradictions.json', views)
    gap = gap_critic.review(claims, evidence, views) if route['assurance'] == 'verified' else {'complete': True, 'findings': [], 'targeted_queries': []}
    _write_json(directory / 'gap-review.json', gap)
    manifest.set_stage(run_id, 'challenge', 'done' if gap['complete'] else 'blocked', detail=None if gap['complete'] else 'gap-fetch-required')

    domain = domain_verify.verify(route, evidence, claims)
    _write_json(directory / 'domain-verification.json', domain)

    if route['assurance'] in {'standard', 'verified'}:
        _check_effects(route, 'citecheck')
        manifest.set_stage(run_id, 'citecheck', 'running')
        citations = citecheck.check(draft_path.read_text(encoding='utf-8'), evidence)
        _write_json(directory / 'citation-binding.json', citations)
        manifest.set_stage(run_id, 'citecheck', 'done' if citations['ok'] else 'failed', detail=None if citations['ok'] else 'citation-binding')
    else:
        citations = {
            'ok': True,
            'skipped': True,
            'reason': 'citecheck not granted for quick assurance',
            'summary': {'pairs': 0, 'unbound': 0, 'dangling': 0, 'unsupported_or_partial': 0},
            'pairs': [], 'unbound': [], 'dangling': [], 'unsupported': [],
        }
        _write_json(directory / 'citation-binding.json', citations)
        manifest.set_stage(run_id, 'citecheck', 'skipped', detail='quick-assurance')

    retract = {'dois_checked': 0, 'results': [], 'block_brief': False, 'unknown_count': 0}
    if route['assurance'] == 'verified':
        _check_effects(route, 'retraction-check', 'patch-sourced-draft')
        manifest.set_stage(run_id, 'retraction', 'running')
        if _dois(evidence):
            retract = retraction.sweep(
                _dois(evidence),
                disclosed=[str(e['doi']) for e in evidence if e.get('doi') and e.get('retraction_disclosed')],
                block_unknown=not allow_unknown_retractions,
            )
        _write_json(directory / 'retraction.json', retract)
        manifest.set_stage(run_id, 'retraction', 'done' if not retract['block_brief'] else 'failed', detail=None if not retract['block_brief'] else 'retraction')
    else:
        manifest.set_stage(run_id, 'retraction', 'skipped')

    if route['assurance'] != 'verified':
        manifest.set_stage(run_id, 'patch', 'skipped')
    elif (directory / 'applied.patch').exists():
        manifest.set_stage(run_id, 'patch', 'done')
    else:
        manifest.set_stage(run_id, 'patch', 'skipped', detail='no correction requested')

    integrity = draft_integrity.check(directory, manifest.load_run(run_id))
    effects = _effect_integrity(run_id, directory)
    _write_json(directory / 'draft-integrity.json', integrity)
    _write_json(directory / 'effect-audit.json', effects)
    checks = {
        'ledger': ledger_result['overall_ok'],
        'domain': domain['ok'],
        'citations': citations['ok'],
        'retraction': not retract['block_brief'],
        'gaps_complete': gap['complete'],
        'draft_integrity': integrity['ok'],
        'effect_accounting': effects['ok'],
    }
    ok = all(checks.values())
    _write_json(directory / 'ship-checks.json', checks)
    for name in ('ledger-check', 'contradictions', 'gap-review', 'domain-verification', 'citation-binding', 'retraction', 'draft-integrity', 'effect-audit', 'ship-checks'):
        path = directory / f'{name}.json'
        if path.exists():
            manifest.attach_artifact(run_id, name, str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'ok': ok, 'checks': checks, 'ledger': ledger_result, 'domain': domain, 'citations': citations, 'retraction': retract, 'gap': gap, 'draft_integrity': integrity, 'effect_audit': effects}


def finalize(run_id: str) -> dict[str, Any]:
    _require_granted(run_id, 'write-output')
    directory = _run_dir(run_id)
    checks = json.loads((directory / 'ship-checks.json').read_text(encoding='utf-8'))
    integrity = draft_integrity.check(directory, manifest.load_run(run_id))
    effects = _effect_integrity(run_id, directory)
    _write_json(directory / 'draft-integrity.json', integrity)
    _write_json(directory / 'effect-audit.json', effects)
    checks['draft_integrity'] = integrity['ok']
    checks['effect_accounting'] = effects['ok']
    _write_json(directory / 'ship-checks.json', checks)
    verdict = 'ship' if all(checks.values()) else 'block'
    manifest.set_stage(run_id, 'ship', 'done' if verdict == 'ship' else 'blocked', detail=None if verdict == 'ship' else 'ship-gate')
    return manifest.finalize(run_id, verdict=verdict, checks=checks)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('init')
    p.add_argument('--intent', required=True)
    p.add_argument('--context')
    p = sub.add_parser('approve')
    p.add_argument('--run-id', required=True)
    p.add_argument('--gate', required=True)
    p.add_argument('--text', required=True)
    p = sub.add_parser('grant')
    p.add_argument('--run-id', required=True)
    p = sub.add_parser('worker')
    p.add_argument('--run-id', required=True)
    p.add_argument('--event', choices=['start', 'finish'], required=True)
    p.add_argument('--units', type=int, default=1)
    p = sub.add_parser('acquire')
    p.add_argument('--run-id', required=True)
    p.add_argument('--query', required=True)
    p.add_argument('--provider')
    p.add_argument('--corpus')
    p.add_argument('--pattern')
    p.add_argument('--limit', type=int, default=5)
    p = sub.add_parser('record-evidence')
    p.add_argument('--run-id', required=True)
    p.add_argument('--record', required=True)
    p = sub.add_parser('record-claim')
    p.add_argument('--run-id', required=True)
    p.add_argument('--record', required=True)
    p = sub.add_parser('render')
    p.add_argument('--run-id', required=True)
    p.add_argument('--title', default='Research brief')
    p = sub.add_parser('issue-patch')
    p.add_argument('--run-id', required=True)
    p.add_argument('--key-file')
    p = sub.add_parser('apply-patch')
    p.add_argument('--run-id', required=True)
    p.add_argument('--diff', required=True)
    p.add_argument('--key-file')
    p = sub.add_parser('verify')
    p.add_argument('--run-id', required=True)
    p.add_argument('--allow-unknown-retractions', action='store_true')
    p = sub.add_parser('finalize')
    p.add_argument('--run-id', required=True)
    args = ap.parse_args(argv)

    if args.cmd == 'init':
        context = json.loads(Path(args.context).read_text(encoding='utf-8')) if args.context else {}
        result = init_run(args.intent, context)
    elif args.cmd == 'approve':
        result = manifest.approve(args.run_id, args.gate, args.text)
    elif args.cmd == 'grant':
        result = grant(args.run_id)
    elif args.cmd == 'worker':
        result = meter_worker(args.run_id, args.event, units=args.units)
    elif args.cmd == 'acquire':
        result = acquire(args.run_id, args.query, provider_name=args.provider, corpus=args.corpus, pattern=args.pattern, limit=args.limit)
    elif args.cmd == 'record-evidence':
        result = record_evidence(args.run_id, json.loads(Path(args.record).read_text(encoding='utf-8')))
    elif args.cmd == 'record-claim':
        result = record_claim(args.run_id, json.loads(Path(args.record).read_text(encoding='utf-8')))
    elif args.cmd == 'render':
        result = render_draft(args.run_id, title=args.title)
    elif args.cmd == 'issue-patch':
        result = issue_patch_receipt(args.run_id, key_file=args.key_file)
    elif args.cmd == 'apply-patch':
        result = apply_draft_patch(args.run_id, args.diff, key_file=args.key_file)
    elif args.cmd == 'verify':
        result = verify(args.run_id, allow_unknown_retractions=args.allow_unknown_retractions)
    else:
        result = finalize(args.run_id)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if result.get('ok', True) or result.get('verdict') == 'ship' else 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
