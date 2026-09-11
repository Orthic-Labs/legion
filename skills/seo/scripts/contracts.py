#!/usr/bin/env python3
"""Validate SEO evidence/finding/recommendation/action/outcome objects.

This is a structural validator. Authorization and effect execution remain owned by Legion's
normal authority/effect boundary; passing this validator never grants permission to mutate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = SEO_ROOT / 'config' / 'contracts.json'


def config() -> dict[str, Any]:
    return json.loads(CONTRACTS.read_text(encoding='utf-8'))


def validate(kind: str, obj: dict[str, Any]) -> list[str]:
    cfg = config()
    field = f'{kind}_required'
    if field not in cfg:
        return [f'unknown contract kind: {kind}']
    errors = []
    for key in cfg[field]:
        if key not in obj or obj.get(key) in (None, ''):
            errors.append(f'{kind}.{key} is required')
    if kind in {'evidence', 'finding'}:
        state = obj.get('coverage_state')
        if state not in cfg['statuses']:
            errors.append(f'{kind}.coverage_state must be one of {cfg["statuses"]}')
    if kind == 'evidence' and obj.get('tier') not in cfg['evidence_tiers']:
        errors.append(f'evidence.tier must be one of {cfg["evidence_tiers"]}')
    if kind == 'finding':
        if obj.get('claim_state') not in cfg['claim_states']:
            errors.append(f'finding.claim_state must be one of {cfg["claim_states"]}')
        if not isinstance(obj.get('evidence_ids'), list) or not obj.get('evidence_ids'):
            errors.append('finding.evidence_ids must be a non-empty list')
        if obj.get('coverage_state') == 'partial' and not (obj.get('tested_scope') and obj.get('untested_scope')):
            errors.append('partial finding requires tested_scope and untested_scope')
        if obj.get('coverage_state') == 'not_testable' and not obj.get('reason'):
            errors.append('not_testable finding requires reason')
    if kind == 'action':
        if obj.get('status') not in {'proposed', 'authorized', 'executed', 'verified', 'rolled_back', 'failed'}:
            errors.append('action.status invalid')
        if obj.get('status') in {'executed', 'verified'} and not obj.get('effect_receipt'):
            errors.append('executed/verified action requires host-observed effect_receipt')
    if kind == 'outcome':
        if obj.get('verdict') not in {'improved', 'declined', 'mixed', 'inconclusive', 'not_measurable'}:
            errors.append('outcome.verdict invalid')
        if obj.get('causal_strength') not in {'observational', 'quasi_experimental', 'controlled'}:
            errors.append('outcome.causal_strength invalid')
    return errors


def validate_bundle(payload: dict[str, Any]) -> dict[str, Any]:
    errors = []
    for kind in ('evidence', 'finding', 'recommendation', 'action', 'outcome'):
        plural = kind + 's'
        for i, obj in enumerate(payload.get(plural, [])):
            for error in validate(kind, obj):
                errors.append(f'{plural}[{i}]: {error}')
    evidence_ids = {x.get('id') for x in payload.get('evidences', [])}
    finding_ids = {x.get('id') for x in payload.get('findings', [])}
    recommendation_ids = {x.get('id') for x in payload.get('recommendations', [])}
    action_ids = {x.get('id') for x in payload.get('actions', [])}
    for i, f in enumerate(payload.get('findings', [])):
        missing = [eid for eid in f.get('evidence_ids', []) if eid not in evidence_ids]
        if missing:
            errors.append(f'findings[{i}] references missing evidence IDs: {missing}')
    for i, r in enumerate(payload.get('recommendations', [])):
        missing = [fid for fid in r.get('finding_ids', []) if fid not in finding_ids]
        if missing:
            errors.append(f'recommendations[{i}] references missing finding IDs: {missing}')
    for i, a in enumerate(payload.get('actions', [])):
        if a.get('recommendation_id') not in recommendation_ids:
            errors.append(f'actions[{i}] references missing recommendation: {a.get("recommendation_id")}')
    for i, o in enumerate(payload.get('outcomes', [])):
        if o.get('action_id') not in action_ids:
            errors.append(f'outcomes[{i}] references missing action: {o.get("action_id")}')
    return {'status': 'pass' if not errors else 'fail', 'errors': errors}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    args = ap.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding='utf-8'))
    result = validate_bundle(payload)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
