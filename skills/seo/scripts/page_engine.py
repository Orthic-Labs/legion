#!/usr/bin/env python3
"""Legion-native Page Engine contract helper.

Validates page-family, page-type, query-ownership, information-gain and claim-control
inputs. It identifies structural blockers before prose changes. It does not invent a
page verdict when evidence is insufficient and does not grant mutation authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = SEO_ROOT / 'config' / 'page-engine.json'


def cfg() -> dict[str, Any]:
    return json.loads(CONFIG.read_text(encoding='utf-8'))


def validate_page_contract(contract: dict[str, Any]) -> list[str]:
    c = cfg()
    errors = []
    page_type = contract.get('page_type')
    if page_type not in c['page_types']:
        errors.append(f'unknown page_type: {page_type}')
        return errors
    for key in c['page_types'][page_type]:
        if contract.get(key) in (None, '', []):
            errors.append(f'{page_type}.{key} is required')
    return errors


def validate_claims(claims: list[dict[str, Any]]) -> list[str]:
    allowed = set(cfg()['claim_states'])
    errors = []
    for i, claim in enumerate(claims):
        if not claim.get('claim'):
            errors.append(f'claims[{i}].claim required')
        if claim.get('state') not in allowed:
            errors.append(f'claims[{i}].state invalid')
        if claim.get('state') == 'approved' and not claim.get('source'):
            errors.append(f'claims[{i}] approved claim requires source')
        if claim.get('state') == 'requires_verification' and claim.get('use_in_output'):
            errors.append(f'claims[{i}] unverified claim cannot be used in output')
        if claim.get('state') == 'banned' and claim.get('use_in_output'):
            errors.append(f'claims[{i}] banned claim cannot be used in output')
    return errors


def detect_blockers(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    blockers = []
    ownership = bundle.get('query_ownership') or []
    for row in ownership:
        kind = row.get('classification')
        if kind in {'ownership switching', 'probable duplicate target'}:
            blockers.append({
                'type': 'multiple_owners_one_intent',
                'subject': row.get('query'),
                'evidence': row,
            })
    page = bundle.get('page') or {}
    if page.get('canonical_expected') and page.get('canonical_observed') and page['canonical_expected'] != page['canonical_observed']:
        blockers.append({'type': 'canonical_mismatch', 'subject': page.get('url'), 'evidence': {'expected': page['canonical_expected'], 'observed': page['canonical_observed']}})
    if page.get('intended_indexable') is True and page.get('observed_indexable') is False:
        blockers.append({'type': 'wrong_indexability', 'subject': page.get('url'), 'evidence': {'intended_indexable': True, 'observed_indexable': False}})
    if page.get('serp_expected_type') and page.get('page_type') and page['serp_expected_type'] != page['page_type']:
        blockers.append({'type': 'wrong_serp_page_type', 'subject': page.get('url'), 'evidence': {'page_type': page['page_type'], 'serp_expected_type': page['serp_expected_type']}})
    if page.get('orphan') is True:
        blockers.append({'type': 'orphan', 'subject': page.get('url'), 'evidence': {'orphan': True}})
    if page.get('intents') and len(set(page['intents'])) > 1 and not page.get('mixed_intent_justified'):
        blockers.append({'type': 'two_intents_one_url', 'subject': page.get('url'), 'evidence': {'intents': page['intents']}})
    return blockers


def information_gain(bundle: dict[str, Any]) -> dict[str, Any]:
    c = cfg()
    gains = bundle.get('information_gain') or []
    valid = []
    invalid = []
    for item in gains:
        if item.get('type') in c['information_gain_types'] and item.get('evidence'):
            valid.append(item)
        else:
            invalid.append(item)
    return {
        'status': 'demonstrated' if valid else 'not_demonstrated',
        'valid': valid,
        'invalid_or_unsubstantiated': invalid,
    }


def assess(bundle: dict[str, Any]) -> dict[str, Any]:
    errors = []
    contract = bundle.get('page_contract') or {}
    if contract:
        errors.extend(validate_page_contract(contract))
    errors.extend(validate_claims(bundle.get('claims') or []))
    blockers = detect_blockers(bundle)
    gain = information_gain(bundle)
    requested_verdict = bundle.get('verdict')
    if requested_verdict and requested_verdict not in cfg()['verdicts']:
        errors.append(f'unknown verdict: {requested_verdict}')
    if requested_verdict in {'EXPAND', 'SPLIT', 'REPOSITION'} and gain['status'] != 'demonstrated':
        errors.append(f'{requested_verdict} requires demonstrated information gain')
    if requested_verdict in {'DELETE', 'REDIRECT', 'NOINDEX', 'CONSOLIDATE'} and not bundle.get('destructive_justification'):
        errors.append(f'{requested_verdict} requires destructive_justification')
    if not requested_verdict:
        recommended = 'INVESTIGATE' if blockers else 'KEEP'
        if not contract or errors:
            recommended = 'INVESTIGATE'
    else:
        recommended = requested_verdict
    return {
        'status': 'pass' if not errors else 'fail',
        'page': (bundle.get('page') or {}).get('url'),
        'blockers': blockers,
        'information_gain': gain,
        'verdict': recommended,
        'errors': errors,
        'rule': 'Structural blockers precede copy changes. This helper validates evidence/contracts; it does not authorize effects.',
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--out')
    args = ap.parse_args()
    result = assess(json.loads(Path(args.input).read_text(encoding='utf-8')))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
