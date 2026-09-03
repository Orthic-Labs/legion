#!/usr/bin/env python3
"""Resolve and grant a two-stage, least-privilege ResearchRoute."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
sys.path.insert(0, str(HERE))
from route_detect import *  # noqa: F401,F403,E402
from route_detect import _unique, _country, _legal_area, _issue  # noqa: E402

def build_subject(intent: str, domain: str, context: dict[str, Any]) -> dict[str, Any]:
    if domain == 'medical':
        explicit = context.get('patient_kind')
        if explicit in {'anonymous', 'self', 'other-identified'}:
            kind = explicit
        elif OTHER_PATIENT.search(intent):
            kind = 'other-identified'
        elif PERSONAL_FIRST_PERSON.search(intent):
            kind = 'self'
        else:
            kind = 'anonymous'
        # Personal routes never infer a patient-history path: the host must supply
        # `history_source` explicitly via context (e.g. a configured patient-history
        # file). No filename or path is hardcoded here.
        history_source = context.get('history_source')
        history_available = bool(history_source and Path(history_source).is_file())
        return {
            'patient': {
                'kind': kind,
                'history_available': history_available,
                'history_source': str(history_source) if history_source else None,
            },
            'issue': str(context.get('issue') or _issue(intent)),
            'urgency': str(context.get('urgency') or 'routine'),
        }
    if domain == 'legal':
        country = context.get('country') or _country(intent)
        area = context.get('area') or _legal_area(intent)
        subject: dict[str, Any] = {
            'country': country,
            'area': area,
            'issue': str(context.get('issue') or _issue(intent)),
        }
        for key in (
            'state_or_region', 'forum_or_regulator', 'posture', 'role_or_side',
            'pecuniary_value', 'cause_of_action_date', 'notice_status', 'desired_outcome',
            'intended_external_action',
        ):
            if key in context and context[key] not in (None, ''):
                subject[key] = context[key]
        return subject
    return dict(context.get('subject') or {})


def resolve(intent: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    domain = str(context.get('domain') or detect_domain(intent))
    operation = str(context.get('operation') or detect_operation(intent))
    methods = list(context.get('methods') or detect_methods(intent))
    provider = str(context.get('provider') or detect_provider(intent, domain, methods))
    assurance = str(context.get('assurance') or detect_assurance(intent, domain, operation))
    scale = str(context.get('scale') or detect_scale(intent))
    subject = build_subject(intent, domain, context)
    patient_kind = subject.get('patient', {}).get('kind') if domain == 'medical' else None
    sensitivity = str(context.get('sensitivity') or detect_sensitivity(intent, domain, patient_kind))

    route = {
        'route_version': 2,
        'domain': domain,
        'operation': operation,
        'methods': _unique(methods),
        'provider': provider,
        'assurance': assurance,
        'scale': scale,
        'subject': subject,
        'sensitivity': sensitivity,
        'decision': str(context.get('decision') or intent).strip(),
        'output': str(context.get('output') or _default_output(domain, operation)),
        'allowed_effects': [],
        'human_gates': [],
        'forbidden_resources': [],
    }
    route['human_gates'], route['forbidden_resources'] = pending_gates(route)
    validate_route(route, stage='route')
    return route


def _default_output(domain: str, operation: str) -> str:
    if domain == 'medical':
        return 'medical-evidence-pack'
    if domain == 'legal' and operation == 'procedure':
        return 'filing-guidance-or-pack'
    if domain == 'legal':
        return 'legal-research-memo'
    if operation == 'generate-artifact':
        return 'requested-artifact'
    return 'evidence-brief'


def pending_gates(route: dict[str, Any]) -> tuple[list[str], list[str]]:
    gates: list[str] = []
    forbidden: list[str] = []
    domain = route['domain']
    subject = route['subject']
    if domain == 'medical':
        kind = subject.get('patient', {}).get('kind')
        if kind in {'self', 'other-identified'}:
            gates.append('confirm-personal-medical-route')
    if domain == 'legal':
        if not subject.get('country'):
            gates.append('confirm-jurisdiction')
        if not subject.get('area'):
            gates.append('confirm-legal-area')
        if not subject.get('issue'):
            gates.append('confirm-legal-issue')
        if subject.get('country') == 'IN' and subject.get('area') == 'criminal':
            forbidden += [
                'skills/research/references/domains/legal/india/consumer/**',
                'src/lib/research-core/workflows/legal/india/consumer/**',
            ]
        if (
            subject.get('country') == 'IN'
            and subject.get('area') == 'consumer'
            and route['operation'] in {'draft', 'procedure'}
        ):
            required = ('pecuniary_value', 'cause_of_action_date', 'notice_status')
            if any(subject.get(key) in (None, '') for key in required):
                gates.append('confirm-consumer-filing-facts')
    if route['provider'] == 'notebooklm' and route['sensitivity'] in {'private', 'highly-sensitive'}:
        gates.append('approve-notebooklm-upload')
    if route['domain'] == 'medical' and route['provider'] == 'notebooklm':
        gates.append('approve-notebooklm-upload')
    if domain == 'legal' and str(subject.get('intended_external_action') or '').lower() in {
        'send', 'sign', 'file', 'notarise', 'notarize', 'accept', 'rely',
    }:
        gates.append('approve-send-sign-file')
    return _unique(gates), _unique(forbidden)


def gate_verdicts(route: dict[str, Any], approvals: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    approvals = approvals or {}
    verdicts: list[dict[str, Any]] = []
    for gate in route.get('human_gates', []):
        approved = gate in approvals and bool(str(approvals[gate].get('text', '')).strip())
        verdicts.append({'gate': gate, 'verdict': 'ok' if approved else 'ask'})
    if route['domain'] == 'medical':
        kind = route['subject']['patient']['kind']
        if kind == 'anonymous':
            verdicts.append({'gate': 'medical.anonymous-no-history', 'verdict': 'ok'})
        elif not route['subject']['patient'].get('history_available'):
            verdicts.append({'gate': 'medical.history-available', 'verdict': 'block', 'reason': 'personal medical route has no readable history source'})
        else:
            verdicts.append({'gate': 'medical.history-available', 'verdict': 'ok'})
    if route['domain'] == 'legal':
        missing = [key for key in ('country', 'area', 'issue') if not route['subject'].get(key)]
        verdicts.append({'gate': 'legal.context-complete', 'verdict': 'ask' if missing else 'ok', 'missing': missing})
        if route['subject'].get('country') == 'IN' and route['subject'].get('area') == 'criminal':
            verdicts.append({'gate': 'legal.criminal-consumer-isolation', 'verdict': 'ok', 'forbidden_resources': route.get('forbidden_resources', [])})
    verdicts.append({'gate': 'notebooklm.answer-not-ledger', 'verdict': 'ok'})
    verdicts.append({'gate': 'discovery.provenance', 'verdict': 'ok'})
    return verdicts


def grant_effects(route: dict[str, Any], approvals: dict[str, Any] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validate_route(route, stage='route')
    verdicts = gate_verdicts(route, approvals)
    if any(v['verdict'] != 'ok' for v in verdicts):
        return {**route, 'allowed_effects': []}, verdicts
    effects = ['read-local', 'search', 'extract', 'synthesize', 'write-output']
    if route['provider'] in {'browser', 'domain-default'}:
        effects.append('fetch')
    if route['assurance'] in {'standard', 'verified'}:
        effects.append('citecheck')
    if route['assurance'] == 'verified':
        effects += ['retraction-check', 'patch-sourced-draft']
    if route['domain'] == 'medical' and route['subject']['patient']['kind'] != 'anonymous':
        effects += ['read-sensitive', 'load-medical-history']
    if route['provider'] == 'notebooklm':
        effects += ['upload-notebooklm', 'create-artifact']
    if route['scale'] in {'broad', 'dossier'}:
        effects.append('spawn-worker')
    return {**route, 'allowed_effects': _unique(effects)}, verdicts


def validate_route(route: dict[str, Any], *, stage: str) -> None:
    missing = [key for key in ('route_version', 'domain', 'operation', 'methods', 'provider', 'assurance', 'scale', 'subject', 'sensitivity', 'decision', 'output', 'allowed_effects', 'human_gates', 'forbidden_resources') if key not in route]
    if missing: raise ValueError(f'route missing keys: {missing}')
    if route['route_version'] != 2: raise ValueError('route_version must be 2')
    if route['domain'] not in DOMAIN_VALUES or route['operation'] not in OPERATIONS: raise ValueError('invalid domain or operation')
    if not route['methods'] or any(m not in METHODS for m in route['methods']): raise ValueError(f"invalid methods: {route['methods']!r}")
    if route['provider'] not in PROVIDERS or route['assurance'] not in ASSURANCE or route['scale'] not in SCALE: raise ValueError('invalid provider/assurance/scale')
    if route['sensitivity'] not in SENSITIVITY: raise ValueError('invalid sensitivity')
    if not route['decision'].strip() or not route['output'].strip(): raise ValueError('decision and output must be non-empty')
    if route['domain'] == 'medical':
        patient = route['subject'].get('patient', {})
        if patient.get('kind') not in {'anonymous', 'self', 'other-identified'}: raise ValueError('medical route requires subject.patient.kind')
        if not route['subject'].get('issue'): raise ValueError('medical route requires subject.issue')
    if route['domain'] == 'legal' and stage == 'grant':
        missing_legal = [k for k in ('country', 'area', 'issue') if not route['subject'].get(k)]
        if missing_legal: raise ValueError(f'legal route incomplete: {missing_legal}')


def _load_json(path: str | None) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding='utf-8')) if path else {}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--intent'); source.add_argument('--route')
    ap.add_argument('--context'); ap.add_argument('--approvals'); ap.add_argument('--grant', action='store_true'); ap.add_argument('--out')
    args = ap.parse_args(argv)
    route = resolve(args.intent, context=_load_json(args.context)) if args.intent is not None else _load_json(args.route)
    validate_route(route, stage='route')
    approvals = _load_json(args.approvals)
    if args.grant:
        route, verdicts = grant_effects(route, approvals)
        if route['allowed_effects']: validate_route(route, stage='grant')
    else:
        verdicts = gate_verdicts(route, approvals)
    output = {'route': route, 'gate_verdicts': verdicts, 'ready': bool(route['allowed_effects']) if args.grant else False}
    text = json.dumps(output, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out: Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if not args.grant or output['ready'] else 2


if __name__ == '__main__': raise SystemExit(main(sys.argv[1:]))
