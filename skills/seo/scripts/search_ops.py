#!/usr/bin/env python3
"""Persistent SEO intervention and recurring-run state.

The state machine keeps recommendation/action/deployment verification/outcome distinct.
It never treats a process/API success as a ranking, citation or business outcome.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2
DEFAULT_STATE = '.legion/seo/interventions/search-ops.json'
OUTCOME_VERDICTS = {'improved', 'declined', 'mixed', 'inconclusive', 'not_measurable', 'immature'}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def load_state(path: Path) -> dict:
    if not path.exists():
        return {'schema_version': SCHEMA_VERSION, 'interventions': [], 'runs': []}
    data = json.loads(path.read_text(encoding='utf-8'))
    version = data.get('schema_version')
    if version == 1:
        data['schema_version'] = SCHEMA_VERSION
        for row in data.get('interventions', []):
            if row.get('status') == 'planned':
                row['status'] = 'proposed'
            elif row.get('status') in ('deployed_verified', 'deployed_unverified'):
                verified = row['status'] == 'deployed_verified'
                row['status'] = 'verified' if verified else 'deployed'
                if row.get('deployment'):
                    row['deployment']['verified'] = verified
        return data
    if version != SCHEMA_VERSION:
        raise SystemExit(f'unsupported state schema: {version}')
    data.setdefault('interventions', [])
    data.setdefault('runs', [])
    return data


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    tmp.replace(path)


def find_intervention(state: dict, intervention_id: str) -> dict:
    for row in state['interventions']:
        if row.get('id') == intervention_id:
            return row
    raise SystemExit(f'unknown intervention: {intervention_id}')


def cmd_start(args, state):
    if any(x.get('id') == args.id for x in state['interventions']):
        raise SystemExit(f'intervention already exists: {args.id}')
    row = {
        'id': args.id,
        'created_at': utc_now(),
        'target': args.target,
        'query_or_topic': args.query_or_topic,
        'hypothesis': args.hypothesis,
        'proposed_action': args.action,
        'primary_metric': args.metric,
        'evaluation': {'earliest_date': args.evaluate_after, 'maturity_condition': args.maturity_condition},
        'guardrails': args.guardrail or [],
        'baseline': json.loads(args.baseline) if args.baseline else {},
        'status': 'proposed',
        'deployment': None,
        'verification': None,
        'outcomes': [],
    }
    state['interventions'].append(row)
    return row


def cmd_deploy(args, state):
    row = find_intervention(state, args.id)
    if row.get('status') not in {'proposed', 'deployed'}:
        raise SystemExit(f"cannot deploy intervention in state {row.get('status')}")
    row['status'] = 'deployed'
    row['deployment'] = {
        'recorded_at': utc_now(),
        'identity': args.identity,
        'evidence': args.evidence,
        'rollback': args.rollback,
    }
    return row


def cmd_verify(args, state):
    row = find_intervention(state, args.id)
    if row.get('status') not in {'deployed', 'verified'}:
        raise SystemExit('verification requires a deployed intervention')
    row['verification'] = {
        'recorded_at': utc_now(),
        'result': args.result,
        'evidence': args.evidence,
    }
    row['status'] = 'verified' if args.result == 'pass' else 'deployed'
    return row['verification']


def cmd_outcome(args, state):
    row = find_intervention(state, args.id)
    if not row.get('deployment'):
        raise SystemExit('outcome cannot be recorded before deployment')
    outcome = {
        'recorded_at': utc_now(),
        'verdict': args.verdict,
        'metrics': json.loads(args.metrics) if args.metrics else {},
        'evidence': args.evidence,
        'confounders': args.confounder or [],
        'causal_strength': args.causal_strength,
    }
    row['outcomes'].append(outcome)
    if args.verdict != 'immature':
        row['status'] = 'outcome_recorded'
    return outcome


def cmd_run(args, state):
    run = {
        'recorded_at': utc_now(),
        'cadence': args.cadence,
        'property': args.property,
        'market': args.market,
        'primary_action': args.primary_action,
        'critical': args.critical or [],
        'watch': args.watch or [],
        'evidence': args.evidence or [],
    }
    state['runs'].append(run)
    return run


def cmd_brief(args, state):
    if not state['runs']:
        return {'status': 'no_runs'}
    run = state['runs'][-1]
    pending = [x for x in state['interventions'] if x.get('status') not in {'outcome_recorded', 'cancelled'}]
    return {
        'run': run,
        'open_interventions': [
            {
                'id': x['id'], 'target': x['target'], 'status': x['status'],
                'evaluation': x.get('evaluation'),
            }
            for x in pending
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description='SEO intervention and recurring-run state')
    ap.add_argument('--state', default=DEFAULT_STATE)
    sub = ap.add_subparsers(dest='command', required=True)

    p = sub.add_parser('start')
    p.add_argument('--id', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--query-or-topic')
    p.add_argument('--hypothesis', required=True)
    p.add_argument('--action', required=True)
    p.add_argument('--metric', required=True)
    p.add_argument('--evaluate-after', required=True)
    p.add_argument('--maturity-condition')
    p.add_argument('--guardrail', action='append')
    p.add_argument('--baseline', help='JSON object')

    p = sub.add_parser('deploy')
    p.add_argument('--id', required=True)
    p.add_argument('--identity', required=True)
    p.add_argument('--evidence')
    p.add_argument('--rollback')

    p = sub.add_parser('verify')
    p.add_argument('--id', required=True)
    p.add_argument('--result', choices=['pass', 'fail'], required=True)
    p.add_argument('--evidence', required=True)

    p = sub.add_parser('outcome')
    p.add_argument('--id', required=True)
    p.add_argument('--verdict', choices=sorted(OUTCOME_VERDICTS), required=True)
    p.add_argument('--metrics', help='JSON object')
    p.add_argument('--evidence')
    p.add_argument('--confounder', action='append')
    p.add_argument('--causal-strength', choices=['observational', 'quasi_experimental', 'controlled'], default='observational')

    p = sub.add_parser('run')
    p.add_argument('--cadence', choices=['daily', 'weekly', 'monthly', 'quarterly', 'deploy'], required=True)
    p.add_argument('--property', required=True)
    p.add_argument('--market')
    p.add_argument('--primary-action')
    p.add_argument('--critical', action='append')
    p.add_argument('--watch', action='append')
    p.add_argument('--evidence', action='append')

    sub.add_parser('brief')

    args = ap.parse_args()
    path = Path(args.state)
    state = load_state(path)
    fn = globals()[f"cmd_{args.command.replace('-', '_')}"]
    result = fn(args, state)
    if args.command != 'brief':
        save_state(path, state)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
