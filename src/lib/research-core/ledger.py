#!/usr/bin/env python3
"""Evidence/claim ledger validation, confidence adjudication, and rendering."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from independence import cluster as cluster_independence  # noqa: E402

CONFIDENCE_RANK = {'low': 1, 'medium': 2, 'high': 3}
STATUSES = {'supported', 'contested', 'unresolved', 'superseded'}
CLAIM_TYPES = {
    'price', 'feature', 'legal', 'case-law', 'benchmark', 'comparative', 'causal',
    'prevalence', 'observation', 'inference', 'recommendation', 'effect-size',
    'adverse-event', 'interaction', 'dosing', 'regulatory', 'guideline', 'mechanistic',
}
LOAD_BEARING = CLAIM_TYPES - {'inference', 'recommendation'}
PRIMARY_REQUIRED = {'price', 'feature', 'legal', 'case-law', 'benchmark', 'regulatory', 'guideline'}
MULTI_SOURCE_HIGH = {'benchmark', 'comparative', 'causal', 'prevalence', 'effect-size', 'adverse-event', 'dosing'}
LEAD_ONLY_SOURCE_TYPES = {'search-hit', 'search-snippet', 'snippet', 'ai-summary', 'provider-answer', 'notebooklm-answer'}
PASSAGE_FIELDS = ('quote_or_paraphrase', 'evidence_text', 'body_plain', 'located_text')


def parse_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for n, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f'{path}:{n}: row must be an object')
        rows.append(value)
    return rows


def _date(value: Any) -> bool:
    try:
        dt.date.fromisoformat(str(value))
        return True
    except ValueError:
        return False


def validate_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    verdicts = []
    seen = set()
    for row in evidence:
        eid = str(row.get('id') or '')
        errors = []
        if not eid or eid in seen:
            errors.append('missing or duplicate id')
        seen.add(eid)
        for key in ('url', 'publisher', 'retrieved_at', 'locator', 'suggested_by', 'seed_chain'):
            if row.get(key) in (None, '', []):
                errors.append(f'missing {key}')
        if row.get('retrieved_at') and not _date(row['retrieved_at']):
            errors.append('retrieved_at is not ISO date')

        policy = row.get('instructionPolicy')
        if policy in (None, ''):
            errors.append('missing instructionPolicy')
        elif policy != 'data_only':
            errors.append('instructionPolicy must be data_only')
        if not any(str(row.get(key) or '').strip() for key in PASSAGE_FIELDS):
            errors.append('missing opened passage text')
        if row.get('body_is_not_from_source') and not row.get('body_substitution'):
            errors.append('body substitution disclosure missing')

        evidence_status = str(row.get('evidence_status') or 'evidence').lower()
        source_type = str(row.get('source_type') or '').lower()
        provider = str(row.get('provider') or '').lower()
        if evidence_status == 'lead':
            errors.append('lead-only record cannot enter the evidence ledger')
        if source_type in LEAD_ONLY_SOURCE_TYPES:
            errors.append(f'lead-only source_type cannot enter the evidence ledger: {source_type}')
        if provider == 'notebooklm':
            errors.append('NotebookLM answers are leads; record the separately opened underlying source instead')

        verdicts.append({'id': eid, 'verdict': 'block' if errors else 'ok', 'reasons': errors})
    return verdicts


def _independent_clusters(source_ids: list[str], by_id: dict[str, dict[str, Any]]) -> set[str]:
    return {
        str(by_id[sid].get('independence_cluster') or sid)
        for sid in source_ids if sid in by_id
    }


def _is_primary_for(claim_type: str, ev: dict[str, Any]) -> bool:
    if not ev.get('url') or not ev.get('retrieved_at') or not ev.get('locator'):
        return False
    if ev.get('is_primary') is True:
        return True
    role = str(ev.get('authority_role') or '').lower()
    if claim_type in {'price', 'feature'}:
        return role in {'vendor-official', 'publisher-of-record'}
    if claim_type in {'legal', 'regulatory', 'guideline'}:
        return role in {'statute', 'regulator', 'official-guideline', 'official'}
    if claim_type == 'case-law':
        return role in {'court', 'official-judgment'}
    if claim_type == 'benchmark':
        return role in {'measurement', 'benchmark-owner', 'study'}
    return role in {'study', 'regulator', 'official', 'measurement'}


def _supporting_confidence(source_ids: list[str], claim_by_id: dict[str, dict], ev_by_id: dict[str, dict]) -> list[str]:
    out = []
    for sid in source_ids:
        if sid in claim_by_id:
            out.append(str(claim_by_id[sid].get('confidence', 'low')))
        elif sid in ev_by_id:
            out.append('high' if ev_by_id[sid].get('url') and ev_by_id[sid].get('locator') else 'low')
        else:
            out.append('low')
    return out


def check(evidence: list[dict[str, Any]], claims: list[dict[str, Any]]) -> dict[str, Any]:
    clustered = cluster_independence(evidence)
    evidence = clustered['evidence']
    ev_by_id = {str(e['id']): e for e in evidence}
    claim_by_id = {str(c.get('id')): c for c in claims}
    evidence_verdicts = validate_evidence(evidence)
    verdicts: list[dict[str, Any]] = []
    overall_ok = not any(v['verdict'] == 'block' for v in evidence_verdicts)

    for claim in claims:
        cid = str(claim.get('id') or '')
        ctype = str(claim.get('claim_type') or '')
        reasons: list[str] = []
        if not cid:
            reasons.append('missing id')
        if ctype not in CLAIM_TYPES:
            reasons.append(f'unknown claim_type: {ctype!r}')
        if not str(claim.get('text') or '').strip():
            reasons.append('missing text')
        confidence = str(claim.get('confidence') or 'low')
        if confidence not in CONFIDENCE_RANK:
            reasons.append('invalid confidence')
            confidence = 'low'
        status = str(claim.get('status') or 'supported')
        if status not in STATUSES:
            reasons.append('invalid status')
        as_of = claim.get('as_of') or claim.get('as_of_date')
        if not as_of or not _date(as_of):
            reasons.append('missing or invalid as_of date')
        source_ids = [str(x) for x in claim.get('source_ids', [])]
        missing_sources = [sid for sid in source_ids if sid not in ev_by_id and sid not in claim_by_id]
        if missing_sources:
            reasons.append(f'unknown source ids: {missing_sources}')
        if ctype in LOAD_BEARING and not source_ids:
            reasons.append('load-bearing claim has no source_ids')

        evidence_sources = [ev_by_id[sid] for sid in source_ids if sid in ev_by_id]
        primary_sources = [ev for ev in evidence_sources if _is_primary_for(ctype, ev)]
        if ctype in PRIMARY_REQUIRED and not primary_sources:
            reasons.append('primary-source fetch missing')

        clusters = _independent_clusters([ev['id'] for ev in evidence_sources], ev_by_id)
        declared = confidence
        if ctype in MULTI_SOURCE_HIGH and confidence == 'high' and len(clusters) < 2:
            confidence = 'medium'
            verdicts.append({
                'id': cid, 'verdict': 'downgrade',
                'reason': f'{ctype} high confidence requires 2+ independent sources, got {len(clusters)}',
                'from': declared, 'to': confidence,
            })
        if ctype == 'mechanistic' and CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK['medium']:
            confidence = 'medium'
            verdicts.append({'id': cid, 'verdict': 'downgrade', 'reason': 'mechanistic claims cap at medium', 'from': declared, 'to': confidence})
        if ctype in {'legal', 'case-law'} and confidence == 'high':
            if not primary_sources:
                confidence = 'medium'
            elif ctype == 'case-law' and any(
                not ev.get('current_as_of') or ev.get('negative_treatment') in {'overruled', 'doubted'}
                for ev in primary_sources
            ):
                confidence = 'medium'
                verdicts.append({'id': cid, 'verdict': 'downgrade', 'reason': 'case-law currentness/negative-treatment verification incomplete', 'from': declared, 'to': confidence})
        if ctype in {'effect-size', 'adverse-event', 'dosing'} and confidence == 'high':
            primary_clusters = _independent_clusters([ev['id'] for ev in primary_sources], ev_by_id)
            if len(primary_clusters) < 2:
                confidence = 'medium'
                verdicts.append({'id': cid, 'verdict': 'downgrade', 'reason': 'medical high confidence requires 2+ independent primary studies', 'from': declared, 'to': confidence})

        if ctype == 'recommendation':
            if not source_ids:
                reasons.append('recommendation with no source_ids')
            else:
                supporting = _supporting_confidence(source_ids, claim_by_id, ev_by_id)
                ceiling = min(supporting, key=lambda x: CONFIDENCE_RANK.get(x, 1))
                if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[ceiling]:
                    verdicts.append({'id': cid, 'verdict': 'downgrade', 'reason': f'recommendation confidence exceeds support ceiling {ceiling}', 'from': confidence, 'to': ceiling})
                    confidence = ceiling

        claim['confidence'] = confidence
        claim['status'] = status
        claim['as_of'] = str(as_of or '')
        if reasons:
            verdicts.append({'id': cid, 'verdict': 'block', 'reasons': reasons})
            overall_ok = False
        else:
            verdicts.append({'id': cid, 'verdict': 'ok', 'confidence': confidence, 'independent_clusters': len(clusters)})

    return {
        'overall_ok': overall_ok,
        'evidence': evidence,
        'claims': claims,
        'clusters': clustered['clusters'],
        'evidence_verdicts': evidence_verdicts,
        'verdicts': verdicts,
    }


def render(evidence: list[dict], claims: list[dict], *, title: str = 'Research brief') -> str:
    checked = check(evidence, claims)
    if not checked['overall_ok']:
        raise ValueError('ledger contains blocking violations')
    evidence = checked['evidence']
    claims = checked['claims']
    ev_by_id = {e['id']: e for e in evidence}
    lines = [f'# {title}', '', f"_as of {dt.date.today().isoformat()}_", '', '## Findings', '']
    for claim in claims:
        prefix = {'observation': '[OBS]', 'inference': '[INF]', 'recommendation': '[REC]'}.get(claim['claim_type'], f"[{claim['claim_type'].upper()}]")
        cited = [sid for sid in claim.get('source_ids', []) if sid in ev_by_id]
        cites = ''.join(f'[+{sid}]' for sid in cited)
        lines.append(f"- {prefix} {claim['text']} {cites} [confidence: {claim['confidence']}] [status: {claim['status']}]")
    lines += ['', '## Sources', '']
    for ev in evidence:
        disclosure = ''
        if ev.get('body_is_not_from_source'):
            disclosure = f" — substituted body: {ev.get('body_substitution', 'disclosed replacement')}"
        lines.append(f"- [{ev['id']}] {ev.get('title') or ev.get('url')} — {ev.get('publisher')} — {ev.get('url', 'local')} — retrieved {ev.get('retrieved_at')}{disclosure}")
        lines.append(f"  - locator: {ev.get('locator')}; suggested_by: {ev.get('suggested_by')}; cluster: {ev.get('independence_cluster')}")
    return '\n'.join(lines) + '\n'


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('check', 'render'):
        p = sub.add_parser(name)
        p.add_argument('--evidence', required=True)
        p.add_argument('--claims', required=True)
        if name == 'render':
            p.add_argument('--out', required=True)
            p.add_argument('--title', default='Research brief')
    args = ap.parse_args(argv)
    evidence = parse_jsonl(Path(args.evidence))
    claims = parse_jsonl(Path(args.claims))
    if args.cmd == 'check':
        result = check(evidence, claims)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0 if result['overall_ok'] else 2
    try:
        text = render(evidence, claims, title=args.title)
    except ValueError as exc:
        print(json.dumps({'ok': False, 'reason': str(exc)}, indent=2))
        return 2
    Path(args.out).write_text(text, encoding='utf-8')
    print(json.dumps({'ok': True, 'out': args.out}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
