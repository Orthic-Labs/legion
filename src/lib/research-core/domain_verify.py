#!/usr/bin/env python3
"""Domain-specific verified-assurance checks for medical and legal routes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _present(value: Any) -> bool:
    return value not in (None, "", [])


def _legal_authority_ok(claim_type: str, evidence: dict[str, Any]) -> bool:
    if not (_present(evidence.get("authority_type")) and _present(evidence.get("current_as_of"))):
        return False
    if claim_type != "case-law":
        return True
    return (
        _present(evidence.get("forum"))
        and _present(evidence.get("precedential_status"))
        and _present(evidence.get("negative_treatment"))
    )


def verify(route: dict[str, Any], evidence: list[dict[str, Any]], claims: list[dict[str, Any]]) -> dict[str, Any]:
    checks = []
    if route['domain'] == 'medical':
        patient = route['subject']['patient']
        checks.append({'name': 'medical.issue', 'ok': bool(route['subject'].get('issue'))})
        checks.append({'name': 'medical.anonymous-no-history', 'ok': not (patient['kind'] == 'anonymous' and any(e.get('patient_history') for e in evidence))})
        for claim in claims:
            if claim['claim_type'] in {'effect-size', 'adverse-event', 'dosing'}:
                sources = [e for e in evidence if e['id'] in claim.get('source_ids', [])]
                checks.append({
                    'name': f"medical.pico.{claim['id']}",
                    'ok': all(e.get('study_design') and e.get('pico') and e.get('applicability') for e in sources),
                })
    elif route['domain'] == 'legal':
        subject = route['subject']
        checks.append({'name': 'legal.context', 'ok': all(subject.get(k) for k in ('country', 'area', 'issue'))})
        forbidden = route.get('forbidden_resources', [])
        if subject.get('country') == 'IN' and subject.get('area') == 'criminal':
            checks.append({'name': 'legal.criminal-consumer-isolation', 'ok': bool(forbidden)})
        for claim in claims:
            if claim['claim_type'] in {'legal', 'case-law'}:
                sources = [e for e in evidence if e['id'] in claim.get('source_ids', [])]
                checks.append({
                    'name': f"legal.authority.{claim['id']}",
                    'ok': all(_legal_authority_ok(claim['claim_type'], e) for e in sources),
                })
    return {'ok': all(c['ok'] for c in checks), 'checks': checks}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--route', required=True)
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--claims', required=True)
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    route = json.loads(Path(args.route).read_text(encoding='utf-8'))
    evidence = [json.loads(x) for x in Path(args.evidence).read_text(encoding='utf-8').splitlines() if x.strip()]
    claims = [json.loads(x) for x in Path(args.claims).read_text(encoding='utf-8').splitlines() if x.strip()]
    result = verify(route, evidence, claims)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
