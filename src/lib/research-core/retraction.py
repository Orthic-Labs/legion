#!/usr/bin/env python3
"""Fresh DOI retraction verification using OpenAlex and Crossref.

A verified run blocks when a DOI is retracted without disclosure or when every
configured verifier fails and the retraction status remains unknown.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = 'ResearchCore/2.0' + (f" (mailto:{os.environ['RESEARCH_CONTACT_EMAIL']})" if os.environ.get('RESEARCH_CONTACT_EMAIL') else '')


def _json(url: str, timeout: int = 25) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode('utf-8'))


def _openalex(doi: str) -> dict[str, Any]:
    data = _json('https://api.openalex.org/works/' + urllib.parse.quote('https://doi.org/' + doi, safe=':/'))
    return {'source': 'openalex', 'retracted': bool(data.get('is_retracted')), 'work_id': data.get('id')}


def _crossref(doi: str) -> dict[str, Any]:
    data = _json('https://api.crossref.org/works/' + urllib.parse.quote(doi, safe=''))
    message = data.get('message', {})
    update_to = message.get('update-to') or []
    relation = message.get('relation') or {}
    retracted = any(str(item.get('type', '')).lower() == 'retraction' for item in update_to)
    retracted = retracted or bool(relation.get('is-retracted-by'))
    return {'source': 'crossref', 'retracted': retracted, 'update_to': update_to, 'relation': relation}


def check_doi(doi: str) -> dict[str, Any]:
    doi = doi.strip().lower().removeprefix('https://doi.org/').removeprefix('doi:')
    if not doi:
        return {'doi': doi, 'status': 'invalid', 'retracted': None, 'errors': ['empty DOI']}
    fixture = os.environ.get('RESEARCH_RETRACTION_FIXTURE')
    if fixture:
        data = json.loads(Path(fixture).read_text(encoding='utf-8'))
        if doi in data:
            return {'doi': doi, 'status': 'verified', **data[doi], 'sources': ['fixture']}
    results, errors = [], []
    for checker in (_openalex, _crossref):
        try:
            results.append(checker(doi))
        except Exception as exc:
            errors.append(f'{checker.__name__}: {type(exc).__name__}: {str(exc)[:200]}')
    if not results:
        return {'doi': doi, 'status': 'unknown', 'retracted': None, 'errors': errors}
    return {'doi': doi, 'status': 'verified', 'retracted': any(bool(r.get('retracted')) for r in results), 'sources': results, 'errors': errors}


def sweep(dois: list[str], *, disclosed: list[str] | None = None, block_unknown: bool = True) -> dict[str, Any]:
    disclosed_set = {d.lower().removeprefix('https://doi.org/') for d in disclosed or []}
    results = []
    for doi in dict.fromkeys(d.strip() for d in dois if d.strip()):
        row = check_doi(doi)
        row['disclosed'] = row['doi'] in disclosed_set
        row['block'] = bool(row.get('retracted') and not row['disclosed']) or bool(block_unknown and row['status'] == 'unknown')
        results.append(row)
    return {'dois_checked': len(results), 'results': results, 'block_brief': any(row['block'] for row in results), 'unknown_count': sum(row['status'] == 'unknown' for row in results)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dois', required=True)
    ap.add_argument('--disclosed')
    ap.add_argument('--allow-unknown', action='store_true')
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    dois = [x.strip() for x in Path(args.dois).read_text(encoding='utf-8').splitlines() if x.strip()]
    disclosed = [x.strip() for x in Path(args.disclosed).read_text(encoding='utf-8').splitlines() if x.strip()] if args.disclosed else []
    result = sweep(dois, disclosed=disclosed, block_unknown=not args.allow_unknown)
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if not result['block_brief'] else 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
