#!/usr/bin/env python3
"""Static closure gate for Legion SEO implementation coverage.

This gate proves repository implementation closure, not authenticated runtime availability or
live ranking outcomes. It fails closed if checklist phases, workflow packs, required scripts,
references, source digests or SEO test fixtures are missing.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = SEO_ROOT / 'config' / 'control-catalog.json'
SOURCE_MANIFEST = SEO_ROOT / 'config' / 'source-manifest.json'
WORKFLOW_PACKS = SEO_ROOT / 'references' / 'workflow-packs.md'
ROUTER = SEO_ROOT / 'SKILL.md'
REQUIRED_SCRIPTS = {
    'site_audit.py', 'gsc_query_v2.py', 'gsc_inspect.py', 'ga4_report.py',
    'pagespeed_check.py', 'crux_history.py', 'ai_visibility_import.py',
    'templated_metadata.py', 'search_ops.py', 'seo_project.py',
    'query_ownership.py', 'question_inventory.py', 'rank_tracker.py', 'seo_closure.py',
}
REQUIRED_REFS = {
    'manual.md', 'operations.md', 'ai-search-2026.md', 'geo.md', 'technical.md',
    'page.md', 'schema.md', 'sitemap.md', 'images.md', 'local.md', 'hreflang.md',
    'programmatic.md', 'backlinks.md', 'off-page.md', 'search-experience.md',
    'topic-clusters.md', 'ecommerce-2026.md', 'workflow-packs.md',
    'openseo-absorption.md', 'free-data-sources.md', 'quality-gates.md',
}
REQUIRED_TEST_FILES = {
    'test_seo_kernel.py', 'fixtures/gsc_rows.json', 'fixtures/ai_google.csv',
    'fixtures/ai_bing.csv', 'fixtures/badseo/noindex.html', 'fixtures/badseo/clean.html',
}
REQUIRED_PACKS = {
    'policy', 'bot-policy', 'logs', 'crawl-efficiency', 'agent-readiness',
    'search-appearance', 'discover', 'media', 'documents', 'ecommerce', 'publisher',
    'access-states', 'migration', 'analytics', 'forecast', 'experiment', 'monitor',
    'release-gate', 'incident', 'feeds',
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def headings(path: Path) -> set[str]:
    text = path.read_text(encoding='utf-8')
    out = set()
    for line in text.splitlines():
        match = re.match(r'^##\s+(.+?)\s*$', line)
        if match:
            out.add(re.sub(r'[^a-z0-9]+', '-', match.group(1).lower()).strip('-'))
    return out


def check() -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not CATALOG.exists():
        return {'status': 'fail', 'errors': [f'missing {CATALOG}'], 'warnings': []}
    catalog = load_json(CATALOG)
    phases = catalog.get('phases') or []
    ids = [p.get('id') for p in phases]
    if ids != list(range(1, 31)):
        errors.append(f'checklist phases must be exactly 1..30; got {ids}')
    if set(catalog.get('statuses') or []) != {'pass', 'partial', 'fail', 'na', 'not_testable'}:
        errors.append('status vocabulary does not match canonical five-state contract')

    for phase in phases:
        if not phase.get('owners'):
            errors.append(f"phase {phase.get('id')} has no owner")
        for rel in phase.get('owners') or []:
            path = SEO_ROOT / rel
            if not path.exists():
                errors.append(f"phase {phase.get('id')} owner missing: {rel}")
        for script in phase.get('scripts') or []:
            path = SEO_ROOT / 'scripts' / script
            if not path.exists():
                errors.append(f"phase {phase.get('id')} script missing: {script}")

    script_dir = SEO_ROOT / 'scripts'
    for name in sorted(REQUIRED_SCRIPTS):
        if not (script_dir / name).exists():
            errors.append(f'required SEO implementation script missing: {name}')
    ref_dir = SEO_ROOT / 'references'
    for name in sorted(REQUIRED_REFS):
        if not (ref_dir / name).exists():
            errors.append(f'required SEO reference missing: {name}')

    declared_packs = set(catalog.get('workflow_packs') or [])
    missing_declared = REQUIRED_PACKS - declared_packs
    if missing_declared:
        errors.append(f'workflow packs missing from catalog: {sorted(missing_declared)}')
    if WORKFLOW_PACKS.exists():
        hs = headings(WORKFLOW_PACKS)
        for pack in sorted(REQUIRED_PACKS):
            if not any(pack in h for h in hs):
                errors.append(f'workflow pack has no documented owner section: {pack}')

    router = ROUTER.read_text(encoding='utf-8') if ROUTER.exists() else ''
    for required in ('workflow-packs.md', 'seo_project.py', 'gsc_query_v2.py', 'ai_visibility_import.py', 'search_ops.py'):
        if required not in router:
            errors.append(f'router does not expose/invoke closure component: {required}')

    test_root = SEO_ROOT / 'tests'
    for rel in sorted(REQUIRED_TEST_FILES):
        if not (test_root / rel).exists():
            errors.append(f'required SEO regression fixture/test missing: {rel}')

    if not SOURCE_MANIFEST.exists():
        errors.append('missing source-manifest.json')
    else:
        manifest = load_json(SOURCE_MANIFEST)
        for source in manifest.get('sources') or []:
            if not source.get('sha256') or not source.get('line_count'):
                errors.append(f"source manifest incomplete for {source.get('name')}")

    legacy = script_dir / 'gsc_query.py'
    if legacy.exists():
        text = legacy.read_text(encoding='utf-8')
        if 'dimensionless' not in text.lower() and 'gsc_query_v2' not in text:
            errors.append('legacy gsc_query.py does not advertise/use provenance-safe v2 aggregate semantics')

    status = 'pass' if not errors else 'fail'
    return {
        'status': status,
        'scope': 'repository implementation closure; live credentials/runtime are separately evidenced',
        'phase_count': len(phases),
        'workflow_pack_count': len(declared_packs),
        'errors': errors,
        'warnings': warnings,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    result = check()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"SEO closure: {result['status'].upper()} — {result['phase_count']} phases, {result['workflow_pack_count']} workflow packs")
        for error in result['errors']:
            print(f'FAIL: {error}')
        for warning in result['warnings']:
            print(f'WARN: {warning}')
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
