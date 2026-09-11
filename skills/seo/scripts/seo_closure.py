#!/usr/bin/env python3
"""Static closure gate for Legion SEO implementation coverage.

Proves repository implementation closure, not authenticated live-account availability or
ranking outcomes. Fails closed on checklist/source drift, missing owners/scripts/tests,
workflow packs, provider registry, contracts, qualification gates, or unwired Python CI.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = SEO_ROOT.parent.parent
CATALOG = SEO_ROOT / 'config' / 'control-catalog.json'
SOURCE_MANIFEST = SEO_ROOT / 'config' / 'source-manifest.json'
PROVIDER_REGISTRY = SEO_ROOT / 'config' / 'provider-registry.json'
CONTRACTS = SEO_ROOT / 'config' / 'contracts.json'
QUALIFICATION = SEO_ROOT / 'config' / 'qualification.json'
WORKFLOW_PACKS = SEO_ROOT / 'references' / 'workflow-packs.md'
ROUTER = SEO_ROOT / 'SKILL.md'
REQUIRED_SCRIPTS = {
    'site_audit.py', 'gsc_query.py', 'gsc_query_v2.py', 'gsc_inspect.py', 'ga4_report.py',
    'pagespeed_check.py', 'crux_history.py', 'ai_visibility_import.py',
    'templated_metadata.py', 'search_ops.py', 'seo_project.py', 'provider_registry.py',
    'query_ownership.py', 'question_inventory.py', 'rank_tracker.py', 'coverage.py',
    'contracts.py', 'checklist_compiler.py', 'seo_closure.py',
}
REQUIRED_REFS = {
    'manual.md', 'operations.md', 'ai-search-2026.md', 'geo.md', 'technical.md',
    'page.md', 'schema.md', 'sitemap.md', 'images.md', 'local.md', 'hreflang.md',
    'programmatic.md', 'backlinks.md', 'off-page.md', 'search-experience.md',
    'topic-clusters.md', 'ecommerce-2026.md', 'workflow-packs.md',
    'openseo-absorption.md', 'free-data-sources.md', 'quality-gates.md',
}
REQUIRED_TEST_FILES = {
    'test_seo_kernel.py', 'test_seo_governance.py', 'test_provider_replay.py',
    'fixtures/gsc_rows.json', 'fixtures/gsc_replay.json', 'fixtures/ai_google.csv',
    'fixtures/ai_bing.csv', 'fixtures/badseo/noindex.html', 'fixtures/badseo/clean.html',
}
REQUIRED_PACKS = {
    'policy', 'bot-policy', 'logs', 'crawl-efficiency', 'agent-readiness',
    'search-appearance', 'discover', 'media', 'documents', 'ecommerce', 'publisher',
    'access-states', 'migration', 'analytics', 'forecast', 'experiment', 'monitor',
    'release-gate', 'incident', 'feeds',
}
REQUIRED_CRITICAL_GATES = {
    'indexability', 'canonical-integrity', 'redirect-integrity', 'security-policy',
    'measurement-integrity', 'deployment-verification', 'authority-boundary',
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def headings(path: Path) -> set[str]:
    out = set()
    for line in path.read_text(encoding='utf-8').splitlines():
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
    if set(catalog.get('critical_gates') or []) != REQUIRED_CRITICAL_GATES:
        errors.append('critical gate set differs from governed SEO closure contract')

    previous_end = 73
    for phase in phases:
        pid = phase.get('id')
        source_lines = phase.get('source_lines')
        if not (isinstance(source_lines, list) and len(source_lines) == 2 and all(isinstance(x, int) for x in source_lines)):
            errors.append(f'phase {pid} missing exact source_lines')
        else:
            start, end = source_lines
            if start != previous_end + 1:
                errors.append(f'phase {pid} source range is not contiguous after line {previous_end}: {source_lines}')
            if end < start:
                errors.append(f'phase {pid} has invalid source range: {source_lines}')
            previous_end = end
        if not phase.get('owners'):
            errors.append(f'phase {pid} has no owner')
        for rel in phase.get('owners') or []:
            if not (SEO_ROOT / rel).exists():
                errors.append(f'phase {pid} owner missing: {rel}')
        for script in phase.get('scripts') or []:
            if not (SEO_ROOT / 'scripts' / script).exists():
                errors.append(f'phase {pid} script missing: {script}')
    if previous_end != catalog.get('source_line_count'):
        errors.append(f'phase source ranges stop at {previous_end}, source line count is {catalog.get("source_line_count")}')

    for name in sorted(REQUIRED_SCRIPTS):
        if not (SEO_ROOT / 'scripts' / name).exists():
            errors.append(f'required SEO implementation script missing: {name}')
    for name in sorted(REQUIRED_REFS):
        if not (SEO_ROOT / 'references' / name).exists():
            errors.append(f'required SEO reference missing: {name}')

    for config_path, label in ((PROVIDER_REGISTRY, 'provider-registry.json'), (CONTRACTS, 'contracts.json'), (QUALIFICATION, 'qualification.json')):
        if not config_path.exists():
            errors.append(f'{label} missing')

    if PROVIDER_REGISTRY.exists():
        providers = load_json(PROVIDER_REGISTRY).get('providers') or {}
        for required in ('local', 'google_gsc', 'google_ga4', 'google_pagespeed_crux', 'google_generative_export', 'bing_ai_export'):
            if required not in providers:
                errors.append(f'provider registry missing core provider: {required}')
    if CONTRACTS.exists():
        contracts = load_json(CONTRACTS)
        for key in ('evidence_required', 'finding_required', 'recommendation_required', 'action_required', 'outcome_required'):
            if not contracts.get(key):
                errors.append(f'contracts missing {key}')
    if QUALIFICATION.exists():
        qual = load_json(QUALIFICATION)
        if not qual.get('provider_replay_required') or not qual.get('runtime_gates') or not qual.get('installed_path_gates'):
            errors.append('qualification.json missing provider/runtime/installed-path gate declarations')

    declared_packs = set(catalog.get('workflow_packs') or [])
    if REQUIRED_PACKS - declared_packs:
        errors.append(f'workflow packs missing from catalog: {sorted(REQUIRED_PACKS - declared_packs)}')
    if WORKFLOW_PACKS.exists():
        hs = headings(WORKFLOW_PACKS)
        for pack in sorted(REQUIRED_PACKS):
            if not any(pack in h for h in hs):
                errors.append(f'workflow pack has no documented owner section: {pack}')

    router = ROUTER.read_text(encoding='utf-8') if ROUTER.exists() else ''
    for required in ('workflow-packs.md', 'seo_project.py', 'provider_registry.py', 'gsc_query_v2.py', 'ai_visibility_import.py', 'search_ops.py', 'coverage.py', 'seo_closure.py'):
        if required not in router:
            errors.append(f'router does not expose/invoke closure component: {required}')

    for rel in sorted(REQUIRED_TEST_FILES):
        if not (SEO_ROOT / 'tests' / rel).exists():
            errors.append(f'required SEO regression fixture/test missing: {rel}')

    if not SOURCE_MANIFEST.exists():
        errors.append('missing source-manifest.json')
    else:
        manifest = load_json(SOURCE_MANIFEST)
        source_by_role = {x.get('role'): x for x in manifest.get('sources') or []}
        checklist = source_by_role.get('control-source')
        implementation = source_by_role.get('implementation-contract')
        if not checklist or not implementation:
            errors.append('source manifest missing control-source or implementation-contract')
        else:
            if checklist.get('sha256') != catalog.get('source_sha256'):
                errors.append('control catalog source digest does not match source manifest')
            if checklist.get('line_count') != catalog.get('source_line_count'):
                errors.append('control catalog line count does not match source manifest')
        for source in manifest.get('sources') or []:
            if not source.get('sha256') or not source.get('line_count'):
                errors.append(f'source manifest incomplete for {source.get("name")}')

    legacy = SEO_ROOT / 'scripts' / 'gsc_query.py'
    if legacy.exists():
        text = legacy.read_text(encoding='utf-8')
        if 'dimensionless' not in text.lower() or 'gsc_query_v2' not in text:
            errors.append('legacy gsc_query.py does not delegate to provenance-safe v2 aggregate semantics')

    test_runner = REPO_ROOT / 'scripts' / 'test-python.mjs'
    if not test_runner.exists() or 'skills/seo/tests' not in test_runner.read_text(encoding='utf-8'):
        errors.append('SEO Python regression suite is not wired into repository Python CI')
    notices = REPO_ROOT / 'docs' / 'THIRD_PARTY_NOTICES.md'
    if not notices.exists() or not all(x in notices.read_text(encoding='utf-8') for x in ('AgriciDaniel/claude-seo', 'every-app/open-seo')):
        errors.append('third-party notices do not record SEO donor methodology provenance')

    status = 'pass' if not errors else 'fail'
    return {
        'status': status,
        'scope': 'repository implementation closure; authenticated runtime availability/outcomes are separately evidenced',
        'phase_count': len(phases),
        'workflow_pack_count': len(declared_packs),
        'critical_gate_count': len(catalog.get('critical_gates') or []),
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
        print(f"SEO closure: {result['status'].upper()} — {result['phase_count']} phases, {result['workflow_pack_count']} workflow packs, {result['critical_gate_count']} critical gates")
        for error in result['errors']:
            print(f'FAIL: {error}')
        for warning in result['warnings']:
            print(f'WARN: {warning}')
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
