from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEO_ROOT = HERE.parent
SCRIPTS = SEO_ROOT / 'scripts'
FIX = HERE / 'fixtures'


def load(name: str):
    path = SCRIPTS / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'seo_gov_{name}', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SeoGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.providers = load('provider_registry')
        cls.coverage = load('coverage')
        cls.compiler = load('checklist_compiler')
        cls.audit = load('site_audit')

    def test_provider_selection_prefers_first_party_and_hides_secret_values(self):
        old = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'C:/secret/credentials.json'
        try:
            discovered = self.providers.discover()
            blob = json.dumps(discovered)
            self.assertNotIn('C:/secret/credentials.json', blob)
            selected = self.providers.choose('search_performance')
            self.assertEqual(selected['provider'], 'google_gsc')
            self.assertFalse(selected['paid'])
        finally:
            if old is None:
                os.environ.pop('GOOGLE_APPLICATION_CREDENTIALS', None)
            else:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = old

    def test_paid_provider_not_selected_without_paid_authority(self):
        old_user, old_pass = os.environ.get('DATAFORSEO_LOGIN'), os.environ.get('DATAFORSEO_PASSWORD')
        os.environ['DATAFORSEO_LOGIN'], os.environ['DATAFORSEO_PASSWORD'] = 'u', 'p'
        try:
            blocked = self.providers.choose('serp', allow_paid=False)
            allowed = self.providers.choose('serp', allow_paid=True)
            self.assertEqual(blocked['status'], 'unavailable')
            self.assertEqual(allowed['provider'], 'dataforseo')
        finally:
            if old_user is None: os.environ.pop('DATAFORSEO_LOGIN', None)
            else: os.environ['DATAFORSEO_LOGIN'] = old_user
            if old_pass is None: os.environ.pop('DATAFORSEO_PASSWORD', None)
            else: os.environ['DATAFORSEO_PASSWORD'] = old_pass

    def test_coverage_keeps_not_testable_in_denominator(self):
        result = self.coverage.calculate([
            {'id':'a','status':'pass','critical':True},
            {'id':'b','status':'not_testable','critical':False,'reason':'no log access'},
            {'id':'c','status':'na','rationale':'not ecommerce'},
        ])
        self.assertEqual(result['applicable_controls'], 2)
        self.assertEqual(result['tested_controls'], 1)
        self.assertEqual(result['evidence_coverage'], 0.5)

    def test_critical_failure_is_not_averaged_away(self):
        result = self.coverage.calculate([
            {'id':'index','status':'fail','critical':True},
            {'id':'nice','status':'pass','critical':False},
        ])
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['critical_failures'], ['index'])

    def test_partial_requires_scope(self):
        result = self.coverage.calculate([{'id':'x','status':'partial'}])
        self.assertEqual(result['status'], 'fail')
        self.assertTrue(result['validation_errors'])

    def test_checklist_compiler_preserves_line_and_digest(self):
        text = '# Header\n\n## PHASE 1 — Baseline\n- [ ] Check rankings\n- [ ] Check traffic\n'
        result = self.compiler.compile_text(text, 'fixture.md')
        self.assertEqual(result['line_count'], 5)
        self.assertEqual(result['candidate_count'], 2)
        self.assertEqual(result['candidates'][0]['phase'], 1)
        self.assertEqual(result['candidates'][0]['line_start'], 4)
        self.assertEqual(result['candidates'][0]['promotion_state'], 'candidate')

    def test_checklist_semantic_diff(self):
        old = self.compiler.compile_text('## PHASE 1\n- [ ] A\n', 'x')
        new = self.compiler.compile_text('## PHASE 1\n- [ ] A\n- [ ] B\n', 'x')
        diff = self.compiler.semantic_diff(old, new)
        self.assertEqual(len(diff['added']), 1)
        self.assertFalse(diff['removed'])

    def test_crawler_parser_detects_mixed_content_and_relative_canonical(self):
        html = '<html><head><title>Example Good Page</title><meta name="description" content="A useful description with enough detail for a realistic test page and its users."><meta name="viewport" content="width=device-width"><link rel="canonical" href="/good/"></head><body><h1>Good</h1><img alt="x" src="http://cdn.example/x.png"></body></html>'
        parsed, _ = self.audit.parse(html)
        self.assertTrue(parsed['mixed_content'])
        self.assertEqual(parsed['canonical'], '/good/')

    def test_control_catalog_has_exact_source_ranges(self):
        catalog = json.loads((SEO_ROOT / 'config/control-catalog.json').read_text())
        self.assertEqual([p['id'] for p in catalog['phases']], list(range(1, 31)))
        self.assertEqual(catalog['phases'][0]['source_lines'], [74, 134])
        self.assertEqual(catalog['phases'][-1]['source_lines'], [1591, 1681])
        previous = 73
        for phase in catalog['phases']:
            self.assertEqual(phase['source_lines'][0], previous + 1)
            previous = phase['source_lines'][1]
        self.assertEqual(previous, catalog['source_line_count'])


if __name__ == '__main__':
    unittest.main()
