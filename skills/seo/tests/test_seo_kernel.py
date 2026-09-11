from __future__ import annotations

import importlib.util
import json
import os
import subprocess
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
    spec = importlib.util.spec_from_file_location(f'seo_test_{name}', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SeoKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = load('seo_project')
        cls.ownership = load('query_ownership')
        cls.questions = load('question_inventory')
        cls.ranks = load('rank_tracker')
        cls.ai = load('ai_visibility_import')
        cls.meta = load('templated_metadata')
        cls.audit = load('site_audit')
        cls.closure = load('seo_closure')

    def test_project_setup_doctor_never_exposes_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get('GOOGLE_API_KEY')
            os.environ['GOOGLE_API_KEY'] = 'super-secret-value'
            try:
                site = self.project.setup_project(td, domain='example.com', market='IN', language='en', gsc_property='sc-domain:example.com')
                self.assertEqual(site['market'], 'IN')
                self.assertTrue((Path(td) / '.legion/seo/site.yaml').exists())
                result = self.project.doctor(td)
                blob = json.dumps(result)
                self.assertNotIn('super-secret-value', blob)
                self.assertEqual(result['providers']['google_api']['state'], 'present')
            finally:
                if old is None:
                    os.environ.pop('GOOGLE_API_KEY', None)
                else:
                    os.environ['GOOGLE_API_KEY'] = old

    def test_cache_key_includes_market_dimensions(self):
        a = self.project.cache_key('dfs', 'serp', 'viewer', country='IN', language='en', device='desktop')
        b = self.project.cache_key('dfs', 'serp', 'viewer', country='US', language='en', device='desktop')
        self.assertNotEqual(a, b)
        self.assertEqual(a, self.project.cache_key('dfs', 'serp', 'viewer', country='IN', language='en', device='desktop'))

    def test_cost_preflight_fails_closed_over_ceiling(self):
        call = self.project.PlannedCall('dataforseo', 'serp', 10, 0.02, 2)
        result = self.project.preflight([call], ceiling_usd=0.10)
        self.assertEqual(result['status'], 'needs_authority')
        self.assertEqual(result['calls'][0]['billable_count'], 8)

    def test_query_ownership_and_switching(self):
        payload = json.loads((FIX / 'gsc_rows.json').read_text())
        out = {x.query: x for x in self.ownership.classify(payload['rows'])}
        self.assertEqual(out['how to use viewright'].classification, 'benign overlap')
        self.assertEqual(out['viewright pricing'].classification, 'stable owner')
        self.assertEqual(out['viewright alternative'].classification, 'ownership switching')

    def test_question_inventory_is_gsc_first(self):
        payload = json.loads((FIX / 'gsc_rows.json').read_text())
        result = self.questions.build(payload)
        qs = {x['question'] for x in result}
        self.assertIn('how to use viewright?', qs)
        self.assertNotIn('viewright pricing?', qs)

    def test_rank_tracker_detects_url_ownership_change(self):
        with tempfile.TemporaryDirectory() as td:
            base = {'market': 'IN', 'language': 'en', 'device': 'desktop', 'provider': 'fixture'}
            self.ranks.ingest(td, [{'keyword':'viewer','position':5,'url':'https://e/x','intended_page':'https://e/x'}], base | {'snapshot':'001'})
            self.ranks.ingest(td, [{'keyword':'viewer','position':4,'url':'https://e/y','intended_page':'https://e/x'}], base | {'snapshot':'002'})
            out = self.ranks.compare(td)
            self.assertEqual(out['ownership_changes'], 1)
            self.assertEqual(out['intended_page_mismatches'], 1)

    def test_ai_import_keeps_google_and_bing_measurements_distinct(self):
        g = self.ai.google(self.ai.load_rows(FIX / 'ai_google.csv'), 'fixture')
        b = self.ai.bing(self.ai.load_rows(FIX / 'ai_bing.csv'), 'fixture')
        self.assertEqual(g['measurement'], 'impressions')
        self.assertEqual(b['measurement'], 'citations')
        self.assertIsNone(g['rows'][0].get('citations'))
        self.assertIn('citation_share', b['rows'][0])

    def test_templated_metadata_detector(self):
        rows = [
            {'url':f'https://e/{i}','title':f'Widget {i}','meta_desc':f'Widget {i}. Learn more'}
            for i in range(5)
        ]
        out = self.meta.analyze(rows)
        self.assertEqual(out['site_risk'], 'high')
        self.assertEqual(out['templated_pages'], 5)

    def test_badseo_noindex_and_clean_control(self):
        bad, _ = self.audit.parse((FIX / 'badseo/noindex.html').read_text())
        good, _ = self.audit.parse((FIX / 'badseo/clean.html').read_text())
        self.assertTrue(bad['noindex'])
        self.assertFalse(good['noindex'])
        self.assertTrue(good['canonical'])
        self.assertEqual(len(good['h1']), 1)

    def test_intervention_state_machine(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / 'ops.json'
            script = SCRIPTS / 'search_ops.py'
            def run(*args):
                return subprocess.run([sys.executable, str(script), '--state', str(state), *args], check=True, capture_output=True, text=True)
            run('start','--id','i1','--target','https://e/x','--hypothesis','better snippet','--action','change title','--metric','ctr','--evaluate-after','2026-10-01')
            run('deploy','--id','i1','--identity','commit:abc')
            run('verify','--id','i1','--result','pass','--evidence','recrawl')
            run('outcome','--id','i1','--verdict','inconclusive','--evidence','gsc')
            data = json.loads(state.read_text())
            self.assertEqual(data['interventions'][0]['status'], 'outcome_recorded')
            self.assertEqual(data['interventions'][0]['verification']['result'], 'pass')

    def test_repository_closure_gate(self):
        result = self.closure.check()
        self.assertEqual(result['status'], 'pass', '\n'.join(result['errors']))
        self.assertEqual(result['phase_count'], 30)


if __name__ == '__main__':
    unittest.main()
