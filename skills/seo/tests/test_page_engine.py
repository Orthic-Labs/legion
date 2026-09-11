from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / 'scripts'


def load(name: str):
    path = SCRIPTS / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'seo_page_{name}', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PageEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load('page_engine')

    def valid_contract(self):
        return {
            'page_type': 'INFORMATIONAL',
            'primary_intent': 'learn how to use the viewer',
            'required_information': ['supported formats', 'steps'],
            'proof_evidence': ['product docs'],
            'internal_link_role': 'documentation spoke',
        }

    def test_structural_blocker_precedes_copy(self):
        result = self.engine.assess({
            'page': {'url':'https://e/guide','page_type':'INFORMATIONAL','canonical_expected':'https://e/guide','canonical_observed':'https://e/other','intended_indexable':True,'observed_indexable':False},
            'page_contract': self.valid_contract(),
            'query_ownership': [{'query':'how to use','classification':'ownership switching'}],
            'claims': [],
        })
        kinds = {x['type'] for x in result['blockers']}
        self.assertIn('canonical_mismatch', kinds)
        self.assertIn('wrong_indexability', kinds)
        self.assertIn('multiple_owners_one_intent', kinds)

    def test_expand_requires_real_information_gain(self):
        result = self.engine.assess({
            'page': {'url':'https://e/guide'},
            'page_contract': self.valid_contract(),
            'verdict': 'EXPAND',
            'information_gain': [{'type':'better_synthesis'}],
            'claims': [],
        })
        self.assertEqual(result['status'], 'fail')
        self.assertIn('EXPAND requires demonstrated information gain', result['errors'])

    def test_verified_information_gain_allows_expand(self):
        result = self.engine.assess({
            'page': {'url':'https://e/guide'},
            'page_contract': self.valid_contract(),
            'verdict': 'EXPAND',
            'information_gain': [{'type':'first_party_data','evidence':'support-ticket analysis'}],
            'claims': [],
        })
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['verdict'], 'EXPAND')

    def test_unverified_claim_cannot_ship(self):
        result = self.engine.assess({
            'page': {'url':'https://e/guide'},
            'page_contract': self.valid_contract(),
            'claims': [{'claim':'Used by one million customers','state':'requires_verification','use_in_output':True}],
        })
        self.assertEqual(result['status'], 'fail')

    def test_destructive_verdict_requires_justification(self):
        result = self.engine.assess({
            'page': {'url':'https://e/legacy'},
            'page_contract': self.valid_contract(),
            'verdict': 'REDIRECT',
            'claims': [],
        })
        self.assertEqual(result['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
