from __future__ import annotations

import importlib.util
import sys
import unittest
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / 'scripts'


def load(name: str):
    path = SCRIPTS / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'seo_contract_{name}', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ContractAndSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts = load('contracts')
        cls.sources = load('source_freshness')

    def test_complete_evidence_and_finding_contract(self):
        evidence = {
            'id':'e1','source_identity':'gsc:sc-domain:example.com','collected_at':'2026-09-11T00:00:00Z',
            'market':'IN/en','tier':'first_party','subject':'https://example.com/','raw_locator':'file:gsc.json#row1','coverage_state':'pass'
        }
        finding = {
            'id':'f1','subject':'https://example.com/','evidence_ids':['e1'],'market':'IN/en','confidence':'high',
            'coverage_state':'fail','claim_state':'observed','observed_condition':'priority page carries noindex'
        }
        self.assertEqual(self.contracts.validate('evidence', evidence), [])
        self.assertEqual(self.contracts.validate('finding', finding), [])

    def test_partial_finding_requires_tested_and_untested_scope(self):
        finding = {
            'id':'f1','subject':'x','evidence_ids':['e1'],'market':'IN/en','confidence':'medium',
            'coverage_state':'partial','claim_state':'observed','observed_condition':'only desktop checked'
        }
        errors = self.contracts.validate('finding', finding)
        self.assertTrue(any('tested_scope' in x for x in errors))

    def test_executed_action_requires_effect_receipt(self):
        action = {
            'id':'a1','recommendation_id':'r1','authorized_capability':'edit-repo','target':'file','exact_change':'x',
            'baseline_ref':'b1','idempotency_key':'k','rollback':'git revert','status':'executed'
        }
        errors = self.contracts.validate('action', action)
        self.assertTrue(any('effect_receipt' in x for x in errors))

    def test_official_sources_current_on_release_date(self):
        result = self.sources.assess(date(2026, 9, 11))
        self.assertEqual(result['status'], 'pass')
        self.assertFalse(result['due'])

    def test_source_freshness_fails_when_review_overdue(self):
        result = self.sources.assess(date(2027, 1, 1))
        self.assertEqual(result['status'], 'fail')
        self.assertTrue(result['due'])


if __name__ == '__main__':
    unittest.main()
