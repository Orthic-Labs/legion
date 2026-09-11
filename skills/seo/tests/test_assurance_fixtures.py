from __future__ import annotations

import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEO_ROOT = HERE.parent
FIX = HERE / 'fixtures'


class AssuranceFixtureTests(unittest.TestCase):
    def test_every_critical_gate_has_adversarial_fixture(self):
        catalog = json.loads((SEO_ROOT / 'config/control-catalog.json').read_text())
        matrix = json.loads((FIX / 'p0_cases.json').read_text())
        gates = set(catalog['critical_gates'])
        represented = {x['critical_gate'] for x in matrix['cases']}
        self.assertEqual(represented, gates)
        for case in matrix['cases']:
            self.assertEqual(case['expected'], 'fail')
            self.assertTrue((FIX / case['fixture']).exists(), case['fixture'])
        for control in matrix['clean_controls']:
            self.assertEqual(control['expected'], 'pass')
            self.assertTrue((FIX / control['fixture']).exists())

    def test_every_declared_workflow_pack_has_qualification_case(self):
        catalog = json.loads((SEO_ROOT / 'config/control-catalog.json').read_text())
        matrix = json.loads((FIX / 'workflow_pack_cases.json').read_text())
        declared = set(catalog['workflow_packs'])
        represented = {x['pack'] for x in matrix['cases']}
        self.assertEqual(represented, declared)
        allowed = {'pass', 'partial', 'fail', 'na', 'not_testable'}
        for case in matrix['cases']:
            self.assertIn(case['expected_state'], allowed)
            if case['expected_state'] == 'not_testable':
                self.assertEqual(case['evidence'], [])
            else:
                self.assertTrue(case['evidence'])

    def test_redirect_loop_fixture_is_actually_cyclic(self):
        data = json.loads((FIX / 'redirect_loop.json').read_text())['redirects']
        start = next(iter(data))
        seen = set()
        cur = start
        for _ in range(len(data) + 1):
            if cur in seen:
                break
            seen.add(cur)
            cur = data[cur]
        self.assertIn(cur, seen)

    def test_measurement_fixture_demonstrates_integrity_failure(self):
        data = json.loads((FIX / 'measurement_broken.json').read_text())
        event = data['events'][0]
        self.assertGreater(event['count'], 1)
        self.assertEqual(data['measurement_id'], data['staging_measurement_id'])

    def test_authority_fixture_has_no_capability_or_confirmation(self):
        data = json.loads((FIX / 'authority_violation.json').read_text())
        self.assertTrue(data['binding'])
        self.assertIsNone(data['authorized_capability'])
        self.assertFalse(data['confirmation'])


if __name__ == '__main__':
    unittest.main()
