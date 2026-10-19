#!/usr/bin/env python3
"""Source-level registration/refusal controls; native execution stays in SDK CI."""
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / 'scripts/ci/audit-c-family-sdk-registration.py'))
GATE = runpy.run_path(str(ROOT / 'scripts/ci/audit-qualification-records.py'))


class CFamilyAdapterTests(unittest.TestCase):
    def entry(self):
        return {'provider': 'code.c-family', 'family': API['FAMILY'], 'stage': 'finding', 'scope': API['SCOPE']}

    def test_dedicated_route_retains_all_tools_and_scope(self):
        self.assertEqual(GATE['adapter'](ROOT, self.entry()), (API['FAMILY'], API['HARNESS'], 'canonical-json', API['HARNESS']))
        self.assertEqual(GATE['VALIDATORS'][API['FAMILY']], API['VALIDATOR'])
        paths = GATE['closure_paths'](ROOT, self.entry())
        self.assertIn(API['SELF'], paths)
        self.assertIn(API['SCHEMA'], paths)
        self.assertIn('engine/crates/legion-audit/tests/c_family_sdk_accuracy.rs', paths)
        self.assertNotIn('src/registry/providers.json', paths)
        scope = API['qualification_fields']()
        self.assertIs(scope['productionQualification'], False)
        self.assertIs(scope['selfProducerQualification'], False)

    def test_scope_and_stage_substitutions_refused(self):
        for key, value in [('provider', 'code.go'), ('stage', 'candidate'), ('scope', 'compiler-only')]:
            entry = self.entry(); entry[key] = value
            with self.assertRaises(AssertionError):
                API['adapter'](entry)

    def test_locator_uses_original_native_artifact_bytes(self):
        row = {'cases': [{'scratchRoot': '/private/tmp/legion-provider-qualification/code-c-family/c-family-sdk-1/evidence/cases/clean'}], 'provider': 'code.c-family', 'qualificationDigest': 'sha256:' + '1' * 64}
        raw = json.dumps(row, indent=2).encode() + b'\n'
        locator = API['locator'](ROOT, row, raw)
        self.assertEqual(locator['path'], '/private/tmp/legion-provider-qualification/code-c-family/c-family-sdk-1/evidence/code-c-family-native-sdk.json')
        self.assertEqual(str(API['receipt_root'](row)), '/private/tmp/legion-provider-qualification/code-c-family')
        self.assertEqual(locator['sha256'], GATE['digest'](raw))
        self.assertNotEqual(locator['sha256'], GATE['digest'](raw.rstrip()))

    def test_observation_enrollment_cannot_qualify(self):
        bootstrap = runpy.run_path(str(ROOT / 'scripts/ci/audit-c-family-sdk-bootstrap.py'))
        for field in ('productionQualification', 'qualificationEligible'):
            manifest = {'schema': bootstrap['SCHEMA'], 'productionQualification': False, 'qualificationEligible': False}
            manifest[field] = True
            with self.assertRaises(ValueError):
                bootstrap['verify_enrollment'](manifest, live=False)

    def test_production_metadata_never_promotes(self):
        entry = self.entry(); entry['record'] = {'path': 'retained', 'sha256': 'sha256:' + '2' * 64, 'qualificationDigest': 'sha256:' + '3' * 64}
        value = GATE['qualification'](entry)
        self.assertIs(value['productionQualification'], False)
        self.assertIs(value['selfProducerQualification'], False)
        self.assertEqual(value['fixtureScope'], API['SCOPE'])


if __name__ == '__main__':
    unittest.main()
