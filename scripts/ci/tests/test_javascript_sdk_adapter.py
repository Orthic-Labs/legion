"""Pinned pnpm qualification runs preserve sealed dependency runtime."""
from pathlib import Path, PurePosixPath
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / 'scripts/ci/audit-javascript-sdk-accuracy.py'))


class JavascriptRuntimeEnvironmentTests(unittest.TestCase):
    def test_pre_run_dependency_writer_is_disabled_with_typed_uppercase_config(self):
        policy = {'profile': {'path': '/scratch/case/run/sandbox/profile.sb'},
                  'cwd': '/scratch/case/source', 'node': {'path': '/tools/node'}}
        environment, allowed = API['expected_environment'](policy)
        self.assertEqual(environment['PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN'], 'false')
        self.assertIn('PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN', allowed)
        self.assertNotIn('pnpm_config_verify_deps_before_run', environment)
        self.assertNotIn('pnpm_config_verify_deps_before_run', allowed)


class JavascriptPreparationRetentionTests(unittest.TestCase):
    def test_preparation_config_is_bound_to_fixture_root_outside_upload_tree(self):
        case = {
            'caseId': 'javascript-manager-mismatch',
            'policyDefinition': {
                'cwd': '/runner-temp/legion-js-sdk-fixtures/javascript-manager-mismatch/source',
                'profile': {'path': '/runner-temp/legion-provider-qualification/javascript-sdk/cases/javascript-manager-mismatch/run/sandbox/profile.sb'},
            },
        }
        config_root = API['preparation_config_root'](case)
        self.assertEqual(
            config_root,
            PurePosixPath('/runner-temp/legion-js-sdk-fixtures/preparations/javascript-manager-mismatch-config'),
        )
        uploaded = PurePosixPath('/runner-temp/legion-provider-qualification/javascript-sdk')
        self.assertFalse(config_root.is_relative_to(uploaded))
        self.assertNotEqual(
            config_root,
            uploaded / 'preparations/javascript-manager-mismatch-config',
        )
        changed = {**case, 'policyDefinition': {'cwd': '/runner-temp/other-fixtures/javascript-manager-mismatch/source'}}
        self.assertNotEqual(API['preparation_config_root'](changed), config_root)
        invalid = {**case, 'policyDefinition': {'cwd': '/runner-temp/legion-js-sdk-fixtures/other-case/source'}}
        with self.assertRaises(AssertionError):
            API['preparation_config_root'](invalid)


if __name__ == '__main__':
    unittest.main()
