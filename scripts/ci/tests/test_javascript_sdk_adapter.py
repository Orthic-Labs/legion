"""Pinned pnpm qualification runs preserve sealed dependency runtime."""
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
