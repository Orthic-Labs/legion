#!/usr/bin/env python3
"""Shared Homebrew Clang config stays inside explicit measured native closure."""
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / 'scripts/ci/audit-c-family-sdk-bootstrap.py'))


class CFamilyBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.prefix = Path(self.temporary.name).resolve() / 'homebrew'
        self.llvm = self.prefix / 'Cellar/llvm/23.1.0'
        (self.llvm / 'bin').mkdir(parents=True)
        (self.llvm / 'etc').mkdir()
        self.config = self.prefix / 'etc/clang'
        self.config.mkdir(parents=True)
        (self.config / 'clang.cfg').write_bytes(b'--sysroot=/selected/sdk\n')
        self.alias = self.llvm / 'etc/clang'
        self.alias.symlink_to('../../../../etc/clang')

    def selected_config(self, roots=None):
        return API['homebrew_clang_config_root'](
            self.llvm / 'bin/clang', self.prefix, [self.llvm] if roots is None else roots)

    def test_exact_config_target_is_measured_with_source_alias(self):
        config = self.selected_config()
        self.assertEqual(config, self.config)
        roots = [self.llvm, config]
        llvm_tree = API['tree'](self.llvm, roots)
        config_tree = API['tree'](config, roots)
        self.assertEqual(llvm_tree['aliases'], {str(self.alias): str(config)})
        self.assertEqual(config_tree['files'], {
            str(config / 'clang.cfg'): API['digest'](b'--sysroot=/selected/sdk\n')})
        self.assertNotIn(str(self.prefix), [part['root'] for part in (llvm_tree, config_tree)])
        with self.assertRaisesRegex(ValueError, 'alias escapes enrolled roots'):
            API['tree'](self.llvm, [self.llvm])

    def test_unexpected_source_link_target_is_rejected(self):
        other = self.prefix / 'etc/other'
        other.mkdir()
        self.alias.unlink()
        self.alias.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'unexpected Homebrew LLVM'):
            self.selected_config()

    def test_shared_config_alias_target_is_rejected(self):
        config = self.config.rename(self.prefix / 'etc/elsewhere')
        self.config.symlink_to(config)
        with self.assertRaisesRegex(ValueError, 'unexpected Homebrew LLVM'):
            self.selected_config()

    def test_formula_root_must_already_be_enrolled(self):
        with self.assertRaisesRegex(ValueError, 'enrolled Homebrew formula root'):
            self.selected_config([])

    def test_shared_config_cannot_escape_other_enrolled_roots(self):
        outside = self.prefix / 'etc/unrelated.cfg'
        outside.write_bytes(b'not enrolled\n')
        (self.config / 'escape.cfg').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'alias escapes enrolled roots'):
            API['tree'](self.selected_config(), [self.llvm, self.config])


if __name__ == '__main__':
    unittest.main()
