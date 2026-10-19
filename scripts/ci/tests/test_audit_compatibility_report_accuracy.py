import json
from pathlib import Path
import runpy
import tempfile
import unittest

API = runpy.run_path(str(Path(__file__).parents[1] / 'validate-compatibility-report-accuracy.py'))


class CompatibilityReplayPrimitiveTests(unittest.TestCase):
    def test_duplicate_json_fields_and_nonfinite_numbers_rejected(self):
        for text in ['{"schema":1,"schema":2}', '{"nested":{"field":1,"field":2}}',
                     '{"number":NaN}', '{"number":Infinity}']:
            with self.subTest(text=text), self.assertRaises(AssertionError):
                API['parsed'](text)

    def test_types_remain_distinct(self):
        for left, right in [(True, 1), (False, 0), ([], {}), ('1', 1)]:
            with self.subTest(left=left, right=right), self.assertRaises(AssertionError):
                API['same'](left, right, 'different types')

    def test_artifact_root_refuses_traversal_absolute_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'file').write_bytes(b'known answer')
            self.assertEqual(API['source'](root, 'file').read_bytes(), b'known answer')
            for name in ('../outside', '/outside', 'a/../file', './file', 'a//file', 'a\\file', 'C:file', ''):
                with self.subTest(name=name), self.assertRaises(AssertionError):
                    API['source'](root, name)
            try:
                (root / 'link').symlink_to(root / 'file')
            except OSError:
                return  # Platform policy may prohibit creating test symlinks.
            with self.assertRaises(AssertionError):
                API['source'](root, 'link')

    def test_known_answer_inventory_has_full_selected_source(self):
        inventory = API['fixed_inventory']()
        self.assertEqual([r['path'] for r in inventory['entries']], ['README.md', 'src/existing.rs'])
        self.assertEqual([r['sourceFile'] for r in inventory['entries']], [False, True])
        self.assertEqual(inventory['digest'], API['digest'](API['encoded']([
            1, inventory['repositoryId'], inventory['generation'], inventory['entries']])))

    def test_three_file_inventory_is_distinct_from_two_schema_contracts(self):
        inventory = API['fixed_inventory'](extra=True)
        self.assertEqual(len(inventory['entries']), 3)
        self.assertEqual([r['path'] for r in inventory['entries']],
                         ['README.md', 'src/additional.rs', 'src/existing.rs'])
        self.assertNotEqual(inventory['digest'], API['fixed_inventory']()['digest'])
        self.assertEqual(inventory['digest'], API['digest'](API['encoded']([
            1, inventory['repositoryId'], inventory['generation'], inventory['entries']])))

    def test_registration_metadata_does_not_create_source_binding_cycle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = root / 'src/registry/providers.json'
            registry.parent.mkdir(parents=True)
            value = {'providers': [{'id': 'compatibility.core', 'selector': {'op': 'always'},
                                    'benchmark': {'status': 'unqualified', 'qualificationDigest': None}}]}
            registry.write_text(json.dumps(value))
            original = API['source_digest'](root, 'src/registry/providers.json')
            value['providers'][0]['benchmark'] = {'status': 'qualified', 'qualification': {'record': 'synthetic'}}
            registry.write_text(json.dumps(value))
            self.assertEqual(API['source_digest'](root, 'src/registry/providers.json'), original)
            value['providers'][0]['selector'] = {'op': 'never'}
            registry.write_text(json.dumps(value))
            self.assertNotEqual(API['source_digest'](root, 'src/registry/providers.json'), original)

    def test_core_retains_evidence_and_omits_only_reserved_projection_field(self):
        value = {'report_id': 'r', 'status': 'incomplete', 'gaps': ['gap'], 'claims': {'coverage': 2}, 'targets': ['root'],
                 'findings': [{'id': 'f', 'severity': 'warning', 'title': 't', 'message': 'm', 'provider': 'p',
                               'locations': ['README.md'], 'evidence': {'source': 'bound', 'legionV2': {'confidence': 'legacy-unknown'}}}]}
        result = API['core'](value)
        self.assertEqual(result['findings'][0]['evidence'], {'source': 'bound'})
        self.assertEqual(result['gaps'], ['gap'])
        self.assertEqual(result['claims'], {'coverage': 2})
        self.assertIn('legionV2', value['findings'][0]['evidence'])


if __name__ == '__main__':
    unittest.main()
