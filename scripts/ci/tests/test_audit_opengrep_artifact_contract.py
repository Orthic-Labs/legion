import runpy
from pathlib import Path
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-opengrep-artifact-accuracy.py"))


class OpenGrepArtifactContractTests(unittest.TestCase):
    def test_selector_digest_binds_source_file_subset_and_full_inventory_context(self):
        inventory = {
            "digest": "sha256:" + "a" * 64,
            "entries": [
                {"path": "app.py", "sourceFile": True, "digest": "sha256:" + "b" * 64},
                {"path": "README.md", "sourceFile": False, "digest": "sha256:" + "c" * 64},
            ],
        }
        selector = {"op": "sourceFilesAtLeast", "count": 1}
        actual, selected = API["selector_denominator"](inventory, selector)
        self.assertEqual(selected, [inventory["entries"][0]])
        self.assertEqual(actual, API["digest"](API["canonical"]([inventory["digest"], selector, selected])))
        self.assertNotEqual(actual, inventory["digest"])
        changed = {**inventory, "digest": "sha256:" + "d" * 64}
        self.assertNotEqual(API["selector_denominator"](changed, selector)[0], actual)
        with self.assertRaises(ValueError):
            API["selector_denominator"](inventory, {"op": "always"})

    def test_version_receipt_defaults_only_omitted_skipped_flag_to_false(self):
        base = {"args": ["--version"], "output": "1.31.0", "exitCode": 0, "qualified": True}
        API["require_not_skipped_by_policy"](base)
        API["require_not_skipped_by_policy"]({**base, "skippedByPolicy": False})
        for changed in ({**base, "skippedByPolicy": True}, {**base, "skippedByPolicy": 0},
                        {**base, "skippedByPolicy": "false"}, {"args": ["--version"], "exitCode": 0, "qualified": True}):
            with self.subTest(receipt=changed), self.assertRaises(ValueError):
                API["require_not_skipped_by_policy"](changed)


if __name__ == "__main__":
    unittest.main()
