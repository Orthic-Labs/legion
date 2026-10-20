import runpy
from pathlib import Path
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-extra-provider-accuracy.py"))


class ExtraProviderReceiptContractTests(unittest.TestCase):
    def test_version_receipt_omitted_false_default_and_explicit_false_are_accepted(self):
        base = {"args": ["--version"], "output": "scanner 1.0", "exitCode": 0, "qualified": True}
        API["require_not_skipped_by_policy"](base)
        API["require_not_skipped_by_policy"]({**base, "skippedByPolicy": False})

    def test_version_receipt_refuses_true_wrong_type_and_missing_required_field(self):
        base = {"args": ["--version"], "output": "scanner 1.0", "exitCode": 0, "qualified": True}
        for changed in ({**base, "skippedByPolicy": True}, {**base, "skippedByPolicy": 0},
                        {**base, "skippedByPolicy": "false"}, {"args": ["--version"], "exitCode": 0, "qualified": True}):
            with self.subTest(receipt=changed), self.assertRaises(ValueError):
                API["require_not_skipped_by_policy"](changed)


if __name__ == "__main__":
    unittest.main()
