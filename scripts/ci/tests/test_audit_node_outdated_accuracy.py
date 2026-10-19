"""Synthetic parser/registration controls; never native npm qualification evidence."""
from pathlib import Path
import runpy
import unittest
api = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-node-outdated-accuracy.py"))


class NodeOutdatedControls(unittest.TestCase):
    def test_valid_array_rows_and_nonempty_clean_report(self):
        row = {"current": "1.3.1", "wanted": "1.3.1", "latest": "1.3.3"}
        self.assertEqual(api["report_rows"]({"tiny-invariant": row}), {"tiny-invariant": [["1.3.1", "1.3.1", "1.3.3"]]})
        self.assertEqual(api["report_rows"]({"tiny-invariant": [row, row]}), {"tiny-invariant": [["1.3.1", "1.3.1", "1.3.3"]] * 2})
        # Empty report is syntactically valid only; validate_record requires
        # nonempty installed + exact + latest proof before accepting clean.
        self.assertEqual(api["report_rows"]({}), {})

    def test_operational_and_malformed_rows_are_rejected(self):
        for value in ([], None, {"error": {"code": "E404"}}, {"pkg": []}, {"pkg": {}},
                      {"pkg": {"current": "1.0.0", "wanted": "^1.0.0", "latest": "2.0.0"}},
                      {"pkg": {"current": "1.0.0", "wanted": "1.0.0", "latest": "1.0.0"}}):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                api["report_rows"](value)

    def test_duplicate_json_cannot_hide_errors(self):
        with self.assertRaises(AssertionError):
            api["parsed"]('{"error":{},"error":null}')

    def test_all_four_sections_conflicting_declarations_rejected(self):
        manifest = {key: {name: "1.0.0"} for key, name in zip(
            ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"), ("a", "b", "c", "d"))}
        deps, commands = api["operations"](manifest)
        self.assertEqual(len(deps), 4)
        self.assertEqual(len(commands), 10)
        manifest["peerDependencies"] = {"a": "2.0.0"}
        with self.assertRaises(AssertionError):
            api["operations"](manifest)
