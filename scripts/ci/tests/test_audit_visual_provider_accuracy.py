"""Validator controls; synthetic state never establishes browser provenance."""
from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import re
import tempfile
import runpy
import unittest
from unittest.mock import patch

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-visual-provider-accuracy.py"))


class VisualFrameEvidenceTests(unittest.TestCase):
    def test_real_frame_completion_requires_both_callbacks(self):
        frames = {"rafAvailable": True, "frameCallbacks": 2, "frameProbeComplete": True, "readyState": "complete"}
        API["frame_completion"]({"animationFrames": frames})
        for changed in ({}, {"frameCallbacks": 1}, {"frameCallbacks": True},
                        {"frameProbeComplete": False}, {"rafAvailable": False}, {"readyState": "loading"}):
            with self.assertRaises(AssertionError):
                API["frame_completion"]({} if not changed else {"animationFrames": {**frames, **changed}})

    def test_poll_count_may_vary_but_admissions_remain_exact(self):
        captured = {"url": "http://127.0.0.1:1234/baseline/index.html"}
        common = {"allowed": True, "sessionId": "control", "url": captured["url"]}
        fixed = [{**common, "action": "Navigate", "detail": None}] + [
            {**common, "action": "Eval", "detail": API[name]}
            for name in ("READY", "START_ANIMATION_FRAMES", "HIGH_ENTROPY_UA", "OBSERVE")]
        poll = {**common, "action": "Eval", "detail": API["ANIMATION_STATE"]}
        for count in (1, 4):
            API["capture_admissions"](captured, fixed + [poll] * count, "control")
        for invalid in (fixed, fixed + [poll, {**poll, "detail": "true"}],
                        fixed + [poll, fixed[2]], fixed + [{**poll, "allowed": False}]):
            with self.assertRaises(AssertionError):
                API["capture_admissions"](captured, invalid, "control")


class VisualReceiptInventoryTests(unittest.TestCase):
    """Pure receipt selection controls; mocked validation cannot certify rendering."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="visual-receipt-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.receipts = self.root / "visual"
        self.receipts.mkdir()
        source_root = Path(__file__).resolve().parents[3]
        source = (source_root / "engine/crates/legion-audit/tests/visual_accuracy.rs").read_text()
        # Read actual producer destinations: this guards cross-language layout.
        self.destinations = dict((name, base) for base, name in re.findall(
            r'fs::write\(\s*(output|root)\.join\("([^"\n]+\.json)"\)', source))
        self.assertEqual(self.destinations["legacy_visual-core.json"], "output")
        self.assertEqual(self.destinations["visual-lifecycle.json"], "root")

    def invoke(self, validation_error=None):
        observed = self.observed = []
        summary = {"provider": "unit-only"}
        def validate(root, row, **options):
            observed.append((root, row, options))
            if validation_error:
                raise AssertionError(validation_error)
            return summary
        output = self.output = io.StringIO()
        with patch("sys.argv", ["audit-visual-provider-accuracy.py", "--root", str(self.root),
                                "--receipts", str(self.receipts)]), patch.dict(API["main"].__globals__, {
                                    "validate_record": validate}), redirect_stdout(output):
            API["main"]()
        return observed, output.getvalue(), summary

    def write_layout(self):
        artifacts = self.receipts / "visual-artifacts-unit"
        artifacts.mkdir()
        for name, base in self.destinations.items():
            directory = self.receipts if base == "output" else artifacts
            (directory / name).write_text(json.dumps({"unitOnly": True}))
        return artifacts

    def test_actual_producer_layout_selects_only_exact_receipt(self):
        artifacts = self.write_layout()
        observed, output, summary = self.invoke()
        self.assertEqual(observed, [(self.root, {"unitOnly": True}, {"receipts": self.receipts})])
        prefix = "VISUAL_PROVIDER_ACCURACY_SUMMARY "
        self.assertEqual(json.loads(output.removeprefix(prefix)), {"records": [summary], "modelCalls": 0})
        self.assertTrue((artifacts / "visual-lifecycle.json").is_file())

    def test_top_level_diagnostic_or_unknown_json_still_refuses_exact_set(self):
        self.write_layout()
        for name in ["visual-lifecycle.json", "unexpected.json"]:
            path = self.receipts / name
            path.write_text("{}")
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "missing/extra visual receipt"):
                self.invoke()
            self.assertEqual(self.observed, [])
            path.unlink()

    def test_missing_or_misnamed_receipt_is_never_selected(self):
        for name in [None, "legacy_visual_core.json", "legacy.visual.core.json"]:
            if name:
                (self.receipts / name).write_text("{}")
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "missing/extra visual receipt"):
                self.invoke()
            self.assertEqual(self.observed, [])
            if name:
                (self.receipts / name).unlink()

    def test_duplicate_json_or_strict_validator_refusal_has_no_summary(self):
        self.write_layout()
        receipt = self.receipts / "legacy_visual-core.json"
        receipt.write_text('{"unitOnly":true,"unitOnly":false}')
        with self.assertRaisesRegex(AssertionError, "duplicate JSON key"):
            self.invoke()
        self.assertEqual(self.observed, [])
        self.assertEqual(self.output.getvalue(), "")
        receipt.write_text('{"unitOnly":true}')
        with self.assertRaisesRegex(AssertionError, "strict record refused"):
            self.invoke(validation_error="strict record refused")
        self.assertEqual(len(self.observed), 1)
        self.assertEqual(self.output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
