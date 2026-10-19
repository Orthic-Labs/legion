"""Routing units only; no fabricated provider evidence or qualification."""
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))

class PythonSdkAdapterTests(unittest.TestCase):
    def test_python_family_has_exact_provider_stage_and_selector(self):
        row = {"provider": "code.python", "family": "code-python-sdk", "stage": "finding"}
        self.assertEqual(gate["adapter"](ROOT, row), ("code-python-sdk", "real_python_code_command_accuracy", "canonical-json", "real_python_code_command_accuracy"))
        for changed in ({"provider": "code.go"}, {"stage": "candidate"}):
            with self.assertRaises(AssertionError): gate["adapter"](ROOT, dict(row, **changed))

    def test_unobserved_or_partial_python_record_is_refused(self):
        entry = {"provider": "code.python", "family": "code-python-sdk", "scope": "known-answer-fixture-cases"}
        for row in ({}, {"provider": "code.python", "schema": "legion-python-code-command-sdk-accuracy/1", "qualificationEligible": False}):
            with self.assertRaises(AssertionError): gate["controls"](row, entry)

    def test_python_retained_reference_set_is_fixed(self):
        self.assertEqual(gate["PYTHON_SDK_EVIDENCE"], {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "pythonEnrollment": "python-sdk-enrollment.json", "providerRecord": "code_python.json"})
        self.assertEqual(len(gate["ADAPTERS"]), 34)
