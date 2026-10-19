"""JVM adapter units only; native qualification comes from original CI execution."""
from pathlib import Path
import json
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
api = runpy.run_path(str(ROOT / "scripts/ci/audit-jvm-sdk-accuracy.py"))


class JvmSdkAdapterTests(unittest.TestCase):
    def test_jvm_family_keeps_exact_provider_stage_and_native_prerequisite(self):
        entry = {"provider": "code.jvm", "family": "code-jvm-sdk", "stage": "finding"}
        self.assertEqual(gate["adapter"](ROOT, entry), ("code-jvm-sdk", "real_jvm_sdk_accuracy", "canonical-json", "real_jvm_sdk_accuracy"))
        self.assertEqual(gate["JVM_SDK_HARNESS"], ["audit_jvm_qualification"])
        for changed in ({"provider": "code.go"}, {"stage": "candidate"}):
            with self.assertRaises(AssertionError):
                gate["adapter"](ROOT, dict(entry, **changed))

    def test_mutable_benchmark_is_excluded_but_execution_semantics_stay_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/registry/providers.json"
            path.parent.mkdir(parents=True)
            provider = {"id": "code.jvm", "selector": {"op": "always"}, "benchmark": {"status": "unqualified"}}
            path.write_text(json.dumps({"providers": [provider]}))
            before = api["source_digest"](root, "src/registry/providers.json")
            provider["benchmark"] = {"status": "qualified", "qualificationDigest": "mutable-registration-metadata"}
            path.write_text(json.dumps({"providers": [provider]}))
            self.assertEqual(api["source_digest"](root, "src/registry/providers.json"), before)
            provider["selector"] = {"op": "none"}
            path.write_text(json.dumps({"providers": [provider]}))
            self.assertNotEqual(api["source_digest"](root, "src/registry/providers.json"), before)

    def test_original_matrix_controls_and_retained_streams_are_fixed(self):
        self.assertEqual(api["ORIGINAL"]["extensions"], ["java", "kt", "kts", "scala"])
        self.assertEqual(api["ORIGINAL"]["tools"], ["wrapper", "compile", "lint", "test", "dependency"])
        names = api["retained_files"](None)
        self.assertEqual(len(api["CONTROLS"]), 15)
        self.assertEqual(len(names), 33)
        self.assertEqual(len(names), len(set(names)))
        for control in api["CONTROLS"]:
            self.assertIn(control + "/child.stdout.log", names)
            self.assertIn(control + "/child.stderr.log", names)
        entry = {"provider": "code.jvm", "family": "code-jvm-sdk", "scope": api["SCOPE"]}
        for record in ({}, {"provider": "code.jvm", "schema": "legion-jvm-sdk-accuracy/1", "qualificationEligible": False}):
            with self.assertRaises(AssertionError):
                gate["controls"](record, entry)
