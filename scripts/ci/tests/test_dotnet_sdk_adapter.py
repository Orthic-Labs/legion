"""Dedicated .NET registration boundaries; these units grant no qualification."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
validator = runpy.run_path(str(ROOT / "scripts/ci/audit-dotnet-sdk-accuracy.py"))


class DotnetSdkAdapterTests(unittest.TestCase):
    def test_native_family_has_exact_provider_stage_and_selector(self):
        entry = {"provider": "code.dotnet", "family": "dotnet-sdk", "stage": "finding"}
        self.assertEqual(gate["adapter"](ROOT, entry), ("dotnet-sdk", "dotnet_sdk_accuracy", "canonical-json", gate["DOTNET_SDK_SELECTOR"]))
        self.assertEqual(gate["DOTNET_SDK_HARNESS"], ["audit_cargo_test", "--lib", gate["DOTNET_SDK_SELECTOR"], "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"])
        for changed in ({"provider": "code.go"}, {"stage": "candidate"}):
            with self.assertRaises(AssertionError):
                gate["adapter"](ROOT, dict(entry, **changed))

    def test_unexecuted_partial_or_wrong_surface_cannot_qualify(self):
        entry = {"provider": "code.dotnet", "family": "dotnet-sdk", "scope": "known-answer-fixture-cases"}
        for row in ({}, {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "qualificationEligible": False},
                    {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "productionQualification": True},
                    {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "executedScope": ["build"]}):
            with self.assertRaises(AssertionError):
                gate["controls"](row, entry)

    def test_schema_requires_original_native_evidence_only_for_dotnet_family(self):
        schema = json.loads((ROOT / gate["SCHEMA"]).read_bytes())["$defs"]
        self.assertIn("dotnet-sdk", schema["entry"]["properties"]["family"]["enum"])
        evidence = schema["dotnetSdkEvidence"]
        self.assertFalse(evidence["additionalProperties"])
        self.assertEqual(set(evidence["required"]), set(gate["DOTNET_SDK_EVIDENCE"]))
        self.assertEqual(set(evidence["properties"]), set(gate["DOTNET_SDK_EVIDENCE"]))
        rule = next(r for r in schema["entry"]["allOf"] if r["if"]["properties"]["family"]["const"] == "dotnet-sdk")
        self.assertEqual(rule["then"], {"required": ["dotnetSdkEvidence"], "properties": {"provider": {"const": "code.dotnet"}, "stage": {"const": "finding"}}})
        self.assertEqual(rule["else"], {"not": {"required": ["dotnetSdkEvidence"]}})

    def test_original_child_and_enrollment_reference_inventory_is_closed(self):
        self.assertEqual(gate["DOTNET_SDK_EVIDENCE"], {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "dotnetEnrollment": "dotnet-sdk-enrollment.json", "providerRecord": "code_dotnet.json"})
        for refs in ({}, {"arbitraryPath": {}}, {**dict.fromkeys(gate["DOTNET_SDK_EVIDENCE"], {}), "extra": {}}):
            with self.assertRaises(AssertionError):
                gate["dotnet_sdk_evidence"](ROOT, {"dotnetSdkEvidence": refs}, {})

    def test_log_binds_dedicated_artifact_marker_and_validator_summary(self):
        # Parser-only synthetic data cannot satisfy record_binding/provenance.
        row = {"provider": "code.dotnet"}
        locator = {"provider": "code.dotnet", "digest": "sha256:" + "1" * 64}
        validated = {"provider": "code.dotnet", "qualificationEligible": True}
        summary = {"records": [validated], "modelCalls": 0}
        lines = ["DOTNET_CODE_COMMAND_SDK_ACCURACY_ARTIFACT " + json.dumps(locator),
                 "DOTNET_CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(summary)]
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/Volumes/D/scratch")) as directory:
            path = Path(directory) / "log"
            path.write_text("\n".join(lines))
            observed = gate["log_evidence"](path, row, validated, "dotnet-sdk", locator)
            self.assertEqual(observed[1:], (1, 2))
            for malformed in ([lines[0], lines[0], lines[1]], [lines[0]], [lines[0].replace("DOTNET_", "PYTHON_"), lines[1]]):
                path.write_text("\n".join(malformed))
                with self.assertRaises(AssertionError):
                    gate["log_evidence"](path, row, validated, "dotnet-sdk", locator)

    def test_diagnostic_parser_binds_real_hashed_finding_reference(self):
        # This parser unit contains no SDK receipt & cannot qualify a provider.
        source = b"public class Answer { public int Double(int x) => x * 2; }\n"
        relative = "csharp/Answer.cs"
        rule = "dotnet:CA1822"
        finding = validator["digest"](("code.dotnet\0" + rule + "\0" + relative + "\0" + "1").encode())
        case = {"language": "csharp", "policyDefinition": {"scratch": "/native/scratch"}, "nativeResult": {
            "findings": [{"id": finding, "severity": "warning"}], "details": {
                "findingEvidence": {finding: {"provider": "code.dotnet", "ruleId": rule, "path": relative, "line": 1, "message": "Mark member static"}},
                "findingLocations": {finding: [relative + ":1"]}}}}
        raw = "/native/scratch/cache/dotnet-source/csharp/Answer.cs(1,34): warning CA1822: Mark member static"
        validator["positive_finding"](case, {relative: source}, raw)
        case["nativeResult"]["findings"] = [{"id": "sha256:" + "0" * 64, "severity": "warning"}]
        with self.assertRaises(AssertionError):
            validator["positive_finding"](case, {relative: source}, raw)
        with self.assertRaises(ValueError):
            validator["positive_finding"](case, {relative: source}, raw.replace("/native/scratch/cache/dotnet-source", "/unbound"))
