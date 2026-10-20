"""Dedicated .NET registration boundaries; these units grant no qualification."""
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
validator = runpy.run_path(str(ROOT / "scripts/ci/audit-dotnet-sdk-accuracy.py"))
provisioner = runpy.run_path(str(ROOT / "scripts/ci/provision-dotnet-qualification-tools.py"))


class DotnetPackageHashTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/Volumes/D/scratch"))
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.packages = self.root / "packages"
        self.cache = self.packages / "example.package/1.0.0"
        self.cache.mkdir(parents=True)
        self.filename = "example.package.1.0.0.nupkg"
        # Synthetic bytes exercise hash domains only; no signed-package claim.
        self.archive = b"archive including signature bytes"
        self.archive_hash = base64.b64encode(hashlib.sha512(self.archive).digest()).decode()
        self.content_hash = base64.b64encode(hashlib.sha512(b"unsigned content").digest()).decode()
        self.row = {"type": "Direct", "resolved": "1.0.0", "contentHash": self.content_hash}
        self.lock = self.root / "packages.lock.json"
        self.lock.write_text(json.dumps({"version": 1, "dependencies": {"net8.0": {"Example.Package": self.row}}}))
        (self.cache / self.filename).write_bytes(self.archive)
        (self.cache / (self.filename + ".sha512")).write_text(self.archive_hash + "\n")
        (self.cache / ".nupkg.metadata").write_text(json.dumps({"version": 2, "contentHash": self.content_hash, "source": "https://api.nuget.org/v3/index.json"}))
        self.failure = self.root / "code-dotnet-sdk/provisioning-failure"

    def provision(self):
        return provisioner["package_provenance"](self.lock, "Example.Package", self.row, self.packages, self.failure)

    def test_distinct_archive_and_content_hashes_remain_separate_in_provenance(self):
        result = self.provision()
        self.assertNotEqual(self.archive_hash, self.content_hash)
        self.assertEqual(result["archiveSha512"], self.archive_hash)
        self.assertEqual(result["contentHash"], self.content_hash)
        self.assertEqual(result["url"], "https://api.nuget.org/v3-flatcontainer/example.package/1.0.0/" + self.filename)
        self.assertFalse(self.failure.exists())

    def test_archive_mismatch_retains_exact_originals_and_both_comparisons(self):
        (self.cache / self.filename).write_bytes(self.archive + b"changed")
        with self.assertRaises(ValueError):
            self.provision()
        for filename in (self.filename, self.filename + ".sha512", ".nupkg.metadata"):
            self.assertEqual((self.failure / filename).read_bytes(), (self.cache / filename).read_bytes())
        self.assertEqual((self.failure / "packages.lock.json").read_bytes(), self.lock.read_bytes())
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertEqual((report["id"], report["version"]), ("Example.Package", "1.0.0"))
        self.assertFalse(report["archiveMatchesSidecar"])
        self.assertTrue(report["metadataMatchesLock"])
        self.assertEqual(report["archiveSha512"], base64.b64encode(hashlib.sha512(self.archive + b"changed").digest()).decode())

    def test_metadata_lock_mismatch_cannot_fall_back_to_archive_hash(self):
        (self.cache / ".nupkg.metadata").write_text(json.dumps({"contentHash": self.archive_hash}))
        with self.assertRaises(ValueError):
            self.provision()
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertTrue(report["archiveMatchesSidecar"])
        self.assertFalse(report["metadataMatchesLock"])
        self.assertEqual(report["lockContentHash"], self.content_hash)
        self.assertEqual(report["metadataContentHash"], self.archive_hash)

    def test_missing_metadata_retains_available_inputs_and_error(self):
        (self.cache / ".nupkg.metadata").unlink()
        with self.assertRaises(ValueError):
            self.provision()
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertIn(".nupkg.metadata", report["inputErrors"])
        self.assertFalse(report["metadataMatchesLock"])
        self.assertEqual((self.failure / self.filename).read_bytes(), self.archive)

    def test_malformed_metadata_fails_closed(self):
        (self.cache / ".nupkg.metadata").write_bytes(b"{malformed metadata")
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual((self.failure / ".nupkg.metadata").read_bytes(), b"{malformed metadata")

    def test_first_failure_evidence_cannot_be_overwritten(self):
        (self.cache / (self.filename + ".sha512")).write_text(self.content_hash)
        with self.assertRaises(ValueError):
            self.provision()
        original = (self.failure / "comparison.json").read_bytes()
        (self.cache / self.filename).write_bytes(b"later corruption")
        with self.assertRaises(FileExistsError):
            self.provision()
        self.assertEqual((self.failure / "comparison.json").read_bytes(), original)


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
