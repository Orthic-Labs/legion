"""Checker units only: synthetic metadata is not provider qualification evidence."""

import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest

SOURCE_ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(SOURCE_ROOT / "scripts/ci/audit-qualification-records.py"))


class RegistrationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qualification-checker-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provider = "checker-unit.fact"
        self.spec = {"id": self.provider, "providerVersion": "1", "benchmark": {
            "status": "qualified", "requiredForCleanClaim": False, "qualificationDigest": None}}
        self.harness = "engine/crates/legion-audit/tests/checker_unit.rs"
        roots = ["engine/crates/legion-audit/src", "engine/crates/legion-audit/tests", "engine/crates/legion-provider-sdk/src",
                 "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "engine/crates/legion-effects/src",
                 "src/registry/rules", "src/registry/controls"]
        for tree in roots:
            self.write(tree + "/unit.rs", "synthetic checker input\n")
        manifests = ["engine/Cargo.lock", "engine/Cargo.toml", "engine/crates/legion-audit/Cargo.toml",
                     "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
                     "engine/crates/legion-rules/Cargo.toml", "engine/crates/legion-effects/Cargo.toml"]
        for path in manifests:
            self.write(path, "synthetic manifest\n")
        self.write(self.harness, "synthetic fixture; never executed\n")
        plan = {"provider": self.provider, "stage": "fact-output", "qualificationEligible": True,
                "measurementKind": "fact-output", "fixtures": [self.harness]}
        self.write_json("bench/provider-accuracy-plan.json", {"providers": [plan]})
        self.write(gate["GATE"], "synthetic gate checksum unit\n")
        self.write(gate["TEST"], "synthetic checker test checksum\n")
        self.write(gate["SCHEMA"], (SOURCE_ROOT / gate["SCHEMA"]).read_text())
        self.write("scripts/ci/audit-provider-accuracy.py", "synthetic validator checksum\n")
        self.write("scripts/ci/right-git-ci.sh", "synthetic CI recipe checksum\n")
        self.write(".github/workflows/ci.yml", "synthetic CI workflow checksum\n")
        bound = lambda path: {"path": path, "digest": gate["digest"]((self.root / path).read_bytes())}
        implementation = [bound(file.relative_to(self.root).as_posix()) for tree in roots for file in (self.root / tree).rglob("*") if file.is_file()]
        implementation += [bound(path) for path in manifests]
        implementation.sort(key=lambda row: row["path"])
        plain_spec = {key: value for key, value in self.spec.items() if key != "benchmark"}
        cases = [{"caseId": "present", "controlKind": "positive", "expected": {"named": 1}, "actual": {"named": 1}, "matched": True},
                 {"caseId": "absent", "controlKind": "absence", "expected": {}, "actual": {}, "matched": True}]
        self.row = {"schema": "legion-file-provider-accuracy/1", "provider": self.provider, "providerVersion": "1", "stage": "fact-output",
                    "scope": "synthetic checker unit; no execution or qualification claim", "executionPath": "native-sdk-frozen-plan-file-only",
                    "modelCalls": 0, "status": "pass", "measurementStatus": "pass", "measurementKind": "fact-output",
                    "coverageState": "complete", "coverageGaps": [], "qualificationEligible": True,
                    "requiredDependencies": {"productionDispatch": "exercised", "positiveControl": "exercised", "absenceControl": "exercised",
                                             "scope": "named native facts; exact full object equality", "externalExecution": "not-required"},
                    "binding": {"implementationRoots": roots, "implementationFileCount": len(implementation),
                                "implementationDigest": gate["digest"](gate["encoded"](implementation)),
                                "providerSpecDigest": gate["digest"](gate["encoded"](plain_spec)), "fixtures": [bound(self.harness)]},
                    "factCases": cases, "metrics": {"cases": 2, "matched": 2, "mismatched": 0}}
        self.entry = {"provider": self.provider, "family": "file", "stage": "fact-output", "scope": self.row["scope"],
                      "record": {"path": gate["ARCHIVE"] + "/records/" + self.provider + "/unit.json", "sha256": "", "qualificationDigest": "", "encoding": "canonical-json"},
                      "sourceClosure": {}, "provenance": {"repository": "Orthic-Labs/legion", "runId": 1, "runAttempt": 1, "jobId": 1,
                          "jobName": "synthetic-checker-unit", "workflow": ".github/workflows/ci.yml", "commit": "a" * 40, "platform": "macos-15",
                          "command": {"harness": ["synthetic-checker-unit"], "validator": ["python3", "scripts/ci/audit-provider-accuracy.py", "--root", "/synthetic"]},
                          "validator": {}, "log": {"path": gate["ARCHIVE"] + "/logs/unit.log", "sha256": ""}},
                      "provenanceVerification": {"path": gate["ARCHIVE"] + "/verification/unit.json", "sha256": ""}}
        self.write(self.entry["provenance"]["log"]["path"], "synthetic checker unit; not authenticated CI evidence\n")
        self.seal()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def write_json(self, relative, value):
        self.write(relative, json.dumps(value, indent=2) + "\n")

    def write_index(self, entries=None):
        self.write_json(gate["INDEX"], {"schema": gate["VERSION"], "entries": entries if entries is not None else [self.entry]})

    def seal(self, refresh_log=True):
        self.row.pop("qualificationDigest", None)
        original = gate["digest"](gate["encoded"](self.row))
        self.row["qualificationDigest"] = original
        self.write_json(self.entry["record"]["path"], self.row)
        self.entry["record"].update({"sha256": gate["digest"]((self.root / self.entry["record"]["path"]).read_bytes()), "qualificationDigest": original})
        paths = gate["closure_paths"](self.root, self.entry)
        closure = {path: gate["digest"]((self.root / path).read_bytes()) for path in paths}
        self.entry["sourceClosure"] = {"sources": closure, "digest": gate["digest"](gate["encoded"](closure))}
        proof = self.entry["provenance"]
        proof["validator"] = {"path": "scripts/ci/audit-provider-accuracy.py", "sha256": closure["scripts/ci/audit-provider-accuracy.py"]}
        self.summary = {self.provider: {key: self.row[key] for key in ("stage", "measurementKind", "coverageState", "qualificationEligible",
                                                                    "qualificationDigest", "metrics", "coverageGaps")}}
        if refresh_log:
            self.write(proof["log"]["path"], "synthetic checker unit; not authenticated CI evidence\nFILE_PROVIDER_ACCURACY "
                       + json.dumps(self.row) + "\nFILE_PROVIDER_ACCURACY_SUMMARY " + json.dumps(self.summary) + "\n")
        proof["log"]["sha256"] = gate["digest"]((self.root / proof["log"]["path"]).read_bytes())
        verified = {"schema": gate["VERIFY_VERSION"], "method": "authenticated-github-retrieval", "verified": True,
                    "repository": proof["repository"], "runId": proof["runId"], "runAttempt": proof["runAttempt"], "jobId": proof["jobId"],
                    "workflow": proof["workflow"], "commit": proof["commit"], "conclusion": "success", "recordSha256": self.entry["record"]["sha256"],
                    "provenanceDigest": gate["digest"](gate["encoded"](proof)), "logSha256": proof["log"]["sha256"], "validatorSha256": proof["validator"]["sha256"],
                    "sourceClosureDigest": self.entry["sourceClosure"]["digest"], "summaryDigest": gate["digest"](gate["encoded"](self.summary))}
        self.write_json(self.entry["provenanceVerification"]["path"], verified)
        self.entry["provenanceVerification"]["sha256"] = gate["digest"]((self.root / self.entry["provenanceVerification"]["path"]).read_bytes())
        qualification = gate["qualification"](self.entry)
        self.spec["benchmark"].update({"qualification": qualification, "qualificationDigest": gate["digest"](gate["encoded"](qualification))})
        self.write_json("src/registry/providers.json", {"providers": [self.spec]})
        self.write_index()

    def test_valid_synthetic_metadata_is_checker_unit_only(self):
        before = (self.root / "src/registry/providers.json").read_bytes()
        self.assertEqual(gate["check"](self.root), {"registeredRecords": 1, "legacyBenchRecords": 0, "promotions": 0})
        self.assertEqual((self.root / "src/registry/providers.json").read_bytes(), before)

    def legacy_only(self):
        for reference in (self.entry["record"], self.entry["provenance"]["log"], self.entry["provenanceVerification"]):
            (self.root / reference["path"]).unlink()
        self.write_index([])
        providers = []
        for provider, bench_class in gate["BENCH"].items():
            original = {"basis": "bench-class", "benchClass": bench_class, "test": "engine/crates/legion-audit/tests/bench_recall.rs",
                        "fixtures": "engine/crates/legion-audit/tests/fixtures/bench/manifest.json", "ciWorkflow": ".github/workflows/ci.yml",
                        "ciJob": "bench", "ciRunner": "macos-15", "claim": "known-answer recall: planted positive detected and negative control clean"}
            providers.append({"id": provider, "benchmark": {"status": "qualified", "requiredForCleanClaim": True,
                              "qualification": original, "qualificationDigest": gate["digest"](gate["encoded"](original))}})
        self.write_json("src/registry/providers.json", {"providers": providers})
        return providers

    def test_empty_index_accepts_exact_legacy_five(self):
        self.legacy_only()
        self.assertEqual(gate["check"](self.root), {"registeredRecords": 0, "legacyBenchRecords": 5, "promotions": 0})

    def test_legacy_id_cannot_exempt_changed_qualification(self):
        providers = self.legacy_only()
        benchmark = providers[0]["benchmark"]
        benchmark["qualification"]["claim"] = "unsupported replacement claim"
        benchmark["qualificationDigest"] = gate["digest"](gate["encoded"](benchmark["qualification"]))
        self.write_json("src/registry/providers.json", {"providers": providers})
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_tampered_original_bytes_rejected(self):
        path = self.root / self.entry["record"]["path"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_stale_implementation_rejected(self):
        self.write("engine/crates/legion-effects/src/unit.rs", "changed implementation\n")
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_partial_freshly_hashed_record_rejected(self):
        self.row.update({"coverageState": "partial", "qualificationEligible": False, "coverageGaps": ["missing-tool"]})
        self.seal()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_missing_contrasting_control_rejected(self):
        self.row["factCases"].pop()
        self.row["metrics"] = {"cases": 1, "matched": 1, "mismatched": 0}
        self.seal()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_duplicate_provider_rejected(self):
        self.write_index([self.entry, copy.deepcopy(self.entry)])
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_duplicate_json_key_rejected(self):
        self.write(gate["INDEX"], '{"schema":"legion-provider-accuracy-index/1","entries":[],"entries":[]}')
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_escaping_record_path_rejected(self):
        self.entry["record"]["path"] = gate["ARCHIVE"] + "/records/../../outside.json"
        self.write_index()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_missing_maintainer_verification_rejected(self):
        (self.root / self.entry["provenanceVerification"]["path"]).unlink()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_refreshed_index_cannot_reuse_verification_after_source_change(self):
        for source in (gate["GATE"], gate["SCHEMA"], ".github/workflows/ci.yml", "scripts/ci/right-git-ci.sh"):
            with self.subTest(source=source):
                path = self.root / source
                original = path.read_text()
                self.write(source, original + "\n")
                sources = self.entry["sourceClosure"]["sources"]
                sources[source] = gate["digest"](path.read_bytes())
                self.entry["sourceClosure"]["digest"] = gate["digest"](gate["encoded"](sources))
                self.write_index()
                with self.assertRaises(AssertionError):
                    gate["check"](self.root)
                self.write(source, original)
                self.seal()

    def test_random_freshly_bound_log_rejected(self):
        self.write(self.entry["provenance"]["log"]["path"], "random nonempty log\n")
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_log_original_must_match_retained_record(self):
        emitted = copy.deepcopy(self.row)
        emitted["scope"] = "different original"
        self.write(self.entry["provenance"]["log"]["path"], "FILE_PROVIDER_ACCURACY " + json.dumps(emitted)
                   + "\nFILE_PROVIDER_ACCURACY_SUMMARY " + json.dumps(self.summary) + "\n")
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_success_summary_must_bind_same_qualification_digest(self):
        summary = copy.deepcopy(self.summary)
        summary[self.provider]["qualificationDigest"] = "sha256:" + "0" * 64
        self.write(self.entry["provenance"]["log"]["path"], "FILE_PROVIDER_ACCURACY " + json.dumps(self.row)
                   + "\nFILE_PROVIDER_ACCURACY_SUMMARY " + json.dumps(summary) + "\n")
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_verification_summary_digest_must_match_retained_summary(self):
        reference = self.entry["provenanceVerification"]
        verified = gate["load"](self.root / reference["path"])
        verified["summaryDigest"] = "sha256:" + "0" * 64
        self.write_json(reference["path"], verified)
        reference["sha256"] = gate["digest"]((self.root / reference["path"]).read_bytes())
        self.write_index()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_external_registration_explicitly_unsupported(self):
        self.entry["family"] = "scanner"
        self.write_index()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_source_closure_cannot_omit_validator(self):
        self.entry["sourceClosure"]["sources"].pop("scripts/ci/audit-provider-accuracy.py")
        self.entry["sourceClosure"]["digest"] = gate["digest"](gate["encoded"](self.entry["sourceClosure"]["sources"]))
        self.write_index()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_symlink_record_rejected(self):
        path = self.root / self.entry["record"]["path"]
        target = self.root / "outside.json"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)


if __name__ == "__main__":
    unittest.main()
