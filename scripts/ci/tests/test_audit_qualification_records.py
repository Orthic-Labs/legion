"""Checker units only: synthetic metadata is not provider qualification evidence."""

import copy
import json
from pathlib import Path, PurePosixPath
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
                          "jobName": "synthetic-checker-unit", "jobConclusion": "failure", "workflow": ".github/workflows/ci.yml", "commit": "a" * 40, "platform": "macos-15",
                          "command": {"harness": gate["FILE_HARNESS"], "validator": ["python3", "scripts/ci/audit-provider-accuracy.py", "--root", "/synthetic", "--receipts", "/synthetic/receipts"]},
                          "validator": {}, "log": {"path": gate["ARCHIVE"] + "/logs/unit.log", "sha256": ""}},
                      "provenanceVerification": {"path": gate["ARCHIVE"] + "/verification/unit.json", "sha256": ""}}
        self.write(self.entry["provenance"]["log"]["path"], "synthetic checker unit; not authenticated CI evidence\n")
        self.seal()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

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
        standard_log = "synthetic checker unit; not authenticated CI evidence\n"
        standard_log += "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 1, "argv": proof["command"]["harness"]}) + "\n"
        standard_log += "FILE_PROVIDER_ACCURACY " + json.dumps(self.row) + "\nAUDIT_QUALIFICATION_COMMAND_END 1 0\n"
        standard_log += "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 2, "argv": proof["command"]["validator"]}) + "\n"
        standard_log += "FILE_PROVIDER_ACCURACY_SUMMARY " + json.dumps(self.summary) + "\nAUDIT_QUALIFICATION_COMMAND_END 2 0\n"
        if refresh_log:
            self.write(proof["log"]["path"], standard_log)
        proof["log"]["sha256"] = gate["digest"]((self.root / proof["log"]["path"]).read_bytes())
        standard_lines = standard_log.encode().splitlines(keepends=True)
        checks = []
        for role, sequence, start, end in (("harness", 1, 2, 4), ("validator", 2, 5, 7)):
            check = {"role": role, "command": proof["command"][role], "conclusion": "success", "exitCode": 0, "sequence": sequence,
                     "logStartLine": start, "logEndLine": end, "logSpanSha256": gate["digest"](b"".join(standard_lines[start - 1:end])),
                     "recordSha256": self.entry["record"]["sha256"]}
            if role == "validator":
                check["summaryDigest"] = gate["digest"](gate["encoded"](self.summary))
            checks.append(check)
        verified = {"schema": gate["VERIFY_VERSION"], "method": "authenticated-github-retrieval", "verified": True,
                    "repository": proof["repository"], "runId": proof["runId"], "runAttempt": proof["runAttempt"], "jobId": proof["jobId"],
                    "workflow": proof["workflow"], "commit": proof["commit"], "platform": proof["platform"], "jobConclusion": proof["jobConclusion"],
                    "qualificationConclusion": "success", "checks": checks, "recordSha256": self.entry["record"]["sha256"],
                    "validationBasis": "native-family-validator",
                    "provenanceDigest": gate["digest"](gate["encoded"](proof)), "logSha256": proof["log"]["sha256"], "validatorSha256": proof["validator"]["sha256"],
                    "sourceClosureDigest": self.entry["sourceClosure"]["digest"], "summaryDigest": gate["digest"](gate["encoded"](self.summary))}
        self.write_json(self.entry["provenanceVerification"]["path"], verified)
        self.entry["provenanceVerification"]["sha256"] = gate["digest"]((self.root / self.entry["provenanceVerification"]["path"]).read_bytes())
        qualification = gate["qualification"](self.entry)
        self.spec["benchmark"].update({"qualification": qualification, "qualificationDigest": gate["digest"](gate["encoded"](qualification))})
        self.write_json("src/registry/providers.json", {"providers": [self.spec]})
        self.write_index()

    def test_compatibility_report_adapter_retains_protocol_only_scope(self):
        scope = gate["helper"]("validate-compatibility-report-accuracy.py")["SCOPE"]
        entry = {"provider": "compatibility.core", "family": "compatibility-report", "stage": "fact-output", "scope": scope,
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("compatibility-report", "compatibility_report_accuracy", "canonical-json", "compatibility_report_native_known_answers"))
        fields = gate["qualification"](entry)
        for key in ("productionQualification", "wholeProviderQualified", "auditCleanClaim", "certificationClaim"):
            self.assertIs(fields[key], False)
        for field, wrong in (("stage", "finding"), ("family", "file"), ("scope", "all compatibility")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["adapter"](self.root, {**entry, field: wrong})
        row = {"schema": "legion-compatibility-report-accuracy/1", "provider": "compatibility.core", "stage": "fact-output",
               "scope": scope, "qualificationEligible": True, "productionQualification": False,
               "wholeProviderQualified": False, "auditCleanClaim": False}
        gate["controls"](row, entry)
        for field, wrong in (("productionQualification", True), ("wholeProviderQualified", True), ("auditCleanClaim", True),
                             ("stage", "finding"), ("scope", "full v2 round trip")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["controls"]({**row, field: wrong}, entry)
        schema = json.loads((SOURCE_ROOT / gate["SCHEMA"]).read_text())
        self.assertIn("compatibility-report", schema["$defs"]["entry"]["properties"]["family"]["enum"])

    def test_compatibility_report_terminal_span_requires_named_native_test(self):
        command = ["audit_compatibility_report_qualification"]
        validator = ["python3", "scripts/ci/validate-compatibility-report-accuracy.py", "--root", "/synthetic", "--record", "/synthetic/record.json"]
        proof = {"command": {"harness": command, "validator": validator}}
        begin = lambda sequence, argv: "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": sequence, "argv": argv}) + "\n"
        log = self.root / "span.log"
        text = begin(1, command) + "test compatibility_report_native_known_answers ... ok\nRECORD\n"
        text += "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\nAUDIT_QUALIFICATION_COMMAND_END 1 0\n"
        text += begin(2, validator) + "SUMMARY\nAUDIT_QUALIFICATION_COMMAND_END 2 0\n"
        log.write_text(text)
        record = {"sha256": "sha256:" + "a" * 64}
        self.assertEqual(len(gate["terminal_checks"](log, proof, record, "summary", 3, 7)), 2)
        for original, replacement in (("1 passed; 0 failed", "0 passed; 1 failed"),
                                      ("compatibility_report_native_known_answers", "unrelated_test")):
            log.write_text(text.replace(original, replacement))
            with self.subTest(original=original), self.assertRaises(AssertionError):
                gate["terminal_checks"](log, proof, record, "summary", 3, 7)

    def test_node_outdated_adapter_scope_and_stage_are_fixed(self):
        provider = "legacy.stack.node-outdated"
        scope = gate["helper"]("audit-node-outdated-accuracy.py")["FAMILY_SCOPE"]
        self.assertEqual(gate["ADAPTERS"][provider],
                         ("node-outdated", "node_outdated_accuracy", "finding", "canonical-json", "real_node_outdated_accuracy"))
        entry = {"provider":provider,"family":"node-outdated","stage":"finding","scope":scope,
                 "record":{"path":"synthetic","sha256":"sha256:"+"a"*64,"qualificationDigest":"sha256:"+"b"*64}}
        self.assertEqual(gate["adapter"](self.root,entry),
                         ("node-outdated", "node_outdated_accuracy", "canonical-json", "real_node_outdated_accuracy"))
        self.assertIs(gate["qualification"](entry)["productionQualification"],False)
        for field, wrong in (("stage","candidate"),("family","file")):
            with self.subTest(field=field), self.assertRaises(AssertionError): gate["adapter"](self.root,{**entry,field:wrong})
        row={"schema":"legion-node-outdated-sdk-accuracy/1","provider":provider,"stage":"finding","scope":scope,
             "productionQualification":False,"qualificationEligible":True,"status":"pass","modelCalls":0}
        gate["controls"](row,entry)
        for field,wrong in (("productionQualification",True),("stage","candidate"),("scope","full registry qualification")):
            with self.subTest(field=field),self.assertRaises(AssertionError):gate["controls"]({**row,field:wrong},entry)

    def test_backend_source_adapter_is_dedicated_and_cannot_qualify_runtime(self):
        api = gate["helper"]("audit-backend-source-facts.py")
        entry = {"provider": "framework.backend", "family": "backend-source-facts", "stage": "fact-output", "scope": api["SCOPE"],
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("backend-source-facts", "backend_source_facts", "canonical-json", "backend_source_native_qualification"))
        for field, value in (("family", "file"), ("stage", "finding")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["adapter"](self.root, {**entry, field: value})
        result = gate["qualification"](entry)
        for key in api["FALSE_CLAIMS"]:
            self.assertIs(result[key], False)
        self.assertEqual(result["runtimeExamined"], 0)
        row = {"schema": api["SCHEMA"], "provider": "framework.backend", "stage": "fact-output", "scope": api["SCOPE"],
               "qualificationEligible": True, "status": "pass", "coverageState": "scoped-controls-complete", "modelCalls": 0, "runtimeExamined": 0,
               **{key: False for key in api["FALSE_CLAIMS"]}}
        gate["controls"](row, entry)
        for key in api["FALSE_CLAIMS"]:
            with self.subTest(claim=key), self.assertRaises(AssertionError):
                gate["controls"]({**row, key: True}, entry)

    def test_backend_source_harness_requires_exact_executed_test_terminal(self):
        command = ["audit_cargo_test", "--test", "backend_source_facts", "backend_source_native_qualification", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
        log = self.root / "backend-unit.log"
        prefix = "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 1, "argv": command}) + "\n"
        record = {"sha256": "sha256:" + "a" * 64}
        proof = {"command": {"harness": command}}
        for output in ("test result: ok. 0 passed; 0 failed; 1 ignored;\n",
                       "test backend_source_native_qualification ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored;\n"):
            log.write_text(prefix + "BACKEND_SOURCE_FACTS_ACCURACY {}\n" + output + "AUDIT_QUALIFICATION_COMMAND_END 1 0\n")
            with self.assertRaises(AssertionError):
                gate["terminal_checks"](log, proof, record, None, 2, None)

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

    def test_unknown_external_registration_explicitly_unsupported(self):
        self.entry["family"] = "scanner"
        self.write_index()
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_emitted_record_before_failed_terminal_is_rejected(self):
        path = self.root / self.entry["provenance"]["log"]["path"]
        path.write_text(path.read_text().replace("COMMAND_END 1 0", "COMMAND_END 1 1"))
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_cancelled_validator_without_terminal_is_rejected(self):
        path = self.root / self.entry["provenance"]["log"]["path"]
        path.write_text(path.read_text().replace("AUDIT_QUALIFICATION_COMMAND_END 2 0\n", ""))
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_command_marker_must_match_authenticated_command(self):
        path = self.root / self.entry["provenance"]["log"]["path"]
        path.write_text(path.read_text().replace('"audit_cargo_test"', '"different-command"'))
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_successful_retry_cannot_replace_failed_attempt(self):
        path = self.root / self.entry["provenance"]["log"]["path"]
        retry = "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 3, "argv": self.entry["provenance"]["command"]["harness"]})
        path.write_text(path.read_text() + retry + "\nAUDIT_QUALIFICATION_COMMAND_END 3 0\n")
        self.seal(refresh_log=False)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_cargo_machete_adapter_preserves_constructed_admission_scope(self):
        entry = {"provider": "legacy.quality.rust-unused-deps", "family": "harness-machete", "stage": "finding",
                 "scope": "constructed-native-sdk-fixture", "record": {"path": "unit.json", "sha256": "sha256:" + "a" * 64,
                 "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("harness-machete", "real_cargo_machete_accuracy", "canonical-json", "real_cargo_machete_accuracy"))
        qualified = gate["qualification"](entry)
        self.assertIs(qualified["productionQualification"], False)
        self.assertIs(qualified["selfProducerQualification"], False)
        self.assertEqual(qualified["fixtureScope"], entry["scope"])
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "provider": "legacy.quality.other"})
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "stage": "candidate"})

    def test_rust_outdated_adapter_preserves_constructed_admission_scope(self):
        entry = {"provider": "legacy.stack.rust-outdated", "family": "harness-rust-outdated", "stage": "finding",
                 "scope": "constructed-native-sdk-fixture", "record": {"path": "unit.json", "sha256": "sha256:" + "a" * 64,
                 "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("harness-rust-outdated", "real_rust_outdated_accuracy", "canonical-json", "real_rust_outdated_accuracy"))
        qualified = gate["qualification"](entry)
        self.assertIs(qualified["productionQualification"], False)
        self.assertIs(qualified["selfProducerQualification"], False)
        self.assertEqual(qualified["fixtureScope"], entry["scope"])
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "provider": "legacy.quality.other"})
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "stage": "candidate"})

    def test_long_tail_dedicated_adapter_preserves_partial_language_scope(self):
        provider = "code.long-tail"
        scope = gate["helper"]("audit-code-long-tail-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": provider, "family": "code-long-tail", "stage": "finding", "scope": scope,
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64,
                            "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("code-long-tail", "code_long_tail_accuracy", "canonical-json", "code_long_tail_native_qualification"))
        qualified = gate["qualification"](entry)
        for flag in ("productionQualification", "wholeProviderQualified", "auditCleanClaim",
                     "compilerCoverageQualified", "languageCoverageQualified"):
            self.assertIs(qualified[flag], False)
        self.assertEqual(qualified["fixtureScope"], scope)
        row = {"schema": "legion-code-long-tail-native-accuracy/1", "provider": provider,
               "stage": "finding", "scope": scope, "productionQualification": False,
               "wholeProviderQualified": False, "auditCleanClaim": False, "compilerCoverageQualified": False,
               "languageCoverageQualified": False, "qualificationEligible": True,
               "coverageState": "scoped-controls-complete", "status": "pass", "modelCalls": 0}
        gate["controls"](row, entry)
        for flag in ("productionQualification", "wholeProviderQualified", "auditCleanClaim",
                     "compilerCoverageQualified", "languageCoverageQualified"):
            with self.subTest(flag=flag), self.assertRaises(AssertionError):
                gate["controls"]({**row, flag: True}, entry)
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "family": "file"})
        with self.assertRaises(AssertionError):
            gate["controls"]({**row, "coverageState": "complete"}, entry)

    def test_mobile_native_adapter_requires_dedicated_scope_and_false_production_flags(self):
        scope = gate["helper"]("audit-mobile-sdk-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider":"code.mobile", "family":"code-mobile-sdk", "stage":"finding", "scope":scope,
                 "record":{"path":"unit.json", "sha256":"sha256:" + "a" * 64, "qualificationDigest":"sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("code-mobile-sdk", "mobile-sdk-native", "canonical-json", gate["CODE_MOBILE_HARNESS"][2]))
        row = {"schema":"legion-mobile-sdk-controls/2", "provider":"code.mobile", "family":"code-mobile-sdk",
               "stage":"finding", "scope":scope, "productionQualification":False, "wholePlatformQualified":False,
               "productionOwnerAdmissionQualified":False, "qualificationEligible":True, "boundedMacosKnownAnswerEligible":True,
               "matrixState":"complete", "status":"observed-known-answer-controls", "modelCalls":0}
        # Identity gate alone is not evidence; record_binding still requires raw native matrix.
        gate["controls"](row, entry)
        for flag in ("productionQualification", "wholePlatformQualified", "productionOwnerAdmissionQualified"):
            self.assertIs(gate["qualification"](entry)[flag], False)
            with self.subTest(flag=flag), self.assertRaises(AssertionError):
                gate["controls"]({**row, flag:True}, entry)
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "family":"file"})
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "stage":"candidate"})
        with self.assertRaises(AssertionError):
            gate["controls"]({**row, "schema":"legion-mobile-sdk-controls/1"}, entry)
        schema = json.loads((SOURCE_ROOT / gate["SCHEMA"]).read_text())
        self.assertIn("code-mobile-sdk", schema["$defs"]["entry"]["properties"]["family"]["enum"])
        self.assertEqual(set(schema["$defs"]["codeMobileEvidence"]["required"]), set(gate["CODE_MOBILE_EVIDENCE"]))

    def test_fixed_external_adapters_preserve_stage_and_encoding(self):
        self.assertEqual(len(gate["ADAPTERS"]), 38)

    def test_javascript_sdk_adapter_retains_fixed_family_scope_and_contract(self):
        api = gate["helper"]("audit-javascript-sdk-accuracy.py")
        entry = {"provider": "code.javascript", "family": "javascript-sdk", "stage": "finding",
                 "scope": api["FAMILY_SCOPE"], "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64,
                                                        "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["ADAPTERS"][entry["provider"]],
                         ("javascript-sdk", "real_javascript_sdk_accuracy", "finding", "canonical-json", "real_javascript_sdk_accuracy"))
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("javascript-sdk", "real_javascript_sdk_accuracy", "canonical-json", "real_javascript_sdk_accuracy"))
        row = {"schema": "legion-javascript-sdk-accuracy/1", "kind": "javascript-sdk-known-answer", "provider": entry["provider"],
               "claimScope": entry["scope"], "productionQualification": False, "qualificationEligible": True,
               "requiredContract": copy.deepcopy(api["CONTRACT"]), "executedScope": list(api["TASKS"]), "modelCalls": 0,
               "metrics": {"cases": len(api["CONTROLS"]), "matched": len(api["CONTROLS"]), "mismatched": 0,
                           "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}}
        gate["controls"](row, entry)
        for field, value in (("family", "file"), ("provider", "code.python"), ("stage", "candidate")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["adapter"](self.root, {**entry, field: value})
        for field, value in (("claimScope", "full language clean"), ("productionQualification", True),
                             ("qualificationEligible", False), ("executedScope", ["type", "lint"]), ("modelCalls", 1)):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["controls"]({**row, field: value}, entry)
        narrowed = copy.deepcopy(row)
        narrowed["requiredContract"]["extensions"].remove("tsx")
        with self.assertRaises(AssertionError):
            gate["controls"](narrowed, entry)
        expanded = copy.deepcopy(row)
        expanded["metrics"]["wholeProviderQualified"] = True
        with self.assertRaises(AssertionError):
            gate["controls"](expanded, entry)
        qualified = gate["qualification"](entry)
        self.assertIs(qualified["productionQualification"], False)
        self.assertIs(qualified["wholeProviderQualified"], False)
        self.assertEqual(qualified["fixtureScope"], api["FAMILY_SCOPE"])
        self.assertEqual(qualified["validationBasis"], "native-family-validator")

    def test_javascript_sdk_substance_and_tsc_protocol_negatives(self):
        # Parser-only adversarial bytes never stand in for real SDK controls.
        api = gate["helper"]("audit-javascript-sdk-accuracy.py")
        self.assertTrue({"build-noop", "test-noop", "test-empty", "test-unmet-plan"} <= set(api["CONTROLS"]))
        cwd = PurePosixPath("/frozen/project")
        listed = "/frozen/project/answer.ts\n"
        self.assertEqual(api["strict_tsc"](listed, cwd, {"answer.ts"}, 0), {"answer.ts"})
        for suffix in ("unrecognized diagnostic\n", "/frozen/project/answer.ts(1,x): error TS2322: malformed\n"):
            with self.subTest(suffix=suffix), self.assertRaises(AssertionError):
                api["strict_tsc"](listed + suffix, cwd, {"answer.ts"}, 0)
        with self.assertRaises(AssertionError):
            api["planned_assertions"](api["TEST_PREAMBLE"])
        with self.assertRaises(AssertionError):
            api["assertion_module"]("import test from 'node:test';\nexport function answer() { return 42; }\n")

    def test_javascript_sdk_retained_evidence_and_source_closure_are_fixed(self):
        api = gate["helper"]("audit-javascript-sdk-accuracy.py")
        entry = {"provider": "code.javascript", "family": "javascript-sdk", "stage": "finding"}
        paths = gate["closure_paths"](SOURCE_ROOT, entry)
        for path in (api["HARNESS"], api["HELPER"], api["INPUTS"], api["SELF"],
                     "engine/crates/legion-audit/src/native_providers/code/javascript_sdk.rs",
                     api["FIXTURES"] + "/clean/package.json", api["FIXTURES"] + "/clean/answer_tsx.tsx"):
            self.assertIn(path, paths)
        schema = json.loads((SOURCE_ROOT / gate["SCHEMA"]).read_text())
        self.assertIn("javascript-sdk", schema["$defs"]["entry"]["properties"]["family"]["enum"])
        self.assertEqual(set(schema["$defs"]["javascriptSdkEvidence"]["required"]), set(gate["JAVASCRIPT_SDK_EVIDENCE"]))
        with self.assertRaises(AssertionError):
            api["validate_record"](SOURCE_ROOT, {"schema": "legion-javascript-sdk-accuracy/1", "kind": "javascript-sdk-known-answer", "provider": "code.javascript", "productionQualification": False, "qualificationEligible": False})

    def test_fixed_external_adapters_preserve_stage_and_encoding(self):
        self.assertEqual(len(gate["ADAPTERS"]), 38)
        for provider, (family, _, stage, mode, _) in gate["ADAPTERS"].items():
            entry = {"provider": provider, "family": family, "stage": stage}
            if provider == "compatibility.core":
                entry["scope"] = gate["helper"]("validate-compatibility-report-accuracy.py")["SCOPE"]
            self.assertEqual(gate["adapter"](self.root, entry)[2], mode)
            entry["stage"] = "outcome"
            with self.assertRaises(AssertionError):
                gate["adapter"](self.root, entry)

    def test_ownership_adapter_uses_native_sdk_controls(self):
        entry = {"provider": "governance.capability-ownership", "family": "ownership-native", "stage": "finding"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("ownership-native", "ownership_native_accuracy", "canonical-json", "ownership_native_sdk_known_answers"))
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "stage": "candidate"})

    def test_secrets_history_adapter_scope_and_stage_are_fixed(self):
        provider = "secrets.current-history"
        scope = "known-answer-fixture-cases"
        expected = ("secrets-history", "security-history-native", "finding", "canonical-json",
                    "native_providers::security::producer::history_qualification_tests::native_current_history_qualification")
        self.assertEqual(gate["ADAPTERS"][provider], expected)
        entry = {"provider": provider, "family": "secrets-history", "stage": "finding", "scope": scope,
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64,
                            "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("secrets-history", "security-history-native", "canonical-json", expected[4]))
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertIs(value["installedCliAdmission"], False)
        self.assertEqual(value["fixtureScope"], scope)
        self.assertEqual(value["validationBasis"], "native-family-validator")

    def test_cargo_audit_adapter_scope_and_stage_are_fixed(self):
        provider = "legacy.security.rust-advisories"
        scope = "constructed native SDK + pinned unchanged official RustSec advisory subset; aggregate unadjudicated candidate only"
        self.assertEqual(gate["ADAPTERS"][provider],
                         ("cargo-audit-sdk", "cargo_audit_accuracy", "candidate", "canonical-json", "real_cargo_audit_accuracy"))
        self.assertEqual(gate["helper"]("audit-cargo-audit-provider-accuracy.py")["FAMILY_SCOPE"], scope)
        entry = {"provider": provider, "family": "cargo-audit-sdk", "stage": "candidate", "scope": scope,
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("cargo-audit-sdk", "cargo_audit_accuracy", "canonical-json", "real_cargo_audit_accuracy"))
        value = gate["qualification"](entry)
        for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification"):
            self.assertIs(value[key], False)
        self.assertEqual(value["fixtureScope"], scope)
        self.assertEqual(value["validationBasis"], "native-family-validator")
        for field, wrong in (("stage", "finding"), ("family", "linter")):
            changed = {**entry, field: wrong}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["adapter"](self.root, changed)

        row = {"schema": "legion-cargo-audit-sdk-accuracy/1", "provider": provider, "stage": "candidate", "scope": scope,
               "productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
               "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        gate["controls"](row, entry)
        for field, wrong in (("scope", "unbounded production qualification"), ("stage", "finding"),
                             ("provider", "legacy.security.rust-policy"), ("productionQualification", True),
                             ("selfProducerQualification", True), ("publicHelperQualification", True)):
            changed = {**row, field: wrong}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate["controls"](changed, entry)

    def test_cargo_deny_adapter_preserves_native_candidate_contract(self):
        entry = {"provider": "legacy.security.rust-policy", "family": "cargo-deny", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("cargo-deny", "cargo_deny_accuracy", "canonical-json", "real_cargo_deny_accuracy"))
        self.assertEqual(gate["VALIDATORS"]["cargo-deny"], "scripts/ci/audit-cargo-deny-accuracy.py")
        for invalid in ({**entry, "stage": "finding"}, {**entry, "family": "harness-quality"}):
            with self.assertRaises(AssertionError):
                gate["adapter"](self.root, invalid)

    def test_cargo_deny_metadata_retains_subset_and_constructed_admission_scope(self):
        scope = gate["helper"]("audit-cargo-deny-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": "legacy.security.rust-policy", "family": "cargo-deny", "stage": "candidate", "scope": scope,
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertEqual(value["fixtureScope"], scope)
        self.assertEqual(value["databaseScope"], "official-advisory-subset fixture; no full/current RustSec database or advisory-detection claim")
        self.assertEqual(value["admissionScope"], "explicit constructed SDK authorizer; no production CLI owner-admission claim")
        self.assertEqual(value["validationBasis"], "native-family-validator")
        self.assertNotIn("qualificationEligible", value)

    def test_cargo_deny_record_cannot_claim_production_qualification(self):
        scope = gate["helper"]("audit-cargo-deny-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": "legacy.security.rust-policy", "family": "cargo-deny", "stage": "candidate", "scope": scope}
        row = {"schema": "legion-cargo-deny-sdk-accuracy/1", "provider": "legacy.security.rust-policy", "stage": "candidate", "scope": scope,
               "productionQualification": True, "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_pip_audit_adapter_is_fixed_to_exact_pin_candidate_controls(self):
        entry = {"provider": "legacy.security.python-dependencies", "family": "pip-audit", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("pip-audit", "pip_audit_accuracy", "canonical-json", "real_pip_audit_accuracy"))
        self.assertEqual(gate["VALIDATORS"]["pip-audit"], "scripts/ci/audit-pip-audit-provider-accuracy.py")
        for key, value in (("provider", "legacy.security.other"), ("family", "file"), ("stage", "finding")):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                gate["adapter"](self.root, {**entry, key: value})

    def test_pip_audit_metadata_preserves_exact_pin_nonproduction_scope(self):
        entry = {"provider": "legacy.security.python-dependencies", "family": "pip-audit", "stage": "candidate",
                 "scope": "exact-listed-online-pins-fixture-controls",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertIs(value["selfProducerQualification"], False)
        self.assertEqual(value["fixtureScope"], entry["scope"])
        self.assertEqual(value["validationBasis"], "native-family-validator")
        self.assertEqual(value["admissionScope"], "explicit constructed SDK authorizer; no production CLI owner-admission claim")
        self.assertEqual(value["advisoryDatabase"], "mutable online PyPI responses; no immutable database identity claim")
        self.assertNotIn("qualificationEligible", value)

    def test_pip_audit_controls_reject_expanded_scope_and_qualification_claims(self):
        entry = {"provider": "legacy.security.python-dependencies", "family": "pip-audit", "stage": "candidate",
                 "scope": "exact-listed-online-pins-fixture-controls"}
        row = {"schema": "legion-pip-audit-sdk-accuracy/1", "provider": entry["provider"], "stage": "candidate",
               "scope": entry["scope"], "productionQualification": False, "selfProducerQualification": False,
               "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        gate["controls"](row, entry)
        for key, value in (("scope", "all-python-dependencies"), ("productionQualification", True),
                           ("selfProducerQualification", True), ("stage", "finding")):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                gate["controls"]({**row, key: value}, entry)
        with self.assertRaises(AssertionError):
            gate["controls"](row, {**entry, "scope": "all-python-dependencies"})

    def rust_receipt_closure_cases(self):
        return (
            ("cargo-deny", "legacy.security.rust-policy", "audit-cargo-deny-accuracy.py", "SOURCE_ROOTS", "SOURCE_FILES", "sources"),
            ("cargo-geiger", "legacy.security.rust-unsafe", "audit-cargo-geiger-accuracy.py", "SOURCE_ROOTS", "SOURCE_FILES", "sources"),
            ("cargo-audit-sdk", "legacy.security.rust-advisories", "audit-cargo-audit-provider-accuracy.py", "SOURCE_ROOTS", "SOURCE_FILES", "source_inventory"),
            ("license-checker", "legacy.security.js-licenses", "audit-license-provider-accuracy.py", "SOURCE_ROOTS", "SOURCE_FILES", "source_inventory"),
            ("harness-machete", "legacy.quality.rust-unused-deps", "audit-cargo-machete-provider-accuracy.py", "ROOTS", "FILES", "source_files"),
        )

    def test_rust_native_receipt_exclusion_preserves_all_other_bytes(self):
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        # Keep receipt distinct from uppercase near-match on case-insensitive hosts.
        receipt = prefix + "c" * 64 + ".json"
        retained = [
            "engine/Cargo.toml", "engine/crates/legion-audit/src/mod.rs",
            "engine/crates/legion-audit/src/nested/.audit/anything.rs",
            prefix + "a" * 64 + ".rs", prefix + "A" * 64 + ".json",
            prefix + "g" * 64 + ".json", prefix + "a" * 63 + ".json",
            prefix + "a" * 65 + ".json", prefix + "nested/" + "a" * 64 + ".json",
            prefix + "b" * 64 + ".json/child.rs",
            "engine/crates/legion-audit/src/nested/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json",
        ]
        for family, provider, script, roots_key, files_key, function in self.rust_receipt_closure_cases():
            with self.subTest(family=family):
                api = gate["helper"](script)
                for relative in api[roots_key]:
                    self.write(relative + "/binding-unit", "synthetic source\n")
                for relative in api[files_key]:
                    self.write(relative, "synthetic fixed source\n")
                for relative in retained:
                    self.write(relative, "before\n")
                entry = {"provider": provider, "family": family, "stage": gate["ADAPTERS"][provider][2]}
                for relative in gate["closure_paths"](self.root, entry):
                    if not (self.root / relative).exists():
                        self.write(relative, "synthetic gate source\n")

                def snapshots():
                    return (api[function](self.root),
                            {name: gate["digest"]((self.root / name).read_bytes())
                             for name in gate["closure_paths"](self.root, entry)})

                before = snapshots()
                self.write(receipt, "generated receipt one\n")
                self.assertEqual(snapshots(), before)
                self.write(receipt, "generated receipt two\n")
                self.assertEqual(snapshots(), before)
                for relative in retained:
                    self.write(relative, "after\n")
                    after = snapshots()
                    for original, changed in zip(before, after):
                        self.assertIn(relative, original)
                        self.assertNotEqual(original[relative], changed[relative], relative)
                    self.write(relative, "before\n")
                (self.root / receipt).unlink()

    def test_rust_native_receipt_exclusion_refuses_matching_name_symlinks(self):
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        receipt = self.root / (prefix + "a" * 64 + ".json")
        for family, provider, script, roots_key, files_key, function in self.rust_receipt_closure_cases():
            with self.subTest(family=family):
                api = gate["helper"](script)
                for relative in api[roots_key]:
                    self.write(relative + "/binding-unit", "synthetic source\n")
                for relative in api[files_key]:
                    self.write(relative, "synthetic fixed source\n")
                entry = {"provider": provider, "family": family, "stage": gate["ADAPTERS"][provider][2]}
                checks = (lambda: api[function](self.root),
                          lambda: gate["closure_paths"](self.root, entry))
                receipt.parent.mkdir(parents=True, exist_ok=True)
                receipt.symlink_to(self.root / "engine/crates/legion-audit/src/unit.rs")
                for check in checks:
                    with self.assertRaises(AssertionError):
                        check()
                receipt.unlink()
                receipt.symlink_to(self.root / "engine/crates/legion-audit/src", target_is_directory=True)
                for check in checks:
                    with self.assertRaises(AssertionError):
                        check()
                receipt.unlink()
                # A symlinked receipt directory is unsafe before any file filter.
                receipt.parent.rmdir()
                receipt.parent.symlink_to(self.root / "engine/crates/legion-audit/src", target_is_directory=True)
                for check in checks:
                    with self.assertRaises(AssertionError):
                        check()
                receipt.parent.unlink()

    def test_supply_chain_closure_uses_actual_library_owned_harness(self):
        api = gate["helper"]("audit-supply-chain-native-accuracy.py")
        entry = {"provider": api["ID"], "family": api["FAMILY"], "stage": "candidate"}
        expected = set(api["source_files"](SOURCE_ROOT)) | {
            gate["GATE"], gate["TEST"], gate["SCHEMA"], ".github/workflows/ci.yml",
            "scripts/ci/right-git-ci.sh", gate["VALIDATORS"][api["FAMILY"]],
            gate["VALIDATORS"]["shellcheck"],
        }
        paths = set(gate["closure_paths"](SOURCE_ROOT, entry))
        self.assertEqual(paths, expected)
        self.assertIn(api["HARNESS"], paths)
        self.assertTrue(api["HARNESS"].startswith("engine/crates/legion-audit/src/"))
        self.assertTrue(all((SOURCE_ROOT / name).is_file() for name in paths))
        self.assertNotIn("engine/crates/legion-audit/tests/security-supply-chain-native.rs", paths)
        self.assertEqual(gate["SUPPLY_CHAIN_HARNESS"], [
            "audit_cargo_test", "--lib", gate["ADAPTERS"][api["ID"]][4],
            "--", "--ignored", "--exact", "--nocapture", "--test-threads=1",
        ])

    def test_new_native_source_closures_exclude_only_generated_receipts(self):
        cases = (("pip-audit", "legacy.security.python-dependencies", "audit-pip-audit-provider-accuracy.py", "ROOTS", "FILES", "source_files"),
                 ("semgrep-sdk", "legacy.security.sast", "audit-semgrep-provider-accuracy.py", "TREES", "FILES", "sources"),
                 ("harness-rust-outdated", "legacy.stack.rust-outdated", "audit-rust-outdated-provider-accuracy.py", "ROOTS", "FILES", "source_files"),
                 ("node-outdated", "legacy.stack.node-outdated", "audit-node-outdated-accuracy.py", "SOURCE_ROOTS", "SOURCE_FILES", "sources"))
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        receipt = prefix + "a" * 64 + ".json"
        bound = ("engine/crates/legion-audit/src/mod.rs",
                 "engine/crates/legion-audit/src/nested/.audit/anything.rs",
                 prefix + "B" * 64 + ".json")
        for family, provider, script, roots_key, files_key, function in cases:
            with self.subTest(family=family):
                api = gate["helper"](script)
                for relative in api[roots_key]:
                    self.write(relative + "/binding-unit", "synthetic source\n")
                for relative in api[files_key]:
                    self.write(relative, "synthetic fixed source\n")
                for relative in bound:
                    self.write(relative, "before\n")
                entry = {"provider": provider, "family": family, "stage": gate["ADAPTERS"][provider][2]}
                for relative in gate["closure_paths"](self.root, entry):
                    if not (self.root / relative).exists():
                        self.write(relative, "synthetic gate source\n")

                def snapshots():
                    validator = api[function](self.root)
                    registration = {relative: gate["digest"]((self.root / relative).read_bytes())
                                    for relative in gate["closure_paths"](self.root, entry)}
                    return validator, registration

                before = snapshots()
                self.write(receipt, "generated receipt one\n")
                self.assertEqual(snapshots(), before)
                self.write(receipt, "generated receipt two\n")
                self.assertEqual(snapshots(), before)
                for relative in bound:
                    self.write(relative, "after\n")
                    after = snapshots()
                    self.assertNotEqual(after[0], before[0], relative)
                    self.assertNotEqual(after[1], before[1], relative)
                    self.write(relative, "before\n")
                path = self.root / receipt
                path.unlink()
                path.symlink_to(self.root / bound[0])
                with self.assertRaises(AssertionError):
                    api[function](self.root)
                with self.assertRaises(AssertionError):
                    gate["closure_paths"](self.root, entry)
                path.unlink()

    def test_new_native_families_require_exact_named_successful_runs(self):
        cases = (("pip_audit_accuracy", "real_pip_audit_accuracy", 1),
                 ("semgrep_accuracy", "real_semgrep_accuracy", 1),
                 ("real_rust_outdated_accuracy", "real_rust_outdated_accuracy", 1),
                 ("node_outdated_accuracy", "real_node_outdated_accuracy", 2))
        path = self.root / "new-native-terminal-unit.log"
        record = {"sha256": "sha256:" + "a" * 64}
        for harness, name, count in cases:
            command = ["audit_cargo_test", "--test", harness, name, "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
            validator = ["python3", "unit-validator.py"]
            proof = {"command": {"harness": command, "validator": validator}}
            success = f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"

            def observed(parts):
                lines = ["AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 1, "argv": command})]
                lines.extend("".join(parts).splitlines())
                lines.append("original checker unit")
                original = len(lines)
                lines.extend(["AUDIT_QUALIFICATION_COMMAND_END 1 0",
                              "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 2, "argv": validator}),
                              "validator checker unit"])
                summary = len(lines)
                lines.append("AUDIT_QUALIFICATION_COMMAND_END 2 0")
                path.write_text("\n".join(lines) + "\n")
                return gate["terminal_checks"](path, proof, record, "sha256:" + "b" * 64, original, summary)

            with self.subTest(harness=harness, case="exact"):
                self.assertEqual(len(observed([success] * count)), 2)
            invalid = ([], [success] * (count - 1), [success] * (count + 1),
                       [success.replace("1 passed", "0 passed")] * count,
                       [success.replace("0 ignored", "1 ignored")] * count,
                       [success.replace(name, "different_test")] * count)
            for parts in invalid:
                with self.subTest(harness=harness, parts=parts), self.assertRaises(AssertionError):
                    observed(parts)

    def test_grouped_tflint_requires_all_seven_named_tests_to_execute(self):
        command = ["audit_tflint_qualification"]
        names = gate["TFLINT_TESTS"]
        path = self.root / "terminal-checker-unit.log"
        begin = "AUDIT_QUALIFICATION_COMMAND_BEGIN " + json.dumps({"sequence": 1, "argv": command})
        results = [f"test tests::{name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n" for name in names]
        record = {"sha256": "sha256:" + "a" * 64}

        def observed(parts):
            path.write_text(begin + "\n" + "".join(parts) + "original checker unit\nAUDIT_QUALIFICATION_COMMAND_END 1 0\n")
            evidence = len(path.read_text().splitlines()) - 1
            return gate["terminal_checks"](path, {"command": {"harness": command}}, record, None, evidence, None)

        self.assertEqual(len(observed(results)), 1)
        for parts in (results[:-1], [text.replace("1 passed", "0 passed") for text in results],
                      [text.replace("0 ignored", "1 ignored") for text in results],
                      [text.replace(names[-1], "different_test") for text in results]):
            with self.subTest(parts=parts), self.assertRaises(AssertionError):
                observed(parts)

    def test_known_answer_adapter_is_fixed_to_existing_five_outcomes(self):
        for provider in gate["BENCH"]:
            entry = {"provider": provider, "family": "bench-known-answer", "stage": "outcome"}
            self.assertEqual(gate["adapter"](self.root, entry),
                             ("bench-known-answer", "bench_recall", "canonical-json", "bench_recall_qualification_receipt"))
            entry["stage"] = "finding"
            with self.assertRaises(AssertionError):
                gate["adapter"](self.root, entry)

    def test_license_adapter_is_fixed_to_real_native_candidate_controls(self):
        entry = {"provider": "legacy.security.js-licenses", "family": "license-checker", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("license-checker", "license_checker_accuracy", "canonical-json", "real_license_checker_accuracy"))
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "stage": "finding"})

    def test_license_controls_cannot_claim_production_admission(self):
        scope = gate["helper"]("audit-license-provider-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": "legacy.security.js-licenses", "family": "license-checker", "stage": "candidate", "scope": scope}
        row = {"schema": "legion-license-checker-native-accuracy/1", "provider": entry["provider"], "stage": "candidate",
               "scope": scope, "productionQualification": False, "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        gate["controls"](row, entry)
        row["productionQualification"] = True
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_osv_adapter_is_fixed_to_native_artifact_fixture(self):
        entry = {"provider": "dependency.osv", "family": "osv-artifact", "stage": "finding"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("osv-artifact", "osv_accuracy", "native-insertion-json", "real_sdk_artifact_accuracy_osv"))
        entry["stage"] = "candidate"
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, entry)

    def test_osv_metadata_preserves_three_nonproduction_scopes(self):
        entry = {"provider": "dependency.osv", "family": "osv-artifact", "stage": "finding", "scope": "constructed controls",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification"):
            self.assertIs(value[key], False)
        self.assertEqual(value["fixtureScope"], entry["scope"])
        self.assertEqual(value["validationBasis"], "native-family-validator")

    def test_osv_record_cannot_claim_public_helper_qualification(self):
        scope = gate["helper"]("audit-osv-artifact-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": "dependency.osv", "family": "osv-artifact", "stage": "finding", "scope": scope}
        row = {"schema": "legion-osv-sdk-artifact-accuracy/1", "provider": "dependency.osv", "stage": "finding",
               "scope": entry["scope"], "productionQualification": False, "selfProducerQualification": False,
               "publicHelperQualification": True, "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_semgrep_adapter_is_fixed_to_native_sdk_fixture(self):
        entry = {"provider": "legacy.security.sast", "family": "semgrep-sdk", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("semgrep-sdk", "semgrep_accuracy", "canonical-json", "real_semgrep_accuracy"))
        self.assertEqual(gate["VALIDATORS"]["semgrep-sdk"], "scripts/ci/audit-semgrep-provider-accuracy.py")
        entry["stage"] = "finding"
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, entry)

    def test_semgrep_qualification_preserves_constructed_scope(self):
        entry = {"provider": "legacy.security.sast", "family": "semgrep-sdk", "stage": "candidate", "scope": "fixed fixture scope",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        qualified = gate["qualification"](entry)
        self.assertIs(qualified["productionQualification"], False)
        self.assertEqual(qualified["fixtureScope"], entry["scope"])
        self.assertEqual(qualified["validationBasis"], "native-family-validator")

    def test_semgrep_record_rejects_production_qualification(self):
        scope = gate["helper"]("audit-semgrep-provider-accuracy.py")["FAMILY_SCOPE"]
        entry = {"provider": "legacy.security.sast", "family": "semgrep-sdk", "stage": "candidate", "scope": scope}
        row = {"schema": "legion-semgrep-provider-accuracy/1", "provider": "legacy.security.sast", "stage": "candidate", "scope": scope,
               "productionQualification": True, "qualificationEligible": True, "status": "pass", "modelCalls": 0}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_opengrep_adapter_is_fixed_to_native_artifact_fixture(self):
        entry = {"provider": "security.opengrep", "family": "opengrep-artifact", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("opengrep-artifact", "opengrep_accuracy", "native-insertion-json", "real_sdk_artifact_accuracy_opengrep"))
        entry["stage"] = "finding"
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, entry)

    def test_opengrep_metadata_preserves_both_nonproduction_scopes(self):
        entry = {"provider": "security.opengrep", "family": "opengrep-artifact", "stage": "candidate", "scope": "constructed-native-sdk-artifact-fixture",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertIs(value["selfProducerQualification"], False)
        self.assertEqual(value["fixtureScope"], entry["scope"])
        self.assertEqual(value["validationBasis"], "native-family-validator")

    def test_opengrep_record_cannot_claim_self_producer_qualification(self):
        entry = {"provider": "security.opengrep", "family": "opengrep-artifact", "stage": "candidate", "scope": "constructed-native-sdk-artifact-fixture"}
        row = {"schema": "legion-opengrep-sdk-artifact-accuracy/1", "provider": "security.opengrep", "stage": "candidate",
               "scope": entry["scope"], "productionQualification": False, "selfProducerQualification": True, "status": "pass", "modelCalls": 0}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_quality_adapter_is_fixed_to_build_and_lint(self):
        for provider in ("legacy.quality.build", "legacy.quality.lint"):
            entry = {"provider": provider, "family": "harness-quality", "stage": "finding"}
            self.assertEqual(gate["adapter"](self.root, entry),
                             ("harness-quality", "real_quality_command_accuracy", "canonical-json", "real_quality_command_accuracy"))
            entry["stage"] = "outcome"
            with self.assertRaises(AssertionError):
                gate["adapter"](self.root, entry)
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {"provider": "legacy.quality.test", "family": "harness-quality", "stage": "finding"})

    def test_quality_metadata_preserves_constructed_scope(self):
        entry = {"provider": "legacy.quality.build", "family": "harness-quality", "stage": "finding", "scope": "known-answer-fixture-cases",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertEqual(value["fixtureScope"], "known-answer-fixture-cases")
        self.assertEqual(value["admissionScope"], "explicit constructed SDK authorizer; no production CLI owner-admission claim")
        self.assertEqual(value["validationBasis"], "source-owned-harness-success")
        self.assertNotIn("qualificationEligible", value)

    def test_quality_record_cannot_claim_production_qualification(self):
        entry = {"provider": "legacy.quality.build", "family": "harness-quality", "stage": "finding", "scope": "known-answer-fixture-cases"}
        row = {"schema": "legion-quality-command-sdk-accuracy/1", "kind": "quality-command-sdk-constructed", "productionQualification": True,
               "claimScope": "known-answer-fixture-cases", "provider": "legacy.quality.build", "status": "pass", "modelCalls": 0}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_quality_closure_keeps_harness_toolchain_and_helper_sources(self):
        paths = gate["closure_paths"](self.root, {"provider": "legacy.quality.lint", "family": "harness-quality", "stage": "finding"})
        self.assertTrue({"engine/crates/legion-audit/tests/real_quality_command_accuracy.rs", "engine/rust-toolchain.toml",
                         "scripts/ci/audit-real-provider-accuracy.py", "scripts/ci/audit-external-provider-accuracy.py"} <= set(paths))

    def test_ast_grep_adapter_is_fixed_to_constructed_native_candidate_controls(self):
        entry = {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate"}
        self.assertEqual(gate["adapter"](self.root, entry),
                         ("harness-ast-grep", "ast_grep_accuracy", "canonical-json", "real_ast_grep_accuracy"))
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, {**entry, "provider": "structural.other"})
        entry["stage"] = "finding"
        with self.assertRaises(AssertionError):
            gate["adapter"](self.root, entry)

    def test_ast_grep_metadata_keeps_fixture_scope_and_production_false(self):
        entry = {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate",
                 "scope": "constructed-native-sdk-artifact-fixture",
                 "record": {"path": "synthetic", "sha256": "sha256:" + "a" * 64, "qualificationDigest": "sha256:" + "b" * 64}}
        value = gate["qualification"](entry)
        self.assertIs(value["productionQualification"], False)
        self.assertIs(value["selfProducerQualification"], False)
        self.assertEqual(value["fixtureScope"], "constructed-native-sdk-artifact-fixture")
        self.assertEqual(value["validationBasis"], "native-family-validator")
        self.assertNotIn("qualificationEligible", value)

    def test_ast_grep_record_cannot_claim_production_qualification(self):
        entry = {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate",
                 "scope": "constructed-native-sdk-artifact-fixture"}
        row = {"schema": "legion-ast-grep-accuracy/1", "providerId": "structural.ast-grep",
               "claimScope": "constructed-native-sdk-artifact-fixture", "productionQualification": True}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_ast_grep_record_cannot_claim_self_producer_qualification(self):
        entry = {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate",
                 "scope": "constructed-native-sdk-artifact-fixture"}
        row = {"schema": "legion-ast-grep-accuracy/1", "providerId": "structural.ast-grep",
               "claimScope": "constructed-native-sdk-artifact-fixture", "productionQualification": False,
               "selfProducerQualification": True}
        with self.assertRaises(AssertionError):
            gate["controls"](row, entry)

    def test_ast_grep_source_closure_includes_rules_and_fixture_files(self):
        self.write_json("src/registry/rules/ast-grep/structural-core.json", {"rules": []})
        self.write("engine/crates/legion-audit/tests/fixtures/ast-grep/planted/src/probe.ts",
                   "// synthetic closure input; never executed\n")
        entry = {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate"}
        paths = set(gate["closure_paths"](self.root, entry))
        self.assertIn("engine/crates/legion-audit/tests/ast_grep_accuracy.rs", paths)
        self.assertIn("src/registry/rules/ast-grep/structural-core.json", paths)
        self.assertIn("engine/crates/legion-audit/tests/fixtures/ast-grep/planted/src/probe.ts", paths)
        self.assertIn("scripts/ci/audit-ast-grep-provider-accuracy.py", paths)
        self.assertNotIn("src/registry/providers.json", paths)

    def qualification_closure_inputs(self):
        entries = [
            {"provider": "structural.ast-grep", "family": "harness-ast-grep", "stage": "candidate"},
            {"provider": "dependency.osv", "family": "osv-artifact", "stage": "finding"},
        ]
        self.write("engine/crates/legion-audit/tests/fixtures/ast-grep/unit.ts", "synthetic fixture\n")
        self.write("engine/crates/legion-audit/tests/fixtures/osv/unit.json", "{}\n")
        # Populate only synthetic closure inputs; these units execute no provider.
        for entry in entries:
            for relative in gate["closure_paths"](self.root, entry):
                if not (self.root / relative).is_file():
                    self.write(relative, "synthetic closure input\n")
        ast = gate["helper"]("audit-ast-grep-provider-accuracy.py")
        osv = gate["helper"]("audit-osv-artifact-accuracy.py")
        return entries, ast, osv

    def qualification_closure_bindings(self, entries, ast, osv):
        paths = lambda names: {name: gate["digest"]((self.root / name).read_bytes()) for name in names}
        return {
            "ast-validator": paths(ast["source_paths"](self.root)),
            "osv-validator": osv["source_binding"](self.root),
            **{entry["provider"] + "-registration": paths(gate["closure_paths"](self.root, entry))
               for entry in entries},
        }

    def test_generated_session_receipts_do_not_stale_qualification_closures(self):
        entries, ast, osv = self.qualification_closure_inputs()
        receipt = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json"
        before = self.qualification_closure_bindings(entries, ast, osv)
        self.write(receipt, '{"runtime":1}\n')
        self.assertEqual(self.qualification_closure_bindings(entries, ast, osv), before)
        self.write(receipt, '{"runtime":2}\n')
        self.assertEqual(self.qualification_closure_bindings(entries, ast, osv), before)
        for entry in entries:
            sources = before[entry["provider"] + "-registration"]
            entry["sourceClosure"] = {"sources": sources, "digest": gate["digest"](gate["encoded"](sources))}
            gate["source_closure"](self.root, entry)

    def test_qualification_closures_bind_source_and_nonmatching_receipt_paths(self):
        entries, ast, osv = self.qualification_closure_inputs()
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        protected = [
            "engine/Cargo.toml",
            "src/registry/rules/unit.rs",
            "engine/crates/legion-audit/src/mod.rs",
            "engine/crates/legion-audit/src/nested/.audit/anything.rs",
            prefix + "a" * 64 + ".rs",
            prefix + "A" * 64 + ".json",
            prefix + "g" * 64 + ".json",
            prefix + "a" * 63 + ".json",
            prefix + "nested/" + "a" * 64 + ".json",
            "engine/crates/legion-audit/src/nested/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json",
        ]
        for relative in protected:
            self.write(relative, "original synthetic input\n")
        before = self.qualification_closure_bindings(entries, ast, osv)
        for relative in protected:
            self.write(relative, "changed synthetic input\n")
            after = self.qualification_closure_bindings(entries, ast, osv)
            for role, binding in before.items():
                with self.subTest(role=role, path=relative):
                    self.assertIn(relative, binding)
                    self.assertNotEqual(after[role][relative], binding[relative])
            for entry in entries:
                sources = before[entry["provider"] + "-registration"]
                entry["sourceClosure"] = {"sources": sources, "digest": gate["digest"](gate["encoded"](sources))}
                with self.subTest(provider=entry["provider"], path=relative), self.assertRaises(AssertionError):
                    gate["source_closure"](self.root, entry)
            before = after

    def test_receipt_exclusion_never_hides_symlinks(self):
        entries, ast, osv = self.qualification_closure_inputs()
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        receipt = self.root / (prefix + "a" * 64 + ".json")
        receipt.parent.mkdir(parents=True)
        receipt.symlink_to(self.root / "engine/crates/legion-audit/src/unit.rs")
        checks = [lambda: ast["source_paths"](self.root), lambda: osv["source_binding"](self.root)]
        checks += [lambda entry=entry: gate["closure_paths"](self.root, entry) for entry in entries]
        for check in checks:
            with self.assertRaises((AssertionError, SystemExit)):
                check()
        receipt.unlink()
        receipt.parent.rmdir()
        receipt.parent.symlink_to(self.root / "engine/crates/legion-audit/src/nested-evidence", target_is_directory=True)
        for check in checks:
            with self.assertRaises((AssertionError, SystemExit)):
                check()

    def test_file_family_generated_receipts_do_not_stale_implementation_binding(self):
        receipt = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json"
        before = gate["check"](self.root)
        self.write(receipt, '{"runtime":1}\n')
        self.assertEqual(gate["check"](self.root), before)
        self.write(receipt, '{"runtime":2}\n')
        self.assertEqual(gate["check"](self.root), before)

    def test_file_family_retains_source_tests_fixtures_and_nonmatching_json(self):
        prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/"
        protected = [
            "engine/Cargo.toml",
            "src/registry/rules/unit.rs",
            self.harness,
            "engine/crates/legion-audit/src/mod.rs",
            "engine/crates/legion-audit/src/nested/.audit/anything.rs",
            prefix + "a" * 64 + ".rs",
            prefix + "A" * 64 + ".json",
            prefix + "g" * 64 + ".json",
            prefix + "a" * 63 + ".json",
            prefix + "nested/" + "a" * 64 + ".json",
            "engine/crates/legion-audit/tests/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json",
        ]
        gate["check"](self.root)
        for relative in protected:
            path = self.root / relative
            original = path.read_bytes() if path.is_file() else None
            self.write(relative, "changed synthetic implementation/fixture input\n")
            with self.subTest(path=relative), self.assertRaises(AssertionError):
                gate["check"](self.root)
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)
        gate["check"](self.root)

    def test_file_family_receipt_exclusion_rejects_file_and_directory_symlinks(self):
        receipt = self.root / ("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json")
        receipt.parent.mkdir(parents=True)
        receipt.symlink_to(self.root / "engine/crates/legion-audit/src/unit.rs")
        with self.assertRaises(AssertionError):
            gate["check"](self.root)
        receipt.unlink()
        receipt.parent.rmdir()
        receipt.parent.symlink_to(self.root / "engine/crates/legion-audit/src/nested-evidence", target_is_directory=True)
        with self.assertRaises(AssertionError):
            gate["check"](self.root)

    def test_failed_known_answer_class_cannot_register_from_emission(self):
        rows = [{"benchClass": value, "status": "pass", "productionQualification": False}
                for value in list(gate["BENCH"].values()) + ["drift"]]
        rows[0]["status"] = "recall-failure"
        with self.assertRaises(AssertionError):
            gate["validate_bench_record"](self.root, {"provider": next(iter(gate["BENCH"]))}, {"results": rows}, {})

    def test_shared_offline_adapters_refuse_duplicate_records(self):
        for script, provider in (("audit-real-provider-accuracy.py", "security.scanner-zizmor"),
                                 ("audit-extra-provider-accuracy.py", "security.scanner-squawk")):
            api = gate["helper"](script)
            with self.subTest(script=script), self.assertRaises(AssertionError):
                api["validate_records"](self.root, [{"provider": provider}] * 2, {}, [], live=False)

    def test_offline_identity_does_not_claim_installed_binary_bytes(self):
        api = gate["helper"]("audit-real-provider-accuracy.py")
        path = "/legion-checker-unit-no-installed-tool/bin/tool"
        identity = "sha256:" + "a" * 64
        self.assertEqual(str(api["executable"](path, identity, live=False)), path)
        with self.assertRaises(AssertionError):
            api["executable"](path, identity)
        with self.assertRaises(AssertionError):
            api["executable"]("/escaped/../tool", identity, live=False)
        with self.assertRaises(AssertionError):
            api["executable"](path, "not-a-digest", live=False)

    def test_code_sdk_snapshot_binds_exact_off_mode_and_genuine_request_home(self):
        api = gate["helper"]("audit-code-sdk-accuracy.py")
        scratch = api["absolute"]("/legion-checker-unit/cases/code-go-malformed")
        suffix = api["digest"](b"").removeprefix("sha256:")
        stage = scratch / "cache" / "govulncheck" / suffix
        home = stage.parent / ("home-" + suffix)
        mode = "Library/Application Support/go/telemetry/mode"
        source_files = {"go.mod": api["digest"](b"module unit\n\ngo not-a-version\n")}
        database = {"root": "/unit/database", "files": {"index/db.json": api["digest"](b"unit")}, "digest": "unit-db"}
        cache = {"root": "/unit/module-cache", "files": {}, "digest": "unit-cache"}
        snapshot = {"schema": "legion-govulncheck-input-snapshot/1", "sourceRoot": str(stage),
                    "sourceFiles": source_files, "sourceDigest": api["digest"](api["encoded"](source_files)),
                    "verifiedModules": {}, "telemetryHome": str(home), "telemetryFiles": {mode: api["digest"](b"off")}}
        for label, value in (("database", database), ("moduleCache", cache)):
            snapshot.update({label + key[0].upper() + key[1:]: item for key, item in value.items()})
        case = {"control": "malformed", "fixtureFiles": {}, "fixtureSources": source_files,
                "sdkExecutions": [{"request": {"taskId": "vulnerability", "environment": {"HOME": str(home)}}}]}
        result = {"vulnerability": ({"state": "failed", "complete": False, "exitCode": 1}, "", "")}
        def check(snap, actual_case=case, after=None):
            receipts = [{"tool": "vulnerability", "nativeInputSnapshots": {"before": snap,
                        "after": copy.deepcopy(snap) if after is None else after, "afterError": None, "unchanged": True}}]
            api["validate_go_inputs"](actual_case, receipts, result, scratch, {"database": database, "moduleCache": cache})
        check(snapshot)
        for label, mutate in (
            ("home", lambda snap: snap.update(telemetryHome="/different/home")),
            ("mode", lambda snap: snap["telemetryFiles"].update({mode: api["digest"](b"on")})),
            ("extra", lambda snap: snap["telemetryFiles"].update({"unexpected": api["digest"](b"extra")})),
            ("missing", lambda snap: snap.pop("telemetryFiles")),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(snapshot)
                mutate(changed)
                with self.assertRaises(AssertionError):
                    check(changed)
        changed_case = copy.deepcopy(case)
        changed_case["sdkExecutions"][0]["request"]["environment"]["HOME"] = "/different/sdk-home"
        with self.assertRaises(AssertionError):
            check(snapshot, actual_case=changed_case)
        after = copy.deepcopy(snapshot)
        after["telemetryFiles"][mode] = api["digest"](b"on")
        with self.assertRaises(AssertionError):
            check(snapshot, after=after)

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

    def test_cargo_geiger_adapter_requires_constructed_candidate_scope(self):
        provider = "legacy.security.rust-unsafe"
        self.assertEqual(gate["ADAPTERS"][provider], ("cargo-geiger", "cargo_geiger_accuracy", "candidate", "canonical-json", "real_cargo_geiger_accuracy"))
        entry = {"provider":provider, "family":"cargo-geiger", "stage":"candidate"}
        self.assertEqual(gate["adapter"](self.root, entry)[0], "cargo-geiger")
        self.assertEqual(gate["VALIDATORS"]["cargo-geiger"], "scripts/ci/audit-cargo-geiger-accuracy.py")
        for key, bad in [("stage", "finding"), ("family", "file")]:
            changed = dict(entry); changed[key] = bad
            with self.assertRaises(AssertionError): gate["adapter"](self.root, changed)
        entry.update({"scope":"fixture-control", "record":{"path":"fixture.json", "sha256":"sha256:"+"a"*64,"qualificationDigest":"sha256:"+"b"*64}})
        result = gate["qualification"](entry)
        self.assertIs(result["productionQualification"], False)
        self.assertEqual(result["validationBasis"], "native-family-validator")
        self.assertEqual(result["admissionScope"], "explicit constructed SDK authorizer; no production CLI owner-admission claim")
