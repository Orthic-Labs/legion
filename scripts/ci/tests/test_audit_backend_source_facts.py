"""Validator units only. Constructed in-memory rows never serve as native evidence."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-backend-source-facts.py"))


def qualified_unit_benchmark():
    # Constructed semantic input only, never an authenticated qualification record.
    qualification = {"basis": "retained-provider-accuracy", "index": "qualification/provider-accuracy/index.json",
        "record": "qualification/provider-accuracy/records/framework.backend/" + "1" * 64 + ".json",
        "recordSha256": "sha256:" + "2" * 64, "originalQualificationDigest": "sha256:" + "1" * 64,
        "validationBasis": "native-family-validator", "stage": "fact-output", "scope": api["SCOPE"],
        "fixtureScope": api["SCOPE"], "runtimeExamined": 0,
        "coverageScope": "exact thirteen named literal source facts only; runtime, mount composition & auth remain unproven",
        **{key: False for key in api["FALSE_CLAIMS"]}}
    return {"status": "qualified", "requiredForCleanClaim": False,
        "qualification": qualification, "qualificationDigest": api["digest"](api["encoded"](qualification))}


def unit_record(benchmark=None):
    corpus = api["contract"](ROOT)
    registry = api["parsed"]((ROOT / "src/registry/providers.json").read_bytes())
    shipped = next(s for s in registry["providers"] if s["id"] == api["ID"])
    spec = {k: v for k, v in shipped.items() if k != "benchmark"}
    benchmark = copy.deepcopy(shipped["benchmark"] if benchmark is None else benchmark)
    retained = "/constructed-unit/legion-provider-qualification/backend-source"
    rows = []
    for case_id in api["CONTROLS"]:
        row, control, files, after = api["fixed_case"](corpus, case_id)
        inventory = api["expected_inventory"](case_id, row, files)
        plan = api["expected_plan"](spec, inventory, benchmark)
        pd = api["digest"](api["encoded"](plan))
        rows.append({"caseId": case_id, "framework": row["framework"], "control": control,
            "fixtureRoot": retained + "/fixtures/" + case_id, "fixtureFiles": files, "postFreezeFiles": after,
            "inventory": inventory, "frozenPlan": plan, "planDigest": pd,
            "planSignature": "hmac-sha256:" + hmac.new(api["KEY"], api["encoded"](plan), hashlib.sha256).hexdigest(),
            "nativeResult": api["expected_result"](row, control, plan),
            "dispatch": {"planDigest": pd, "inventoryDigest": inventory["digest"], "plannedProviders": [api["ID"]], "pendingHost": [], "skipped": False}})
    raw = b"".join(api["encoded"](row) + b"\n" for row in rows)
    sources = {path: api["digest"]((ROOT / path).read_bytes()) for path in api["source_files"](ROOT)}
    record = {"schema": api["SCHEMA"], "provider": api["ID"], "providerVersion": spec["providerVersion"],
        "family": api["FAMILY"], "stage": "fact-output", "scope": api["SCOPE"],
        "executionPath": "native-frozen-plan-self-sourced-backend-source-facts", "status": "pass",
        "qualificationEligible": True, "coverageState": "scoped-controls-complete", "modelCalls": 0, "runtimeExamined": 0,
        **{key: False for key in api["FALSE_CLAIMS"]}, "frameworkDenominator": api["FRAMEWORKS"], "controls": api["CONTROLS"],
        "binding": {"providerSpec": spec, "providerSpecDigest": api["digest"](api["encoded"](spec)), "benchmarkAtExecution": benchmark,
            "fixture": api["HARNESS"], "sources": sources, "sourcesDigest": api["digest"](api["encoded"](sources))},
        "rawStream": {"path": "native-results.jsonl", "sha256": api["digest"](raw), "bytes": len(raw), "cases": 60}, "retainedRoot": retained,
        "metrics": {"frameworks": 13, "cases": 60, "matched": 60, "mismatched": 0, "runtimeExamined": 0}}
    record["qualificationDigest"] = api["digest"](api["encoded"](record))
    return record, raw


class BackendSourceReplayUnits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record, cls.raw = unit_record()

    def test_exact_thirteen_and_sixty_controls_are_required(self):
        self.assertEqual(len(api["FRAMEWORKS"]), 13)
        self.assertEqual(len(set(api["CONTROLS"])), 60)
        summary = api["validate_record"](ROOT, self.record, self.raw)
        self.assertEqual((summary["frameworks"], summary["cases"], summary["runtimeExamined"]), (13, 60, 0))
        for key in api["FALSE_CLAIMS"]:
            self.assertIs(summary[key], False)

    def test_execution_benchmark_matches_shipped_registry_without_promoting_claims(self):
        registry = api["parsed"]((ROOT / "src/registry/providers.json").read_bytes())
        shipped = next(row for row in registry["providers"] if row["id"] == api["ID"])
        self.assertEqual(self.record["binding"]["benchmarkAtExecution"], shipped["benchmark"])
        summary = api["validate_record"](ROOT, self.record, self.raw)
        for claim in api["FALSE_CLAIMS"]:
            self.assertIs(summary[claim], False)

    def test_retained_benchmarks_replay_without_claiming_current_registry_or_ci_authentication(self):
        # Offline replay is semantic only; canonical gate separately authenticates original CI bytes.
        unproven = {"status": "unproven", "requiredForCleanClaim": False, "qualificationDigest": None}
        registry = api["parsed"]((ROOT / "src/registry/providers.json").read_bytes())
        shipped = next(row for row in registry["providers"] if row["id"] == api["ID"])
        for historical in (unproven, {**unproven, "qualification": None}, qualified_unit_benchmark()):
            record, raw = unit_record(historical)
            summary = api["validate_record"](ROOT, record, raw, live=False)
            self.assertEqual(summary["cases"], 60)
            for claim in api["FALSE_CLAIMS"]:
                self.assertIs(summary[claim], False)
            if shipped["benchmark"] != historical:
                with self.assertRaisesRegex(AssertionError, "live execution benchmark differs from shipped registry"):
                    api["validate_record"](ROOT, record, raw, live=True)

    def test_historical_benchmark_rejects_type_status_digest_and_claim_widening(self):
        unproven = {"status": "unproven", "requiredForCleanClaim": False, "qualificationDigest": None}
        invalid = [None, [], {**unproven, "status": "pass"}, {**unproven, "requiredForCleanClaim": 0},
            {**unproven, "requiredForCleanClaim": True}, {**unproven, "qualificationDigest": "sha256:" + "0" * 64},
            {**unproven, "qualification": {}}, {**unproven, "qualification": False},
            {**unproven, "qualification": None, "extra": None}]
        benchmark = qualified_unit_benchmark()
        for field, value in (("runtimeExamined", False), ("runtimeExamined", 1), ("scope", "whole-provider"),
                             ("recordSha256", "sha256:bad"), ("originalQualificationDigest", 0)):
            changed = copy.deepcopy(benchmark)
            changed["qualification"][field] = value
            changed["qualificationDigest"] = api["digest"](api["encoded"](changed["qualification"]))
            invalid.append(changed)
        for claim in api["FALSE_CLAIMS"]:
            changed = copy.deepcopy(benchmark)
            changed["qualification"][claim] = True
            changed["qualificationDigest"] = api["digest"](api["encoded"](changed["qualification"]))
            invalid.append(changed)
        for changed in invalid:
            with self.subTest(benchmark=changed), self.assertRaises(AssertionError):
                api["execution_benchmark"](changed)

    def test_resealed_execution_benchmark_change_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["binding"]["benchmarkAtExecution"]["qualificationDigest"] = "sha256:" + "0" * 64
        changed.pop("qualificationDigest")
        changed["qualificationDigest"] = api["digest"](api["encoded"](changed))
        with self.assertRaisesRegex(AssertionError, "historical qualification seal differs|unproven execution benchmark differs"):
            api["validate_record"](ROOT, changed, self.raw)

    def test_frozen_plan_benchmark_must_match_execution_binding(self):
        rows = [api["parsed"](line) for line in self.raw.splitlines()]
        observation = rows[0]
        observation["frozenPlan"]["providers"][0]["configuration"]["benchmark"]["qualificationDigest"] = "sha256:" + "0" * 64
        raw_plan = api["encoded"](observation["frozenPlan"])
        observation["planDigest"] = api["digest"](raw_plan)
        observation["planSignature"] = "hmac-sha256:" + hmac.new(api["KEY"], raw_plan, hashlib.sha256).hexdigest()
        observation["dispatch"]["planDigest"] = observation["planDigest"]
        with self.assertRaisesRegex(AssertionError, "frozen original provider/selector/bounds altered"):
            self.replay(rows)

    def test_resealed_semantic_mutations_are_rejected(self):
        self.assertEqual(api["rejection_controls"](ROOT, self.record, self.raw), 20)

    def test_ktor_inventory_matches_literal_gradle_dependency_and_native_seal(self):
        corpus = api["contract"](ROOT)
        row, _, files, _ = api["fixed_case"](corpus, "ktor-positive")
        # Independent known answer from FilesystemInventorySource's Gradle coordinate contract.
        expected = {"schemaVersion": 1, "repositoryId": "ktor-positive",
            "generation": "filesystem:sha256:dbf31705bb2a8b0538176bdffe6d9536f4541fbdaac3b29ea40f019386d64405",
            "entries": [
                {"path": "build.gradle.kts", "sourceFile": True, "symbols": [],
                 "dependencies": ["io.ktor:ktor-server-core"], "packageScripts": [],
                 "digest": "sha256:5c810080c82ba42a9a06ddae5fa9760d7956227fe0ff30b5b1dca7e8df326980"},
                {"path": "src/Routes.kt", "sourceFile": True, "symbols": [], "dependencies": [], "packageScripts": [],
                 "digest": "sha256:8ffe2d73ab1fd5a4d882fa6eb5eb5a5ea915d74d7feb8b000f1cc76b71a3033d"}],
            "digest": "sha256:3a05b6ccbb2889a63c799d7b516368ed342683f1db43e250dfd4610b8e7aeb2d"}
        self.assertEqual(api["expected_inventory"]("ktor-positive", row, files), expected)

    def test_resealed_ktor_inventory_cannot_omit_or_replace_declared_dependency(self):
        for dependencies in ([], ["io.ktor:other-module"]):
            rows = [json.loads(line) for line in self.raw.splitlines()]
            row = next(item for item in rows if item["caseId"] == "ktor-positive")
            inventory = row["inventory"]
            inventory["entries"][0]["dependencies"] = dependencies
            inventory["generation"] = "filesystem:" + api["digest"](api["encoded"](inventory["entries"]))
            inventory["digest"] = api["digest"](api["encoded"](
                [1, inventory["repositoryId"], inventory["generation"], inventory["entries"]]))
            plan = row["frozenPlan"]
            plan.update(inventoryDigest=inventory["digest"], inventoryGeneration=inventory["generation"])
            plan["providers"][0]["configuration"]["denominatorDigest"] = inventory["digest"]
            raw_plan = api["encoded"](plan)
            row["planDigest"] = api["digest"](raw_plan)
            row["planSignature"] = "hmac-sha256:" + hmac.new(api["KEY"], raw_plan, hashlib.sha256).hexdigest()
            row["dispatch"].update(planDigest=row["planDigest"], inventoryDigest=inventory["digest"])
            row["nativeResult"]["coverage"]["denominator_digest"] = inventory["digest"]
            with self.subTest(dependencies=dependencies), self.assertRaisesRegex(AssertionError, "filesystem inventory/denominator altered"):
                self.replay(rows)

    def test_always_denominator_uses_independent_inventory_seal(self):
        def encoded(value):
            return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()

        rows = [json.loads(line) for line in self.raw.splitlines()]
        for row in rows:
            inventory = row["inventory"]
            identity = [1, inventory["repositoryId"], inventory["generation"], inventory["entries"]]
            seal = "sha256:" + hashlib.sha256(encoded(identity)).hexdigest()
            configuration = row["frozenPlan"]["providers"][0]["configuration"]
            self.assertEqual(configuration["selector"], {"op": "always"})
            self.assertEqual(inventory["digest"], seal)
            self.assertEqual(configuration["denominatorDigest"], seal)

        row = rows[0]
        inventory = row["inventory"]
        configuration = row["frozenPlan"]["providers"][0]["configuration"]
        wrong = "sha256:" + hashlib.sha256(encoded([inventory["digest"], configuration["selector"], inventory["entries"]])).hexdigest()
        configuration["denominatorDigest"] = wrong
        row["nativeResult"]["coverage"]["denominator_digest"] = wrong
        raw_plan = encoded(row["frozenPlan"])
        row["planDigest"] = "sha256:" + hashlib.sha256(raw_plan).hexdigest()
        row["planSignature"] = "hmac-sha256:" + hmac.new(api["KEY"], raw_plan, hashlib.sha256).hexdigest()
        row["dispatch"]["planDigest"] = row["planDigest"]
        with self.assertRaisesRegex(AssertionError, "frozen original provider/selector/bounds altered"):
            self.replay(rows)

    def replay(self, rows):
        corpus = api["contract"](ROOT)
        return api["replay_stream"](b"".join(api["encoded"](r) + b"\n" for r in rows), corpus,
            self.record["binding"]["providerSpec"], self.record["binding"]["benchmarkAtExecution"], self.record["retainedRoot"])

    def test_every_route_identity_field_is_bound_to_source(self):
        for field, wrong in (("method", "DELETE"), ("path", "/wrong"), ("file", "other.js"), ("line", 99), ("auth", "public")):
            rows = [api["parsed"](line) for line in self.raw.splitlines()]
            rows[0]["nativeResult"]["details"]["nativeInput"]["artifacts"]["backendFrameworks"][0]["routes"][0][field] = wrong
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.replay(rows)

    def test_ordinary_multiline_strings_remain_explicitly_unsupported(self):
        rows = [api["parsed"](line) for line in self.raw.splitlines()]
        for name in ("rails-quoted-decoy", "laravel-quoted-decoy"):
            row = next(r for r in rows if r["caseId"] == name)
            result = row["nativeResult"]
            self.assertEqual(result["details"]["nativeInput"]["artifacts"]["backendFrameworks"][0]["routes"], [])
            self.assertTrue(any(g.startswith("producer-backend-source-syntax-unsupported:") for g in result["coverage_gaps"]))
            self.assertIn("runtime-evidence-trust-unavailable", result["coverage_gaps"])

    def test_missing_manifest_is_unavailable_not_absent_clean(self):
        rows = [api["parsed"](line) for line in self.raw.splitlines()]
        for row in rows:
            if row["control"] == "missing-manifest":
                self.assertEqual(row["nativeResult"]["details"]["availability"], {"state": "unavailable", "reason": "no-backend-framework-detected"})
                self.assertIs(row["nativeResult"]["complete"], False)

    def test_full_native_result_rejects_unknown_nested_or_top_fields(self):
        for nested in (False, True):
            rows = [api["parsed"](line) for line in self.raw.splitlines()]
            target = rows[0]["nativeResult"]["details"] if nested else rows[0]
            target["forgedEvidence"] = True
            with self.subTest(nested=nested), self.assertRaises(AssertionError):
                self.replay(rows)

    def test_frozen_plan_resealed_input_and_selector_still_reject(self):
        for field, value in (("input", {"complete": True}), ("selector", {"op": "none"}), ("denominatorCount", 0)):
            rows = [api["parsed"](line) for line in self.raw.splitlines()]
            observation = rows[0]
            observation["frozenPlan"]["providers"][0]["configuration"][field] = value
            raw_plan = api["encoded"](observation["frozenPlan"])
            observation["planDigest"] = api["digest"](raw_plan)
            observation["planSignature"] = "hmac-sha256:" + hmac.new(api["KEY"], raw_plan, hashlib.sha256).hexdigest()
            observation["dispatch"]["planDigest"] = observation["planDigest"]
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.replay(rows)

    def test_duplicate_keys_nonfinite_and_raw_frame_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(AssertionError):
                api["parsed"](raw)
        for raw in (self.raw[:-1], self.raw.replace(b"\n", b"\r\n"), b"\n" + self.raw):
            with self.assertRaises(AssertionError):
                api["replay_stream"](raw, api["contract"](ROOT), self.record["binding"]["providerSpec"], self.record["binding"]["benchmarkAtExecution"], self.record["retainedRoot"])


if __name__ == "__main__":
    unittest.main()
