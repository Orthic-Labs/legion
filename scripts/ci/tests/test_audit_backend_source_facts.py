"""Validator units only. Constructed in-memory rows never serve as native evidence."""
import copy
import hashlib
import hmac
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-backend-source-facts.py"))


def unit_record():
    corpus = api["contract"](ROOT)
    registry = api["parsed"]((ROOT / "src/registry/providers.json").read_bytes())
    spec = {k: v for k, v in next(s for s in registry["providers"] if s["id"] == api["ID"]).items() if k != "benchmark"}
    retained = "/constructed-unit/legion-provider-qualification/backend-source"
    rows = []
    for case_id in api["CONTROLS"]:
        row, control, files, after = api["fixed_case"](corpus, case_id)
        inventory = api["expected_inventory"](case_id, row, files)
        plan = api["expected_plan"](spec, inventory, api["EXECUTION_BENCHMARK"])
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
        "binding": {"providerSpec": spec, "providerSpecDigest": api["digest"](api["encoded"](spec)), "benchmarkAtExecution": api["EXECUTION_BENCHMARK"],
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

    def test_resealed_semantic_mutations_are_rejected(self):
        self.assertEqual(api["rejection_controls"](ROOT, self.record, self.raw), 20)

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
                api["replay_stream"](raw, api["contract"](ROOT), self.record["binding"]["providerSpec"], api["EXECUTION_BENCHMARK"], self.record["retainedRoot"])


if __name__ == "__main__":
    unittest.main()
