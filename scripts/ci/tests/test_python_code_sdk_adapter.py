"""Routing & denominator boundary units; constructed inputs are never native evidence."""
import copy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
python = runpy.run_path(str(ROOT / "scripts/ci/audit-python-code-sdk-accuracy.py"))

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
        self.assertEqual(
            gate["ADAPTERS"]["legacy.runtime.app"],
            ("runtime-app-sdk", "runtime_app_accuracy", "finding", "canonical-json", "real_runtime_app_accuracy"),
        )
        self.assertEqual(len(gate["ADAPTERS"]), 39)


class PythonReceiptProjectionUnits(unittest.TestCase):
    def receipt(self, owner=False):
        row = dict.fromkeys(python["RECEIPT_FIELDS"])
        row["policyId"] = "audit-native-owner-admission-v1" if owner else "constructed-fixture-policy"
        row["policy"] = {"id": row["policyId"]}
        if owner:
            policy = {"externalProcesses":"owner-admission-required", "admissionStatus":"unavailable", "effectiveMode":"deny-external"}
            identity = {"id":row["policyId"], "version":1, "digest":python["digest"](python["encoded"](policy))}
            row.update(executionPolicy=policy, executionPolicyIdentity=identity,
                       policy=dict(identity, allowed=False, reason="native-owner-admission-unavailable"))
        return row

    def test_source_owned_denial_projection_is_required_and_exact(self):
        row = self.receipt(owner=True)
        python["receipt_fields"](row, owner_projection=True)
        for edit in (lambda r:r.pop("executionPolicy"), lambda r:r.pop("executionPolicyIdentity"),
                     lambda r:r["executionPolicy"].update(effectiveMode="allow-external"),
                     lambda r:r["executionPolicyIdentity"].update(digest="sha256:" + "0" * 64),
                     lambda r:r["policy"].update(allowed=True), lambda r:r.update(policyId="foreign"),
                     lambda r:r.update(unexpected="unbound")):
            changed = copy.deepcopy(row)
            edit(changed)
            with self.subTest(row=changed), self.assertRaises(AssertionError):
                python["receipt_fields"](changed, owner_projection=True)

    def test_other_receipts_and_generic_keys_stay_strict(self):
        row = self.receipt()
        python["receipt_fields"](row, owner_projection=True)
        for field in ("executionPolicy", "executionPolicyIdentity", "unexpected"):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                python["receipt_fields"](dict(row, **{field: {}}), owner_projection=True)
        with self.assertRaises(AssertionError):
            python["receipt_fields"](self.receipt(owner=True))
        with self.assertRaises(AssertionError):
            python["keys"](self.receipt(owner=True), python["RECEIPT_FIELDS"])


class PythonFrozenDenominatorUnits(unittest.TestCase):
    def setUp(self):
        self.entries = [{"path": "fixture.py", "sourceFile": True, "symbols": [], "dependencies": [],
                         "packageScripts": [], "digest": python["digest"](b"pass\n")}]
        generation = "filesystem:" + python["digest"](python["encoded"](self.entries))
        seal = python["digest"](python["encoded"]([1, "constructed-boundary-unit", generation, self.entries]))
        self.spec = {"providerVersion": "constructed-boundary-unit", "selector": {"op": "always"}}
        self.case = {"planDigest": python["digest"](b"constructed-boundary-plan"), "inventory": {"digest": seal},
            "frozenProvider": {"id": "code.python", "version": self.spec["providerVersion"],
                "configuration": {"selector": {"op": "always"}, "denominatorCount": 1, "denominatorDigest": seal}}}

    def test_always_denominator_uses_independent_inventory_seal(self):
        python["frozen_denominator"](self.case, self.spec, self.entries)

    def test_rehashed_always_denominator_is_refused(self):
        changed = copy.deepcopy(self.case)
        changed["frozenProvider"]["configuration"]["denominatorDigest"] = python["digest"](python["encoded"](
            [self.case["inventory"]["digest"], self.spec["selector"], self.entries]))
        with self.assertRaisesRegex(AssertionError, "original provider denominator changed"):
            python["frozen_denominator"](changed, self.spec, self.entries)

    def test_changed_digest_count_selector_or_provider_is_refused(self):
        for field, value in (("denominatorDigest", "sha256:" + "0" * 64), ("denominatorCount", 0),
                             ("selector", {"op": "none"})):
            changed = copy.deepcopy(self.case)
            changed["frozenProvider"]["configuration"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                python["frozen_denominator"](changed, self.spec, self.entries)
        for field, value in (("id", "code.go"), ("version", "wrong")):
            changed = copy.deepcopy(self.case)
            changed["frozenProvider"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                python["frozen_denominator"](changed, self.spec, self.entries)
        with self.assertRaisesRegex(AssertionError, "original Python always selector changed"):
            python["frozen_denominator"](self.case, dict(self.spec, selector={"op": "none"}), self.entries)
