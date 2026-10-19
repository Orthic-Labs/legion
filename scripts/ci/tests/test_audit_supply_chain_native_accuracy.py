"""Consumer parser/refusal checks; synthetic documents never stand in for native SDK evidence."""
import copy
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / "scripts/ci/audit-supply-chain-native-accuracy.py"))

class SupplyChainNativeReplayTests(unittest.TestCase):
    def documents(self, license="MIT", omit=None):
        names = [("direct", "1.0.0", "MIT"), ("transitive", "2.0.0", license), ("dev-only", "3.0.0", "Apache-2.0")]
        cdx, spdx = [], []
        for name, version, value in names:
            if name == omit:
                continue
            url = "pkg:npm/" + name + "@" + version
            cdx.append({"type": "library", "purl": url, "licenses": [{"license": {"id": value}}]})
            spdx.append({"externalRefs": [{"referenceType": "purl", "referenceLocator": url}], "licenseDeclared": value, "licenseConcluded": "NOASSERTION"})
        return API["encoded"]({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": cdx}), API["encoded"]({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": spdx})

    def test_full_constructed_lock_keeps_development_and_nested_packages(self):
        expected = API["lock_packages"](API["fixture_lock"]("MIT"))
        self.assertEqual(expected, {"pkg:npm/direct@1.0.0", "pkg:npm/transitive@2.0.0", "pkg:npm/dev-only@3.0.0"})
        result = API["reconcile"](expected, *self.documents())
        self.assertTrue(result["complete"])
        self.assertEqual((result["expected"], result["examined"]), (3, 3))
        self.assertFalse(API["reconcile"](expected, *self.documents(omit="dev-only"))["complete"])

    def test_explicit_whole_license_policy_and_unknown_refusal(self):
        expected = API["lock_packages"](API["fixture_lock"]("MIT"))
        denied = API["reconcile"](expected, *self.documents("GPL-3.0-only"))
        self.assertTrue(denied["complete"])
        self.assertEqual(denied["findings"][0]["license"], "GPL-3.0-only")
        unknown = API["reconcile"](expected, *self.documents("MIT OR GPL-3.0-only"))
        self.assertFalse(unknown["complete"])
        self.assertEqual(unknown["coverageGaps"][0]["kind"], "supply-chain-license-undecided")
        self.assertFalse(API["reconcile"](expected, *self.documents(), policy={})["complete"])

    def test_native_receipt_cannot_be_replaced_by_parseable_json(self):
        self.assertIsNone(API["document_bytes"]({"raw": "{}", "digest": API["digest"](b"{}")}, "cyclonedx", {}, {}))
        for raw in (b"{}", b"{", b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}'):
            self.assertIsNotNone(API["sbom"]("cyclonedx", raw)[1])
        with self.assertRaises(AssertionError):
            API["parsed"]('{"x":1,"x":2}')

    def test_only_qualification_metadata_is_normalized(self):
        registry = {"providers": [{"id": API["ID"], "selector": {"op": "always"}, "denominatorKind": "selected-scope", "benchmark": {"status": "unproven", "qualificationDigest": None, "requiredForCleanClaim": False}}]}
        promoted = copy.deepcopy(registry)
        promoted["providers"][0]["benchmark"].update(status="qualified", qualificationDigest="digest", qualification={"fixtureScope": API["SCOPE"]})
        self.assertEqual(API["semantics"](registry), API["semantics"](promoted))
        promoted["providers"][0]["denominatorKind"] = "subset"
        self.assertNotEqual(API["semantics"](registry), API["semantics"](promoted))

    def test_target_build_provenance_never_follows_from_shape(self):
        self.assertEqual(API["provenance"]({}, {}), {"present": False, "verified": False, "reasons": ["absent", "authority-unavailable"]})
        observation = API["provenance"]({"provenance": {"raw": "{", "executionReceipt": None}}, {})
        self.assertFalse(observation["verified"])
        self.assertIn("malformed-statement", observation["reasons"])
        self.assertIn("authority-unavailable", observation["reasons"])

    def test_dedicated_registration_keeps_target_gap(self):
        gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
        entry = {"provider": API["ID"], "family": API["FAMILY"], "stage": "candidate", "scope": API["SCOPE"], "record": {"path": "record", "sha256": "hash", "qualificationDigest": "seal"}}
        self.assertEqual(gate["adapter"](ROOT, entry)[0], API["FAMILY"])
        fields = gate["qualification"](entry)
        self.assertFalse(fields["targetBuildProvenanceVerified"])
        self.assertFalse(fields["wholeProviderQualification"])
        self.assertFalse(fields["productionQualification"])
        self.assertEqual(fields["requiredTargetGap"], "supply-chain-provenance-invalid")
        schema = json.loads((ROOT / "scripts/ci/schemas/audit-supply-chain-native-accuracy.schema.json").read_text())
        self.assertTrue(schema["properties"]["qualificationEligible"]["const"])
        self.assertEqual(len(schema["properties"]["cases"]["prefixItems"]), len(API["CONTROLS"]))
        for forged in ({}, {"qualificationEligible": True, "status": "pass"}):
            with self.assertRaises(AssertionError):
                API["validate_record"](ROOT, forged, live=False)

if __name__ == "__main__":
    unittest.main()
