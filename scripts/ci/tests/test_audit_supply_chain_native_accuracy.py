"""Consumer parser/refusal checks; synthetic documents never stand in for native SDK evidence."""
import copy
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / "scripts/ci/audit-supply-chain-native-accuracy.py"))

class SupplyChainNativeReplayTests(unittest.TestCase):
    def documents(self, license="MIT", omit=None, spec_version="1.6"):
        names = [("direct", "1.0.0", "MIT"), ("transitive", "2.0.0", license), ("dev-only", "3.0.0", "Apache-2.0")]
        cdx, spdx = [], []
        for name, version, value in names:
            if name == omit:
                continue
            url = "pkg:npm/" + name + "@" + version
            cdx.append({"type": "library", "purl": url, "licenses": [{"license": {"id": value}}]})
            spdx.append({"externalRefs": [{"referenceType": "purl", "referenceLocator": url}], "licenseDeclared": value, "licenseConcluded": "NOASSERTION"})
        return API["encoded"]({"bomFormat": "CycloneDX", "specVersion": spec_version, "components": cdx}), API["encoded"]({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": spdx})

    def test_full_constructed_lock_keeps_development_and_nested_packages(self):
        expected = API["lock_packages"](API["fixture_lock"]("MIT"))
        self.assertEqual(expected, {"pkg:npm/direct@1.0.0", "pkg:npm/transitive@2.0.0", "pkg:npm/dev-only@3.0.0"})
        result = API["reconcile"](expected, *self.documents())
        self.assertTrue(result["complete"])
        self.assertEqual((result["expected"], result["examined"]), (3, 3))
        self.assertFalse(API["reconcile"](expected, *self.documents(omit="dev-only"))["complete"])

    def test_always_selector_uses_full_inventory_digest_and_exact_fixture_binding(self):
        inv = API["inventory"]("nonempty-clean", API["fixture_lock"]("BSD-3-Clause"))
        spec = {"providerVersion": "1.0.0"}
        provider = {"id": API["ID"], "version": spec["providerVersion"], "cleanClaim": "evidence-only", "benchmarkRequiredForCleanClaim": False, "configuration": {"selector": {"op": "always"}, "denominatorCount": 1, "denominatorDigest": inv["digest"], "supplyChainLicensePolicy": copy.deepcopy(API["LICENSE_POLICY"])}}
        API["validate_fixture_provider"](provider, spec, inv)
        config = provider["configuration"]
        subset_digest = API["digest"](API["encoded"]([inv["digest"], config["selector"], inv["entries"]]))
        self.assertNotEqual(subset_digest, inv["digest"])
        mutations = [
            ("id", lambda item: item.update(id="other-provider")),
            ("version", lambda item: item.update(version="2.0.0")),
            ("clean-claim", lambda item: item.update(cleanClaim="clean")),
            ("benchmark", lambda item: item.update(benchmarkRequiredForCleanClaim=True)),
            ("selector", lambda item: item["configuration"].update(selector={"op": "paths", "paths": ["package-lock.json"]})),
            ("count", lambda item: item["configuration"].update(denominatorCount=0)),
            ("subset-digest", lambda item: item["configuration"].update(denominatorDigest=subset_digest)),
            ("foreign-inventory", lambda item: item["configuration"].update(denominatorDigest=API["inventory"]("other", API["fixture_lock"]("BSD-3-Clause"))["digest"])),
            ("policy", lambda item: item["configuration"]["supplyChainLicensePolicy"].update(deny=[])),
        ]
        for name, mutate in mutations:
            changed = copy.deepcopy(provider)
            mutate(changed)
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "frozen fixture provider/denominator/policy differs"):
                API["validate_fixture_provider"](changed, spec, inv)

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

    def test_cyclonedx_17_keeps_native_shapes_and_full_denominator(self):
        expected = API["lock_packages"](API["fixture_lock"]("MIT"))
        for version in ("1.5", "1.6", "1.7"):
            cdx, spdx = map(json.loads, self.documents(spec_version=version))
            # Real Syft emits non-package file/root rows alongside all dependencies.
            cdx["components"].append({"type": "file", "name": "package-lock.json"})
            spdx["packages"].append({"name": ".", "primaryPackagePurpose": "FILE", "licenseDeclared": "NOASSERTION"})
            result = API["reconcile"](expected, API["encoded"](cdx), API["encoded"](spdx))
            self.assertTrue(result["complete"])
            self.assertEqual((result["expected"], result["examined"]), (3, 3))
        missing = API["reconcile"](expected, *self.documents(omit="dev-only", spec_version="1.7"))
        self.assertFalse(missing["complete"])
        self.assertEqual((missing["expected"], missing["examined"]), (3, 2))
        self.assertIn({"kind": "sbom-package-missing", "name": "pkg:npm/dev-only@3.0.0"}, missing["coverageGaps"])
        denied = API["reconcile"](expected, *self.documents("GPL-3.0-only", spec_version="1.7"))
        self.assertTrue(denied["complete"])
        self.assertEqual(denied["findings"][0]["license"], "GPL-3.0-only")
        unknown = API["reconcile"](expected, *self.documents("MIT OR GPL-3.0-only", spec_version="1.7"))
        self.assertFalse(unknown["complete"])
        self.assertEqual(unknown["coverageGaps"][0]["kind"], "supply-chain-license-undecided")

    def test_cyclonedx_17_still_refuses_invalid_package_documents(self):
        cdx = json.loads(self.documents(spec_version="1.7")[0])
        cases = []
        for version in ("1.4", "1.8", "1.7.0", ""):
            invalid = copy.deepcopy(cdx)
            invalid["specVersion"] = version
            cases.append((invalid, "sbom-format-invalid"))
        wrong_format = copy.deepcopy(cdx)
        wrong_format["bomFormat"] = "SPDX"
        missing_components = copy.deepcopy(cdx)
        del missing_components["components"]
        invalid_components = copy.deepcopy(cdx)
        invalid_components["components"] = {}
        duplicate = copy.deepcopy(cdx)
        duplicate["components"].append(copy.deepcopy(duplicate["components"][0]))
        unidentified = copy.deepcopy(cdx)
        del unidentified["components"][0]["purl"]
        invalid_purl = copy.deepcopy(cdx)
        invalid_purl["components"][0]["purl"] = "not-a-purl"
        empty = copy.deepcopy(cdx)
        empty["components"] = []
        invalid_license = copy.deepcopy(cdx)
        invalid_license["components"][0]["licenses"] = [{}]
        cases.extend(((wrong_format, "sbom-format-invalid"), (missing_components, "sbom-components-missing"), (invalid_components, "sbom-components-missing"), (duplicate, "sbom-package-duplicate"), (unidentified, "sbom-package-purl-missing"), (invalid_purl, "sbom-purl-invalid"), (empty, "sbom-package-inventory-empty"), (invalid_license, "sbom-license-invalid")))
        for invalid, reason in cases:
            with self.subTest(reason=reason, document=invalid):
                self.assertEqual(API["sbom"]("cyclonedx", API["encoded"](invalid)), (None, reason))

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
