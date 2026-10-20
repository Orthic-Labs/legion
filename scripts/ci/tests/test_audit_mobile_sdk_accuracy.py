"""Parser/refusal units only; positive controls require original retained native execution."""
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-mobile-sdk-accuracy.py"))


class MobileRetainedValidatorTests(unittest.TestCase):
    def test_producer_seals_preserve_original_nested_order(self):
        # Minimal serde_json::to_vec(Value) bytes, not native execution evidence.
        original = b'{"schema":"unit","nested":{"z":1,"a":2},"cases":[]}'
        row = api["parsed"](original)
        self.assertEqual(api["producer_encoded"](row), original)
        row["qualificationDigest"] = api["digest"](original)
        self.assertEqual(api["record_digest"](row), row["qualificationDigest"])
        sorted_row = api["parsed"](api["encoded"](row))
        self.assertNotEqual(api["record_digest"](sorted_row), row["qualificationDigest"])
        self.assertEqual(api["encoded"](row), api["encoded"](sorted_row))

    def test_plan_seal_uses_producer_order_after_semantic_command_replay(self):
        raw = b'{"inventory":"unit","commands":[{"tool":"compiler","argv":[],"programs":["swift"],"accepted":[0]}],"inputBinding":{"bindingDigest":"unit","inputs":{"z":1,"a":2}}}'
        row = api["parsed"](raw)
        self.assertEqual(api["plan_digest"](row["inventory"], row["commands"], row["inputBinding"]), api["digest"](raw))
        reordered = api["parsed"](api["encoded"](row["commands"]))
        self.assertNotEqual(api["plan_digest"](row["inventory"], reordered, row["inputBinding"]), api["digest"](raw))

    def test_duplicate_non_json_and_trailing_json_are_refused(self):
        for raw in (b'{"scope":1,"scope":2}', b'{"value":NaN}', b'{} {}', b'{'):
            with self.subTest(raw=raw), self.assertRaises((AssertionError, ValueError)):
                api["parsed"](raw)

    def test_absolute_and_relative_artifacts_cannot_escape(self):
        for value in ("relative", "/tmp/../foreign", "/tmp//artifact", "//tmp/artifact", "/tmp/artifact\n", "/tmp/./artifact"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                api["absolute"](value)
        for value in ("", "../artifact", "/tmp/artifact", "tmp//artifact", "tmp/./artifact", "tmp\\artifact"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                api["relative"](value)

    def test_no_partial_native_record_is_accepted(self):
        # Metadata from old diagnostic slices supplies no native evidence.
        for row in ({}, {"schema":"legion-mobile-sdk-controls/1"},
                    {"provider":"code.mobile", "qualificationEligible":True},
                    {"schema":"legion-mobile-sdk-controls/2", "cases":[], "boundedMacosKnownAnswerEligible":True}):
            with self.subTest(row=row), self.assertRaises((AssertionError, KeyError)):
                api["validate_record"](ROOT, row)

    def test_original_evidence_is_required_even_with_declared_hash(self):
        reference = {"path":"/tmp/original-mobile-native.json", "digest":"sha256:" + "0" * 64}
        with self.assertRaises(AssertionError):
            api["evidence_bytes"](reference, False, {})
        with self.assertRaises(AssertionError):
            api["evidence_bytes"](reference, False, {reference["path"]:b"{}"})

    def test_empty_output_cannot_substitute_native_assertions(self):
        with self.assertRaises(AssertionError):
            api["native_test_lines"](b"", b"")

    def test_registry_digest_ignores_only_downstream_qualification_metadata(self):
        original = {"providers":[{"id":"code.mobile", "selector":{"op":"always"}, "denominatorKind":"selected-scope", "benchmark":{"status":"unproven", "requiredForCleanClaim":False, "qualificationDigest":None}}]}
        registered = json.loads(json.dumps(original))
        registered["providers"][0]["benchmark"].update(status="qualified", qualificationDigest="sha256:" + "a" * 64, qualification={"record":"retained"})
        semantic = api["prep"]["registry_semantics"]
        self.assertEqual(semantic(original), semantic(registered))
        for key, value in (("requiredForCleanClaim", True), ("newSemanticField", "preserved")):
            changed = json.loads(json.dumps(registered))
            changed["providers"][0]["benchmark"][key] = value
            self.assertNotEqual(semantic(original), semantic(changed))
        changed = json.loads(json.dumps(original))
        changed["providers"][0]["denominatorKind"] = "narrowed"
        self.assertNotEqual(semantic(original), semantic(changed))
        self.assertEqual(original["providers"][0]["benchmark"]["status"], "unproven")

    def test_native_contract_remains_complete(self):
        self.assertEqual(api["CONTRACT"]["extensions"], ["swift", "m", "mm"])
        self.assertEqual(api["CONTRACT"]["tools"], ["compiler", "analyzer", "test"])
        self.assertEqual(api["CONTRACT"]["requiredContext"], ["platform"])
        self.assertEqual(len(api["CONTROLS"]), 13)
        self.assertEqual(len(set(api["CONTROLS"])), 13)


if __name__ == "__main__":
    unittest.main()
