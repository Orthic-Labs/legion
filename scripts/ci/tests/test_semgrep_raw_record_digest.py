"""Raw Semgrep record seals preserve Rust-issued numeric lexemes."""
import runpy
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-semgrep-provider-accuracy.py"))
central = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))


class SemgrepRawRecordDigestTests(unittest.TestCase):
    def test_nested_float_tokens_are_bound_without_numeric_reserialization(self):
        raw = (b'{"nested":{"exp":1e-20,"fixed":0.000030994415283203125},'
               b'"numericString":"1e-20",'
               b'"qualificationDigest":"sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"}')
        self.assertEqual(api["record_digest"](raw),
                         "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96")

    def test_key_order_and_whitespace_do_not_change_canonical_record_seal(self):
        raw = (b'{ "qualificationDigest": "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96", '
               b'"numericString": "1e-20", "nested": {"fixed": 0.000030994415283203125, "exp": 1e-20} }')
        self.assertEqual(api["record_digest"](raw),
                         "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96")

    def test_float_tampering_without_matching_seal_is_rejected(self):
        raw = (b'{"nested":{"exp":1e-20,"fixed":0.000030994415283203125},'
               b'"numericString":"1e-20",'
               b'"qualificationDigest":"sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"}')
        with self.assertRaises(AssertionError):
            api["record_digest"](raw.replace(b"0.000030994415283203125", b"0.000030994415283203126"))

    def test_same_float_value_with_changed_token_is_rejected_by_original_seal(self):
        original = (b'{"nested":{"exp":1e-20,"fixed":0.000030994415283203125},'
                    b'"numericString":"1e-20",'
                    b'"qualificationDigest":"sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"}')
        changed_token = original.replace(b"0.000030994415283203125", b"3.0994415283203125e-05")
        self.assertEqual(float(b"0.000030994415283203125"), float(b"3.0994415283203125e-05"))
        with self.assertRaises(AssertionError):
            api["record_digest"](changed_token)

    def test_direct_semantic_row_api_rejects_row_not_parsed_from_sealed_bytes(self):
        raw = (b'{"value":0.000030994415283203125,'
               b'"qualificationDigest":"sha256:d71621c1a565c42f7666e7e37fda3a302500f046c4c34d0feb5ca159fc23888a"}')
        row = {"value": 0.5,
               "qualificationDigest": "sha256:d71621c1a565c42f7666e7e37fda3a302500f046c4c34d0feb5ca159fc23888a"}
        with self.assertRaisesRegex(AssertionError, "raw bytes differ"):
            api["validate_record"](ROOT, row, raw_record=raw)

    def test_central_digest_and_adapter_paths_receive_original_raw_bytes(self):
        raw = (b'{"nested":{"exp":1e-20,"fixed":0.000030994415283203125},'
               b'"numericString":"1e-20",'
               b'"qualificationDigest":"sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"}')
        self.assertEqual(central["validate_semgrep_record_digest"](
            raw, "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"),
            "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96")
        captured = {}
        fake_helper = lambda name: {"validate_record_bytes": lambda root, data, **kw: captured.update({"raw": data, "kwargs": kw}) or {"ok": True}}
        entry = {"provider": "legacy.security.sast", "family": "semgrep-sdk", "stage": "candidate",
                 "provenance": {"platform": "macos-15"}}
        row = {"qualificationDigest": "sha256:e38693166fe25d222d75c53511a38512dfe2b96e803d6524c0a2e8bd0dd47f96"}
        with patch.dict(central["record_binding"].__globals__, {"helper": fake_helper}):
            result = central["record_binding"](ROOT, entry, ROOT / "record.json", row, {}, raw_record=raw)
        self.assertEqual(result, {"ok": True})
        self.assertIs(captured["raw"], raw)
        self.assertIs(captured["kwargs"]["expected_row"], row)

    def test_duplicate_nonfinite_and_digestless_records_are_rejected(self):
        cases = (
            b'{"qualificationDigest":"sha256:0","qualificationDigest":"sha256:0"}',
            b'{"value":NaN,"qualificationDigest":"sha256:0"}',
            b'{"value":Infinity,"qualificationDigest":"sha256:0"}',
            b'{"value":1e999,"qualificationDigest":"sha256:0"}',
            b'{"value":1.0}',
            b'{"value":1.0,"qualificationDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}',
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                api["record_digest"](raw)


if __name__ == "__main__":
    unittest.main()
