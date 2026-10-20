import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("runtime_app_accuracy", ROOT / "scripts/ci/audit-runtime-app-accuracy.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class RuntimeAppAccuracyTests(unittest.TestCase):
    def test_owner_actions_bind_original_load_metrics_and_bundled_axe(self):
        actions = validator.expected_actions(ROOT, "/scratch/shot.png")
        self.assertEqual([row["type"] for row in actions], ["eval", "screenshot", "eval", "eval"])
        self.assertIn("chrome-error:", actions[0]["expression"])
        self.assertIn("domContentLoaded", actions[2]["expression"])
        self.assertIn((ROOT / "engine/crates/legion-audit/assets/axe-core-4.14.0.min.js").read_text(), actions[3]["expression"])
        self.assertIn("values:['wcag2a','wcag2aa']", actions[3]["expression"])

    def test_console_cannot_replace_precompletion_eval_evidence(self):
        raw = b'[qa] 3:eval value {"ttfb":1}\n[qa] actions complete /a.json\n[qa] 1 console error/warning(s) -- see /log\n[qa]   console.error: [qa] 3:eval value {"ttfb":999}\n[qa] 3:eval value {"ttfb":999}\n'
        values, _, completed, console, _ = validator.qa_output(raw)
        self.assertEqual(values, {3: {"ttfb": 1}})
        self.assertTrue(completed)
        self.assertEqual(len(console), 1)

    def test_duplicate_eval_and_incomplete_console_are_rejected(self):
        for raw in (b'[qa] 3:eval value {}\n[qa] 3:eval value {}\n', b'[qa] 2 console error/warning(s) -- see /log\n[qa]   console.error: one\n'):
            with self.assertRaises(AssertionError):
                validator.qa_output(raw)

    def test_retention_preserves_native_relative_path_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence").mkdir()
            (root / "evidence/stdout").write_bytes(b"native output")
            ref = {"path": "evidence/stdout", "nativePath": "requests/id/stdout", "sha256": validator.digest(b"native output"), "bytes": 13}
            self.assertEqual(validator.artifact(root, ref, "requests/id/stdout"), b"native output")
            (root / "evidence/stdout").write_bytes(b"forged output")
            with self.assertRaises(AssertionError):
                validator.artifact(root, ref, "requests/id/stdout")
            with self.assertRaises(AssertionError):
                validator.relative(root, "../escape")

    def test_png_requires_original_complete_viewport_bytes(self):
        def chunk(kind, data):
            return len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")
        raw = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 640, 480, 8, 6, 0, 0, 0))
        raw += chunk(b"IDAT", zlib.compress((b"\0" + b"\xff" * 2560) * 480)) + chunk(b"IEND", b"")
        validator.png(raw)
        for invalid in (b"invented screenshot", raw[:-1], raw[:-12]):
            with self.assertRaises(AssertionError):
                validator.png(invalid)


if __name__ == "__main__":
    unittest.main()
