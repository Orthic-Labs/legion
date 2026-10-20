"""JVM adapter units only; native qualification comes from original CI execution."""
from pathlib import Path
import json
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
api = runpy.run_path(str(ROOT / "scripts/ci/audit-jvm-sdk-accuracy.py"))


class JvmSdkAdapterTests(unittest.TestCase):
    def test_jvm_family_keeps_exact_provider_stage_and_native_prerequisite(self):
        entry = {"provider": "code.jvm", "family": "code-jvm-sdk", "stage": "finding"}
        self.assertEqual(gate["adapter"](ROOT, entry), ("code-jvm-sdk", "real_jvm_sdk_accuracy", "canonical-json", "real_jvm_sdk_accuracy"))
        self.assertEqual(gate["JVM_SDK_HARNESS"], ["audit_jvm_qualification"])
        for changed in ({"provider": "code.go"}, {"stage": "candidate"}):
            with self.assertRaises(AssertionError):
                gate["adapter"](ROOT, dict(entry, **changed))

    def test_mutable_benchmark_is_excluded_but_execution_semantics_stay_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/registry/providers.json"
            path.parent.mkdir(parents=True)
            provider = {"id": "code.jvm", "selector": {"op": "always"}, "benchmark": {"status": "unqualified"}}
            path.write_text(json.dumps({"providers": [provider]}))
            before = api["source_digest"](root, "src/registry/providers.json")
            provider["benchmark"] = {"status": "qualified", "qualificationDigest": "mutable-registration-metadata"}
            path.write_text(json.dumps({"providers": [provider]}))
            self.assertEqual(api["source_digest"](root, "src/registry/providers.json"), before)
            provider["selector"] = {"op": "none"}
            path.write_text(json.dumps({"providers": [provider]}))
            self.assertNotEqual(api["source_digest"](root, "src/registry/providers.json"), before)


    def source_fixture(self, root):
        for relative in api["SOURCE_ROOTS"]:
            (root / relative).mkdir(parents=True, exist_ok=True)
        for relative in api["SOURCE_FILES"]:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"bound source\n")
        (root / "src/registry/providers.json").write_text(json.dumps({"providers": []}))

    def source_binding(self, root):
        return {relative: api["source_digest"](root, relative) for relative in api["source_files"](root)}

    def test_source_collector_excludes_only_regular_exact_session_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            source = "engine/crates/legion-audit/src"
            prefix = source + "/.audit/arcane/receipts/session-provenance"
            receipt = prefix + "/" + "a" * 64 + ".json"
            protected = [
                source + "/actual.rs",
                prefix + "/" + "C" * 64 + ".json",
                prefix + "/" + "g" * 64 + ".json",
                prefix + "/" + "a" * 63 + ".json",
                prefix + "/" + "a" * 65 + ".json",
                prefix + "/" + "a" * 64 + ".json.bak",
                prefix + "/nested/" + "a" * 64 + ".json",
                source + "/nested/.audit/arcane/receipts/session-provenance/" + "a" * 64 + ".json",
                prefix + "/" + "b" * 64 + ".json/child.rs",
            ]
            for relative in [receipt] + protected:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"original source\n")
            before = self.source_binding(root)
            self.assertNotIn(receipt, before)
            for relative in protected:
                self.assertFalse(api["generated_session_provenance"](relative))
                self.assertEqual(before[relative], api["digest"](b"original source\n"))
            (root / receipt).write_bytes(b"changed generated receipt\n")
            self.assertEqual(self.source_binding(root), before)
            for relative in protected:
                (root / relative).write_bytes(b"changed source\n")
                self.assertNotEqual(self.source_binding(root)[relative], before[relative])
                self.assertEqual(self.source_binding(root)[relative], api["digest"](b"changed source\n"))
                (root / relative).write_bytes(b"original source\n")

    def test_source_collector_retains_literal_backslash_alias_and_digest_refuses_it(self):
        if Path(r"a\b").name != r"a\b":
            self.skipTest("literal backslash filenames require Unix")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            alias = root / "engine/crates/legion-audit/src" / (
                r".audit\arcane\receipts\session-provenance" + "\\" + "a" * 64 + ".json")
            alias.write_bytes(b"literal-backslash source\n")
            relative = alias.relative_to(root).as_posix()
            self.assertFalse(api["generated_session_provenance"](relative))
            self.assertIn(relative, api["source_files"](root))
            before = api["digest"](alias.read_bytes())
            alias.write_bytes(b"changed literal-backslash source\n")
            self.assertIn(relative, api["source_files"](root))
            self.assertNotEqual(api["digest"](alias.read_bytes()), before)
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                api["source_digest"](root, relative)

    def test_source_collector_refuses_matching_receipt_file_and_directory_symlinks(self):
        if Path(r"a\b").name != r"a\b":
            self.skipTest("Unix symlink controls")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            prefix = root / "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance"
            prefix.mkdir(parents=True)
            receipt = prefix / ("a" * 64 + ".json")
            target_file = root / "target.rs"
            target_file.write_bytes(b"bound target\n")
            target_dir = root / "target-directory"
            target_dir.mkdir()
            (target_dir / "child.rs").write_bytes(b"bound child\n")
            for target in (target_file, target_dir):
                receipt.symlink_to(target, target_is_directory=target.is_dir())
                with self.assertRaisesRegex(AssertionError, "source closure symlink"):
                    api["source_files"](root)
                receipt.unlink()
            prefix.rmdir()
            prefix.symlink_to(target_dir, target_is_directory=True)
            with self.assertRaisesRegex(AssertionError, "source closure symlink"):
                api["source_files"](root)

    def test_original_matrix_controls_and_retained_streams_are_fixed(self):
        self.assertEqual(api["ORIGINAL"]["extensions"], ["java", "kt", "kts", "scala"])
        self.assertEqual(api["ORIGINAL"]["tools"], ["wrapper", "compile", "lint", "test", "dependency"])
        names = api["retained_files"](None)
        self.assertEqual(len(api["CONTROLS"]), 15)
        self.assertEqual(len(names), 33)
        self.assertEqual(len(names), len(set(names)))
        for control in api["CONTROLS"]:
            self.assertIn(control + "/child.stdout.log", names)
            self.assertIn(control + "/child.stderr.log", names)
        entry = {"provider": "code.jvm", "family": "code-jvm-sdk", "scope": api["SCOPE"]}
        for record in ({}, {"provider": "code.jvm", "schema": "legion-jvm-sdk-accuracy/1", "qualificationEligible": False}):
            with self.assertRaises(AssertionError):
                gate["controls"](record, entry)
