"""Capsule source Git setup preserves isolated fixture bytes."""

import subprocess
import tempfile
from pathlib import Path
import runpy
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-capsule-preflight.py"))


class CapsuleFixtureGitTests(unittest.TestCase):
    def test_fixture_baseline_commits_exact_source_files_without_rewriting_them(self):
        with tempfile.TemporaryDirectory(prefix="capsule-fixture-git-") as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            texts = {"src/main.rs": "fn main() {}\n", "README.md": "café\r\nsource-owned fixture\n"}
            expected = {relative: text.encode("utf-8") for relative, text in texts.items()}
            hashes = API["write_fixture_sources"](source, texts)

            API["initialize_fixture_git"](source, hashes)

            tracked = subprocess.run(["git", "-C", str(source), "ls-files", "-z"],
                                     check=True, capture_output=True).stdout.split(b"\0")
            self.assertEqual({path.decode() for path in tracked if path}, set(expected))
            self.assertTrue(subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                           check=True, capture_output=True).stdout.strip())
            self.assertEqual({relative: (source / relative).read_bytes() for relative in expected}, expected)


if __name__ == "__main__":
    unittest.main()
