"""Behavioural coverage for run-worker.sh (Mac/Linux), mirroring test_windows_runner.py's
coverage of run-worker.ps1's invocation contract: profile/model extraction, stdin-as-brief
plumbing, timeout handling, and the gateway-down/empty-brief guards documented in
skills/alchemist/references/manual.md.

Skips cleanly on Windows: run-worker.sh is an explicit POSIX-only port (no isolated CODEX_HOME,
no sandbox, no --cd — see manual.md "Runner differences") and is never invoked there.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-worker.sh"
BASH = "bash"


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _write_fake(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    _make_executable(path)


@unittest.skipIf(os.name == "nt", "run-worker.sh is a POSIX-only Mac/Linux port; not invoked on Windows")
class PosixRunnerTest(unittest.TestCase):
    def _fake_bin_env(self, tmp: Path) -> tuple[Path, dict]:
        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
        return fake_bin, env

    def _write_profile(self, codex_home: Path, profile: str, model: str) -> Path:
        codex_home.mkdir(parents=True, exist_ok=True)
        profile_path = codex_home / f"{profile}.config.toml"
        profile_path.write_text(f'model = "{model}"\n', encoding="utf-8")
        return profile_path

    def _write_healthy_curl(self, fake_bin: Path) -> None:
        _write_fake(fake_bin / "curl", 'echo -n "200"\nexit 0')

    def test_model_extraction_from_profile_is_required_flag(self):
        """--model is REQUIRED per manual.md; the script must extract it from the profile
        and pass it through, never relying on the CLI's own default."""
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            self._write_profile(codex_home, "mimo", "opencode-go/mimo-v2.5")
            self._write_healthy_curl(fake_bin)
            args_file = tmp / "args.txt"
            _write_fake(
                fake_bin / "omniroute",
                f'echo "$@" > "{args_file}"\ncat > /dev/null\necho \'{{"type":"item.completed","item":{{"type":"agent_message","text":"FAKE_OK"}}}}\'',
            )
            env["CODEX_HOME"] = str(codex_home)
            result = subprocess.run(
                [BASH, str(RUNNER), "mimo", "10", str(tmp / "run.jsonl")],
                input="<task>probe</task>",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = args_file.read_text(encoding="utf-8")
            self.assertIn("--model opencode-go/mimo-v2.5", args)
            self.assertNotIn("--ignore-user-config", args)
            self.assertIn("FAKE_OK", result.stdout)

    def test_missing_model_in_profile_is_a_typed_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            codex_home.mkdir()
            (codex_home / "broken.config.toml").write_text("not_a_model = true\n", encoding="utf-8")
            env["CODEX_HOME"] = str(codex_home)
            result = subprocess.run(
                [BASH, str(RUNNER), "broken", "10"],
                input="<task>probe</task>",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 5)
            self.assertIn("No safe model value", result.stderr)

    def test_stdin_is_the_only_brief_channel(self):
        """The brief must arrive on stdin so shell quoting cannot damage it — never on argv."""
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            self._write_profile(codex_home, "mimo", "opencode-go/mimo-v2.5")
            self._write_healthy_curl(fake_bin)
            stdin_capture = tmp / "stdin.txt"
            _write_fake(
                fake_bin / "omniroute",
                f'cat > "{stdin_capture}"\necho \'{{"type":"item.completed","item":{{"text":"OK"}}}}\'',
            )
            env["CODEX_HOME"] = str(codex_home)
            brief = "<task>first\nsecond</task>"
            result = subprocess.run(
                [BASH, str(RUNNER), "mimo", "10", str(tmp / "run.jsonl")],
                input=brief,
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stdin_capture.read_text(encoding="utf-8"), brief)

    def test_empty_brief_refuses_to_spawn(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            self._write_profile(codex_home, "mimo", "opencode-go/mimo-v2.5")
            self._write_healthy_curl(fake_bin)
            env["CODEX_HOME"] = str(codex_home)
            result = subprocess.run(
                [BASH, str(RUNNER), "mimo", "10"],
                input="   ",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Empty brief", result.stderr)

    def test_gateway_down_exits_4_and_names_the_url(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            self._write_profile(codex_home, "mimo", "opencode-go/mimo-v2.5")
            _write_fake(fake_bin / "curl", 'echo -n "000"\nexit 0')
            env["CODEX_HOME"] = str(codex_home)
            env["OMNIROUTE_URL"] = "http://127.0.0.1:20128"
            result = subprocess.run(
                [BASH, str(RUNNER), "mimo", "10"],
                input="<task>probe</task>",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 4)
            self.assertIn("http://127.0.0.1:20128", result.stderr)
            self.assertIn("not reachable", result.stderr)

    def test_timeout_reports_124_and_persists_both_streams(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin, env = self._fake_bin_env(tmp)
            codex_home = tmp / ".codex"
            self._write_profile(codex_home, "mimo", "opencode-go/mimo-v2.5")
            self._write_healthy_curl(fake_bin)
            _write_fake(
                fake_bin / "omniroute",
                'cat > /dev/null\n'
                'echo \'{"type":"item.completed","item":{"text":"stdout-marker"}}\'\n'
                'echo stderr-marker 1>&2\n'
                'sleep 10\n',
            )
            env["CODEX_HOME"] = str(codex_home)
            event_log = tmp / "run.jsonl"
            result = subprocess.run(
                [BASH, str(RUNNER), "mimo", "1", str(event_log)],
                input="<task>probe</task>",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn(f"EVENT_LOG={event_log}", result.stderr)
            self.assertIn("TIMED OUT", result.stderr)
            self.assertIn("stdout-marker", event_log.read_text(encoding="utf-8"))
            self.assertIn("stderr-marker", Path(f"{event_log}.stderr").read_text(encoding="utf-8"))

    def test_no_timeout_binary_falls_back_to_unbounded_with_a_warning(self):
        """manual.md: 'falls back to gtimeout ... then to unbounded with a warning.' Pin the
        documented fallback message so a silent removal of the warning is caught."""
        runner_source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('command -v timeout', runner_source)
        self.assertIn('gtimeout', runner_source)
        self.assertIn("no timeout binary found; running unbounded", runner_source)

    def test_no_concurrency_cap_is_a_known_gap_not_silently_reintroduced(self):
        """Unlike run-worker.ps1 (named-mutex cap, ALCHEMIST_MAX_CONCURRENT, default/max 10),
        run-worker.sh enforces no concurrency cap at all — this is an existing, documented
        asymmetry (skills/alchemist/references/manual.md, 'Runner differences'), not something
        this suite invents. Pinning it here means a future parity fix must update this test
        deliberately instead of the gap drifting unnoticed."""
        runner_source = RUNNER.read_text(encoding="utf-8")
        self.assertNotIn("ALCHEMIST_MAX_CONCURRENT", runner_source)
        self.assertNotIn("Mutex", runner_source)


if __name__ == "__main__":
    unittest.main()
