import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-worker.ps1"
MODEL_CATALOG = ROOT / "model-catalog.json"
class WindowsRunnerTest(unittest.TestCase):
    def test_model_catalog_defaults_to_deepseek_flash(self):
        catalog = json.loads(MODEL_CATALOG.read_text(encoding="utf-8"))
        self.assertEqual(catalog["models"][0]["slug"], "opencode-go/deepseek-v4-flash")

    def test_worker_cap_defaults_to_ten(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("[Math]::Min(10, [int]$env:ALCHEMIST_MAX_CONCURRENT)", runner)
        self.assertIn("} else { 10 }", runner)

    def test_routes_stdin_through_omniroute_launcher(self):
        self.assertNotIn("Console.In", RUNNER.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            codex_home = tmp / ".codex"
            codex_home.mkdir()
            (codex_home / "mimo.config.toml").write_text('model = "opencode-go/mimo-v2.5"\n', encoding="utf-8")
            args_file = tmp / "args.txt"
            stdin_file = tmp / "stdin.txt"
            codex_home_file = tmp / "codex-home.txt"
            codex_config_file = tmp / "codex-config.txt"
            workdir = tmp / "workspace"
            workdir.mkdir()
            fake = fake_bin / "omniroute.cmd"
            fake.write_text(
                "@echo off\r\n"
                'echo %* > "%FAKE_ARGS%"\r\n'
                'echo %CODEX_HOME% > "%FAKE_CODEX_HOME%"\r\n'
                'type "%CODEX_HOME%\\config.toml" > "%FAKE_CODEX_CONFIG%"\r\n'
                'more > "%FAKE_STDIN%"\r\n'
                "echo booting 1>&2\r\n"
                'echo {"type":"item.completed","item":{"type":"agent_message","text":"FAKE_OK"}}\r\n'
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            event_log = tmp / "run.jsonl"
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            env["CODEX_HOME"] = str(codex_home)
            env["FAKE_ARGS"] = str(args_file)
            env["FAKE_STDIN"] = str(stdin_file)
            env["FAKE_CODEX_HOME"] = str(codex_home_file)
            env["FAKE_CODEX_CONFIG"] = str(codex_config_file)
            env["ALCHEMIST_PYTHON"] = sys.executable
            env["ALCHEMIST_MAX_CONCURRENT"] = "10"
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(RUNNER),
                    "-Profile",
                    "mimo",
                    "-TimeoutSeconds",
                    "10",
                    "-EventLog",
                    str(event_log),
                    "-WorkDir",
                    str(workdir),
                ],
                input="<task>probe</task>",
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("FAKE_OK", result.stdout, result.stderr + result.stdout)
            args = args_file.read_text(encoding="utf-8").strip()
            self.assertIn("launch-codex --profile mimo -- exec", args)
            self.assertIn("--dangerously-bypass-approvals-and-sandbox", args)
            self.assertNotIn("--sandbox workspace-write", args)
            self.assertIn("--skip-git-repo-check", args)
            self.assertIn(f'--cd "{workdir}"', args)
            self.assertIn("--model opencode-go/mimo-v2.5", args)
            self.assertNotIn("brief", args.lower())
            isolated_home = Path(codex_home_file.read_text(encoding="utf-8").strip())
            self.assertNotEqual(isolated_home, codex_home)
            self.assertFalse(isolated_home.exists())
            config = codex_config_file.read_text(encoding="utf-8")
            self.assertIn("model_providers.omniroute", config)
            self.assertIn("model_catalog_json", config)
            self.assertEqual(stdin_file.read_text(encoding="utf-8").strip(), "<task>probe</task>")
            self.assertIn('"text":"FAKE_OK"', event_log.read_text(encoding="utf-8"))
            self.assertIn("booting", Path(str(event_log) + ".stderr").read_text(encoding="utf-8"))
            self.assertFalse(Path(str(event_log) + ".stdin").exists())

    def test_pipeline_multiline_input_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            codex_home = tmp / ".codex"
            codex_home.mkdir()
            (codex_home / "mimo.config.toml").write_text('model = "opencode-go/mimo-v2.5"\n', encoding="utf-8")
            stdin_file = tmp / "stdin.txt"
            fake = fake_bin / "omniroute.cmd"
            fake.write_text(
                "@echo off\r\n"
                'more > "%FAKE_STDIN%"\r\n'
                'echo {"type":"item.completed"}\r\n',
                encoding="utf-8",
            )
            brief_file = tmp / "brief.txt"
            brief_file.write_text("<task>first\nsecond</task>", encoding="utf-8")
            event_log = tmp / "pipeline.jsonl"
            env = os.environ.copy()
            env.update({"PATH": str(fake_bin) + os.pathsep + env["PATH"], "CODEX_HOME": str(codex_home), "FAKE_STDIN": str(stdin_file), "ALCHEMIST_PYTHON": sys.executable})
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f'Get-Content -Raw "{brief_file}" | & "{RUNNER}" -Profile mimo -TimeoutSeconds 10 -EventLog "{event_log}" -WorkDir "{tmp}"'],
                text=True, capture_output=True, env=env, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stdin_file.read_text(encoding="utf-8").strip(), "<task>first\nsecond</task>")

    def test_timeout_persists_both_streams_then_cleans_up(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            codex_home = tmp / ".codex"
            codex_home.mkdir()
            (codex_home / "mimo.config.toml").write_text('model = "opencode-go/mimo-v2.5"\n', encoding="utf-8")
            fake = fake_bin / "omniroute.cmd"
            fake.write_text(
                "@echo off\r\n"
                "more > nul\r\n"
                'echo {"type":"item.completed","item":{"text":"stdout-marker"}}\r\n'
                "echo stderr-marker 1>&2\r\n"
                "ping -n 10 127.0.0.1 > nul\r\n",
                encoding="utf-8",
            )
            event_log = tmp / "%ALCHEMIST_DEFINED_PATH%-timeout.jsonl"
            env = os.environ.copy()
            env.update({"PATH": str(fake_bin) + os.pathsep + env["PATH"], "CODEX_HOME": str(codex_home), "ALCHEMIST_DEFINED_PATH": "expanded", "ALCHEMIST_PYTHON": sys.executable})
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(RUNNER), "-Profile", "mimo", "-TimeoutSeconds", "1", "-EventLog", str(event_log), "-WorkDir", str(tmp)],
                input="<task>probe</task>", text=True, capture_output=True, env=env, timeout=20,
            )
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn(f"EVENT_LOG={event_log}", result.stderr)
            self.assertIn("stdout-marker", event_log.read_text(encoding="utf-8"))
            self.assertIn("stderr-marker", Path(str(event_log) + ".stderr").read_text(encoding="utf-8"))
            self.assertFalse(Path(str(event_log) + ".stdin").exists())

    def test_rejects_zero_event_launcher_output(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            codex_home = tmp / ".codex"
            codex_home.mkdir()
            (codex_home / "mimo.config.toml").write_text(
                'model = "opencode-go/mimo-v2.5"\n', encoding="utf-8"
            )
            fake = fake_bin / "omniroute.cmd"
            fake.write_text(
                "@echo off\r\n"
                "more > nul\r\n"
                "echo Loaded env\r\n"
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            event_log = tmp / "empty.jsonl"
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            env["CODEX_HOME"] = str(codex_home)
            env["ALCHEMIST_PYTHON"] = sys.executable
            env["ALCHEMIST_MAX_CONCURRENT"] = "10"
            result = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(RUNNER), "-Profile", "mimo", "-TimeoutSeconds", "10",
                    "-EventLog", str(event_log), "-WorkDir", str(tmp),
                ],
                input="<task>probe</task>", text=True, capture_output=True, env=env, timeout=20,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("zero JSON events", result.stderr)
if __name__ == "__main__":
    unittest.main()
