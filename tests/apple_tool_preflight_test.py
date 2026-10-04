"""Portable tests for both standalone Apple bundles; no installed Apple tools required."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ("ios-development", "macos-development")


class ToolPreflightTests(unittest.TestCase):
    def setUp(self):
        self.bundles = []
        for name in SKILLS:
            path = ROOT / "skills" / name
            spec = importlib.util.spec_from_file_location(name, path / "scripts/tool_preflight.py")
            module = importlib.util.module_from_spec(spec)
            # Avoid even test-time bytecode writes in a shipped bundle.
            previous = sys.dont_write_bytecode
            sys.dont_write_bytecode = True
            try:
                spec.loader.exec_module(module)
            finally:
                sys.dont_write_bytecode = previous
            self.bundles.append((name, path, module, json.loads((path / "config/tool-catalog.json").read_text())))

    def test_existing_installation_is_reused_without_reinstall_claim(self):
        for name, _, module, catalog in self.bundles:
            with self.subTest(skill=name):
                result = module.inspect_selected(catalog, ["asc"], "Darwin", lambda cmd: "/existing/asc" if cmd == "asc" else None)
                self.assertEqual(result[0]["state"], "installed-candidate")
                self.assertIn("do not reinstall", result[0]["nextStep"])
                self.assertFalse(result[0]["versionVerified"])
                self.assertFalse(result[0]["mcpRegistrationVerified"])

    def test_missing_cli_requires_connected_tool_check_before_setup(self):
        for _, _, module, catalog in self.bundles:
            result = module.inspect_selected(catalog, ["mobilebuildmcp"], "Darwin", lambda _: None)[0]
            self.assertEqual(result["state"], "not-on-path")
            self.assertIn("connected MCP", result["nextStep"])

    def test_old_server_executable_is_preserved(self):
        for _, _, module, catalog in self.bundles:
            result = module.inspect_selected(catalog, ["mobilebuildmcp"], "Darwin", lambda cmd: "/existing/xcodebuildmcp" if cmd == "xcodebuildmcp" else None)[0]
            self.assertEqual(result["state"], "installed-candidate")
            self.assertEqual(result["found"][0]["command"], "xcodebuildmcp")

    def test_unsupported_environment_does_not_suggest_install(self):
        for _, _, module, catalog in self.bundles:
            result = module.inspect_selected(catalog, ["axe"], "Linux", lambda _: None)[0]
            self.assertEqual(result["state"], "unsupported-environment")
            self.assertIn("do not install here", result["nextStep"])

    def test_project_tools_require_manual_inspection(self):
        for _, _, module, catalog in self.bundles:
            result = module.inspect_selected(catalog, ["inject", "docsetquery"], "Darwin", lambda _: None)
            self.assertTrue(all(item["state"] == "manual-check" for item in result))

    def test_repeated_selection_and_invocation_are_idempotent(self):
        for _, _, module, catalog in self.bundles:
            first = module.inspect_selected(catalog, ["asc", "asc", "axe"], "Darwin", lambda _: None)
            second = module.inspect_selected(catalog, ["asc", "axe"], "Darwin", lambda _: None)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 2)

    def test_asc_and_ascctl_are_not_interchangeable(self):
        for _, _, module, catalog in self.bundles:
            result = module.inspect_selected(catalog, ["asc", "ascctl"], "Darwin", lambda cmd: "/existing/ascctl" if cmd == "ascctl" else None)
            self.assertEqual([item["state"] for item in result], ["not-on-path", "installed-candidate"])

    def test_unknown_selection_fails_closed(self):
        for _, _, module, catalog in self.bundles:
            with self.assertRaises(ValueError):
                module.inspect_selected(catalog, ["invented-cli"], "Darwin", lambda _: None)

    def test_helper_does_not_write_config_or_execute_discovered_binary(self):
        for name, path, _, _ in self.bundles:
            with self.subTest(skill=name), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                config = home / "config.toml"
                original = '# user comment\n[mcp_servers.existing]\ncommand = "keep"\n'
                config.write_text(original)
                # A fake found executable must not be run, even to get its version.
                executable = home / "asc"
                executable.write_text('#!/bin/sh\ntouch "' + str(home / 'executed') + '"\n')
                executable.chmod(0o755)
                environment = {"HOME": str(home), "PATH": str(home)}
                for _ in range(2):
                    completed = subprocess.run([sys.executable, str(path / "scripts/tool_preflight.py"), "--tool", "asc"], env=environment, capture_output=True, text=True, check=True)
                    self.assertTrue(json.loads(completed.stdout)["readOnly"])
                self.assertEqual(config.read_text(), original)
                self.assertFalse((home / "executed").exists())
                self.assertEqual(sorted(p.name for p in home.iterdir()), ["asc", "config.toml"])

    def test_bundles_share_identical_catalog_and_helper(self):
        for relative in ("config/tool-catalog.json", "scripts/tool_preflight.py", "references/tool-setup.md"):
            self.assertEqual((self.bundles[0][1] / relative).read_bytes(), (self.bundles[1][1] / relative).read_bytes())


if __name__ == "__main__":
    unittest.main()
