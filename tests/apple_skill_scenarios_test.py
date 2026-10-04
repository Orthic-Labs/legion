"""Static source/eval regressions, not live agent or Apple-platform trials."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AppleStaticScenarios(unittest.TestCase):
    def check_both(self, file, terms):
        for skill in ("ios-development", "macos-development"):
            with self.subTest(skill=skill):
                text = (ROOT / "skills" / skill / file).read_text()
                for term in terms:
                    self.assertIn(term, text)

    def test_tauri_host_is_preserved(self):
        self.check_both("references/tauri-rust-interop.md", ["Preserve the consuming app's Rust", "IPC contracts", "web UI"])

    def test_old_ios_core_data_target_stays_supported(self):
        self.check_both("references/persistence.md", ["Core Data", "migration"])
        self.check_both("SKILL.md", ["deployment", "existing"])
        data = json.loads((ROOT / "skills/ios-development/evals/evals.json").read_text())
        self.assertTrue(any("no unrequested SwiftData migration" in case.get("expected_behavior", "") for case in data["output_quality"]))

    def test_mcp_schema_mismatch_requires_discovery(self):
        self.check_both("references/toolchain.md", ["current capability listing and input schema", "do not silently update or install"])

    def test_task_group_timeout_is_not_promised_hard(self):
        self.check_both("references/concurrency.md", ["Cancellation is cooperative", "not a hard timeout", "Throwing discarding groups"])

    def test_ascctl_is_distinct_from_asc_and_account_authority(self):
        self.check_both("references/release.md", ["ascctl", "different asc CLI", "not interchangeable", "Installation does not authorize account access"])

    def test_liquid_glass_remains_conditional(self):
        self.check_both("references/swiftui.md", ["Conditional Liquid Glass adoption", "older-OS fallback", "Reduce Transparency/Reduce Motion"])


if __name__ == "__main__":
    unittest.main()
