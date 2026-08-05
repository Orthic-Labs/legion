import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SKILLS = ROOT / "tools" / "skills"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def eval_text(skill: str) -> tuple[dict, str]:
    manifest = json.loads(read(SKILLS / skill / "evals" / "evals.json"))
    return manifest, json.dumps(manifest, ensure_ascii=False)


class SkillRegressionContractTests(unittest.TestCase):
    def test_workspace_skill_surface_is_consolidated_and_routes_are_live(self):
        top_level = {
            path.parent.name
            for path in SKILLS.glob("*/SKILL.md")
        }
        for skill in ("designer", "content", "writing", "marketing"):
            self.assertIn(skill, top_level)

        retired = {
            "redesign", "design", "impeccable", "contentcreation", "writing-pro", "blogs",
            "copywriting", "email-pro", "offer-and-bio-writer", "plan", "growth", "optimize",
            "ideas", "product-marketing-context", "daily-mvp", "seedance", "kdp",
            "image-enhancer", "remotion-best-practices", "transcribe", "changelog-generator",
            "claude-api", "connect", "context-hygiene", "context-metrics", "dictate",
            "file-organizer", "file-search", "hardeningscan", "hooks-automation", "init",
            "invoice-organizer", "meeting-insights-analyzer", "mem-recency",
            "raffle-winner-picker", "scrapegraph", "skillopt-sleep", "status", "token-audit",
            "writing-skills", "jury",
        }
        self.assertFalse(top_level & retired, f"retired skills still visible: {top_level & retired}")

        expected_guides = (
            SKILLS / "designer" / "engine" / "GUIDE.md",
            SKILLS / "designer" / "specialists" / "static-creative" / "GUIDE.md",
            SKILLS / "content" / "specialists" / "seedance" / "GUIDE.md",
            SKILLS / "content" / "specialists" / "kdp" / "GUIDE.md",
            SKILLS / "content" / "specialists" / "remotion" / "GUIDE.md",
            SKILLS / "content" / "specialists" / "transcription" / "GUIDE.md",
            SKILLS / "writing" / "specialists" / "blogs" / "GUIDE.md",
            SKILLS / "writing" / "specialists" / "copywriting" / "GUIDE.md",
            SKILLS / "writing" / "specialists" / "email" / "GUIDE.md",
            SKILLS / "marketing" / "specialists" / "growth" / "GUIDE.md",
            SKILLS / "marketing" / "specialists" / "cro" / "GUIDE.md",
            SKILLS / "marketing" / "specialists" / "ideas" / "GUIDE.md",
        )
        for guide in expected_guides:
            self.assertTrue(guide.is_file(), f"missing consolidated guide: {guide}")

        designer_engine_text = "\n".join(
            read(path)
            for path in (SKILLS / "designer" / "engine").rglob("*.md")
        )
        self.assertNotIn("tools/skills/designer/scripts", designer_engine_text)
        self.assertIn("tools/skills/designer/engine/scripts", designer_engine_text)
        self.assertTrue((SKILLS / "designer" / "engine" / "scripts" / "detect.mjs").is_file())
        self.assertFalse((SKILLS / "designer" / "engine" / "scripts" / "pin.mjs").exists())
        hook_admin = read(SKILLS / "designer" / "engine" / "scripts" / "hook-admin.mjs")
        self.assertNotIn("skills/designer/scripts", hook_admin)
        self.assertIn("skills/designer/engine/scripts/hook.mjs", hook_admin)

        active_files = (
            ROOT / "AGENTS.md",
            ROOT / "CLAUDE.md",
            ROOT / ".claude" / "rules" / "skills.md",
            ROOT / ".codex" / "rules" / "skills.md",
            ROOT / "PIPELINES.md",
        )
        active_text = "\n".join(read(path) for path in active_files)
        for command in (
            "/redesign", "/design", "/impeccable", "/contentcreation", "/writing-pro",
            "/blogs", "/copywriting", "/email-pro", "/offer-and-bio-writer", "/plan",
            "/growth", "/optimize", "/ideas", "/product-marketing-context", "/daily-mvp",
            "/seedance", "/kdp", "/transcribe", "/hardeningscan", "/status", "/init",
        ):
            pattern = rf"(?m)(^|[\s`\"'(]){re.escape(command)}(?![-A-Za-z0-9_])"
            self.assertNotRegex(active_text, pattern, f"stale live command route: {command}")

        release = read(
            ROOT / "tools" / "rightkit" / "packages" / "release" / "cli" / "right-release.mjs"
        )
        self.assertIn('["hardeningscan", "hardeningscan.mjs"]', release)
        self.assertNotIn('"skills", "hardeningscan"', release)

        roadmap = read(ROOT / "coderight" / "docs" / "skill-engineering" / "ROADMAP-2026-07-10.md")
        self.assertIn("unified runtime and observability layer", roadmap)
        self.assertIn("native`, `emulated`, or `unavailable", roadmap)
        self.assertNotIn("do not expose lifecycle hooks", roadmap)

        # Historical point-in-time snapshot from 2026-07-10. Live SKILL.md files have
        # since evolved (and jury was unified into council), so the snapshot is only
        # asserted immutable — never byte-equal to the live skills.
        comparison = ROOT / "docs" / "skill-changes-2026-07-10"
        self.assertEqual(
            sorted(path.name for path in comparison.iterdir()),
            ["architect.md", "audit.md", "commit.md", "jury.md"],
        )

    def test_architect_uses_blast_radius_not_single_file_absolutes(self):
        skill = read(SKILLS / "architect" / "SKILL.md")

        self.assertNotIn("A single-file change is NEVER substantive", skill)
        self.assertIn("A single file can be", skill)
        self.assertIn("substantive** when many consumers", skill)
        self.assertIn("an exported or", skill)
        self.assertIn("public contract", skill)
        self.assertIn("Embedded design lenses", skill)
        self.assertNotIn("Council instantiation", skill)
        self.assertIn("same parallel wave", skill)
        self.assertIn("when backward compatibility or live traffic requires it", skill)

    def test_audit_v2_contract_is_rendered_and_legacy_reports_still_work(self):
        skill = read(SKILLS / "audit" / "SKILL.md")
        renderer = read(SKILLS / "audit" / "render-report.mjs")

        for token in (
            '"schema_version": 2',
            '"evidence_strength"',
            '"judgment"',
            '"status"',
            '"caused_by"',
            '"constraints_surface"',
        ):
            self.assertIn(token, skill)
        self.assertNotIn('"root_cause"', skill)
        self.assertNotIn('"affects"', skill)
        self.assertIn("Unknown is an acceptable result", skill)

        for token in (
            "evidence_strength",
            "judgment",
            "status",
            "caused_by",
            "constraints_surface",
        ):
            self.assertIn(token, renderer)

        with tempfile.TemporaryDirectory(prefix="audit-render-v2-") as tmp:
            tmp_path = Path(tmp)
            facts_path = tmp_path / "facts.json"
            report_path = tmp_path / "report.json"
            legacy_path = tmp_path / "legacy.json"
            output_path = tmp_path / "report.md"
            legacy_output_path = tmp_path / "legacy.md"

            facts = {
                "workspace": str(tmp_path),
                "generated_at": "2026-07-10T00:00:00Z",
                "out_dir": str(tmp_path),
                "incomplete": False,
                "checks": [
                    {"check": "repo", "status": "ran", "exit_code": 0, "findings_count": 0, "meta": {"commit": "abc123"}},
                    {"check": "lint", "status": "ran", "exit_code": 0, "findings_count": 0},
                    {"check": "types", "status": "ran", "exit_code": 0, "findings_count": 0},
                    {"check": "build", "status": "ran", "exit_code": 0, "findings_count": 0},
                ],
                "decomposition": {"threshold": 500, "oversized": [], "mechanical_splits": []},
            }
            report = {
                "schema_version": 2,
                "lenses_ran": ["architecture"],
                "constraints_surface": [
                    {"scope": "runtime", "constraint": "Node 20", "evidence": "package.json#engines", "status": "verified"},
                    {"scope": "latency", "constraint": "unknown", "evidence": "", "status": "unknown"},
                ],
                "triage_top": ["ra-002"],
                "findings": [
                    {
                        "id": "ra-002",
                        "category": "architecture",
                        "severity": "medium",
                        "tier": "GUIDED",
                        "evidence_strength": "strong-inference",
                        "judgment": "interpretive",
                        "status": "open",
                        "caused_by": ["ra-001"],
                        "file": "src/app.ts",
                        "line": 42,
                        "evidence": "src/app.ts:42",
                        "title": "Hidden coupling",
                        "detail": "Boundary is implicit.",
                        "action": "Extract the boundary.",
                        "sources": ["architecture-lens"],
                    }
                ],
                "summary": {},
            }
            legacy = {
                "lenses_ran": ["correctness"],
                "triage_top": ["old-1"],
                "findings": [
                    {
                        "id": "old-1",
                        "category": "correctness",
                        "severity": "low",
                        "tier": "AUTO",
                        "file": "src/old.ts",
                        "line": 1,
                        "title": "Legacy finding",
                        "detail": "Old schema still renders.",
                        "sources": ["legacy"],
                    }
                ],
                "summary": {},
            }
            facts_path.write_text(json.dumps(facts), encoding="utf-8")
            report_path.write_text(json.dumps(report), encoding="utf-8")
            legacy_path.write_text(json.dumps(legacy), encoding="utf-8")

            subprocess.run(
                ["node", str(SKILLS / "audit" / "render-report.mjs"), "--facts", str(facts_path), "--report", str(report_path), "--out", str(output_path)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            rendered = read(output_path)
            self.assertIn("Constraints surface", rendered)
            self.assertIn("package.json#engines", rendered)
            self.assertIn("strong-inference", rendered)
            self.assertIn("interpretive", rendered)
            self.assertIn("caused by: `ra-001`", rendered)
            self.assertIn("| latency | unknown | unknown | unknown |", rendered)

            agent = subprocess.run(
                ["node", str(SKILLS / "audit" / "render-report.mjs"), "--facts", str(facts_path), "--report", str(report_path), "--agent"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            agent_json = json.loads(agent.stdout)
            self.assertEqual(agent_json["schema_version"], 2)
            self.assertEqual(agent_json["findings"][0]["evidence_strength"], "strong-inference")
            self.assertEqual(agent_json["findings"][0]["caused_by"], ["ra-001"])
            self.assertEqual(agent_json["constraints_surface"][0]["scope"], "runtime")
            self.assertEqual(agent_json["constraints_surface"][1]["evidence"], "unknown")
            self.assertEqual(agent_json["constraints_surface"][1]["status"], "unknown")

            subprocess.run(
                ["node", str(SKILLS / "audit" / "render-report.mjs"), "--facts", str(facts_path), "--report", str(legacy_path), "--out", str(legacy_output_path)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            legacy_rendered = read(legacy_output_path)
            self.assertIn("Legacy finding", legacy_rendered)
            self.assertNotIn("undefined", legacy_rendered)

    def test_commit_uses_shared_axes_and_fast_clean_path(self):
        skill = read(SKILLS / "commit" / "SKILL.md")

        self.assertIn("Fast clean path", skill)
        self.assertIn("Evidence strength:", skill)
        self.assertIn("Fixability:", skill)
        self.assertNotIn("Classify findings before fixing", skill)
        self.assertNotIn("Security — real CVE / leak path, hard stop (manual, escalate)", skill)

    def test_council_preserves_jury_independence_and_ship_gate(self):
        # Jury was unified into council (0bf8b7d5); the independence and
        # evidence-over-averaging contracts now live in the council skill.
        self.assertFalse((SKILLS / "jury").exists())
        council = read(SKILLS / "council" / "SKILL.md")

        self.assertNotIn("Council wins on taste", council)
        self.assertNotIn("prepend it to the `/jury` input", council)
        self.assertIn("Jury receives only the revised packet", council)
        self.assertIn("Seats never see one another's output", council)
        self.assertIn("Do not average the panels into one vote", council)
        self.assertIn("tools/review/models.yaml", council)
        self.assertTrue((ROOT / "tools" / "review" / "models.yaml").is_file())

    def test_eval_manifests_match_current_public_contracts(self):
        architect, architect_text = eval_text("architect")
        commit, commit_text = eval_text("commit")
        council, council_text = eval_text("council")
        audit, audit_text = eval_text("audit")

        self.assertEqual(architect["skill"], "architect")
        self.assertNotIn('"expected_skill": "architecture"', architect_text)
        self.assertNotIn("get approval (HARD-GATE)", architect_text)
        self.assertIn("single-file", architect_text)
        self.assertIn("trivial two-file", architect_text)
        for category in ("should_trigger", "output_quality", "safety", "pressure", "compatibility"):
            self.assertTrue(
                all(case.get("expected_skill") == "architect" for case in architect[category]),
                f"architect:{category} contains stale expected_skill",
            )

        self.assertNotIn("review-cli", commit_text)
        self.assertIn("fast clean path", commit_text.lower())
        self.assertIn("auto-fixable security", commit_text.lower())

        self.assertEqual(council["skill"], "council")
        self.assertNotIn("Cheap internal preflight", council_text)
        self.assertIn("unprimed", council_text)

        self.assertIn("evidence_strength", audit_text)
        self.assertIn("constraints_surface", audit_text)
        for manifest in (architect, audit, commit):
            for category in (
                "should_trigger",
                "should_not_trigger",
                "output_quality",
                "safety",
                "pressure",
                "compatibility",
            ):
                self.assertTrue(manifest[category], f"{manifest['skill']}:{category} is empty")
        # The council manifest is post-unification and carries a narrower category set.
        for category in ("should_trigger", "should_not_trigger", "output_quality", "pressure"):
            self.assertTrue(council[category], f"council:{category} is empty")


if __name__ == "__main__":
    unittest.main()
