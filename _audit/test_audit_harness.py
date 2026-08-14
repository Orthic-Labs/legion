import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_evals
import validate_skills


class AuditHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="skill-audit-test-"))
        (self.tmp / "tools" / "skills").mkdir(parents=True)
        (self.tmp / ".claude" / "rules").mkdir(parents=True)
        (self.tmp / ".codex" / "rules").mkdir(parents=True)
        (self.tmp / ".claude" / "rules" / "skills.md").write_text(
            """# Skills

## Top-Level Router Skills

| Skill | Use For |
|---|---|
| `/router-one` | routes work |

## Direct Top-Level Skills

| Skill | Use For |
|---|---|
| `/good-skill` | good fixture |
| `/alias-public` | public alias fixture |

## Council Pipeline
""",
            encoding="utf-8",
        )
        (self.tmp / ".codex" / "rules" / "skills.md").write_text(
            """# Codex Skill Compatibility

## Router Skills

- `router-one` routes to `router-one/references/*.md`

## Translation

Shared skills stay canonical.
""",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_skill(self, folder, name=None, body="", evals=None):
        skill_dir = self.tmp / "tools" / "skills" / folder
        skill_dir.mkdir(parents=True)
        skill_name = name or folder
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {skill_name}\ndescription: Use when testing {skill_name}\n---\n\n# {skill_name}\n\n{body}\n",
            encoding="utf-8",
        )
        if evals is not None:
            eval_dir = skill_dir / "evals"
            eval_dir.mkdir()
            (eval_dir / "evals.json").write_text(json.dumps(evals), encoding="utf-8")
        return skill_dir

    def valid_evals(self, skill="good-skill"):
        case = {
            "id": "case-1",
            "prompt": "use the good skill",
            "expected_behavior": "select the skill",
            "assertions": [{"type": "expected_skill", "value": skill}],
        }
        return {
            "schema_version": 1,
            "skill": skill,
            "should_trigger": [case],
            "should_not_trigger": [
                {
                    "id": "case-2",
                    "prompt": "do unrelated work",
                    "expected_behavior": "do not select the skill",
                    "assertions": [{"type": "forbidden_skill", "value": skill}],
                }
            ],
            "output_quality": [case],
            "safety": [case],
            "pressure": [case],
            "compatibility": [case],
        }

    def test_validate_reports_current_failure_modes(self):
        self.write_skill(
            "good-skill",
            body="[missing](references/missing.md)\n\nUse `D:/Claude/does-not-exist.py`.\n\nOutput to `/mnt/user-data/outputs/`.",
        )
        result = validate_skills.run_validation(self.tmp)
        codes = {issue["code"] for issue in result["issues"]}

        self.assertIn("MISSING_EVALS", codes)
        self.assertIn("BROKEN_MARKDOWN_LINK", codes)
        self.assertIn("MISSING_LOCAL_PATH", codes)
        self.assertIn("LINUX_PATH_LEAK", codes)

    def test_compatibility_matrix_allows_documented_name_mismatch(self):
        self.write_skill("alias-folder", name="alias-public", evals=self.valid_evals("alias-public"))
        matrix = self.tmp / "tools" / "skills" / "_audit" / "compatibility-matrix.json"
        matrix.parent.mkdir(exist_ok=True)
        matrix.write_text(
            json.dumps(
                {
                    "aliases": [
                        {
                            "folder": "alias-folder",
                            "frontmatter_name": "alias-public",
                            "public_invocations": ["alias-public"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = validate_skills.run_validation(self.tmp)
        codes = {issue["code"] for issue in result["issues"]}

        self.assertNotIn("FOLDER_NAME_MISMATCH", codes)

    def test_windows_workspace_path_maps_to_selected_root(self):
        target = self.tmp / "tools" / "skills" / "fixture.py"
        target.write_text("pass\n", encoding="utf-8")

        self.assertTrue(
            validate_skills.local_path_exists(
                self.tmp, r"D:\Claude\tools\skills\fixture.py"
            )
        )
        self.assertFalse(
            validate_skills.local_path_exists(
                self.tmp, r"D:\Claude\tools\skills\missing.py"
            )
        )

    def test_schema_validation_requires_all_eval_categories(self):
        invalid = {"schema_version": 1, "skill": "good-skill", "should_trigger": []}
        errors = run_evals.validate_eval_manifest(invalid)

        self.assertIn("missing category: should_not_trigger", errors)
        self.assertIn("missing category: output_quality", errors)

    def test_legacy_eval_expected_output_is_supported(self):
        legacy = {
            "skill_name": "brief",
            "evals": [
                {
                    "id": 1,
                    "prompt": "/brief explain hooks",
                    "expected_output": "Short accurate answer",
                    "expectations": ["No filler"],
                }
            ],
        }

        errors = run_evals.validate_eval_manifest(legacy)

        self.assertNotIn("should_trigger[0] missing field: expected_behavior", errors)

    def test_legacy_eval_zero_id_is_supported(self):
        legacy = {
            "skill_name": "brief",
            "evals": [
                {
                    "id": 0,
                    "prompt": "/brief explain hooks",
                    "expected_output": "Short accurate answer",
                    "expectations": ["No filler"],
                }
            ],
        }

        errors = run_evals.validate_eval_manifest(legacy)

        self.assertNotIn("should_trigger[0] missing field: id", errors)
        self.assertNotIn("output_quality[0] missing field: id", errors)

    def test_discovery_dry_run_requires_trigger_and_non_trigger(self):
        self.write_skill(
            "good-skill",
            evals={
                "schema_version": 1,
                "skill": "good-skill",
                "should_trigger": [],
                "should_not_trigger": [],
                "output_quality": [],
                "safety": [],
                "pressure": [],
                "compatibility": [],
            },
        )

        result = run_evals.run_schema_checks(self.tmp, discovery=True)
        codes = {issue["code"] for issue in result["issues"]}

        self.assertIn("NO_SHOULD_TRIGGER_CASES", codes)
        self.assertIn("NO_SHOULD_NOT_TRIGGER_CASES", codes)

    def test_discovery_accepts_legacy_manifest_with_migration_warning(self):
        self.write_skill(
            "good-skill",
            evals={
                "skill_name": "good-skill",
                "evals": [
                    {
                        "id": 0,
                        "prompt": "use the good skill",
                        "expected_output": "select the skill",
                        "expectations": ["uses good-skill"],
                    }
                ],
            },
        )

        result = run_evals.run_schema_checks(self.tmp, discovery=True)
        codes = {issue["code"] for issue in result["issues"]}

        self.assertEqual(result["error_count"], 0)
        self.assertIn("LEGACY_EVAL_SCHEMA", codes)

    def test_parse_model_judge_response_extracts_fenced_json(self):
        parsed = run_evals.parse_model_judge_response(
            '```json\n{"skill":"status","verdict":"PASS","score":9,"blockers":[]}\n```'
        )

        self.assertEqual(parsed["skill"], "status")
        self.assertEqual(parsed["verdict"], "PASS")

    def test_build_model_judge_prompt_contains_skill_and_eval_categories(self):
        skill_dir = self.write_skill("good-skill", evals=self.valid_evals("good-skill"))
        manifest = json.loads((skill_dir / "evals" / "evals.json").read_text(encoding="utf-8"))
        prompt = run_evals.build_model_judge_prompt(skill_dir / "SKILL.md", manifest)

        self.assertIn("good-skill", prompt)
        self.assertIn("should_trigger", prompt)
        self.assertIn("should_not_trigger", prompt)


if __name__ == "__main__":
    unittest.main()
