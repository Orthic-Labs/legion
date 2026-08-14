#!/usr/bin/env python3
"""Eval manifest checks for local skills.

Default schema/discovery modes are no-network and deterministic. Optional
model-judged eval quality checks run only when --model-judge is passed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path("D:/Claude")
SKILL_ROOT = Path("tools/skills")
EXCLUDED_EVAL_PREFIXES = (("legion", "repos"),)
CATEGORIES = [
    "should_trigger",
    "should_not_trigger",
    "output_quality",
    "safety",
    "pressure",
    "compatibility",
]
ASSERTION_TYPES = {
    "required_text",
    "forbidden_text",
    "expected_skill",
    "forbidden_skill",
    "requires_confirmation",
    "requires_source_check",
    "requires_verification",
    "path_exists",
    "command_help_ok",
}
COUNCIL_DIR = Path("D:/Claude/tools/jury")


def issue(code: str, severity: str, path: Path | str, message: str) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "path": str(path),
        "message": message,
    }


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "manifest root must be an object"
    return data, None


def normalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a best-effort normalized manifest.

    Current legacy eval files use `{skill_name, evals}`. Treat those cases as
    should-trigger/output-quality material until `migrate_evals.py` upgrades
    them.
    """

    if "schema_version" in manifest:
        return manifest

    if "skill_name" in manifest and isinstance(manifest.get("evals"), list):
        evals = [normalize_legacy_case(case) for case in manifest.get("evals", [])]
        return {
            "schema_version": 0,
            "skill": manifest.get("skill_name"),
            "should_trigger": evals,
            "should_not_trigger": [],
            "output_quality": evals,
            "safety": [],
            "pressure": [],
            "compatibility": [],
            "_legacy": True,
        }

    return manifest


def normalize_legacy_case(case: Any) -> Any:
    if not isinstance(case, dict):
        return case
    normalized = dict(case)
    if "expected_behavior" not in normalized and "expected_output" in normalized:
        normalized["expected_behavior"] = normalized["expected_output"]
    if "assertions" not in normalized and "expectations" in normalized:
        normalized["assertions"] = normalized["expectations"]
    return normalized


def validate_assertions(case: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    assertions = case.get("assertions", [])
    if isinstance(assertions, list):
        for index, assertion in enumerate(assertions):
            if isinstance(assertion, str):
                continue
            if not isinstance(assertion, dict):
                errors.append(f"{prefix}.assertions[{index}] must be a string or object")
                continue
            assertion_type = assertion.get("type")
            if assertion_type not in ASSERTION_TYPES:
                errors.append(f"{prefix}.assertions[{index}] unknown assertion type: {assertion_type!r}")
    else:
        errors.append(f"{prefix}.assertions must be a list")
    return errors


def validate_case(case: Any, prefix: str) -> list[str]:
    if not isinstance(case, dict):
        return [f"{prefix} must be an object"]
    errors: list[str] = []
    for field in ("id", "prompt", "expected_behavior"):
        if field not in case or case[field] is None or case[field] == "":
            errors.append(f"{prefix} missing field: {field}")
    errors.extend(validate_assertions(case, prefix))
    return errors


def validate_eval_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    normalized = normalize_manifest(manifest)
    if not normalized.get("skill"):
        errors.append("missing field: skill")

    for category in CATEGORIES:
        if category not in normalized:
            errors.append(f"missing category: {category}")
            continue
        if not isinstance(normalized[category], list):
            errors.append(f"category must be a list: {category}")
            continue
        for index, case in enumerate(normalized[category]):
            errors.extend(validate_case(case, f"{category}[{index}]"))

    return errors


def skill_roots(root: Path) -> list[Path]:
    """Return supported workspace & packaged Legion skill roots."""
    candidates = [root / SKILL_ROOT, root / "skills"]
    return [candidate for candidate in candidates if candidate.exists()]


def eval_files(root: Path, skill: str | None = None) -> list[Path]:
    roots = skill_roots(root)
    if not roots:
        return []
    if skill:
        return [
            path
            for skill_root in roots
            if (path := skill_root / skill / "evals" / "evals.json").exists()
        ]
    candidates: list[Path] = []
    for skill_root in roots:
        candidates.extend(
            path for path in skill_root.rglob("evals/evals.json")
            if not any(path.relative_to(skill_root).parts[:len(prefix)] == prefix for prefix in EXCLUDED_EVAL_PREFIXES)
        )
    return sorted(set(candidates))


def run_schema_checks(
    root: str | Path = REPO_ROOT,
    discovery: bool = False,
    skill: str | None = None,
) -> dict[str, Any]:
    root = Path(root)
    issues: list[dict[str, str]] = []
    files = eval_files(root, skill=skill)
    if skill and not files:
        issues.append(
            issue(
                "MISSING_EVALS",
                "error",
                root / "skills" / skill / "evals" / "evals.json",
                "No evals/evals.json for requested skill.",
            )
        )
    for path in files:
        manifest, error = load_json(path)
        if error or manifest is None:
            issues.append(issue("INVALID_JSON", "error", path, error or "invalid JSON"))
            continue

        if "schema_version" not in manifest:
            issues.append(issue("LEGACY_EVAL_SCHEMA", "warning", path, "Eval manifest uses legacy schema."))

        for error_text in validate_eval_manifest(manifest):
            issues.append(issue("EVAL_SCHEMA_ERROR", "error", path, error_text))

        normalized = normalize_manifest(manifest)
        if discovery:
            if not normalized.get("should_trigger"):
                issues.append(issue("NO_SHOULD_TRIGGER_CASES", "error", path, "No should-trigger cases."))
            if not normalized.get("should_not_trigger"):
                issues.append(
                    issue("NO_SHOULD_NOT_TRIGGER_CASES", "error", path, "No should-not-trigger cases.")
                )

    return {
        "root": str(root),
        "eval_file_count": len(files),
        "issue_count": len(issues),
        "error_count": sum(1 for item in issues if item["severity"] == "error"),
        "warning_count": sum(1 for item in issues if item["severity"] == "warning"),
        "issues": issues,
    }


def parse_model_judge_response(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    try:
        parsed = json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            raise ValueError(f"model judge returned non-JSON: {text[:200]}")
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("model judge JSON must be an object")
    return parsed


def build_model_judge_prompt(skill_file: Path, manifest: dict[str, Any]) -> str:
    skill_text = skill_file.read_text(encoding="utf-8", errors="replace")
    if len(skill_text) > 5000:
        skill_text = skill_text[:5000] + "\n\n[TRUNCATED]"
    compact_manifest = {
        "skill": manifest.get("skill"),
        "should_trigger": manifest.get("should_trigger", [])[:3],
        "should_not_trigger": manifest.get("should_not_trigger", [])[:3],
        "output_quality": manifest.get("output_quality", [])[:2],
        "safety": manifest.get("safety", [])[:2],
        "pressure": manifest.get("pressure", [])[:2],
        "compatibility": manifest.get("compatibility", [])[:2],
    }
    return (
        "Judge whether this local Agent Skill eval manifest is adequate for a first model-backed gate.\n"
        "Return JSON only with keys: skill, verdict, score, blockers, notes.\n"
        "verdict must be PASS, NEEDS_REVISION, or FAIL. score is 0-10.\n"
        "Criteria: trigger cases match the skill; non-trigger cases are meaningful near misses; "
        "output/safety/pressure/compatibility cases test real risk; confirmation/source/verification gates are represented when relevant; "
        "no OS portability requirement.\n\n"
        f"SKILL_FILE: {skill_file}\n"
        f"SKILL_MD:\n{skill_text}\n\n"
        f"EVAL_MANIFEST:\n{json.dumps(compact_manifest, indent=2)}\n"
    )


def build_provider(provider_name: str):
    if str(COUNCIL_DIR) not in sys.path:
        sys.path.insert(0, str(COUNCIL_DIR))
    import yaml
    from providers import build_provider as make_provider

    config = yaml.safe_load((COUNCIL_DIR / "models.yaml").read_text(encoding="utf-8"))
    provider_cfg = config["providers"][provider_name]
    return make_provider(provider_name, provider_cfg)


def skill_dirs_for_model(root: Path, skill: str | None = None, max_skills: int | None = None) -> list[Path]:
    skill_root = root / SKILL_ROOT
    if skill:
        direct = skill_root / skill
        if (direct / "SKILL.md").exists():
            return [direct]
        for path in skill_root.rglob("evals/evals.json"):
            manifest, _ = load_json(path)
            if manifest and manifest.get("skill") == skill:
                return [path.parent.parent]
        return []
    dirs = sorted(path.parent.parent for path in skill_root.rglob("evals/evals.json"))
    if max_skills is not None:
        return dirs[:max_skills]
    return dirs


def run_model_judged_checks(
    root: str | Path = REPO_ROOT,
    skill: str | None = None,
    provider_name: str = "groq",
    model: str = "openai/gpt-oss-120b",
    max_skills: int | None = None,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(root)
    started = datetime.now(timezone.utc).isoformat()
    out_base = Path(out_dir) if out_dir else root / SKILL_ROOT / "_audit" / "model-eval-runs"
    out_base.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    provider = build_provider(provider_name)
    system = "You are a strict eval-quality judge. Return JSON only."
    results: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []

    for skill_dir in skill_dirs_for_model(root, skill=skill, max_skills=max_skills):
        eval_path = skill_dir / "evals" / "evals.json"
        skill_file = skill_dir / "SKILL.md"
        manifest, error = load_json(eval_path)
        if error or manifest is None:
            issues.append(issue("MODEL_EVAL_INPUT_ERROR", "error", eval_path, error or "invalid manifest"))
            continue
        prompt = build_model_judge_prompt(skill_file, manifest)
        t0 = time.time()
        try:
            raw = provider.call(model, system=system, user=prompt, max_tokens=1024)
            parsed = parse_model_judge_response(raw)
            elapsed_ms = int((time.time() - t0) * 1000)
            record = {
                "skill": manifest.get("skill") or skill_dir.name,
                "provider": provider_name,
                "model": model,
                "elapsed_ms": elapsed_ms,
                "parsed": parsed,
                "raw": raw,
            }
            if parsed.get("verdict") not in ("PASS", "NEEDS_REVISION", "FAIL"):
                issues.append(issue("MODEL_EVAL_BAD_VERDICT", "error", eval_path, f"Bad verdict: {parsed.get('verdict')}"))
            if parsed.get("verdict") in ("NEEDS_REVISION", "FAIL"):
                issues.append(
                    issue(
                        "MODEL_EVAL_NEEDS_REVISION",
                        "warning" if parsed.get("verdict") == "NEEDS_REVISION" else "error",
                        eval_path,
                        f"{parsed.get('verdict')}: {parsed.get('blockers') or parsed.get('notes')}",
                    )
                )
            results.append(record)
        except Exception as exc:
            issues.append(issue("MODEL_EVAL_ERROR", "error", eval_path, str(exc)))

    artifact = {
        "run_id": run_id,
        "started_at": started,
        "root": str(root),
        "provider": provider_name,
        "model": model,
        "result_count": len(results),
        "issue_count": len(issues),
        "error_count": sum(1 for item in issues if item["severity"] == "error"),
        "warning_count": sum(1 for item in issues if item["severity"] == "warning"),
        "issues": issues,
        "results": results,
    }
    out_path = out_base / f"{run_id}-model-evals.json"
    out_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    artifact["artifact_path"] = str(out_path)
    return artifact


def print_human_summary(result: dict[str, Any]) -> None:
    print(f"Root: {result['root']}")
    print(f"Eval files: {result['eval_file_count']}")
    print(
        f"Issues: {result['issue_count']} "
        f"({result['error_count']} errors, {result['warning_count']} warnings)"
    )
    for item in result["issues"]:
        print(f"[{item['severity']}] {item['code']}: {item['path']} - {item['message']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate local skill eval manifests.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Workspace root.")
    parser.add_argument("--schema-only", action="store_true", help="Validate eval schemas.")
    parser.add_argument("--discovery", action="store_true", help="Require trigger/non-trigger coverage.")
    parser.add_argument("--dry-run", action="store_true", help="No-op flag for no-network compatibility.")
    parser.add_argument("--model-judge", action="store_true", help="Run model-backed eval quality judging.")
    parser.add_argument("--provider", default="groq", help="Council provider for --model-judge.")
    parser.add_argument("--model", default="openai/gpt-oss-120b", help="Model for --model-judge.")
    parser.add_argument("--max-skills", type=int, help="Limit number of skills for --model-judge.")
    parser.add_argument("--out-dir", help="Output directory for model-judge artifacts.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("--skill", help="Only validate one skill folder.")
    args = parser.parse_args(argv)

    if args.model_judge:
        result = run_model_judged_checks(
            args.root,
            skill=args.skill,
            provider_name=args.provider,
            model=args.model,
            max_skills=args.max_skills,
            out_dir=args.out_dir,
        )
    else:
        discovery = bool(args.discovery)
        result = run_schema_checks(args.root, discovery=discovery, skill=args.skill)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human_summary(result)
    return 1 if result["error_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
