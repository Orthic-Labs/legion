#!/usr/bin/env python3
"""Create a local-first priority snapshot for direct skill remediation."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import validate_skills


REPO_ROOT = Path("D:/Claude")
HIGH_RISK = {
    "connect",
    "file-organizer",
    "invoice-organizer",
    "seedance",
    "dictate",
    "transcribe",
    "notebooklm",
    "youtube-downloader",
}
STRUCTURAL = {
    "hooks-automation",
    "remotion-best-practices",
    "youtube-downloader",
    "offer-and-bio-writer",
    "notebooklm",
    "writing-skills",
}


def classify(skill: str, issue_codes: set[str]) -> str:
    if skill in STRUCTURAL or {"INVALID_SKILL_NAME", "FOLDER_NAME_MISMATCH", "BROKEN_MARKDOWN_LINK"} & issue_codes:
        return "structural-blocker"
    if skill in HIGH_RISK:
        return "high-risk-action"
    if "MISSING_EVALS" in issue_codes:
        return "missing-evals"
    return "remaining"


def make_snapshot(root: Path) -> dict:
    validation = validate_skills.run_validation(root)
    by_skill: dict[str, set[str]] = {}
    for item in validation["issues"]:
        parts = Path(item["path"]).parts
        try:
            skill = parts[parts.index("skills") + 1]
        except (ValueError, IndexError):
            continue
        by_skill.setdefault(skill, set()).add(item["code"])

    skills = []
    for skill, codes in sorted(by_skill.items()):
        band = classify(skill, codes)
        skills.append(
            {
                "skill": skill,
                "priority_band": band,
                "issue_codes": sorted(codes),
                "risk_score": (3 if band == "structural-blocker" else 2 if band == "high-risk-action" else 1),
            }
        )

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "skills": sorted(skills, key=lambda item: (-item["risk_score"], item["skill"])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create skill remediation priority snapshot.")
    parser.add_argument("--root", default=str(REPO_ROOT))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    root = Path(args.root)
    snapshot = make_snapshot(root)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
