#!/usr/bin/env python3
"""Static validation for Adrian's local skill library.

This tool is intentionally local-first: it reads the skill tree and shared
indexes, checks static structure, and never calls model or network APIs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - fallback exists for lean envs
    yaml = None

try:
    import tiktoken
except Exception:  # pragma: no cover - setup-workspace installs it
    tiktoken = None


REPO_ROOT = Path("D:/Claude")
SKILL_ROOT = Path("tools/skills")
# Name kept as CLAUDE_INDEX for backward compatibility with external readers
# (e.g. seed_skill_evals.py) that import this attribute by name. There is no
# longer a separate Claude/Codex split: the two former per-agent rule indexes
# were merged into this single catalogue.
CLAUDE_INDEX = Path("docs/SKILL-ARCHITECTURE.md")
AUDIT_DIR = Path("tools/skills/legion/_audit")
COMPATIBILITY_MATRIX = AUDIT_DIR / "compatibility-matrix.json"
CAPABILITY_ALIASES = AUDIT_DIR / "capability-aliases.json"
DESCRIPTION_TOKEN_LIMIT = 60
ROUTER_BODY_TOKEN_LIMIT = 300
DIRECT_BODY_TOKEN_LIMIT = 600


@dataclass
class Issue:
    code: str
    severity: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
        }


def issue(code: str, severity: str, path: Path | str, message: str) -> Issue:
    return Issue(code=code, severity=severity, path=str(path), message=message)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def token_count(text: str) -> int | None:
    if tiktoken is None:
        return None
    return len(tiktoken.get_encoding("o200k_base").encode(text))


def load_capability_aliases(root: Path) -> dict[str, str]:
    path = root / CAPABILITY_ALIASES
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {}
    aliases = data.get("aliases", {}) if isinstance(data, dict) else {}
    return {str(key): str(value) for key, value in aliases.items()} if isinstance(aliases, dict) else {}


def extract_frontmatter(raw: str) -> tuple[dict[str, Any], str, str | None]:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", raw, re.S)
    if not match:
        return {}, raw, "missing YAML frontmatter"

    frontmatter_text, body = match.group(1), match.group(2)
    if yaml is None:
        parsed: dict[str, Any] = {}
        for line in frontmatter_text.splitlines():
            if ":" in line and not line.startswith((" ", "\t")):
                key, value = line.split(":", 1)
                parsed[key.strip()] = value.strip().strip("\"'")
        return parsed, body, None

    try:
        parsed_yaml = yaml.safe_load(frontmatter_text) or {}
    except Exception as exc:
        return {}, body, f"YAML parse error: {exc}"

    if not isinstance(parsed_yaml, dict):
        return {}, body, "YAML frontmatter must be a mapping"
    return parsed_yaml, body, None


def parse_skill_index(index_text: str) -> dict[str, set[str]]:
    def section_between(start_header: str, end_header: str) -> str:
        if start_header not in index_text:
            return ""
        after = index_text.split(start_header, 1)[1]
        if end_header and end_header in after:
            return after.split(end_header, 1)[0]
        return after

    routers = section_between("**Top-level router skills**", "**Direct top-level skills**")
    direct = section_between("**Direct top-level skills**", "### Council pipeline")
    pattern = re.compile(r"^\| `/([^` ]+)", re.M)
    result = {
        "routers": set(pattern.findall(routers)),
        "direct": set(pattern.findall(direct)),
    }
    if result["routers"] or result["direct"]:
        return result

    # Current catalogue format: "### Core routers" table (first column = name)
    # and "### Direct top-level specialists" table (a "Skills" column of
    # backtick names, no leading slash).
    routers_section = section_between("### Core routers", "### Direct top-level specialists")
    direct_section = section_between("### Direct top-level specialists", "###")
    router_names = set(re.findall(r"^\| `([^` ]+)`", routers_section, re.M))
    direct_names = set(re.findall(r"`([^`]+)`", direct_section))
    return {
        "routers": router_names,
        "direct": direct_names,
    }


def load_compatibility_matrix(root: Path) -> dict[str, Any]:
    path = root / COMPATIBILITY_MATRIX
    if not path.exists():
        return {"aliases": []}
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {"aliases": []}
    if not isinstance(data, dict):
        return {"aliases": []}
    data.setdefault("aliases", [])
    return data


def alias_allows_mismatch(matrix: dict[str, Any], folder: str, frontmatter_name: str) -> bool:
    for entry in matrix.get("aliases", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("folder") == folder and entry.get("frontmatter_name") == frontmatter_name:
            return True
    return False


def local_markdown_links(body: str) -> list[str]:
    links: list[str] = []
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", body):
        if re.match(r"^[a-z][a-z0-9+.-]*:", link, re.I):
            continue
        if link.startswith(("#", "mailto:")):
            continue
        clean = link.split("#", 1)[0].strip().strip("<>")
        if clean.startswith("./"):
            clean = clean[2:]
        if not clean or "$" in clean or "<" in clean or ">" in clean:
            continue
        links.append(clean)
    return links


def local_windows_paths(raw: str) -> list[str]:
    paths = []
    for match in re.findall(r"(?<![A-Za-z])\b[A-Za-z]:[\\/][^\s`)\"']+", raw):
        cleaned = match.rstrip(".,;:")
        if any(token in cleaned for token in ("<", ">", "$", "*")):
            continue
        if re.search(r"[\\/]path[\\/]to[\\/]", cleaned, re.I):
            continue
        paths.append(cleaned)
    return paths


def optional_local_paths(matrix: dict[str, Any]) -> set[str]:
    return {str(path).replace("\\", "/") for path in matrix.get("optional_local_paths", [])}


def local_path_exists(root: Path, raw_path: str) -> bool:
    portable = raw_path.replace("\\", "/")
    workspace = re.match(r"(?i)^D:/Claude(?:/(.*))?$", portable)
    if workspace:
        suffix = workspace.group(1)
        return (root / suffix).exists() if suffix else root.exists()
    return Path(raw_path).exists()


def validate_skill_file(
    root: Path,
    skill_file: Path,
    indexes: dict[str, set[str]],
    matrix: dict[str, Any],
    require_evals: bool = True,
) -> list[Issue]:
    issues: list[Issue] = []
    raw = read_text(skill_file)
    frontmatter, body, frontmatter_error = extract_frontmatter(raw)
    folder = skill_file.parent.name

    name = str(frontmatter.get("name") or folder)
    description = str(frontmatter.get("description") or "")

    is_router = folder in indexes["routers"] or name in indexes["routers"]
    is_direct = folder in indexes["direct"] or name in indexes["direct"]

    if frontmatter_error:
        issues.append(issue("FRONTMATTER_ERROR", "error", skill_file, frontmatter_error))

    if not is_direct and not is_router:
        issues.append(
            issue(
                "UNINDEXED_SKILL",
                "error",
                skill_file,
                f"Skill '{name}' in folder '{folder}' is neither direct nor router in Claude index.",
            )
        )

    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        issues.append(issue("INVALID_SKILL_NAME", "error", skill_file, f"Invalid skill name: {name!r}"))

    if name != folder and not alias_allows_mismatch(matrix, folder, name):
        issues.append(
            issue(
                "FOLDER_NAME_MISMATCH",
                "error",
                skill_file,
                f"Folder '{folder}' does not match frontmatter name '{name}' and no compatibility alias covers it.",
            )
        )

    if not description.strip():
        issues.append(issue("MISSING_DESCRIPTION", "error", skill_file, "Missing skill description."))
    elif len(description) > 1024:
        issues.append(
            issue("DESCRIPTION_TOO_LONG", "error", skill_file, "Description exceeds 1024 characters.")
        )

    description_tokens = token_count(description)
    body_tokens = token_count(body)
    if description_tokens is not None and description_tokens > DESCRIPTION_TOKEN_LIMIT:
        issues.append(issue(
            "DESCRIPTION_TOKEN_BUDGET",
            "error",
            skill_file,
            f"Description has {description_tokens} o200k tokens; limit is {DESCRIPTION_TOKEN_LIMIT}.",
        ))
    body_limit = ROUTER_BODY_TOKEN_LIMIT if is_router else DIRECT_BODY_TOKEN_LIMIT
    if body_tokens is not None and body_tokens > body_limit:
        issues.append(issue(
            "SKILL_BODY_TOKEN_BUDGET",
            "error",
            skill_file,
            f"Body has {body_tokens} o200k tokens; limit is {body_limit}.",
        ))

    body_lines = len(body.splitlines())
    if body_lines > 700:
        issues.append(
            issue("SKILL_BODY_TOO_LONG", "error", skill_file, f"SKILL.md body has {body_lines} lines.")
        )
    elif body_lines > 500:
        issues.append(
            issue("SKILL_BODY_LONG", "warning", skill_file, f"SKILL.md body has {body_lines} lines.")
        )

    if require_evals and (is_direct or is_router) and not (skill_file.parent / "evals" / "evals.json").exists():
        issues.append(issue("MISSING_EVALS", "error", skill_file, "Top-level skill has no evals/evals.json."))

    for link in local_markdown_links(body):
        target = skill_file.parent / link
        if not target.exists():
            issues.append(
                issue("BROKEN_MARKDOWN_LINK", "error", skill_file, f"Missing local markdown target: {link}")
            )

    optional_paths = optional_local_paths(matrix)
    for raw_path in local_windows_paths(raw):
        if raw_path.replace("\\", "/") in optional_paths:
            continue
        if not local_path_exists(root, raw_path):
            issues.append(issue("MISSING_LOCAL_PATH", "warning", skill_file, f"Local path does not exist: {raw_path}"))

    if re.search(r"/mnt/user-data(?:/|\b)", raw):
        issues.append(
            issue("LINUX_PATH_LEAK", "warning", skill_file, "Contains /mnt/user-data path in local Windows skill.")
        )

    if re.search(r"<<\s*'PY'|<<\s*\"PY\"", raw):
        issues.append(
            issue("BASH_HEREDOC", "warning", skill_file, "Contains Bash heredoc Python example.")
        )

    return issues


def validate_indexes(root: Path, indexes: dict[str, set[str]]) -> list[Issue]:
    issues: list[Issue] = []
    index_path = root / CLAUDE_INDEX
    if not index_path.exists():
        issues.append(issue("MISSING_SKILL_INDEX", "error", index_path, "Missing skill catalogue (docs/SKILL-ARCHITECTURE.md)."))
        return issues

    if not indexes["direct"]:
        issues.append(issue("NO_DIRECT_SKILLS", "error", index_path, "No direct skills found in skill catalogue."))
    return issues


def validate_capability_aliases(root: Path, indexes: dict[str, set[str]]) -> list[Issue]:
    issues: list[Issue] = []
    path = root / CAPABILITY_ALIASES
    aliases = load_capability_aliases(root)
    if not aliases:
        return [issue("MISSING_CAPABILITY_ALIASES", "error", path, "Capability alias table is missing or empty.")]
    known = indexes["routers"] | indexes["direct"]
    for source, target in aliases.items():
        if not re.fullmatch(r"/[a-z0-9]+(?:-[a-z0-9]+)*", source):
            issues.append(issue("INVALID_CAPABILITY_ALIAS", "error", path, f"Invalid alias: {source}"))
        if target.startswith("/"):
            destination = target[1:].split(None, 1)[0]
            if destination not in known:
                issues.append(issue("MISSING_ALIAS_TARGET", "error", path, f"{source} targets missing /{destination}."))
        elif not target.startswith(("hook:", "tool:")):
            issues.append(issue("INVALID_ALIAS_TARGET", "error", path, f"{source} has invalid target: {target}"))

    retired = "|".join(re.escape(source[1:]) for source in aliases)
    pattern = re.compile(rf"(^|[\s`'\"(])/({retired})(?=[\s`'\",.;:)]|$)", re.M)
    skill_root = root / SKILL_ROOT
    for candidate in sorted(skill_root.rglob("*")):
        if not candidate.is_file() or candidate.suffix.lower() not in {".md", ".json"}:
            continue
        relative = candidate.relative_to(skill_root)
        if any(part in {"examples", "snapshots", "golden", "model-eval-runs"} for part in relative.parts):
            continue
        if candidate == path:
            continue
        match = pattern.search(read_text(candidate))
        if match:
            source = "/" + match.group(2)
            issues.append(issue(
                "STALE_CAPABILITY_POINTER",
                "error",
                candidate,
                f"Replace retired {source} with {aliases[source]}.",
            ))
    return issues


def run_validation(root: str | Path = REPO_ROOT, require_evals: bool = True) -> dict[str, Any]:
    root = Path(root)
    issues: list[Issue] = []
    index_path = root / CLAUDE_INDEX
    if index_path.exists():
        indexes = parse_skill_index(read_text(index_path))
    else:
        indexes = {"routers": set(), "direct": set()}
        issues.append(issue("MISSING_SKILL_INDEX", "error", index_path, "Missing skill catalogue (docs/SKILL-ARCHITECTURE.md)."))

    issues.extend(validate_indexes(root, indexes))
    issues.extend(validate_capability_aliases(root, indexes))
    matrix = load_compatibility_matrix(root)

    skill_root = root / SKILL_ROOT
    if tiktoken is None:
        issues.append(issue(
            "TOKENIZER_UNAVAILABLE",
            "error",
            skill_root,
            "Install workspace dependencies with setup-workspace; o200k token budgets cannot be checked.",
        ))
    if not skill_root.exists():
        issues.append(issue("MISSING_SKILL_ROOT", "error", skill_root, "Missing tools/skills directory."))
    else:
        for skill_file in sorted(skill_root.glob("*/SKILL.md")):
            if skill_file.parent.name == "_audit":
                continue
            issues.extend(validate_skill_file(root, skill_file, indexes, matrix, require_evals=require_evals))

    issue_dicts = [item.as_dict() for item in issues]
    return {
        "root": str(root),
        "issue_count": len(issue_dicts),
        "error_count": sum(1 for item in issue_dicts if item["severity"] == "error"),
        "warning_count": sum(1 for item in issue_dicts if item["severity"] == "warning"),
        "issues": issue_dicts,
    }


def filter_result_by_skill(result: dict[str, Any], skill: str) -> dict[str, Any]:
    marker = f"\\{skill}\\SKILL.md"
    marker_alt = f"/{skill}/SKILL.md"
    filtered = [
        item
        for item in result["issues"]
        if marker in item["path"] or marker_alt in item["path"] or f"\\{skill}\\" in item["path"]
    ]
    return {
        **result,
        "issue_count": len(filtered),
        "error_count": sum(1 for item in filtered if item["severity"] == "error"),
        "warning_count": sum(1 for item in filtered if item["severity"] == "warning"),
        "issues": filtered,
    }


def snapshot_discovery(root: str | Path = REPO_ROOT) -> dict[str, Any]:
    root = Path(root)
    result = run_validation(root, require_evals=False)
    skills: list[dict[str, Any]] = []
    for skill_file in sorted((root / SKILL_ROOT).glob("*/SKILL.md")):
        if skill_file.parent.name == "_audit":
            continue
        raw = read_text(skill_file)
        frontmatter, body, frontmatter_error = extract_frontmatter(raw)
        skills.append(
            {
                "folder": skill_file.parent.name,
                "name": frontmatter.get("name") or skill_file.parent.name,
                "description": frontmatter.get("description", ""),
                "body_lines": len(body.splitlines()),
                "frontmatter_error": frontmatter_error,
            }
        )
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "skills": skills,
        "validation": result,
        "paths": {
            "claude_index": str(root / CLAUDE_INDEX),
            "skill_root": str(root / SKILL_ROOT),
            "claude_skill_root": str(Path.home() / ".claude" / "skills"),
            "codex_skill_root": str(Path.home() / ".codex" / "skills"),
        },
        "resolved_paths": {
            "claude_skill_root": str((Path.home() / ".claude" / "skills").resolve()),
            "codex_skill_root": str((Path.home() / ".codex" / "skills").resolve()),
        },
    }


def print_human_summary(result: dict[str, Any]) -> None:
    print(f"Root: {result['root']}")
    print(
        f"Issues: {result['issue_count']} "
        f"({result['error_count']} errors, {result['warning_count']} warnings)"
    )
    for item in result["issues"]:
        print(f"[{item['severity']}] {item['code']}: {item['path']} - {item['message']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate local Agent Skill files.")
    subparsers = parser.add_subparsers(dest="command")
    snapshot_parser = subparsers.add_parser("snapshot", help="Capture current discovery state.")
    snapshot_parser.add_argument("--out", required=True, help="Output JSON path.")

    parser.add_argument("--root", default=str(REPO_ROOT), help="Workspace root.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("--compatibility", action="store_true", help="Run compatibility validation.")
    parser.add_argument("--no-require-evals", action="store_true", help="Do not require eval manifests.")
    parser.add_argument("--skill", help="Only report issues for one skill folder/name.")

    args = parser.parse_args(argv)
    root = Path(args.root)

    if args.command == "snapshot":
        data = snapshot_discovery(root)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(out)
        return 0

    result = run_validation(root, require_evals=not args.no_require_evals)
    if args.skill:
        result = filter_result_by_skill(result, args.skill)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human_summary(result)
    return 1 if result["error_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
