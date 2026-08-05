#!/usr/bin/env python3
"""Local security scan for Adrian's skill libraries.

The scanner is intentionally deterministic and offline. It looks for harmful
instructions and operational risks in skill text/scripts:

- committed secret literals and private-key blocks
- curl/wget/iwr/irm piped into shells or Invoke-Expression
- prompt-injection-style instructions inside skills
- destructive shell guidance
- remote code/dependency install guidance
- unusually link-heavy skills

It is not a substitute for gitleaks or Semgrep on application repos. It is a
fast safety pass for the local skill layer itself.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path("D:/Claude")
AUDIT_DIR = REPO_ROOT / "tools/skills/_audit"
REPORT_DIR = AUDIT_DIR / "security-reports"

DEFAULT_ROOTS = [
    Path("D:/Claude/tools/skills"),
    Path("C:/Users/adrds/.agents/skills"),
    Path("D:/Claude/.agents/skills"),
]

PLUGIN_CACHE_ROOTS = [
    Path("C:/Users/adrds/.codex/plugins/cache"),
]

TEXT_SUFFIXES = {
    ".bat",
    ".cjs",
    ".cmd",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

SKIP_DIRS = {
    ".cache",
    ".agents",
    ".factory",
    ".git",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "model-eval-runs",
    "node_modules",
    "out",
    "security-reports",
    "site-packages",
    "snapshots",
    "venv",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Rule:
    code: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    recommendation: str


@dataclass
class Finding:
    severity: str
    code: str
    root: str
    skill: str
    path: str
    line: int
    message: str
    evidence: str
    recommendation: str


RULES = [
    Rule(
        "PRIVATE_KEY_LITERAL",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.I),
        "Private-key material appears in skill files.",
        "Remove the key, rotate it if real, and keep only secret-free placeholders.",
    ),
    Rule(
        "OPENAI_KEY_LITERAL",
        "critical",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "OpenAI-style API key literal appears in skill files.",
        "Remove the value, rotate it if real, and reference an environment variable instead.",
    ),
    Rule(
        "GITHUB_TOKEN_LITERAL",
        "critical",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
        "GitHub token literal appears in skill files.",
        "Remove the value, rotate it if real, and keep only a redacted example.",
    ),
    Rule(
        "SLACK_TOKEN_LITERAL",
        "critical",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "Slack token literal appears in skill files.",
        "Remove the value, rotate it if real, and keep only a redacted example.",
    ),
    Rule(
        "AWS_ACCESS_KEY_LITERAL",
        "critical",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key literal appears in skill files.",
        "Remove the value, rotate it if real, and keep only a redacted example.",
    ),
    Rule(
        "GENERIC_SECRET_ASSIGNMENT",
        "high",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|token|client_secret|private_key)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
        ),
        "Hardcoded secret-like assignment appears in skill files.",
        "Replace with a placeholder or an environment/config reference.",
    ),
    Rule(
        "PIPE_TO_SHELL",
        "high",
        re.compile(
            r"(?i)\b(curl|wget|irm|iwr|invoke-webrequest|invoke-restmethod)\b[^\n|;]*"
            r"\|\s*(sh|bash|zsh|iex|invoke-expression)\b"
        ),
        "Remote content is piped directly into a shell/evaluator.",
        "Download, inspect, pin/checksum, and run explicitly only when trusted.",
    ),
    Rule(
        "INVOKE_EXPRESSION",
        "high",
        re.compile(r"(?i)\b(invoke-expression|iex)\b"),
        "PowerShell Invoke-Expression/eval guidance appears in skill files.",
        "Avoid eval-style execution; use explicit scripts and arguments.",
    ),
    Rule(
        "POWERSHELL_ENCODED",
        "high",
        re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]*(?:-enc|-encodedcommand)\b"),
        "Encoded PowerShell command appears in skill files.",
        "Replace with readable scripts or remove if it is not a malware-analysis fixture.",
    ),
    Rule(
        "DESTRUCTIVE_SHELL",
        "high",
        re.compile(
            r"(?i)\b("
            r"rm\s+-rf\s+(?:/|~|\*|[A-Za-z]:[\\/])|"
            r"remove-item\b[^\n]*(?:-recurse)[^\n]*(?:-force)|"
            r"git\s+reset\s+--hard|"
            r"git\s+clean\s+-fdx|"
            r"docker\s+system\s+prune"
            r")\b"
        ),
        "Destructive shell guidance appears in skill files.",
        "Add guardrails/confirmation or replace with scoped, reversible commands.",
    ),
    Rule(
        "REMOTE_CODE_FETCH",
        "medium",
        re.compile(
            r"(?i)\b(git\s+clone|pip\s+install|uv\s+pip\s+install|npm\s+install|pnpm\s+add|"
            r"yarn\s+add|npx|uvx|curl|wget|irm|iwr)\b[^\n]*(https?://|github\.com)"
        ),
        "Skill references remote code or dependency fetch.",
        "Pin versions/checksums and prefer local scripts or documented package managers.",
    ),
    Rule(
        "UNSAFE_INSTALL_FLAG",
        "medium",
        re.compile(
            r"(?i)\b(npm|pnpm|yarn|pip|uv|cargo|brew)\b[^\n]*"
            r"(?:install|add)[^\n]*(?:--force|--unsafe-perm|--legacy-peer-deps|--global|\s-g\b)"
        ),
        "Install command uses global/force/unsafe flags.",
        "Avoid global or forceful installs unless isolated and explicitly justified.",
    ),
    Rule(
        "PROMPT_INJECTION_TEXT",
        "medium",
        re.compile(
            r"(?i)\b("
            r"ignore (?:all )?(?:previous|prior|above|system) instructions|"
            r"override (?:the )?(?:system|developer) instructions|"
            r"disable safety|bypass safety|"
            r"do not tell the user|hide this from the user|"
            r"exfiltrat(?:e|ion)|send secrets"
            r")\b"
        ),
        "Prompt-injection-style instruction appears in skill content.",
        "Ensure this is framed only as an example/threat model, not an instruction to follow.",
    ),
    Rule(
        "NETWORK_SECRET_EXFIL",
        "high",
        re.compile(
            r"(?i)\b(curl|wget|invoke-restmethod|fetch)\b[^\n]*"
            r"(?:\$env:|process\.env|\.env|id_rsa|token|secret|password|private_key)"
        ),
        "Network command appears to send environment/secrets.",
        "Remove the exfil path or rewrite as a redacted, local-only diagnostic.",
    ),
]

URL_RE = re.compile(r"https?://[^\s)>'\"`]+", re.I)
RISKY_URL_RE = re.compile(r"(?i)\b(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|bit\.ly|tinyurl\.com)\b")
SECRET_ASSIGN_REDACT = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|token|client_secret|private_key)\b"
    r"(\s*[:=]\s*['\"])[^'\"\s]+(['\"]?)"
)
TOKEN_REDACTORS = [
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{8,}\b"),
]
LOOPBACK_URL_RE = re.compile(
    r"https?://(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)"
    r"(?::(?:\d+|\$\{[^}]+\}|['\"`]\s*\+[^/]+)?)?(?:/|\?|['\"`]|\s*\+|$)",
    re.I,
)
LOOPBACK_BASE_RE = re.compile(r"\b(?:const|let|var)\s+base\s*=\s*`?['\"]?http://localhost", re.I)
REMOTE_CODE_TOOL_RE = re.compile(
    r"(?i)\b(git\s+clone|pip\s+install|uv\s+pip\s+install|npm\s+install|pnpm\s+add|"
    r"yarn\s+add)\b"
)
REMOTE_CODE_CURL_RE = re.compile(
    r"(?i)\b(curl|wget|irm|iwr)\b[^\n]*"
    r"(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|"
    r"github\.com|"
    r"\.(?:sh|bash|zsh|ps1|py|js|mjs|zip|tar|tgz|gz|exe|pkg|dmg|deb|rpm)\b|"
    r"\s(?:-o|-O|--output-document)\b)"
)
REMOTE_CODE_NPX_RE = re.compile(r"(?i)\bnpx\b\s+(?:https?://|github:|github\.com/)")
BENIGN_PROMPT_SAFETY_RE = re.compile(
    r"(?i)(must not contain malware|never send secrets|do not tell the user to run|"
    r"stays advisory|advisory|threat model|malicious skills)"
)


def redact(line: str) -> str:
    line = SECRET_ASSIGN_REDACT.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>{m.group(3)}", line)
    for pattern in TOKEN_REDACTORS:
        line = pattern.sub("<redacted-token>", line)
    line = line.strip()
    if len(line) > 220:
        line = line[:217] + "..."
    return line


def default_roots(include_plugin_cache: bool) -> list[Path]:
    roots = list(DEFAULT_ROOTS)
    if include_plugin_cache:
        roots.extend(PLUGIN_CACHE_ROOTS)
    return roots


def existing_unique_roots(roots: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            resolved = str(root.resolve()).lower()
        except Exception:
            resolved = str(root).lower()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(root)
    return result


def iter_text_files(root: Path) -> Iterable[Path]:
    scanner_path = Path(__file__).resolve()
    for path in root.rglob("*"):
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.resolve() == scanner_path:
                continue
        except Exception:
            pass
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        yield path


def skill_for(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return "_unknown"
    if not rel.parts:
        return "_root"
    return rel.parts[0]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def is_loopback_network_line(line: str) -> bool:
    return bool(LOOPBACK_URL_RE.search(line))


def is_remote_code_fetch_line(line: str) -> bool:
    if REMOTE_CODE_TOOL_RE.search(line) and re.search(r"(?i)(https?://|github\.com|git\+)", line):
        return True
    if REMOTE_CODE_NPX_RE.search(line):
        return True
    if REMOTE_CODE_CURL_RE.search(line):
        return True
    return False


def scan_file(root: Path, path: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    try:
        text = read_text(path)
    except Exception:
        return findings, []

    skill = skill_for(root, path)
    rel = str(path)
    urls = URL_RE.findall(text)
    has_loopback_base = bool(LOOPBACK_BASE_RE.search(text))

    for line_no, line in enumerate(text.splitlines(), 1):
        if "skill-security-scan: allow" in line:
            continue
        for rule in RULES:
            if rule.code == "PRIVATE_KEY_LITERAL" and ("..." in line or "<redacted>" in line.lower()):
                continue
            if rule.code == "NETWORK_SECRET_EXFIL" and (is_loopback_network_line(line) or (has_loopback_base and "${base}" in line)):
                continue
            if rule.code == "REMOTE_CODE_FETCH" and not is_remote_code_fetch_line(line):
                continue
            if rule.code == "PROMPT_INJECTION_TEXT" and BENIGN_PROMPT_SAFETY_RE.search(line):
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        severity=rule.severity,
                        code=rule.code,
                        root=str(root),
                        skill=skill,
                        path=rel,
                        line=line_no,
                        message=rule.message,
                        evidence=redact(line),
                        recommendation=rule.recommendation,
                    )
                )
        for url in URL_RE.findall(line):
            if RISKY_URL_RE.search(url):
                findings.append(
                    Finding(
                        severity="medium",
                        code="RISKY_EXTERNAL_URL",
                        root=str(root),
                        skill=skill,
                        path=rel,
                        line=line_no,
                        message="Skill links to raw/shortened/paste-style external content.",
                        evidence=redact(line),
                        recommendation="Prefer local references or stable official documentation; avoid raw executable snippets.",
                    )
                )
    return findings, urls


def scan_roots(roots: list[Path], max_urls_per_skill: int) -> dict:
    findings: list[Finding] = []
    files_scanned = 0
    url_counts: dict[tuple[str, str], set[str]] = defaultdict(set)
    first_skill_path: dict[tuple[str, str], Path] = {}

    for root in roots:
        for path in iter_text_files(root):
            files_scanned += 1
            file_findings, urls = scan_file(root, path)
            findings.extend(file_findings)
            skill = skill_for(root, path)
            key = (str(root), skill)
            first_skill_path.setdefault(key, path)
            url_counts[key].update(urls)

    for (root, skill), urls in sorted(url_counts.items()):
        if len(urls) > max_urls_per_skill:
            path = first_skill_path[(root, skill)]
            findings.append(
                Finding(
                    severity="low",
                    code="LINK_HEAVY_SKILL",
                    root=root,
                    skill=skill,
                    path=str(path),
                    line=1,
                    message=f"Skill contains {len(urls)} unique external URLs.",
                    evidence=f"{len(urls)} unique URLs",
                    recommendation="Move volatile/link-heavy context into local references or cite only stable primary docs.",
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.root.lower(), f.skill.lower(), f.path.lower(), f.line, f.code))
    counts = Counter(f.severity for f in findings)
    code_counts = Counter(f.code for f in findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": [str(root) for root in roots],
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "counts_by_severity": dict(sorted(counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 9))),
        "counts_by_code": dict(code_counts.most_common()),
        "findings": [asdict(f) for f in findings],
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Skill Security Scan",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Files scanned: `{report['files_scanned']}`",
        f"- Findings: `{report['findings_count']}`",
        f"- Roots: {', '.join(f'`{root}`' for root in report['roots'])}",
        "",
        "## Severity",
        "",
    ]
    if report["counts_by_severity"]:
        for severity, count in report["counts_by_severity"].items():
            lines.append(f"- `{severity}`: {count}")
    else:
        lines.append("- No findings.")

    lines.extend(["", "## Finding Types", ""])
    for code, count in report["counts_by_code"].items():
        lines.append(f"- `{code}`: {count}")

    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Code | Skill | Location | Evidence | Recommendation |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for finding in report["findings"]:
        evidence = str(finding["evidence"]).replace("|", "\\|")
        recommendation = str(finding["recommendation"]).replace("|", "\\|")
        location = f"{finding['path']}:{finding['line']}".replace("|", "\\|")
        lines.append(
            f"| {finding['severity']} | `{finding['code']}` | `{finding['skill']}` | "
            f"`{location}` | {evidence} | {recommendation} |"
        )
    return "\n".join(lines) + "\n"


def write_reports(report: dict, out_json: Path | None, out_md: Path | None) -> tuple[Path, Path]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if out_json is None:
        out_json = REPORT_DIR / f"skill-security-{ts}.json"
    if out_md is None:
        out_md = REPORT_DIR / f"skill-security-{ts}.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    return out_json, out_md


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan local skill libraries for security/safety hazards.")
    parser.add_argument("--roots", nargs="*", type=Path, help="Skill roots to scan. Defaults to local skill roots.")
    parser.add_argument("--include-plugin-cache", action="store_true", help="Also scan cached third-party/bundled plugin skills.")
    parser.add_argument("--max-urls-per-skill", type=int, default=12)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--json", action="store_true", help="Print the full JSON report to stdout.")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit non-zero if any finding at this severity or higher exists.",
    )
    return parser.parse_args(argv)


def should_fail(report: dict, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for severity, count in report["counts_by_severity"].items():
        if count and SEVERITY_ORDER.get(severity, 99) <= threshold:
            return True
    return False


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    roots = args.roots if args.roots else default_roots(args.include_plugin_cache)
    roots = existing_unique_roots(roots)
    if not roots:
        sys.stderr.write("No existing skill roots found.\n")
        return 2

    report = scan_roots(roots, args.max_urls_per_skill)
    json_path, md_path = write_reports(report, args.out_json, args.out_md)

    if args.json:
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    else:
        counts = report["counts_by_severity"]
        severity_summary = ", ".join(f"{severity}={count}" for severity, count in counts.items()) or "none"
        sys.stdout.write(
            f"Scanned {report['files_scanned']} files across {len(roots)} roots. "
            f"Findings: {report['findings_count']} ({severity_summary}).\n"
            f"JSON: {json_path}\n"
            f"Markdown: {md_path}\n"
        )

    return 1 if should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
