#!/usr/bin/env python3
"""Adversarial smoke checks for external-review packet validator."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VALIDATOR = HERE / "validate-external-review-packet.py"
TEMPLATE = ROOT / "assets" / "external-review-packet-template.md"
EXAMPLES = ROOT / "examples"
CASES = EXAMPLES / "cases"


def fixture(path: Path | None = None, inline: bool = False) -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    replacements = {
        "SHORT_TITLE": "Dispatch authoring failure",
        "ISO_8601_TIMESTAMP": "2026-07-28T20:00:00+05:30",
        "THIRD_PARTY_AGENT_OR_REVIEWER": "MiniMax and Qwen reviewers",
        "ABSOLUTE_PATH_OR_INLINE": "INLINE" if inline else str(path.resolve()),
        "DIAGNOSIS_DESIGN_REWRITE_OR_REVIEW": "Diagnose and propose enforceable repair",
        "SIMPLE_CONTEXT_COMPLETE_PROBLEM_DESCRIPTION": "Agent produced readable dispatch but omitted executable recovery and durable audit artifact.",
        "USER_WORDS_VERBATIM": "Build a dummy-proof dispatch skill that a zero-context agent can execute end to end.",
        "CONCRETE_END_STATE": "Every dispatch is durable, executable, validated, and recoverable.",
        "OBSERVABLE_SUCCESS_CRITERIA": "Fresh agent completes or returns evidence-backed TRUE_BLOCKER after bounded recovery.",
        "FAILURE": "Temporary-only dispatch",
        "RAW_ERROR_QUOTE_OR_ARTIFACT_EXCERPT": "I used a temporary validation file.",
        "IMPACT": "No canonical task record exists for audit or replay.",
        "MINIMUM_ARCHITECTURE_WORKFLOW_OR_DOCUMENT_STATE_NEEDED_TO_REASON_CORRECTLY": "Orchestrator authors task packet, validates it, sends it to smaller executor, observes work, and verifies evidence.",
        "MUST_PRESERVE": "Dispatch and handoff remain independent skills.",
        "MUST_NOT_DO": "Do not run Council in packet-only mode.",
        "AUTHORITY_OR_SAFETY_BOUNDARY": "No secrets, deployment, or destructive actions.",
        "ATTEMPT_OR_OTHER_AGENT_PROPOSAL": "Prose checklist",
        "OBSERVED_RESULT": "Readable packet still allowed temporary-only storage and silent inference.",
        "DISPOSITION_OR_OPEN": "Keep intent; replace prose-only requests with validator gates.",
        "EVIDENCE": "Observed statement: I used a temporary validation file. Required correction: canonical named Markdown plus adjacent receipt before any agent receives task.",
        "UNKNOWN_AND_WHY_IT_MATTERS_OR_NONE": "NONE — failure and desired contract are explicit.",
    }
    for key, value in replacements.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def run(text: str, inline: bool = False) -> subprocess.CompletedProcess[str]:
    CASES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=CASES) as directory:
        packet = Path(directory).resolve() / "packet.md"
        bound = re.sub(
            r"(?m)^- \*\*Packet path:\*\* .*$",
            lambda _: f"- **Packet path:** {'INLINE' if inline else packet}",
            text,
        )
        packet.write_text(bound, encoding="utf-8")
        command = [sys.executable, str(VALIDATOR), str(packet)]
        if inline:
            command.append("--inline")
        return subprocess.run(command, check=False, capture_output=True, text=True)


def main() -> int:
    spec = importlib.util.spec_from_file_location("council_packet_validator", VALIDATOR)
    assert spec and spec.loader
    validator_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator_module)
    assert validator_module.normalized(
        "/Volumes/D/Claude/Packet.md", "posix"
    ) != validator_module.normalized(
        "/Volumes/D/Claude/packet.md", "posix"
    )

    template = subprocess.run(
        [sys.executable, str(VALIDATOR), str(TEMPLATE), "--template-self-check"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert template.returncode == 0, template.stdout + template.stderr

    seed_path = (EXAMPLES / "seed.md").resolve()
    good = fixture(seed_path)
    assert run(good).returncode == 0
    assert run(fixture(inline=True), inline=True).returncode == 0

    wrong_mode = run(good.replace("PACKET_ONLY — DO_NOT_RUN_COUNCIL", "RUN_COUNCIL", 1))
    assert wrong_mode.returncode == 1 and "Mode must be" in wrong_mode.stdout

    weak_evidence = re.sub(
        r"```text\n.+?\n```",
        "```text\nthin\n```",
        good,
        count=1,
        flags=re.S,
    )
    assert "substantive embedded evidence" in run(weak_evidence).stdout

    shortcut = run(good.replace(
        "Agent produced readable dispatch",
        "As discussed, agent produced readable dispatch",
        1,
    ))
    assert shortcut.returncode == 1 and "old-context dependency" in shortcut.stdout

    prior_context = run(good.replace(
        "Agent produced readable dispatch",
        "Use prior-thread context; agent produced readable dispatch",
        1,
    ))
    assert prior_context.returncode == 1
    assert "old-context dependency" in prior_context.stdout

    bearer = run(good.replace(
        "No secrets, deployment, or destructive actions.",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        1,
    ))
    assert bearer.returncode == 1
    assert "possible secret detected" in bearer.stdout

    markdown_secret = run(good.replace(
        "No secrets, deployment, or destructive actions.",
        "token: `abcdefghijklmnopqrstuv`",
        1,
    ))
    assert markdown_secret.returncode == 1
    assert "possible secret detected" in markdown_secret.stdout

    slack_secret = run(good.replace(
        "No secrets, deployment, or destructive actions.",
        "xoxb-" + "1" * 40,
        1,
    ))
    assert slack_secret.returncode == 1
    assert "possible secret detected" in slack_secret.stdout

    prior_session = run(good.replace(
        "Agent produced readable dispatch",
        "Read earlier messages before reviewing; agent produced readable dispatch",
        1,
    ))
    assert prior_session.returncode == 1
    assert "old-context dependency" in prior_session.stdout

    cache_packet = (EXAMPLES / "cache" / "packet.md").resolve()
    cache_errors = validator_module.validate(
        fixture(cache_packet), cache_packet, inline=False
    )
    assert any("temporary/cache/review-run storage" in error for error in cache_errors)

    validator_packet = (EXAMPLES / ".validator-case" / "packet.md").resolve()
    validator_errors = validator_module.validate(
        fixture(validator_packet), validator_packet, inline=False
    )
    assert any("temporary/cache/review-run storage" in error for error in validator_errors)

    with tempfile.TemporaryDirectory() as directory:
        packet = Path(directory).resolve() / "packet.md"
        packet.write_text(fixture(packet), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "temporary/cache/review-run storage" in result.stdout

    print("PASS: Council packet validator accepts Markdown/inline briefs + rejects review mode, weak evidence, old-context, and temporary-storage bypasses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
