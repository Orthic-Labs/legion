#!/usr/bin/env python3
"""Adversarial smoke checks for validate-handoff.py."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VALIDATOR = HERE / "validate-handoff.py"
TEMPLATE = ROOT / "assets" / "handoff-template.md"
EXAMPLES = ROOT / "examples"
CASES = EXAMPLES / "cases"


def bind_paths(
    text: str, path: Path, receipt: Path, bind_commands: bool = True
) -> str:
    text = re.sub(
        r"(?m)^- \*\*Packet path:\*\* .*$",
        lambda _: f"- **Packet path:** {path.resolve()}",
        text,
    )
    text = re.sub(
        r"(?m)^- \*\*Receipt path:\*\* .*$",
        lambda _: f"- **Receipt path:** {receipt.resolve()}",
        text,
    )
    if not bind_commands:
        return text
    text = re.sub(
        r"(- \*\*Validator command:\*\*\s*```[^\n]*\n).*?(\n```)",
        lambda match: (
            match.group(1)
            + f"{sys.executable} {VALIDATOR} {path.resolve()} --write-receipt {receipt.resolve()}"
            + match.group(2)
        ),
        text,
        count=1,
        flags=re.S,
    )
    return re.sub(
        r"(- \*\*Receiver receipt check:\*\*\s*```[^\n]*\n).*?(\n```)",
        lambda match: (
            match.group(1)
            + f"{sys.executable} {VALIDATOR} {path.resolve()} --verify-receipt {receipt.resolve()}"
            + match.group(2)
        ),
        text,
        count=1,
        flags=re.S,
    )


def run(
    text: str, bind_commands: bool = True
) -> subprocess.CompletedProcess[str]:
    CASES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=CASES) as directory:
        path = Path(directory).resolve() / "handoff-case.md"
        receipt = path.with_name("handoff-case.receipt.json")
        path.write_text(
            bind_paths(text, path, receipt, bind_commands=bind_commands),
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(path),
                "--write-receipt",
                str(receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
        )


def fixture() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")

    def replacement(match: re.Match[str]) -> str:
        token = match.group(0)[2:-2]
        exact = {
            "READY_OR_READY_WITH_GAPS_OR_NOT_READY": "READY",
            "IMMEDIATE_OR_READBACK_ONLY_OR_REVIEW_ONLY_OR_DECISION": "IMMEDIATE",
            "CODE_DOCUMENT_RESEARCH_OPERATIONS_OR_MIXED": "CODE",
            "LOCKED_ACTIVE_ASSUMPTION_OR_REVISIT_ON": "LOCKED",
            "FATAL_HIGH_MEDIUM_LOW_OR_NONE": "NONE",
            "GAP_OR_NONE_CHECKED": "NONE_CHECKED — context complete",
            "NONE_OR_COUNT_BY_SEVERITY": "NONE — context checked complete",
            "TRANSCRIPT_INGEST_OR_LIVE_CONTEXT": "LIVE_CONTEXT",
            "ABSOLUTE_COMPILED_EVIDENCE_PATH_OR_NOT_APPLICABLE_REASON": "NOT_APPLICABLE: packet authored from current live context",
            "PLATFORM_SESSION_ID_CUTOFF_SHA256_PARSER_VERSION_OR_NOT_APPLICABLE_REASON": "NOT_APPLICABLE: packet authored from current live context",
        }
        if token in exact:
            return exact[token]
        if "TIMESTAMP" in token:
            return "2026-07-28T18:00:00+05:30"
        if any(word in token for word in ("PATH", "LOCATION", "DIRECTORY", "WORKSPACE", "REPO")):
            return "D:/workspace/artifacts/handoff-evidence.log"
        if any(word in token for word in ("COMMAND", "ACTION", "OPERATION", "CHECK", "VALIDATION", "RELOAD", "SEQUENCE")):
            return "Run Get-Item -LiteralPath D:/workspace/artifacts/handoff-evidence.log"
        if "NUMERIC_BOUND" in token:
            return "2 attempts within 30 seconds"
        if "OWNER" in token or "AUTHOR" in token:
            return "cold-chat owner"
        if "SHA" in token or "VERSION" in token or "REVISION" in token:
            return "sha256:0123456789abcdef checked 2026-07-28T18:00:00+05:30"
        if "USER_WORDS" in token:
            return "Build a zero-memory handoff that transfers exact context."
        if "EXACT_RESULT" in token or "OBSERVABLE_RESULT" in token:
            return "command exits 0 and D:/workspace/artifacts/handoff-evidence.log exists"
        if "EVIDENCE" in token:
            return "D:/workspace/artifacts/handoff-evidence.log"
        if "CONDITION" in token:
            return "Only when user changes locked objective in writing"
        if "NONE" in token:
            return "NONE_CHECKED — no applicable item after live inventory"
        return "documented exact cold-start context"

    text = re.sub(r"\{\{[^{}\n]+\}\}", replacement, text)
    return text.replace("- [ ]", "- [x]")


def main() -> int:
    spec = importlib.util.spec_from_file_location("handoff_validator", VALIDATOR)
    assert spec and spec.loader
    validator_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator_module)
    assert validator_module.normalized_path(
        "/Volumes/D/Claude/Packet.md", "posix"
    ) != validator_module.normalized_path(
        "/Volumes/D/Claude/packet.md", "posix"
    )

    template = subprocess.run(
        [sys.executable, str(VALIDATOR), str(TEMPLATE), "--template-self-check"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert template.returncode == 0, template.stdout + template.stderr

    good = fixture()
    passed = run(good)
    assert passed.returncode == 0, passed.stdout + passed.stderr

    fatal_ready = run(good.replace(
        "| NONE_CHECKED — context complete | NONE |",
        "| Missing private dataset | FATAL |",
    ))
    assert fatal_ready.returncode == 1
    assert "READY cannot contain FATAL" in fatal_ready.stdout

    fatal_ready_with_gaps = run(good.replace(
        "**Readiness:** READY",
        "**Readiness:** READY_WITH_GAPS",
    ).replace(
        "| NONE_CHECKED — context complete | NONE |",
        "| Missing private dataset | FATAL |",
    ))
    assert fatal_ready_with_gaps.returncode == 1
    assert "READY_WITH_GAPS cannot contain FATAL" in fatal_ready_with_gaps.stdout

    shortcut = run(good.replace(
        "**Current objective:** documented exact cold-start context",
        "**Current objective:** continue where we left off",
    ))
    assert shortcut.returncode == 1
    assert "orphan continuation" in shortcut.stdout

    secret = run(good.replace(
        "**Credentials / access:** documented exact cold-start context",
        "**Credentials / access:** token=abcdefghijklmnopqrstuv",
    ))
    assert secret.returncode == 1
    assert "possible secret detected" in secret.stdout

    bearer = run(good.replace(
        "**Credentials / access:** documented exact cold-start context",
        "**Credentials / access:** Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    ))
    assert bearer.returncode == 1
    assert "possible secret detected" in bearer.stdout

    markdown_secret = run(good.replace(
        "**Credentials / access:** documented exact cold-start context",
        "**Credentials / access:** token : `abcdefghijklmnopqrstuv`",
    ))
    assert markdown_secret.returncode == 1
    assert "possible secret detected" in markdown_secret.stdout

    slack_secret = run(good.replace(
        "**Credentials / access:** documented exact cold-start context",
        "**Credentials / access:** xoxb-" + "1" * 40,
    ))
    assert slack_secret.returncode == 1
    assert "possible secret detected" in slack_secret.stdout

    prior_context = run(good.replace(
        "**Current objective:** documented exact cold-start context",
        "**Current objective:** Use prior-thread context for current branch and credentials",
    ))
    assert prior_context.returncode == 1
    assert "old-chat dependency" in prior_context.stdout

    prior_session = run(good.replace(
        "**Current objective:** documented exact cold-start context",
        "**Current objective:** Read old messages from prior session before resuming",
    ))
    assert prior_session.returncode == 1
    assert "old-chat dependency" in prior_session.stdout

    cache_packet = (EXAMPLES / "cache" / "handoff.md").resolve()
    cache_receipt = cache_packet.with_name("handoff.receipt.json")
    cache_errors = validator_module.storage_errors(
        bind_paths(good, cache_packet, cache_receipt),
        cache_packet,
        cache_receipt,
        None,
    )
    assert any("temporary/cache/review-run storage" in error for error in cache_errors)

    validator_packet = (EXAMPLES / ".validator-case" / "handoff.md").resolve()
    validator_receipt = validator_packet.with_name("handoff.receipt.json")
    validator_errors = validator_module.storage_errors(
        bind_paths(good, validator_packet, validator_receipt),
        validator_packet,
        validator_receipt,
        None,
    )
    assert any("temporary/cache/review-run storage" in error for error in validator_errors)

    prose_receipt = run(re.sub(
        r"(- \*\*Receiver receipt check:\*\*\s*```[^\n]*\n).*?(\n```)",
        r"\1verify receipt per team process\2",
        good,
        count=1,
        flags=re.S,
    ), bind_commands=False)
    assert prose_receipt.returncode == 1
    assert "Receiver receipt check must execute" in prose_receipt.stdout

    unchecked = run(good.replace("- [x]", "- [ ]", 1))
    assert unchecked.returncode == 1
    assert "unchecked item" in unchecked.stdout

    weak_text = re.sub(
        r"(### Resume Step 1.*?\*\*Exact action:\*\*\s*```text\n).*?(\n```)",
        r"\1think about it\2",
        good,
        count=1,
        flags=re.S,
    )
    weak_resume = run(weak_text)
    assert weak_resume.returncode == 1

    malformed = run(good.replace(
        "| documented exact cold-start context | documented exact cold-start context |",
        "| malformed |",
        1,
    ))
    assert malformed.returncode == 1
    assert "row 1 must contain" in malformed.stdout

    with tempfile.TemporaryDirectory(prefix="case-", dir=CASES) as directory:
        packet = Path(directory).resolve() / "handoff.md"
        receipt = Path(directory).resolve() / "handoff.receipt.json"
        bound_good = bind_paths(good, packet, receipt)
        packet.write_bytes(bound_good.encode("utf-8"))
        neither = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet)],
            check=False, capture_output=True, text=True,
        )
        assert neither.returncode == 1
        assert "exactly one receipt mode is required" in neither.stdout
        dual = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(packet),
                "--write-receipt",
                str(receipt),
                "--verify-receipt",
                str(receipt),
            ],
            check=False, capture_output=True, text=True,
        )
        assert dual.returncode == 2
        written = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--write-receipt", str(receipt)],
            check=False, capture_output=True, text=True,
        )
        assert written.returncode == 0, written.stdout + written.stderr
        verified = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--verify-receipt", str(receipt)],
            check=False, capture_output=True, text=True,
        )
        assert verified.returncode == 0

        alternate = Path(directory).resolve() / "alternate" / "handoff.receipt.json"
        alternate.parent.mkdir()
        alternate.write_bytes(receipt.read_bytes())
        nonadjacent = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--verify-receipt", str(alternate)],
            check=False, capture_output=True, text=True,
        )
        assert nonadjacent.returncode == 1
        assert "receipt must be adjacent" in nonadjacent.stdout

        wrong_declared = bound_good.replace(
            f"- **Receipt path:** {receipt}",
            f"- **Receipt path:** {packet.with_name('wrong.receipt.json')}",
        )
        packet.write_bytes(wrong_declared.encode("utf-8"))
        mismatched_declared = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--verify-receipt", str(receipt)],
            check=False, capture_output=True, text=True,
        )
        assert mismatched_declared.returncode == 1
        assert "declared receipt path does not match" in mismatched_declared.stdout

        packet.write_bytes(bound_good.replace("\n", "\r\n").encode("utf-8"))
        newline_tampered = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--verify-receipt", str(receipt)],
            check=False, capture_output=True, text=True,
        )
        assert newline_tampered.returncode == 1
        assert "bytes do not match receipt" in newline_tampered.stdout

        packet.write_bytes((bound_good + "\nchanged").encode("utf-8"))
        tampered = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--verify-receipt", str(receipt)],
            check=False, capture_output=True, text=True,
        )
        assert tampered.returncode == 1
        assert "do not match receipt" in tampered.stdout

    with tempfile.TemporaryDirectory() as directory:
        packet = Path(directory).resolve() / "handoff.md"
        receipt = Path(directory).resolve() / "handoff.receipt.json"
        packet.write_text(bind_paths(good, packet, receipt), encoding="utf-8")
        temporary = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--write-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert temporary.returncode == 1
        assert "temporary/cache/review-run storage" in temporary.stdout

    transcript_good = good.replace(
        "**Source evidence mode:** LIVE_CONTEXT",
        "**Source evidence mode:** TRANSCRIPT_INGEST",
        1,
    ).replace(
        "**Transcript evidence path:** NOT_APPLICABLE: packet authored from current live context",
        "**Transcript evidence path:** D:/workspace/tasks/handoffs/source.evidence.json",
        1,
    ).replace(
        "**Source prefix receipt:** NOT_APPLICABLE: packet authored from current live context",
        "**Source prefix receipt:** PLATFORM:codex; SESSION_ID:thread-123; CUTOFF_BYTES:42; SHA256:"
        + "a" * 64
        + "; PARSER_VERSION:handoff.transcript.v1",
        1,
    )
    transcript_result = run(transcript_good)
    assert transcript_result.returncode == 0, transcript_result.stdout + transcript_result.stderr

    raw_unbound = run(
        transcript_good.replace(
            "CUTOFF_BYTES:42; SHA256:" + "a" * 64,
            "CUTOFF_BYTES:0; SHA256:unknown",
            1,
        )
    )
    assert raw_unbound.returncode == 1
    assert "positive cutoff" in raw_unbound.stdout
    assert "64-hex SHA256" in raw_unbound.stdout

    print("PASS: handoff validator accepts durable live/compiled packets + rejects readiness, source binding, secret, context, resume, table, checklist, path, temporary-storage, and receipt bypasses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
