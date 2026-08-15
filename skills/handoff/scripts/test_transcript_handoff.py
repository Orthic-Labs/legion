#!/usr/bin/env python3
"""Deterministic tests for transcript-handoff.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "transcript-handoff.py"


def load_module():
    spec = importlib.util.spec_from_file_location("transcript_handoff", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> bytes:
    raw = b"".join(
        (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
        for row in rows
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def main() -> int:
    module = load_module()
    with tempfile.TemporaryDirectory(prefix="handoff-transcript-") as directory:
        root = Path(directory)
        codex = (
            root / ".codex" / "sessions" / "2026" / "07" / "28"
            / "rollout-test-thread.jsonl"
        )
        rows = [
            {
                "type": "session_meta",
                "timestamp": "2026-07-28T10:00:00Z",
                "payload": {
                    "id": "test-thread",
                    "cwd": "D:\\Claude",
                    "originator": "codex_desktop",
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:01Z",
                "payload": {
                    "type": "message",
                    "role": "developer",
                    "content": [{"type": "input_text", "text": "hidden control"}],
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:02Z",
                "payload": {
                    "type": "reasoning",
                    "encrypted_content": "private chain",
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:03Z",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{
                        "type": "input_text",
                        "text": "Fix route. api_key=abcdefghijklmnop",
                    }],
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:04Z",
                "payload": {
                    "type": "function_call",
                    "name": "shell_command",
                    "call_id": "call-1",
                    "arguments": "{\"command\":\"git status\"}",
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:05Z",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "call-1",
                    "output": "Exit code: 0\nM file.txt",
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:06Z",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": "Current state: route fixed.",
                    }],
                },
            },
            {
                "type": "response_item",
                "timestamp": "2026-07-28T10:00:06Z",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": "Current state: route fixed.",
                    }],
                },
            },
            {
                "type": "event_msg",
                "payload": {"type": "token_count", "info": {"total": 999999}},
            },
        ]
        raw = write_jsonl(codex, rows)
        codex.write_bytes(raw + b'{"type":')
        digest = hashlib.sha256(raw).hexdigest()

        pointer = module.build_pointer(
            "codex", "test-thread", "D:\\Claude", root
        )
        assert pointer["session_id"] == "test-thread"
        assert pointer["cutoff_bytes"] == len(raw)
        assert pointer["sha256"] == digest
        assert pointer["last_complete_row"] == len(rows)
        prompt = module.paste_prompt(pointer)
        assert "TRANSCRIPT_INGEST" in prompt
        assert "Do not load raw transcript into model context" in prompt
        assert "test-thread" in prompt and digest in prompt
        mac_prompt = module.paste_prompt({
            **pointer,
            "platform": "claude",
            "workspace": "/workspace",
            "source_path": "/Users/test/.claude/projects/p/claude-test.jsonl",
        })
        assert mac_prompt.startswith("You are target chat")
        assert 'python3 "/workspace/legion/lib/handoff/transcript-handoff.py"' in mac_prompt

        output = root / "evidence.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "compile",
                "--platform",
                "codex",
                "--session-id",
                "test-thread",
                "--source-path",
                str(codex),
                "--cutoff-bytes",
                str(len(raw)),
                "--sha256",
                digest,
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        evidence = json.loads(output.read_text(encoding="utf-8"))
        kinds = [event["kind"] for event in evidence["events"]]
        joined = json.dumps(evidence)
        assert kinds == [
            "user_message",
            "tool_call",
            "tool_result",
            "assistant_message",
        ]
        assert evidence["stats"]["duplicates_dropped"] == 1
        assert "[REDACTED]" in joined
        assert "hidden control" not in joined
        assert "private chain" not in joined
        assert "999999" not in joined

        mismatch = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "compile",
                "--platform",
                "codex",
                "--session-id",
                "test-thread",
                "--source-path",
                str(codex),
                "--cutoff-bytes",
                str(len(raw)),
                "--sha256",
                "0" * 64,
                "--output",
                str(root / "bad.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert mismatch.returncode == 1
        assert "SHA-256 mismatch" in mismatch.stderr
        assert not (root / "bad.json").exists()

        claude = root / ".claude" / "projects" / "D--Claude" / "claude-test.jsonl"
        claude_raw = write_jsonl(
            claude,
            [
                {
                    "type": "user",
                    "sessionId": "claude-test",
                    "cwd": "D:\\Claude",
                    "timestamp": "2026-07-28T10:01:00Z",
                    "message": {"content": "Continue exact implementation."},
                },
                {
                    "type": "assistant",
                    "sessionId": "claude-test",
                    "cwd": "D:\\Claude",
                    "timestamp": "2026-07-28T10:01:01Z",
                    "message": {
                        "content": [
                            {"type": "thinking", "thinking": "private"},
                            {"type": "text", "text": "Implemented file."},
                            {
                                "type": "tool_use",
                                "id": "tool-1",
                                "name": "Read",
                                "input": {"file_path": "D:\\Claude\\file.txt"},
                            },
                        ]
                    },
                },
            ],
        )
        compiled = module.compile_transcript(
            claude,
            "claude",
            "claude-test",
            len(claude_raw),
            hashlib.sha256(claude_raw).hexdigest(),
        )
        assert [event["kind"] for event in compiled["events"]] == [
            "user_message",
            "assistant_message",
            "tool_call",
        ]
        assert '"thinking": "private"' not in json.dumps(compiled)

    print(
        "PASS: source pointer binds exact transcript bytes; compiler keeps observable "
        "events, excludes private/control noise, redacts secrets, & rejects hash drift"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
