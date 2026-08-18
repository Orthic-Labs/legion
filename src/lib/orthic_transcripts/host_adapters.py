"""Host adapters for Claude Code + Codex JSONL transcripts (plan 5.1).

Each adapter takes a single JSONL row and returns a list of normalized event
dicts. The events share a common shape so downstream projections can ingest
all hosts identically.

Claude Code row format (real, observed):
    {"type":"user"|"assistant", "message":{...}, "sessionId":"...", ...}
    - message.content can be a string OR a list of blocks
    - blocks: {"type":"text", "text": "..."} / {"type":"thinking",
      "thinking": "..."} / {"type":"tool_use", "id":"...", "name":"...",
      "input": {...}} (assistant only)
    - tool_results appear as the next "user" row with content list blocks
      of shape {"type":"tool_result", "tool_use_id":"...", "content":...}

Codex row format (real, observed):
    {"type":"response_item", "timestamp":"...", "payload":{...}}
    - payload.type == "message" with role + content blocks
      (input_text/output_text/text)
    - payload.type == "function_call" / "function_call_output" with call_id
    - payload.type == "reasoning" with encrypted_content — OMITTED (private
      reasoning flag)
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable


# ---- Secret redaction patterns (shared with transcript-handoff.py) ----

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)\b(password|passphrase|api[_-]?key|secret|token)\s*[:=]\s*\S{6,}"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
        r"-----END [A-Z ]*PRIVATE KEY-----"
    ),
)

BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{512,}={0,2}")


# ---- Helpers ----

def _text_blocks(content: Any, allowed: set[str]) -> list[str]:
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return []
    result: list[str] = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") not in allowed:
            continue
        text = block.get("text")
        if isinstance(text, str):
            result.append(text)
    return result


# ---- Host detection ----

def detect_host(path: Any) -> str:
    """Detect whether ``path`` is Claude Code or Codex JSONL.

    Strategy: scan the first non-empty row. Codex rows carry ``type`` in
    ``{"session_meta", "response_item", "event_msg"}`` with a nested
    ``payload``. Claude Code rows carry ``type`` in ``{"user", "assistant",
    "queue-operation"}`` with a flat ``message`` field.
    """
    from pathlib import Path
    p = Path(path)
    with p.open("rb") as handle:
        for _ in range(20):
            raw = handle.readline()
            if not raw:
                break
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(obj, dict):
                continue
            row_type = obj.get("type")
            if row_type in {"session_meta", "response_item", "event_msg"}:
                return "codex"
            if row_type in {"user", "assistant", "queue-operation"}:
                return "claude_code"
    # Final fallback — default to claude_code (matches transcript-handoff.py).
    return "claude_code"


# ---- Claude Code adapter ----

def _claude_events(obj: dict[str, Any]) -> list[dict[str, Any]]:
    row_type = obj.get("type")
    if row_type not in {"user", "assistant"}:
        # queue-operation, etc. — meta events
        if row_type in {"queue-operation", "file-history-snapshot", "summary"}:
            return [{
                "kind": "meta",
                "timestamp": obj.get("timestamp"),
                "text": str(obj.get("content") or row_type),
                "meta": True,
                "synthetic": True,
            }]
        return []

    if obj.get("isSidechain"):
        return []

    message = obj.get("message")
    if not isinstance(message, dict):
        return []

    timestamp = obj.get("timestamp")
    content = message.get("content")
    events: list[dict[str, Any]] = []

    if isinstance(content, str):
        text = content.strip()
        if text:
            events.append({
                "kind": f"{row_type}_message",
                "role": row_type,
                "timestamp": timestamp,
                "text": text,
            })
        return events

    if not isinstance(content, list):
        return []

    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text" and isinstance(block.get("text"), str):
            events.append({
                "kind": f"{row_type}_message",
                "role": row_type,
                "timestamp": timestamp,
                "text": block["text"],
            })
        elif block_type == "thinking":
            # Private reasoning block — omitted but flagged so downstream
            # projections can record the omission.
            events.append({
                "kind": "thinking",
                "role": row_type,
                "timestamp": timestamp,
                "text": "",
                "private_reasoning_omitted": True,
                "meta": True,
            })
        elif row_type == "assistant" and block_type == "tool_use":
            events.append({
                "kind": "tool_call",
                "role": "assistant",
                "timestamp": timestamp,
                "tool": str(block.get("name") or "unknown"),
                "call_id": block.get("id"),
                "text": json.dumps(block.get("input", {}), ensure_ascii=False, sort_keys=True),
                "tool_input": block.get("input", {}),
            })
        elif row_type == "user" and block_type == "tool_result":
            content_value = block.get("content", "")
            if isinstance(content_value, list):
                content_value = json.dumps(content_value, ensure_ascii=False, sort_keys=True)
            events.append({
                "kind": "tool_result",
                "role": "user",
                "timestamp": timestamp,
                "call_id": block.get("tool_use_id"),
                "text": str(content_value),
                "is_error": bool(block.get("is_error", False)),
            })
    return events


# ---- Codex adapter ----

def _codex_events(obj: dict[str, Any]) -> list[dict[str, Any]]:
    if obj.get("type") != "response_item":
        return []
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        return []
    kind = payload.get("type")
    timestamp = obj.get("timestamp")

    if kind == "message":
        role = payload.get("role")
        if role not in {"user", "assistant"}:
            return []
        blocks = _text_blocks(payload.get("content"), {"input_text", "output_text", "text"})
        text = "\n".join(blocks).strip()
        return (
            [{
                "kind": f"{role}_message",
                "role": role,
                "timestamp": timestamp,
                "text": text,
            }]
            if text
            else []
        )
    if kind in {"function_call", "custom_tool_call"}:
        name = str(payload.get("name") or payload.get("tool_name") or "unknown")
        arguments = payload.get("arguments", payload.get("input", ""))
        return [{
            "kind": "tool_call",
            "role": "assistant",
            "timestamp": timestamp,
            "tool": name,
            "call_id": payload.get("call_id"),
            "text": str(arguments),
            "tool_input": arguments,
        }]
    if kind in {"function_call_output", "custom_tool_call_output"}:
        output = payload.get("output", payload.get("content", ""))
        return [{
            "kind": "tool_result",
            "role": "user",
            "timestamp": timestamp,
            "call_id": payload.get("call_id"),
            "text": str(output),
            "is_error": bool(payload.get("is_error", False)),
        }]
    if kind == "reasoning":
        return [{
            "kind": "thinking",
            "role": "assistant",
            "timestamp": timestamp,
            "text": "",
            "private_reasoning_omitted": True,
            "meta": True,
        }]
    if kind == "event_msg":
        return [{
            "kind": "meta",
            "timestamp": timestamp,
            "text": str(payload.get("type") or "event_msg"),
            "meta": True,
            "synthetic": True,
        }]
    return []


# ---- Public dispatch ----

_HOST_ADAPTERS = {
    "claude_code": _claude_events,
    "codex": _codex_events,
}


def iter_events_for_host(host: str, obj: dict[str, Any]) -> list[dict[str, Any]]:
    fn = _HOST_ADAPTERS.get(host)
    if fn is None:
        return []
    return list(fn(obj))


__all__ = [
    "detect_host",
    "iter_events_for_host",
    "SECRET_PATTERNS",
    "BASE64_BLOB",
]