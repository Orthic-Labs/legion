#!/usr/bin/env python3
"""Classify Research effects for internal callers."""
from __future__ import annotations

import re
from typing import Any

WORKER_NAMES = {"agent", "task", "workflow"}
EXTERNAL_NAMES = {"websearch", "webfetch", "web.search", "web.open", "web.find", "web.run"}
NETWORK_COMMAND = re.compile(
    r"(?:^|[;&|]\s*)(?:curl|wget|aria2c|git\s+(?:clone|fetch|pull|ls-remote)|"
    r"gh\s+api|npm\s+(?:install|view|search)|pnpm\s+(?:install|view)|"
    r"pip\s+install|python\s+-m\s+pip\s+install)\b",
    re.IGNORECASE,
)


def normalized(tool: str) -> str:
    return tool.strip().lower()


def is_worker(tool: str) -> bool:
    name = normalized(tool)
    if name in WORKER_NAMES:
        return True
    return name.startswith("mcp__") and any(part in WORKER_NAMES for part in name.split("__"))


def is_external(tool: str, tool_input: dict[str, Any] | None = None) -> bool:
    name = normalized(tool)
    if name in EXTERNAL_NAMES:
        return True
    if name.startswith("mcp__"):
        return not is_worker(tool)
    if name in {"bash", "shell", "terminal", "exec", "container.exec"}:
        value = (tool_input or {}).get("command", (tool_input or {}).get("cmd", ""))
        command = " ".join(value) if isinstance(value, list) else str(value)
        return bool(NETWORK_COMMAND.search(command))
    return False
