"""Subprocess provider for one-shot CLI jurors."""
from __future__ import annotations
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .base import ProviderError

# Make D:/workspace/tools/lib importable so we can use agent_spawn.ensure_directive
_LIB_DIR = Path(__file__).resolve().parent.parent.parent / "lib"
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))


def _resolve_executable(name: str) -> str:
    """On Windows, Node CLIs install as .cmd shims that subprocess can't find without help."""
    found = shutil.which(name)
    if found:
        return found
    if sys.platform == "win32":
        for ext in (".cmd", ".exe", ".bat", ".ps1"):
            found = shutil.which(name + ext)
            if found:
                return found
    return name  # last resort — let subprocess raise FileNotFoundError


class SubprocessProvider:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.command_template: list = config["command_template"]
        self.timeout_s = int(config.get("timeout_s", 180))
        # If template contains "{prompt}" we substitute as argv;
        # if it contains "-" we send prompt via stdin (preferred for long prompts on Windows).
        self.prompt_via_stdin = "{prompt}" not in " ".join(config["command_template"])

    def call(self, model: str, system: str, user: str, max_tokens: int = 2048, images: list | None = None) -> str:
        # Subprocess CLIs do not consistently accept inline base64 images
        # via stdin in the wrapped form. The image paths are already in `user`
        # (auto-jury input.md format) and the CLI's own toolchain re-reads them
        # if supported. Acknowledged but not forwarded — graceful degrade.
        _ = images
        # Phase 6 (2026-05-04): apply machine-minimal directive + JSON mode
        # contract idempotently. Jury jurors output JSON only by rubric;
        # mode='json' lets the inbound validator catch chatty regressions.
        try:
            from agent_spawn import ensure_directive  # type: ignore
            user_enforced = ensure_directive(user, mode="json")
        except Exception:
            user_enforced = user
        full_prompt = f"{system}\n\n---\n\n{user_enforced}"
        cmd = []
        for i, piece in enumerate(self.command_template):
            if i == 0:
                cmd.append(_resolve_executable(piece))
            elif "{model}" in piece:
                cmd.append(piece.replace("{model}", model))
            elif "{prompt}" in piece:
                cmd.append(piece.replace("{prompt}", full_prompt))
            else:
                cmd.append(piece)
        try:
            if self.prompt_via_stdin:
                proc = subprocess.run(
                    cmd,
                    input=full_prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    encoding="utf-8",
                    errors="replace",
                )
            else:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    encoding="utf-8",
                    errors="replace",
                    stdin=subprocess.DEVNULL,
                )
            if proc.returncode != 0:
                # Cap raised from 500 → 4000 on 2026-05-05 after the codex
                # ChatGPT-account "model not supported" 400 was being cut off
                # at 500 chars, hiding the actual fix. 4000 matches engine.py
                # response clipping.
                err = (proc.stderr or proc.stdout or "")[:4000]
                raise ProviderError(f"{self.name}/{model} exit {proc.returncode}: {err}")
            return proc.stdout
        except subprocess.TimeoutExpired:
            raise ProviderError(f"{self.name}/{model} timeout after {self.timeout_s}s", is_quota=False)
        except FileNotFoundError:
            raise ProviderError(f"{self.name}: CLI not found ({cmd[0]})")
        except Exception as e:
            raise ProviderError(f"{self.name}/{model} error: {e}")
