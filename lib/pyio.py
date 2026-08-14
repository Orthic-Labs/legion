"""Shared stdio helper for workspace Python CLIs.

Windows consoles default to cp1252, which cannot encode status glyphs (✅ ⛔ …);
the first such print raises UnicodeEncodeError. Call ensure_utf8_stdio() before
any glyph output. No-op on already-utf8 streams and on streams that cannot be
reconfigured (e.g. StringIO in tests).
"""
from __future__ import annotations

import sys


def ensure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        enc = getattr(stream, "encoding", None)
        if enc and enc.lower() not in ("utf-8", "utf8") and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                # Detached or non-reconfigurable stream — leave it as-is.
                pass
