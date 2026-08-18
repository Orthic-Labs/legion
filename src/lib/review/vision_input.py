"""Vision input prep — extract image bytes from auto-jury input.md.

The auto-jury writes a structured input.md with paths to the artifact and
(for video) extracted frame paths. This module:

  1. Parses the input.md text for absolute paths matching .png/.jpg/.jpeg/.webp/.mp4
  2. For videos: extracts up to N keyframes via ffmpeg into a temp directory
  3. Base64-encodes the images and returns a list of dicts:
       [{ "mime": "image/png", "b64": "...", "source": "<original path>" }]
  4. Caps total images to MAX_IMAGES (default 6) to keep API payloads sane.

Used by: engine.py when skill_cfg["needs_vision_input"] is True.
"""
from __future__ import annotations
import base64
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

MAX_IMAGES = 6
VIDEO_KEYFRAMES = 4  # extract this many frames per video at evenly-spaced timestamps
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB per image cap (skip larger)

_PATH_RE = re.compile(
    r"""
    (
      (?:[A-Za-z]:[\\/]|/)        # drive letter (Windows) or absolute slash (Unix)
      [^\s"'`<>]+
      \.(?:png|jpg|jpeg|webp|mp4|mov|webm)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp"}
VIDEO_EXTS = {".mp4", ".mov", ".webm"}

MIME_BY_EXT = {
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}


def _extract_paths(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _PATH_RE.finditer(text or ""):
        p = m.group(1).strip().rstrip(",.;")
        # Normalize Windows mixed slashes
        p_norm = p.replace("\\", "/")
        if p_norm in seen:
            continue
        seen.add(p_norm)
        out.append(p)
    return out


def _ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def _video_duration(video_path: str) -> float | None:
    """Probe duration in seconds via ffprobe; None if unavailable."""
    if not shutil.which("ffprobe"):
        return None
    try:
        r = subprocess.run(
            [
                "ffprobe", "-v", "error",
                "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1",
                video_path,
            ],
            capture_output=True, text=True, timeout=20,
        )
        return float(r.stdout.strip())
    except Exception:
        return None


def _extract_video_keyframes(video_path: str, n: int = VIDEO_KEYFRAMES, scale: int = 512) -> list[str]:
    """Extract n keyframes from video, returns list of png paths in a temp dir."""
    if not _ffmpeg_available():
        return []
    duration = _video_duration(video_path) or 0
    if duration <= 0:
        return []
    timestamps = []
    if n == 1:
        timestamps = [duration / 2.0]
    else:
        # Sample n frames evenly, skip pure boundaries
        step = duration / (n + 1)
        timestamps = [round(step * (i + 1), 2) for i in range(n)]

    tmpdir = tempfile.mkdtemp(prefix="council-frames-")
    out_paths: list[str] = []
    for i, ts in enumerate(timestamps):
        out_path = os.path.join(tmpdir, f"frame-{i:02d}-t{ts:.2f}s.png")
        try:
            subprocess.run(
                [
                    "ffmpeg", "-y", "-ss", str(ts), "-i", video_path,
                    "-vframes", "1",
                    "-vf", f"scale={scale}:-1:flags=lanczos",
                    "-loglevel", "error",
                    out_path,
                ],
                capture_output=True, timeout=30,
            )
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                out_paths.append(out_path)
        except Exception:
            continue
    return out_paths


def _b64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def _resolve_path(p: str) -> str | None:
    """Readable path, normalizing a Git Bash / MSYS drive path (/d/foo -> D:/foo).
    Without this, an agent on Windows Git Bash feeds /d/... , Python can't open it,
    the image is silently dropped, and the vision model hallucinates a blank image."""
    if os.path.exists(p):
        return p
    m = re.match(r"^/([a-zA-Z])/(.*)$", p)
    if m:
        win = f"{m.group(1).upper()}:/{m.group(2)}"
        if os.path.exists(win):
            return win
    return None


def prepare_vision_payload(text: str, max_images: int = MAX_IMAGES) -> list[dict]:
    """
    Parse text for image/video paths, expand videos to keyframes, encode all
    found images to base64. Returns up to max_images items.

    Returns: [{ "mime": "image/png", "b64": "...", "source": "<path>" }, ...]
    """
    paths = _extract_paths(text)
    if not paths:
        return []

    payload: list[dict] = []
    for p in paths:
        if len(payload) >= max_images:
            break
        resolved = _resolve_path(p)
        if resolved is None:
            continue
        p = resolved
        ext = os.path.splitext(p)[1].lower()
        size = 0
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if ext in IMAGE_EXTS:
            if size <= 0 or size > MAX_IMAGE_BYTES:
                continue
            try:
                payload.append({
                    "mime":   MIME_BY_EXT[ext],
                    "b64":    _b64(p),
                    "source": p,
                })
            except Exception:
                continue
        elif ext in VIDEO_EXTS:
            frames = _extract_video_keyframes(p)
            for fp in frames:
                if len(payload) >= max_images:
                    break
                try:
                    fsize = os.path.getsize(fp)
                    if fsize <= 0 or fsize > MAX_IMAGE_BYTES:
                        continue
                    payload.append({
                        "mime":   "image/png",
                        "b64":    _b64(fp),
                        "source": f"{p} (keyframe {os.path.basename(fp)})",
                    })
                except Exception:
                    continue
    return payload
