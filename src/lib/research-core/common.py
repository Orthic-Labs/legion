#!/usr/bin/env python3
"""Shared deterministic helpers for the Research Core."""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def today() -> str:
    return dt.date.today().isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n')


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(value, sort_keys=True, ensure_ascii=False) + '\n'
    with path.open('a', encoding='utf-8', newline='\n') as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


@contextlib.contextmanager
def file_lock(path: Path, timeout_s: float = 10.0) -> Iterator[None]:
    """Cross-platform, process-level lock using atomic lock-file creation.

    The state files are small and writes are short. A stale lock older than 5 minutes is
    reclaimed. This avoids platform-specific fcntl/msvcrt branches and works on network drives.
    """
    lock_path = path.with_suffix(path.suffix + '.lock')
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f'{os.getpid()} {utc_now()}\n'.encode('utf-8'))
            os.close(fd)
            break
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
                if age > 300:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError(f'timed out acquiring lock: {lock_path}')
            time.sleep(0.05)
    try:
        yield
    finally:
        lock_path.unlink(missing_ok=True)
