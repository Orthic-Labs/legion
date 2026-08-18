#!/usr/bin/env python3
"""Canonical query persistence and wrapper-contract separation."""
from __future__ import annotations

import hashlib
from pathlib import Path


def persist(run_dir: Path, query: str, wrapper_contract: str | None = None) -> dict:
    text = query.rstrip() + '\n'
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'query.md').write_text(text, encoding='utf-8', newline='\n')
    if wrapper_contract is not None:
        (run_dir / 'request-contract.md').write_text(wrapper_contract.rstrip() + '\n', encoding='utf-8', newline='\n')
    return {'query_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(), 'query_path': str(run_dir / 'query.md')}
