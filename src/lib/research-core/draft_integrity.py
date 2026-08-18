#!/usr/bin/env python3
"""Detect any sourced-draft edit that bypasses the authenticated patch path."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(run_dir: Path, manifest_doc: dict[str, Any]) -> dict[str, Any]:
    draft = run_dir / 'draft.md'
    if not draft.is_file():
        return {'ok': False, 'reason': 'draft.md is missing'}

    artifacts = manifest_doc.get('artifacts', {})
    patched = artifacts.get('patched-draft')
    sourced = artifacts.get('sourced-draft')
    patch_exists = (run_dir / 'applied.patch').is_file()

    if patch_exists:
        if not patched or not patched.get('sha256'):
            return {'ok': False, 'reason': 'applied.patch exists without a hash-bound patched-draft artifact'}
        expected = str(patched['sha256'])
        authority = 'patched-draft'
    else:
        if patched:
            return {'ok': False, 'reason': 'patched-draft artifact exists without applied.patch'}
        if not sourced or not sourced.get('sha256'):
            return {'ok': False, 'reason': 'sourced-draft artifact is missing its hash'}
        expected = str(sourced['sha256'])
        authority = 'sourced-draft'

    actual = _sha256(draft)
    return {
        'ok': actual == expected,
        'reason': 'ok' if actual == expected else 'draft hash differs from the last authorized draft artifact',
        'authority': authority,
        'expected_sha256': expected,
        'actual_sha256': actual,
    }
