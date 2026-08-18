#!/usr/bin/env python3
"""Issue authenticated Research patch-stage receipts."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any


def default_key_path() -> Path:
    override = os.environ.get('RESEARCH_PATCH_KEY')
    return Path(override).expanduser() if override else Path.home() / '.claude' / 'research-patch.key'


def load_or_create_key(path: Path | None = None) -> bytes:
    path = (path or default_key_path()).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        try:
            path.chmod(0o600)
        except OSError:
            pass
    key = path.read_bytes()
    if len(key) < 32:
        raise ValueError('research patch signing key must be at least 32 bytes')
    return key


def canonical_payload(receipt: dict[str, Any]) -> bytes:
    body = {k: v for k, v in receipt.items() if k != 'signature'}
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sign(receipt: dict[str, Any], key: bytes) -> str:
    return 'hmac-sha256:' + hmac.new(key, canonical_payload(receipt), hashlib.sha256).hexdigest()


def issue_receipt(draft: Path, run_id: str, *, key_path: Path | None = None) -> dict[str, Any]:
    from datetime import datetime, timezone
    receipt: dict[str, Any] = {
        'receipt_version': 2,
        'issued_by': 'research-core.patch-guard',
        'issued_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'run_id': run_id,
        'stage': 'patch',
        'allowed_tools': ['Read', 'Edit'],
        'sourced_draft_sha256': hashlib.sha256(draft.read_bytes()).hexdigest(),
        'max_hunks': 8,
        'max_hunk_bytes': 4096,
    }
    receipt['signature'] = sign(receipt, load_or_create_key(key_path))
    return receipt


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--draft', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--key-file')
    args = ap.parse_args(argv)
    receipt = issue_receipt(Path(args.draft), args.run_id, key_path=Path(args.key_file) if args.key_file else None)
    Path(args.out).write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
