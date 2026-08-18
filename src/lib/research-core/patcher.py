#!/usr/bin/env python3
"""Mechanical patch-only correction with receipt and hunk caps."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

DEFAULT_MAX_HUNKS = 8
DEFAULT_MAX_HUNK_BYTES = 4096
HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


def parse_unified(diff: str) -> list[dict[str, Any]]:
    hunks = []
    current = None
    for line in diff.splitlines(keepends=True):
        if line.startswith(('--- ', '+++ ')):
            continue
        if line.startswith('@@'):
            match = HUNK_RE.match(line.rstrip('\n'))
            if not match:
                raise ValueError(f'invalid hunk header: {line.strip()}')
            if current:
                hunks.append(current)
            current = {
                'header': line.strip(),
                'old_start': int(match.group(1)),
                'new_start': int(match.group(3)),
                'old': [], 'new': [], 'body': '',
            }
            continue
        if current is None:
            continue
        current['body'] += line
        if line.startswith('\\ No newline'):
            continue
        if line.startswith('-'):
            current['old'].append(line[1:])
        elif line.startswith('+'):
            current['new'].append(line[1:])
        elif line.startswith(' '):
            current['old'].append(line[1:])
            current['new'].append(line[1:])
        else:
            raise ValueError(f'invalid hunk line: {line[:80]!r}')
    if current:
        hunks.append(current)
    return hunks


def _locate(lines: list[str], block: list[str], expected: int, lower_bound: int) -> int | None:
    if not block:
        return min(max(expected, lower_bound), len(lines))
    candidates = [expected]
    candidates += [expected + delta for radius in range(1, 9) for delta in (-radius, radius)]
    candidates += list(range(lower_bound, len(lines) - len(block) + 1))
    seen = set()
    for index in candidates:
        if index in seen or index < lower_bound or index < 0 or index + len(block) > len(lines):
            continue
        seen.add(index)
        if lines[index:index + len(block)] == block:
            return index
    return None


def apply_patch(source: str, diff: str, *, max_hunks: int = DEFAULT_MAX_HUNKS, max_hunk_bytes: int = DEFAULT_MAX_HUNK_BYTES) -> dict[str, Any]:
    try:
        hunks = parse_unified(diff)
    except ValueError as exc:
        return {'ok': False, 'reason': str(exc), 'applied': 0}
    if not hunks:
        return {'ok': False, 'reason': 'patch contains no hunks', 'applied': 0}
    if len(hunks) > max_hunks:
        return {'ok': False, 'reason': f'too many hunks: {len(hunks)} > {max_hunks}', 'applied': 0}
    lines = source.splitlines(keepends=True)
    offset = 0
    lower_bound = 0
    applied = 0
    for hunk in hunks:
        body_bytes = len(hunk['body'].encode('utf-8'))
        if body_bytes > max_hunk_bytes:
            return {'ok': False, 'reason': f'hunk too large: {body_bytes} > {max_hunk_bytes}', 'applied': applied}
        expected = max(0, hunk['old_start'] - 1 + offset)
        index = _locate(lines, hunk['old'], expected, lower_bound)
        if index is None:
            return {'ok': False, 'reason': f"context not found for {hunk['header']}", 'applied': applied}
        lines[index:index + len(hunk['old'])] = hunk['new']
        offset += len(hunk['new']) - len(hunk['old'])
        lower_bound = index + len(hunk['new'])
        applied += 1
    return {'ok': True, 'applied': applied, 'output': ''.join(lines)}


def _default_key_path() -> Path:
    override = os.environ.get('RESEARCH_PATCH_KEY')
    return Path(override).expanduser() if override else Path.home() / '.claude' / 'research-patch.key'


def _canonical_payload(receipt: dict[str, Any]) -> bytes:
    body = {k: v for k, v in receipt.items() if k != 'signature'}
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def validate_correction_receipt(receipt: dict[str, Any], *, source_bytes: bytes | None = None, key_path: Path | None = None) -> tuple[bool, str]:
    if receipt.get('receipt_version') != 2 or receipt.get('issued_by') != 'rhook.research-patch-guard':
        return False, 'receipt must be an authenticated rhook patch receipt v2'
    if receipt.get('stage') != 'patch':
        return False, 'receipt stage must be patch'
    allowed = set(receipt.get('allowed_tools') or [])
    if allowed != {'Read', 'Edit'}:
        return False, f'patch stage allowed_tools must be exactly Read+Edit, got {sorted(allowed)}'
    bound = str(receipt.get('sourced_draft_sha256') or '')
    if not re.fullmatch(r'[0-9a-f]{64}', bound):
        return False, 'receipt must bind the sourced draft sha256'
    if source_bytes is not None and not hmac.compare_digest(hashlib.sha256(source_bytes).hexdigest(), bound):
        return False, 'receipt draft hash does not match source bytes'
    path = (key_path or _default_key_path()).expanduser()
    try:
        key = path.read_bytes()
    except OSError:
        return False, f'patch signing key unavailable: {path}'
    signature = str(receipt.get('signature') or '')
    expected = 'hmac-sha256:' + hmac.new(key, _canonical_payload(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, 'patch receipt signature mismatch'
    return True, 'ok'


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', required=True)
    ap.add_argument('--diff', required=True)
    ap.add_argument('--out')
    ap.add_argument('--receipt', required=True)
    ap.add_argument('--max-hunks', type=int, default=DEFAULT_MAX_HUNKS)
    ap.add_argument('--max-hunk-bytes', type=int, default=DEFAULT_MAX_HUNK_BYTES)
    ap.add_argument('--key-file')
    args = ap.parse_args(argv)
    receipt = json.loads(Path(args.receipt).read_text(encoding='utf-8'))
    source_bytes = Path(args.source).read_bytes()
    ok, reason = validate_correction_receipt(receipt, source_bytes=source_bytes, key_path=Path(args.key_file) if args.key_file else None)
    if not ok:
        print(json.dumps({'ok': False, 'reason': reason, 'applied': 0}, indent=2))
        return 2
    result = apply_patch(source_bytes.decode('utf-8'), Path(args.diff).read_text(encoding='utf-8'), max_hunks=min(args.max_hunks, int(receipt.get('max_hunks', DEFAULT_MAX_HUNKS))), max_hunk_bytes=min(args.max_hunk_bytes, int(receipt.get('max_hunk_bytes', DEFAULT_MAX_HUNK_BYTES))))
    if result['ok'] and args.out:
        Path(args.out).write_text(result['output'], encoding='utf-8')
    printable = {k: v for k, v in result.items() if k != 'output'}
    print(json.dumps(printable, indent=2, sort_keys=True))
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv[1:]))
