#!/usr/bin/env python3
"""Compile Markdown checklist items into reviewable SEO control candidates.

This compiler never promotes prose to executable truth. It preserves exact source digest,
line count, phase/heading path, and line pointers so a human can review candidates into the
governed control catalog. Source updates can be diffed semantically.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

CHECK_RE = re.compile(r'^\s*-\s*\[\s*\]\s+(.+?)\s*$')
HEADING_RE = re.compile(r'^(#{1,6})\s+(.+?)\s*$')
PHASE_RE = re.compile(r'^PHASE\s+(\d+)\b', re.I)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def slug(text: str, max_len: int = 56) -> str:
    value = re.sub(r'[^a-z0-9]+', '-', text.casefold()).strip('-')
    return value[:max_len].rstrip('-') or 'control'


def compile_text(text: str, source_name: str = 'checklist') -> dict[str, Any]:
    lines = text.splitlines()
    heading_stack: dict[int, str] = {}
    phase = None
    seen: dict[str, int] = {}
    candidates = []
    for lineno, line in enumerate(lines, 1):
        hm = HEADING_RE.match(line)
        if hm:
            level = len(hm.group(1))
            title = hm.group(2).strip()
            heading_stack = {k: v for k, v in heading_stack.items() if k < level}
            heading_stack[level] = title
            pm = PHASE_RE.match(title)
            if pm:
                phase = int(pm.group(1))
            continue
        cm = CHECK_RE.match(line)
        if not cm:
            continue
        text_value = cm.group(1).strip()
        base = f"phase-{phase or 0:02d}.{slug(text_value)}"
        seen[base] = seen.get(base, 0) + 1
        cid = base if seen[base] == 1 else f"{base}-{seen[base]}"
        candidates.append({
            'candidate_id': cid,
            'source': source_name,
            'phase': phase,
            'heading_path': [heading_stack[k] for k in sorted(heading_stack)],
            'line_start': lineno,
            'line_end': lineno,
            'text': text_value,
            'promotion_state': 'candidate',
        })
    return {
        'source': source_name,
        'sha256': digest(text),
        'line_count': len(lines),
        'candidate_count': len(candidates),
        'candidates': candidates,
    }


def semantic_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_map = {x['candidate_id']: x for x in old.get('candidates', [])}
    new_map = {x['candidate_id']: x for x in new.get('candidates', [])}
    added = [new_map[k] for k in sorted(new_map.keys() - old_map.keys())]
    removed = [old_map[k] for k in sorted(old_map.keys() - new_map.keys())]
    changed = []
    for key in sorted(old_map.keys() & new_map.keys()):
        if old_map[key].get('text') != new_map[key].get('text') or old_map[key].get('heading_path') != new_map[key].get('heading_path'):
            changed.append({'id': key, 'before': old_map[key], 'after': new_map[key]})
    return {'added': added, 'removed': removed, 'changed': changed}


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='command', required=True)
    c = sub.add_parser('compile')
    c.add_argument('source')
    c.add_argument('--name')
    c.add_argument('--out', required=True)
    v = sub.add_parser('verify')
    v.add_argument('source')
    v.add_argument('--sha256', required=True)
    v.add_argument('--line-count', type=int, required=True)
    d = sub.add_parser('diff')
    d.add_argument('old')
    d.add_argument('new')
    args = ap.parse_args()

    if args.command == 'compile':
        src = Path(args.source)
        text = src.read_text(encoding='utf-8')
        out = compile_text(text, args.name or src.name)
        Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps({'sha256': out['sha256'], 'line_count': out['line_count'], 'candidate_count': out['candidate_count'], 'out': args.out}, indent=2))
        return 0
    if args.command == 'verify':
        text = Path(args.source).read_text(encoding='utf-8')
        got_sha, got_lines = digest(text), len(text.splitlines())
        ok = got_sha == args.sha256 and got_lines == args.line_count
        print(json.dumps({'status': 'pass' if ok else 'fail', 'sha256': got_sha, 'line_count': got_lines}, indent=2))
        return 0 if ok else 1
    old = json.loads(Path(args.old).read_text(encoding='utf-8'))
    new = json.loads(Path(args.new).read_text(encoding='utf-8'))
    print(json.dumps(semantic_diff(old, new), indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
