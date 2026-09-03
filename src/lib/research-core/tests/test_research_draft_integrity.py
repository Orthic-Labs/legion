#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import tempfile
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'draft_integrity.py'
spec = importlib.util.spec_from_file_location('research_draft_integrity', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
draft_integrity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(draft_integrity)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        draft = root / 'draft.md'
        draft.write_text('sourced\n', encoding='utf-8')
        manifest = {'artifacts': {'sourced-draft': {'sha256': digest(draft)}}}
        assert draft_integrity.check(root, manifest)['ok']

        draft.write_text('edited directly\n', encoding='utf-8')
        result = draft_integrity.check(root, manifest)
        assert not result['ok'] and 'differs' in result['reason']

        draft.write_text('sourced\n', encoding='utf-8')
        (root / 'applied.patch').write_text('@@\n', encoding='utf-8')
        missing = draft_integrity.check(root, manifest)
        assert not missing['ok'] and 'patched-draft' in missing['reason']

        draft.write_text('patched\n', encoding='utf-8')
        manifest['artifacts']['patched-draft'] = {'sha256': digest(draft)}
        assert draft_integrity.check(root, manifest)['ok']
        draft.write_text('changed after patch\n', encoding='utf-8')
        assert not draft_integrity.check(root, manifest)['ok']

    print('OK: direct and post-patch draft mutations are blocked by hash authority')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
