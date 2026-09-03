#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'resource_guard.py'

spec = importlib.util.spec_from_file_location('research_resource_guard', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
resource_guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resource_guard)


def main() -> int:
    route = {
        'forbidden_resources': [
            'skills/research/references/domains/legal/india/consumer/**',
            'src/lib/research-core/workflows/legal/india/consumer/**',
        ]
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        allowed = root / 'skills/research/references/domains/legal/GUIDE.md'
        denied = root / 'skills/research/references/domains/legal/india/consumer/GUIDE.md'
        allowed.parent.mkdir(parents=True)
        denied.parent.mkdir(parents=True)
        allowed.write_text('legal', encoding='utf-8')
        denied.write_text('consumer', encoding='utf-8')

        assert resource_guard.authorize(route, allowed, root)['ok']
        verdict = resource_guard.authorize(route, denied, root)
        assert not verdict['ok'], verdict
        assert verdict['matched_pattern'].endswith('consumer/**')

        escape = resource_guard.authorize(route, root.parent / 'outside.md', root)
        assert not escape['ok'], escape

    print('OK: frozen-route forbidden resources and workspace escapes are rejected')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
