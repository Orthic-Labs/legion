#!/usr/bin/env python3
"""Route-bound authorization and loading for Research resources."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import manifest  # noqa: E402
from common import utc_now  # noqa: E402


def _relative_path(workspace: Path, requested: str | Path) -> tuple[Path, str]:
    workspace = workspace.resolve()
    raw = Path(requested)
    candidate = raw.resolve() if raw.is_absolute() else (workspace / raw).resolve()
    if candidate != workspace and workspace not in candidate.parents:
        raise PermissionError(f'resource escapes workspace: {requested}')
    relative = candidate.relative_to(workspace).as_posix()
    return candidate, relative


def _matches(relative: str, pattern: str) -> bool:
    normalized = pattern.replace('\\', '/').lstrip('./')
    path = PurePosixPath(relative)
    if path.match(normalized) or fnmatch.fnmatchcase(relative, normalized):
        return True
    if normalized.endswith('/**'):
        prefix = normalized[:-3].rstrip('/')
        return relative == prefix or relative.startswith(prefix + '/')
    return False


def authorize(
    route: dict[str, Any],
    requested: str | Path,
    workspace: Path,
    *,
    require_file: bool = True,
) -> dict[str, Any]:
    try:
        candidate, relative = _relative_path(workspace, requested)
    except PermissionError as exc:
        return {'ok': False, 'reason': str(exc), 'path': str(requested)}

    forbidden = [str(pattern) for pattern in route.get('forbidden_resources', [])]
    matched = next((pattern for pattern in forbidden if _matches(relative, pattern)), None)
    if matched:
        return {
            'ok': False,
            'reason': f'resource denied by frozen route: {matched}',
            'path': relative,
            'matched_pattern': matched,
        }
    if require_file and not candidate.is_file():
        return {'ok': False, 'reason': 'resource is not a readable file', 'path': relative}
    return {'ok': True, 'path': relative, 'absolute_path': str(candidate)}


def read_resource(run_id: str, requested: str | Path, workspace: Path) -> dict[str, Any]:
    run = manifest.load_run(run_id)
    verdict = authorize(run['route'], requested, workspace, require_file=True)
    if not verdict['ok']:
        manifest.record_event(run_id, 'resource.denied', verdict)
        raise PermissionError(verdict['reason'])

    path = Path(verdict['absolute_path'])
    content = path.read_text(encoding='utf-8')
    digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
    receipt = {
        'receipt_version': 1,
        'run_id': run_id,
        'route_sha256': run['route_sha256'],
        'path': verdict['path'],
        'content_sha256': digest,
        'issued_at': utc_now(),
    }
    manifest.record_event(run_id, 'resource.allowed', receipt)
    return {'content': content, 'receipt': receipt}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--path', required=True)
    args = parser.parse_args(argv)
    try:
        result = read_resource(args.run_id, args.path, args.workspace)
    except PermissionError as exc:
        print(json.dumps({'ok': False, 'reason': str(exc)}, indent=2))
        return 2
    print(json.dumps({'ok': True, **result}, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
