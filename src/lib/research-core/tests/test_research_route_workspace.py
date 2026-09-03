#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[4]
MODULE = WORKSPACE / 'src' / 'lib' / 'research-core' / 'router' / 'route_resolve.py'

spec = importlib.util.spec_from_file_location('route_resolve_workspace_check', MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {MODULE}')
route_resolve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route_resolve)


def main() -> int:
    # RETIRED: the original assertion here checked that a personal medical
    # route's `history_source` resolved to a hardcoded, identifying path
    # (`.../history/adrian.yaml`) under the workspace. That behavior was
    # removed by de-personalisation: route_resolve.py now never infers a
    # patient-history path at all — the host must supply `history_source`
    # explicitly via context (see the comment above `build_subject` in
    # route_resolve.py). So that half of the original test is gone by
    # design, not by regression, and is not ported forward.
    #
    # What survives, and is the part this test actually existed to catch
    # (defects 1 and 3 in the router-move review): domain detection must
    # still route a real personal-medical query to `medical`, and the
    # module's own WORKSPACE resolution must land on the real repository
    # root rather than some interior `src/` subtree.
    route = route_resolve.resolve('Could my TRT protocol explain this lab?')
    assert route['domain'] == 'medical', route
    assert route['subject']['patient']['kind'] == 'self', route
    assert 'confirm-personal-medical-route' in route['human_gates'], route

    # A host-supplied history source is honored explicitly, never inferred.
    history = WORKSPACE / 'history-fixture.yaml'
    try:
        history.write_text('patient: fixture\n', encoding='utf-8')
        route_with_history = route_resolve.resolve(
            'Could my TRT protocol explain this lab?',
            context={'history_source': str(history)},
        )
        subject = route_with_history['subject']['patient']
        assert subject['history_source'] == str(history), route_with_history
        assert subject['history_available'] is True, route_with_history
    finally:
        history.unlink(missing_ok=True)

    assert route_resolve.WORKSPACE == WORKSPACE, (route_resolve.WORKSPACE, WORKSPACE)
    assert (route_resolve.WORKSPACE / 'skills' / 'research').is_dir(), route_resolve.WORKSPACE

    print('OK: personal medical route resolves domain/gates and route_resolve.WORKSPACE is the real repository root')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
