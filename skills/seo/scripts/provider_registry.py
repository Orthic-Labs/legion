#!/usr/bin/env python3
"""Discover and select SEO evidence providers from the governed registry.

This helper never reads or prints secret values. It selects providers by capability,
availability, first-party/local preference and paid-provider authority constraints.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

SEO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = SEO_ROOT / 'config' / 'provider-registry.json'


def load_registry() -> dict[str, Any]:
    return json.loads(REGISTRY.read_text(encoding='utf-8'))


def availability(provider: dict[str, Any], host_tools: set[str] | None = None) -> str:
    kind = provider.get('availability')
    envs = provider.get('env') or []
    if kind == 'builtin':
        return 'available'
    if kind == 'manual':
        return 'manual'
    if kind == 'host_tool':
        hint = provider.get('tool_hint')
        return 'available' if hint and hint in (host_tools or set()) else 'unknown'
    vals = [bool(os.environ.get(name)) for name in envs]
    if kind == 'env_all':
        return 'available' if vals and all(vals) else ('partial' if any(vals) else 'unavailable')
    if kind == 'env_any':
        return 'available' if any(vals) else 'unavailable'
    return 'unknown'


def discover(host_tools: set[str] | None = None) -> dict[str, Any]:
    reg = load_registry()
    out = {}
    for name, provider in reg['providers'].items():
        out[name] = {
            'class': provider.get('class'),
            'paid': provider.get('paid'),
            'priority': provider.get('priority'),
            'capabilities': provider.get('capabilities') or [],
            'availability': availability(provider, host_tools),
        }
    return {'providers': out, 'selection_rules': reg.get('selection_rules') or []}


def choose(capability: str, *, host_tools: set[str] | None = None,
           allow_paid: bool = False, allow_manual: bool = True) -> dict[str, Any]:
    reg = load_registry()
    candidates = []
    for name, provider in reg['providers'].items():
        if capability not in (provider.get('capabilities') or []):
            continue
        state = availability(provider, host_tools)
        if state == 'manual' and not allow_manual:
            continue
        if state not in {'available', 'manual'}:
            continue
        if provider.get('paid') is True and not allow_paid:
            continue
        class_rank = {
            'first_party': 5,
            'first_party_manual_export': 5,
            'first_party_write': 4,
            'local': 4,
            'host_tool': 3,
            'paid_provider': 2,
            'paid_host_tool': 2,
        }.get(provider.get('class'), 1)
        candidates.append((class_rank, int(provider.get('priority') or 0), name, provider, state))
    candidates.sort(reverse=True)
    if not candidates:
        return {
            'status': 'unavailable',
            'capability': capability,
            'reason': 'no eligible provider is currently available under the paid/manual policy',
        }
    class_rank, priority, name, provider, state = candidates[0]
    return {
        'status': 'selected',
        'capability': capability,
        'provider': name,
        'class': provider.get('class'),
        'availability': state,
        'paid': provider.get('paid'),
        'priority': priority,
        'alternatives': [x[2] for x in candidates[1:]],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='command', required=True)
    p = sub.add_parser('discover')
    p.add_argument('--host-tool', action='append', default=[])
    p = sub.add_parser('choose')
    p.add_argument('capability')
    p.add_argument('--host-tool', action='append', default=[])
    p.add_argument('--allow-paid', action='store_true')
    p.add_argument('--no-manual', action='store_true')
    args = ap.parse_args()
    tools = set(args.host_tool)
    if args.command == 'discover':
        result = discover(tools)
    else:
        result = choose(args.capability, host_tools=tools, allow_paid=args.allow_paid, allow_manual=not args.no_manual)
    print(json.dumps(result, indent=2))
    return 0 if args.command == 'discover' or result.get('status') == 'selected' else 2


if __name__ == '__main__':
    raise SystemExit(main())
