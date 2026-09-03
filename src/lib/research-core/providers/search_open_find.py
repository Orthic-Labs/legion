#!/usr/bin/env python3
"""Provider-neutral search/open/find dispatcher with Research-metered effects."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parent
WORKSPACE = CORE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(CORE))

from command_bridge import CommandBridgeProvider  # noqa: E402
from local_corpus import LocalCorpusProvider  # noqa: E402
from scholarly import ScholarlyProvider  # noqa: E402
import meter as research_meter  # noqa: E402


def provider(name: str, *, corpus: str | None = None):
    if name == 'local-corpus':
        if not corpus:
            raise ValueError('--corpus is required for local-corpus')
        return LocalCorpusProvider(Path(corpus))
    if name in {'browser', 'domain-default'}:
        return CommandBridgeProvider('browser', 'RESEARCH_BROWSER_CMD')
    if name == 'legal-authority':
        return CommandBridgeProvider('legal-authority', 'RESEARCH_AUTHORITY_CMD')
    if name == 'scholarly':
        return ScholarlyProvider()
    raise ValueError(f'provider {name!r} does not expose search/open/find')


def meter(run_id: str | None, effect: str) -> None:
    if not run_id:
        return
    result = research_meter.consume(WORKSPACE, run_id, effect)
    if not result['ok']:
        raise RuntimeError(result['reason'])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--provider', required=True, choices=['browser', 'domain-default', 'local-corpus', 'scholarly', 'legal-authority'])
    ap.add_argument('--corpus')
    ap.add_argument('--run-id')
    sub = ap.add_subparsers(dest='op', required=True)
    p = sub.add_parser('search'); p.add_argument('--query', required=True); p.add_argument('--limit', type=int, default=10); p.add_argument('--seed-chain', default='[]')
    p = sub.add_parser('open'); p.add_argument('--url', required=True)
    p = sub.add_parser('find'); p.add_argument('--opened', required=True); p.add_argument('--pattern', required=True)
    args = ap.parse_args(argv)
    impl = provider(args.provider, corpus=args.corpus)
    if args.op == 'search':
        if 'search' in set(getattr(impl, 'external_ops', ())): meter(args.run_id, 'external_request')
        result = [h.to_dict() for h in impl.search(args.query, limit=args.limit, seed_chain=json.loads(args.seed_chain))]
    elif args.op == 'open':
        if 'open' in set(getattr(impl, 'external_ops', ())): meter(args.run_id, 'external_request')
        result = impl.open(args.url).to_dict()
    else:
        from base import OpenedSource
        raw = json.loads(Path(args.opened).read_text(encoding='utf-8'))
        opened = OpenedSource(url=raw['url'], title=raw['title'], publisher=raw['publisher'], retrieved_at=raw['retrieved_at'], content=raw['content'], content_sha256=raw['content_sha256'], instruction_policy=raw.get('instructionPolicy', 'data_only'), provider=raw['provider'], metadata=raw.get('metadata') or {})
        if 'find' in set(getattr(impl, 'external_ops', ())): meter(args.run_id, 'external_request')
        passage = impl.find(opened, args.pattern)
        result = passage.to_dict() if passage else None
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
