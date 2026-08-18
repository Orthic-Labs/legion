#!/usr/bin/env python
"""Council CLI — multi-LLM review pipeline.

Usage:
  python council.py review-code --input path/to/file.py [--flag irreversible=true] [--no-cache] [--json]
  echo "code here" | python council.py review-code --input -

Flags:
  --input <path|->     Path to input file, or - for stdin
  --flag k=v           Set a rubric flag (repeatable). Booleans: true/false.
  --no-cache           Skip cache reads (still writes results)
  --json               Output raw JSON instead of markdown
  --shadow             Save full result to shadow_log/<ts>.json for parity comparison
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from pyio import ensure_utf8_stdio  # noqa: E402
ensure_utf8_stdio()

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from engine import Engine
from synthesizer import render


def parse_flag(s: str) -> tuple[str, object]:
    if "=" not in s:
        return s, True
    k, v = s.split("=", 1)
    if v.lower() in ("true", "yes", "1"):
        return k, True
    if v.lower() in ("false", "no", "0"):
        return k, False
    try:
        return k, int(v)
    except ValueError:
        return k, v


def main():
    p = argparse.ArgumentParser()
    p.add_argument("skill", help="skill name (e.g. review-code)")
    p.add_argument("--input", required=True, help="path to input file, or - for stdin")
    p.add_argument("--flag", action="append", default=[], help="rubric flag, k=v (repeatable)")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--no-escalation", action="store_true", help=argparse.SUPPRESS)
    p.add_argument(
        "--allow-cli-escalation",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument("--json", action="store_true", help="output raw JSON")
    p.add_argument("--shadow", action="store_true", help="save result to shadow_log/")
    args = p.parse_args()

    # Read input
    if args.input == "-":
        user_input = sys.stdin.read()
    else:
        user_input = Path(args.input).read_text(encoding="utf-8")

    flags = dict(parse_flag(f) for f in args.flag)

    engine = Engine()
    t0 = time.time()
    result = engine.run(
        skill=args.skill,
        user_input=user_input,
        flags=flags,
        no_cache=args.no_cache,
        no_escalation=(not args.allow_cli_escalation) or args.no_escalation,
    )
    result["wall_seconds"] = round(time.time() - t0, 2)

    if args.shadow:
        ts = int(time.time())
        out_path = ROOT / "shadow_log" / f"{args.skill}_{ts}.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render(result))
        print(f"\n_wall: {result['wall_seconds']}s_")


if __name__ == "__main__":
    main()
