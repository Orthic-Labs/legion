#!/usr/bin/env python3
"""Covenant's packet-only external review packet validator."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

CANONICAL = "PACKET_ONLY — DO_NOT_RUN_COVENANT"
ENGINE_VALIDATOR = Path(__file__).resolve().parents[1] / "engine" / "packet-validator.py"


def _load_engine_validator():
    spec = importlib.util.spec_from_file_location("covenant_packet_validator", ENGINE_VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Covenant packet validator: {ENGINE_VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(text: str, path: Path, inline: bool, template: bool = False) -> list[str]:
    if CANONICAL not in text:
        return [f"Mode must be {CANONICAL}"]
    return _load_engine_validator().validate(text, path, inline, template)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--inline", action="store_true")
    parser.add_argument("--template-self-check", action="store_true")
    args = parser.parse_args()
    if not args.packet.is_file():
        print(f"FAIL: packet file not found: {args.packet}", file=sys.stderr)
        return 2
    errors = validate(args.packet.read_text(encoding="utf-8"), args.packet, args.inline, args.template_self_check)
    if errors:
        print(f"FAIL: {len(errors)} packet defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS: Covenant packet is zero-context complete & packet-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
