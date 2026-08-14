#!/usr/bin/env python3
"""Validate packet cost routing locally; never an API client or registered hook."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


TIERS = {"FRONTIER", "MID", "CHEAP_STRICT", "NONE"}
PROFILES = {"strict", "standard", "advanced"}
VALIDATOR = Path(__file__).with_name("validate-dispatch.py")


def load_validator():
    spec = importlib.util.spec_from_file_location("dispatch_validator", VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load typed dispatch validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def routing_errors(packet: object, path: Path, validator: object) -> list[str]:
    errors, _ = validator.authority_packet_errors(packet, path.resolve())
    routing = packet.get("modelRouting") if isinstance(packet, dict) else None
    if not isinstance(routing, dict):
        return sorted(set(errors))
    tier, profile = routing.get("modelTier"), routing.get("workerProfile")
    if tier not in TIERS:
        errors.append("modelTier must be one of FRONTIER, MID, CHEAP_STRICT, NONE")
    if profile not in PROFILES:
        errors.append("workerProfile must be one of strict, standard, advanced")
    if tier == "CHEAP_STRICT" and profile != "strict":
        errors.append("CHEAP_STRICT requires strict workerProfile")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packets", nargs="+", type=Path)
    args = parser.parse_args()
    validator = load_validator()
    for path in args.packets:
        path = path.resolve()
        try:
            packet = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL: packet unreadable: {exc}")
            return 2
        errors = routing_errors(packet, path, validator)
        if errors:
            print(f"FAIL: {len(errors)} routing defect(s)")
            for error in errors:
                print(f"- {error}")
            return 1
        print(f"PASS: cost routing is valid: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
