#!/usr/bin/env python3
"""Compatibility validator for typed Legion task packets; never a hook."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


VALIDATOR = Path(__file__).with_name("validate-dispatch.py")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packets", nargs="+", type=Path)
    parser.add_argument("--packet-type", choices=("authority", "worker"), default="authority")
    parser.add_argument("--receipt-mode", choices=("write", "verify"), default="write")
    parser.add_argument("--receipt-dir", type=Path)
    args = parser.parse_args()

    for packet in args.packets:
        packet = packet.resolve()
        if not packet.is_file():
            print(f"FAIL: packet file not found: {packet}", file=sys.stderr)
            return 2
        receipt_dir = (args.receipt_dir or packet.parent).resolve()
        receipt = receipt_dir / f"{packet.stem}.receipt.json"
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(packet), "--packet-type", args.packet_type,
             f"--{args.receipt_mode}-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
