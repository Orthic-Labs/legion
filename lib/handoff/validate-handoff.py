#!/usr/bin/env python3
"""CLI compatibility wrapper for :mod:`validate_handoff`."""

from validate_handoff import main


if __name__ == "__main__":
    raise SystemExit(main())
