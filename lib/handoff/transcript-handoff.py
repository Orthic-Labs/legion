#!/usr/bin/env python3
"""CLI compatibility wrapper for :mod:`transcript_handoff`."""

from transcript_handoff import main


if __name__ == "__main__":
    raise SystemExit(main())
