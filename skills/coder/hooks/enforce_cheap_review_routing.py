"""Retired compatibility hook.

Native graph, SEO, & commit review routing is intentionally left alone. `/coder` is explicit opt-in
and owns its bounded Pi CLI invocation; no Agent spawn is intercepted here.
The file remains as a harmless compatibility target for old local installs.
"""
import sys


def main() -> int:
    return 0


if __name__ == "__main__":
    sys.exit(main())
