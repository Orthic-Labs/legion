#!/bin/sh
set -eu
python release/surface.py
case "$TARGET" in
  macos) sh release/signing/macos.sh ;;
  windows) pwsh -File release/signing/windows.ps1 ;;
  *) echo "unsupported target" >&2; exit 2 ;;
esac
