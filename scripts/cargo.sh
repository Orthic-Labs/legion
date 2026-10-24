#!/usr/bin/env bash
# Run cargo through managed RustRight when it is installed (developer machines,
# where direct cargo is denied by policy), and directly otherwise (CI runners,
# which have no RustRight). Package scripts call this instead of either.
set -euo pipefail
if command -v rustright >/dev/null 2>&1; then
  exec rustright cargo "$@"
fi
exec cargo "$@"
