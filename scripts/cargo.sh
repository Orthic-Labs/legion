#!/usr/bin/env bash
# Run cargo through managed RightKit when it is installed (developer machines,
# where direct cargo is denied by policy), and directly otherwise (CI runners,
# which have no RightKit). Package scripts call this instead of either.
set -euo pipefail
if command -v rightkit >/dev/null 2>&1; then
  exec rightkit cargo "$@"
fi
exec cargo "$@"
