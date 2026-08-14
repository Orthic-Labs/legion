#!/usr/bin/env bash
# Alchemist worker (Mac/Linux) — bash port of run-worker.ps1, same invocation contract.
# The brief arrives on stdin so shell quoting cannot damage it.
#
#   printf '%s' "$BRIEF" | run-worker.sh <profile> [timeout_seconds] [event_log_path]
#
# stdout: worker assistant text · stderr: progress + EVENT_LOG= path
# Exit: 0 ok · 2 usage · 4 gateway down · 5 unknown profile · 124 timeout
#
# Contract (verified 2026-08-09 on both machines — do not "simplify" these):
#   * --model is REQUIRED. Without it Codex sends its own default model, OmniRoute
#     resolves that to the unconnected `codex` provider and 404s.
#   * NEVER add --ignore-user-config. It discards ~/.codex/config.toml, which holds
#     both the profile and [model_providers.omniroute]; Codex then silently falls
#     back to the ChatGPT account and fails with an OpenAI-side error.
#   * launch-codex does NOT inject the provider table — it must exist in config.toml.

set -uo pipefail

PROFILE="${1:-}"
TIMEOUT="${2:-900}"
EVENT_LOG="${3:-}"
GATEWAY="${OMNIROUTE_URL:-http://127.0.0.1:20128}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$PROFILE" ]; then
  echo "usage: run-worker.sh <profile> [timeout_seconds] [event_log_path]  (brief on stdin)" >&2
  exit 2
fi

PROFILE_FILE="${CODEX_HOME_DIR}/${PROFILE}.config.toml"
if [ ! -f "$PROFILE_FILE" ]; then
  echo "No such Codex profile: $PROFILE_FILE" >&2
  echo "Available:" >&2
  ls -1 "${CODEX_HOME_DIR}"/*.config.toml 2>/dev/null | sed 's#.*/##; s/\.config\.toml$//; s/^/  /' >&2
  exit 5
fi

# Pull the model id out of the profile — same regex intent as the PowerShell runner.
MODEL="$(sed -nE 's/^[[:space:]]*model[[:space:]]*=[[:space:]]*"([A-Za-z0-9._:/-]+)".*/\1/p' "$PROFILE_FILE" | head -1)"
if [ -z "$MODEL" ]; then
  echo "No safe model value in profile: $PROFILE_FILE" >&2
  exit 5
fi

CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${GATEWAY}/healthz" 2>/dev/null || true)"
case "$CODE" in
  200|204|301|302|307|401) ;;
  *) echo "OmniRoute not reachable at ${GATEWAY} (healthz=${CODE:-none}). Start it: omniroute serve" >&2
     exit 4 ;;
esac

BRIEF="$(cat)"
if [ -z "${BRIEF// }" ]; then
  echo "Empty brief on stdin — refusing to spawn a worker with no task." >&2
  exit 2
fi

if [ -z "$EVENT_LOG" ]; then
  RUN_DIR="${ALCHEMIST_RUN_DIR:-$HOME/.alchemist/runs}"
  mkdir -p "$RUN_DIR"
  EVENT_LOG="${RUN_DIR}/$(date +%Y%m%d-%H%M%S)-${PROFILE}.jsonl"
else
  mkdir -p "$(dirname "$EVENT_LOG")"
fi

# macOS has no coreutils `timeout` by default; fall back to gtimeout, then to none.
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
fi

echo "── alchemist worker: profile=${PROFILE} model=${MODEL} timeout=${TIMEOUT}s events=${EVENT_LOG} ──" >&2
[ -z "$TIMEOUT_BIN" ] && echo "── note: no timeout binary found; running unbounded ──" >&2

run_worker() {
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$TIMEOUT" omniroute launch-codex --profile "$PROFILE" exec \
      --model "$MODEL" -c features.multi_agent=false --json -
  else
    omniroute launch-codex --profile "$PROFILE" exec \
      --model "$MODEL" -c features.multi_agent=false --json -
  fi
}

printf '%s' "$BRIEF" \
  | run_worker 2>>"${EVENT_LOG}.stderr" \
  | tee "$EVENT_LOG" \
  | python3 "${SCRIPT_DIR}/parse_events.py" --stream
STATUS=${PIPESTATUS[1]}

case $STATUS in
  0)   echo "── worker finished ──" >&2 ;;
  124) echo "── worker TIMED OUT after ${TIMEOUT}s; partial edits may exist — review git diff ──" >&2 ;;
  *)   echo "── worker exited ${STATUS} (see ${EVENT_LOG}.stderr) ──" >&2 ;;
esac

echo "EVENT_LOG=${EVENT_LOG}" >&2
exit $STATUS
