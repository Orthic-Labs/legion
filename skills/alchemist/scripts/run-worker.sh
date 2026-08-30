#!/usr/bin/env bash
# Alchemist worker (Mac/Linux) — bash port of run-worker.ps1, same invocation contract.
# The brief arrives on stdin so shell quoting cannot damage it.
#
#   printf '%s' "$BRIEF" | run-worker.sh <profile> [timeout_seconds] [event_log_path]
#
# stdout: worker assistant text · stderr: progress + EVENT_LOG= path
# Exit: 0 ok · 2 usage · 4 gateway down · 5 unknown profile · 124 timeout
#
# Contract (verified 2026-08-09 against a live OmniRoute gateway — do not "simplify" these):
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

# macOS has no coreutils `timeout` by default; use gtimeout when available, then
# enforce the same bound with the shell when neither binary is installed.
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
fi

echo "── alchemist worker: profile=${PROFILE} model=${MODEL} timeout=${TIMEOUT}s events=${EVENT_LOG} ──" >&2
[ -z "$TIMEOUT_BIN" ] && echo "── note: no timeout binary found; using the shell watchdog ──" >&2

run_worker() {
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$TIMEOUT" omniroute launch-codex --profile "$PROFILE" exec \
      --model "$MODEL" -c features.multi_agent=false --json -
    return $?
  fi

  # Keep the worker and watchdog state beside the event log.  mkdir gives this
  # invocation an exclusive, dependency-free state directory without relying
  # on mktemp or a non-POSIX timeout implementation.
  WATCHDOG_DIR="${EVENT_LOG}.watchdog.$$"
  if ! mkdir "$WATCHDOG_DIR" 2>/dev/null; then
    echo "Unable to create shell watchdog state: $WATCHDOG_DIR" >&2
    return 4
  fi
  WORKER_PID_FILE="${WATCHDOG_DIR}/worker.pid"
  WORKER_DONE_FILE="${WATCHDOG_DIR}/worker.done"

  # The wrapper owns the actual launcher child.  Its trap forwards TERM and
  # waits for that child, so the watchdog can escalate to KILL without leaving
  # the launcher behind when TERM is ignored.
  (
    child_pid=""
    trap 'if [ -n "${child_pid:-}" ]; then kill -TERM "$child_pid" 2>/dev/null || :; wait "$child_pid" 2>/dev/null || :; fi; exit 143' TERM INT HUP
    omniroute launch-codex --profile "$PROFILE" exec \
      --model "$MODEL" -c features.multi_agent=false --json - &
    child_pid=$!
    printf '%s\n' "$child_pid" > "$WORKER_PID_FILE"
    wait "$child_pid"
    worker_status=$?
    printf '%s\n' "$worker_status" > "$WORKER_DONE_FILE"
    rm -f "$WORKER_PID_FILE"
    exit "$worker_status"
  ) &
  worker_pid=$!

  # Put sleep in its own child so the watchdog can be terminated and reaped
  # cleanly when the worker finishes before the deadline.
  (
    sleep_pid=""
    stop_watchdog() {
      if [ -n "${sleep_pid:-}" ]; then
        kill -TERM "$sleep_pid" 2>/dev/null || :
        wait "$sleep_pid" 2>/dev/null || :
      fi
      exit 143
    }
    trap stop_watchdog TERM INT HUP
    sleep "$TIMEOUT" &
    sleep_pid=$!
    wait "$sleep_pid"
    sleep_status=$?
    [ "$sleep_status" -eq 0 ] || exit 143

    # A completed worker writes this marker before it exits.  This avoids
    # treating a just-reaped normal exit as a timeout at the boundary.
    if [ -f "$WORKER_DONE_FILE" ]; then
      exit 0
    fi

    child_pid=""
    if [ -f "$WORKER_PID_FILE" ]; then
      child_pid="$(cat "$WORKER_PID_FILE" 2>/dev/null || :)"
      case "$child_pid" in
        ''|*[!0-9]*) child_pid="" ;;
      esac
    fi
    kill -TERM "$worker_pid" 2>/dev/null || :
    if [ -n "$child_pid" ]; then
      kill -TERM "$child_pid" 2>/dev/null || :
    fi
    # Give TERM a short grace period, then force both wrapper and launcher.
    sleep 1
    if kill -0 "$worker_pid" 2>/dev/null; then
      kill -KILL "$worker_pid" 2>/dev/null || :
    fi
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || :
    fi
    exit 124
  ) &
  watchdog_pid=$!

  wait "$worker_pid"
  worker_status=$?
  if [ -f "$WORKER_DONE_FILE" ]; then
    # Normal completion: stop and reap the watchdog, including its sleep.
    kill -TERM "$watchdog_pid" 2>/dev/null || :
    wait "$watchdog_pid" 2>/dev/null || :
    rm -rf "$WATCHDOG_DIR"
    return "$worker_status"
  fi

  # Timeout path: let the watchdog finish its TERM/KILL sequence, then reap
  # it before returning the documented timeout status.
  watchdog_status=0
  wait "$watchdog_pid" 2>/dev/null || watchdog_status=$?
  rm -rf "$WATCHDOG_DIR"
  [ "${watchdog_status:-0}" -eq 124 ] && return 124
  return "$worker_status"
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
