# Alchemist — manual

Detail behind `SKILL.md`.

## Visible relay architecture

Alchemist uses two layers:

1. Host calls `collaboration.spawn_agent` once per independent lane. This native relay is what
   Codex shows in Subagents UI.
2. Relay invokes `run-worker.ps1` or `run-worker.sh`; isolated CLI sends routed-model request to
   OmniRoute.

Relay itself inherits host OpenAI model. Routed implementation model runs only behind its nested
isolated CLI. This preserves native visibility without pretending third-party model is directly
hosted by Codex. When native spawn tool exists, direct host-to-runner invocation is prohibited.

Use `fork_turns=none` to keep relay context small. Give relay complete zero-context brief plus
profile, workdir, timeout, event-log path, acceptance criteria, non-goals, and verification.

## Aliases → Codex profiles

| Alias | Model | Profile | Use for |
|---|---|---|---|
| `mimo` | `opencode-go/mimo-v2.5` | `mimo` | general implementation |
| `mimo-pro` | `opencode-go/mimo-v2.5-pro` | `mimo-pro` | harder changes, xhigh reasoning |
| `flash` *(default)* | `opencode-go/deepseek-v4-flash` | `opencode-go-deepseek-v4-flash` | general implementation |
| `m3` | `minimax/MiniMax-M3` | `minimax-minimax-m3` | long context (1M) |

Confirm before spawning: `ls ~/.codex/<profile>.config.toml`. Regenerate the set with
`omniroute setup-codex --only "minimax/,opencode-go/,cp/cline-pass"`.

**Rotation is the gateway's job, not this skill's.** Do not write failover in script. Create an
OmniRoute combo (`omniroute combo create <name> --strategy round-robin`, needs the gateway key),
generate one profile for it, and pass that profile. Fixed aliases stay available for reproducible
runs.

## Invocation contract

The runners call `omniroute launch-codex --profile <p> exec --model <id> -c
features.multi_agent=false --json -`. Three rules, each learned from a real failure:

- **`--model` is required.** Omit it and the CLI sends its own default model; OmniRoute resolves
  that to the `codex` provider, which is not connected → `404 No active credentials for provider:
  codex` at `/v1/responses`. The runners extract the id from the profile's `model = "..."` line.
- **Never pass `--ignore-user-config`.** It discards `~/.codex/config.toml`, which holds both the
  profile and `[model_providers.omniroute]`, defeating the injection. The CLI then silently falls
  back to the ChatGPT account and fails with *"The '<model>' model is not supported when using
  Codex with a ChatGPT account"* — an OpenAI-side error, easily misread as a model problem.
- **`launch-codex` does not inject the provider table.** `[model_providers.omniroute]` must
  already exist in `~/.codex/config.toml` or you get `Model provider 'omniroute' not found`.

## Preconditions

1. Gateway healthy — the runners probe `/healthz` (**not** `/health`, which 404s). If it is
   unreachable, stop and say so; never silently do the work yourself instead.
2. The named profile file exists.
3. Repo is a git worktree. Record `git status --porcelain` first — pre-existing dirt must be
   excluded from the review or the diff is unattributable.

## Runner differences

`run-worker.ps1` (Windows) builds an **isolated `CODEX_HOME`** containing only the provider table,
profile, and model catalog, then passes `--dangerously-bypass-approvals-and-sandbox --cd <dir>`.
The operator accepts this full-host trust boundary when managed Windows workers stay read-only.
limits concurrency with named mutexes (`ALCHEMIST_MAX_CONCURRENT`, default and maximum 10), and fails when the
launcher emits zero JSON events. Isolation matters: without it the worker loads every configured
MCP server and skill, and a trivial turn costs ~75k input tokens.

`run-worker.sh` (Mac) is a simpler port — no isolated home, sandbox, or `--cd` yet. It falls back
to `gtimeout` when GNU `timeout` is absent, and when neither binary exists it enforces the same
bound with a shell watchdog: a wrapper owns the launcher child and forwards `TERM`, the watchdog
escalates `TERM` then `KILL`, and a timeout exits `124`. The bound is always enforced — stock macOS
ships neither binary, and the previous unbounded fallback meant a wedged worker ran forever.

Both write raw JSONL to `~/.alchemist/runs/<timestamp>-<profile>.jsonl` (override with
`ALCHEMIST_RUN_DIR`), emit assistant text on stdout, and put activity plus the final `EVENT_LOG=`
path on stderr.

## Event parsing

`parse_events.py` handles both `--stream` (live) and `--summary <log>`. Codex `--json` nests the
payload under `item`: `{"type":"item.completed","item":{"type":"agent_message","text":…}}` — a
parser assuming `msg` sees nothing. `classify()` is shared with `viewer.py`, so the live page and
the CLI summary can never disagree.

## Review discipline

The summary reports what the worker **claims**. Read every hunk of the real `git diff` against the
checkpoint, re-run the verification commands yourself, and confirm the non-goals held. Two
correction rounds maximum — beyond that, stop and report, because repeated failure is signal.
