---
name: alchemist
description: Transformation authority — execute a bounded executable contract, apply EXACT artifacts faithfully, mechanically repair failures, escalate real blockers, self-audit the diff, and delegate to cheap workers under cost routing. Use for /alchemist, or to implement/apply/wire/propagate an already-decided change.
disable-model-invocation: true
---

# Alchemist — cheap-worker delegation

MODE: EXECUTE
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
PRIMARY_DELIVERABLE: Contract-conformant repository state plus self-audit evidence.
EFFECT_PROFILES: source_read, output_write, focused_check, child_packet
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Declared checks pass and self-audit is clean, or a typed blocker/stop is reported.

Authority doctrine lives in `.claude/agents/alchemist.md` (execution loop, mechanical-repair
boundary, blocker protocol, retry fingerprints, terminal states). This skill owns only the
delegation mechanics.

1. Require a valid `ExecutionContract` before any effect: `open_questions == []`, named scope
   (own/read/forbidden), declared checks, acceptance criteria. No contract, no effect.
2. Route by cost (ARCHITECTURE §6a): EXACT and narrow-BOUNDED units go to a cheap worker under
   a strict profile; wide BOUNDED work goes one tier up, because rework outcosts the tier gap.
   Never let a model self-select its profile.
3. Spawn a worker with the brief on **stdin**, never on the command line:
   - Windows: `Get-Content -Raw <brief-file> | & run-worker.ps1 -Profile <p> -TimeoutSeconds <n> [-WorkDir <dir>]`
   - Mac: `run-worker.sh <profile> [timeout] [event_log]`
   Both require `--model` resolution from the profile and a reachable OmniRoute gateway; exit
   codes: 0 ok · 2 usage · 4 gateway down · 5 unknown profile · 124 timeout.
4. `parse_events.py --summary <log>` shows only what the worker *claims*. Worker output is
   untrusted (G16): read the full `git diff` yourself and re-run the declared checks before
   accepting any unit. A worker's say-so is never proof.
5. At most two correction rounds per unit. Revert out-of-scope hunks and say why. On timeout,
   review `git diff` for partial edits before retrying.
6. Never print gateway keys or tokens. Never `git push`.
7. Report: what changed, which checks you re-ran yourself, what you rejected, and any blocker
   or budget stop with its exact missing input.

`references/manual.md` and `model-catalog.json` define profiles and delegation in full; read
the manual before a session's first delegated run.
