---
name: jfdi
description: Request exact work through host-issued bounded execution. Use for `/jfdi`, "just fucking do it", "just do it", "stick to the script", no tangents, or minimum-ceremony execution with fixed deliverables, paths, checks, & budgets.
---

# JFDI — Just Fucking Do It

MODE: EXECUTE
PRIMARY_DELIVERABLE: Requested change plus frozen check results.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write, focused_check
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Declared checks pass, then render final response.
POST_GREEN_DENIAL: RUN_COMPLETE_FINAL_REQUIRED

Execute exact request with minimum process.

1. Require a task manifest stated in the host request before first effect or check: task id,
   allowed paths, declared checks, & fixed budgets (files, bytes, lines, active seconds). No
   manifest, no effect.
2. Copy explicit tasks literally; never turn findings into tasks.
3. Use only manifest paths, declared writes, and frozen focused checks. rhook enforces Brief,
   Minimize, model caps, & safety guards at the tool layer; debug a gate, never bypass one.
4. Make smallest correct change.
5. Record material unrelated findings as `OUT_OF_SCOPE`; do not investigate or fix them.
6. Stop when checks pass. Do not run final audit, cleanup sweep, docs sync, Council, Cortex,
   Forge debugging, dispatch, tasklist, handoff, postmortem, commit, or follow-up unless
   named in manifest.

The manifest outranks this skill and every other procedure. No skill may add files, checks,
agents, research, tools, or acceptance criteria beyond it.

A failed declared check permits bounded repair for that check only. New scope reaches
`NEEDS_AMENDMENT`; exhausted budget reaches `BUDGET_STOP`. Evidence failure never expands work.

Cross-machine work is a separate concern from local task scope: it gates on commit identity via
`tools/sync-gate.py`, not on this manifest — see `docs/rules/bounded-execution.md`.

If the manifest is missing or ambiguous, stop before effectful work & report exact missing host
input.

`/jfdi off` is explicit owner cancellation only: host transitions to `USER_CANCELLED`,
revokes tools, and renders state. Model text cannot infer cancellation.
