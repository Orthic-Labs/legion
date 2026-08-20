---
name: dispatch
description: Create a validated zero-context work packet for another agent or executor while current orchestrator retains responsibility. Use for delegation, parallel workers, or copy-paste executor instructions. Same-agent work stays inline; session continuity uses handoff.
kind: entrypoint
discoverability: explicit
target: orchestration:dispatch
operations:
  - route
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
---

# Dispatch

PRIMARY_DELIVERABLE: Validated zero-context dispatch packet.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Packet has scope, checks, recovery, ownership, & receipt-backed evidence.

1. Freeze objective, authority, exact OWN/READ/FORBIDDEN paths, dependencies, integration owner, acceptance checks, & bounded recovery.
2. Copy `assets/direct-packet.json` to declared packet path, then add one worker object per independent owner. Never add GoalRoute, timing, Minimize, or author-gate ceremony unless work is locked, contracted, or the user/caller explicitly requests it.
3. Validate with `python3 skills/dispatch/scripts/validate-dispatch.py <packet> --packet-type authority --write-receipt <receipt>`.
4. Return packet path, receipt, executors, integration owner, & `TRUE_BLOCKER` only after bounded recovery evidence.

Use `assets/dispatch-template.md` with `--packet-type legacy` only for explicit legacy compatibility. Read `references/manual.md` for experiment, correction, or lifecycle work. Read `references/agent-routing.md` for authority routing. Never rely on unseen chat or delegate user-reserved decisions.
