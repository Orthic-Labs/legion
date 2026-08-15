---
name: dispatch
description: Create a validated zero-context work packet for another agent or executor while current orchestrator retains responsibility. Use for delegation, parallel workers, or copy-paste executor instructions. Same-agent work stays inline; session continuity uses handoff.
---

# Dispatch

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Validated zero-context dispatch packet.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Packet has scope, checks, recovery, ownership, & receipt-backed evidence.

1. Freeze objective, authority, exact OWN/READ/FORBIDDEN paths, dependencies, integration owner, acceptance checks, & bounded recovery.
2. Copy `assets/direct-packet.json` to declared packet path, then add one worker object per independent owner. Never add GoalRoute, timing, Minimize, or author-gate ceremony unless work is locked, contracted, or Adrian explicitly requests it.
3. Validate with `python3 legion/skills/dispatch/scripts/validate-dispatch.py <packet> --packet-type authority --write-receipt <receipt>`.
4. Return packet path, receipt, executors, integration owner, & `TRUE_BLOCKER` only after bounded recovery evidence.

Use `assets/dispatch-template.md` with `--packet-type legacy` only for explicit legacy compatibility. Read `references/manual.md` for experiment, correction, or lifecycle work. Read `references/agent-routing.md` for authority routing. Never rely on unseen chat or delegate user-reserved decisions.
