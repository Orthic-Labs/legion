---
name: dispatch
description: Create a validated zero-context work packet for another agent or executor while current orchestrator retains responsibility. Use for dispatch, delegation, parallel workers, or copy-paste executor instructions. Same-agent execution uses tasklist; session continuation uses handoff.
---

# Dispatch

```text
MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Validated zero-context dispatch packet.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One packet names scope, checks, recovery, ownership, & evidence.
```

Use dispatch only when another executor adds isolation, parallelism, machine access, or focused
ownership. Keep same-agent work inline or in `tasklist`.

1. Ground request, nearest rules, exact source paths, dirty state, & live routing config.
2. Freeze objective, scope, non-goals, authority, reserved decisions, dependencies, & owner.
3. Copy [template](assets/dispatch-template.md) to declared durable path.
4. Give each step exact cwd, command/action, expected result, evidence, & bounded recovery.
5. Define acceptance as executable checks; define `TRUE_BLOCKER` as exhausted recovery plus proof.
6. Run validator & bind receipt:

   `python3 tools/skills/dispatch/scripts/validate-dispatch.py <packet.md> --write-receipt <receipt.json>`

7. Return packet path, receipt path, executor identity, & integration owner.

Read [advanced manual](references/manual.md) only for experiments, benchmarks, semantic
corrections, multi-agent ownership graphs, paid tools, generated scripts, or complex recovery.

Never write `as discussed`, rely on unseen chat, delegate user-reserved decisions, or call blocked
work complete.
