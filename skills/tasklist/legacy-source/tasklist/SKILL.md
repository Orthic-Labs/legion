---
name: tasklist
description: Create a compact same-agent execution list or Codex goal. Use `/tasklist`; default inline, persist only when requested. Use Dispatch for delegation & Handoff for session continuation.
---

# Tasklist

```text
MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Inline same-agent execution list.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Ordered list names verified end state & next action.
```

Default output is inline, not a document.

1. State current condition, desired condition, scope, constraints, & proof of completion.
2. State the scope inputs before the number: files touched, lines changed, lines-per-minute rate,
   & fixed overhead. The total is `round(lines / rate) + overhead` — show it, never assert it from
   feel, never give a low/high range. Files & lines are also the plan's ceilings; breaching either
   stops work for a report.
3. Write each step as an elapsed-clock span counted from minute 0 — `0–2`, `3–20`, `21–45` —
   never a duration ("15 min") & never a range ("15–25 min"). Spans cover the whole total &
   parallel lanes overlap on that one clock.
4. Parallelize independent steps by default; a step that must run serially states why it blocks
   the next.
5. Give each step an action, done check, expected result, & recovery path.
6. Start step 1 immediately when user asked to execute.

Create files only when user explicitly requests persistence, audit receipts, or a reusable task
record. Then read [durable workflow](references/legacy-durable-workflow.md), use
[template](assets/tasklist-template.md), & run:

`python3 tools/skills/tasklist/scripts/validate-tasklist.py <tasklist.md> --write-receipt <receipt.json>`

Do not turn same-agent work into dispatch, handoff, architecture design, or project-management
ceremony.
