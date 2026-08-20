---
name: tasklist
description: Create an executable same-agent task list. Use `/tasklist`; keep it inline unless persistence, audit receipts, or a reusable record is requested. Use Dispatch for another agent & Handoff for a new chat.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - analyze
  - produce
  - execute
effects:
  - source-read
  - artifact-write
  - process-exec
hostRequirements: []
---

# Tasklist

This public entrypoint routes durable validation to package-local `lib/dispatch-validator`; it owns no second validator.

1. Freeze current state, target state, scope, constraints, & completion proof.
2. For inline work, give elapsed-clock spans, action, done check, expected result, & recovery. Parallelize independent steps. Start step 1 when execution was requested.
3. For persistent or auditable work, read [durable workflow](references/durable-workflow.md), copy [template](assets/tasklist-template.md), & validate typed execution packet with `python3 skills/tasklist/scripts/validate-tasklist.py <packet.json>`. It writes a sibling receipt.
4. Keep direct same-agent scope. Route delegation to Dispatch, continuity to Handoff, & unresolved target design to Architect.
