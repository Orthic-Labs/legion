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
hostRequirements:
  - python-runtime
---

# Tasklist

This public entrypoint routes durable validation to package-local `lib/dispatch-validator`; it owns no second validator.

1. Freeze current state, target state, scope, constraints, & completion proof. Then emit exact numbered next actions now; every action names exact repository-relative or absolute file paths it may touch, or `PATHS: none`.
2. For inline work, each numbered action gives elapsed-clock span, exact action, dependency (`START` or prior step IDs), parallel lane (`LANE <id>` or `SERIAL`), done check, expected result, evidence path, & bounded recovery. Parallelize every independent action; serialize only concrete dependency. Start step 1 when execution was requested.
3. Maintain one-touch path ledger: every planned changed file appears exactly once with owner, operation, lane, & final check. No unlisted file edits, broad directory ownership, hidden cleanup, or integrator repair edits.
4. Before submission, obtain fresh adversarial subagent review of exact next actions, path coverage, dependency order, maximum safe parallelism, scope, & completion proof. Any change after review requires a fresh review.
5. For persistent or auditable work, read [durable workflow](references/durable-workflow.md), copy [template](assets/tasklist-template.md), & validate typed execution packet with `python3 skills/tasklist/scripts/validate-tasklist.py <packet.json>`. It writes a sibling receipt.
6. Keep direct same-agent scope. Route delegation to Dispatch, continuity to Handoff, & unresolved target design to Architect.
