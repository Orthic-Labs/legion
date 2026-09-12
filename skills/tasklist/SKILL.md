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

1. Freeze current state, target state, scope, constraints, & completion proof. Then emit concise numbered next actions now.
2. For inline work, each action states the action, necessary dependency (`START` or a prior step), & completion check. Include paths, expected result, or evidence when known and helpful. Parallelize independent actions & serialize concrete dependencies. Start step 1 when execution was requested.
3. For explicit contract or locked-domain/effect work, use exact path allowlists, one-touch ownership, bounded recovery, & governing evidence. Ordinary inline work may iterate within accepted scope; do not impose a ledger or repair ban on it.
4. Ordinary inline plans need no packet, receipt, adversarial review, timing formula, line-rate estimate, or invented ETA. Use [durable workflow](references/durable-workflow.md) only for an explicit contract or locked-domain/effect requirement.
5. Keep direct same-agent scope. Route delegation to Dispatch, continuity to Handoff, & unresolved target design to Architect.
