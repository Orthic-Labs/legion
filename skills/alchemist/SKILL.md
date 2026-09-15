---
name: alchemist
description: Execute a settled, bounded change through Legion's Alchemist authority. Use /alchemist after scope, ownership, checks, and acceptance are decided.
kind: entrypoint
discoverability: explicit
target: authority:alchemist
operations:
  - execute
effects:
  - source-read
  - repository-write
  - process-exec
hostRequirements: []
---

# Alchemist

PRIMARY_DELIVERABLE: Requested repository state with declared checks passing.
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Declared checks pass, or an exact blocker is reported.

Contracts, events, and checkpoints apply only where the work is governed — a locked domain,
an explicit contract, or a Sage freeze handoff. Ordinary bounded implementation runs ambient:
the operator's settled request is the authorization, and routine decisions inside acceptance
criteria stay with the executor.

Cancellation is explicit owner action only. Model text narrating an intent to stop, or a user
message that merely questions or pauses work, must never be inferred as cancellation — only a
direct owner instruction to cancel/stop does.

This entrypoint routes to Legion's existing Alchemist authority. It does not own execution
infrastructure or create a second contract system.

The packaged worker scripts under `scripts/` are an **adapter** for one specific host: a local
OmniRoute gateway plus a Codex CLI profile set. They are not Legion's general execution path and
must not be treated as one. Their host requirements are adapter-scoped in
`references/route-resources.json`: a host that never selects the adapter needs neither the
`omniroute` command nor `python-runtime`. When the adapter is selected and its probe fails,
report that adapter as unavailable — host-native Alchemist execution is unaffected.

1. Require settled scope, ownership boundaries, acceptance criteria, and focused checks.
   EXECUTOR:
     semantic: required
     capabilities:
       - repository-truth-read
       - source-read
2. Route implementation to Alchemist; it applies bounded work and escalates changed
   requirements, public boundaries, or material tradeoffs to Sage.
   EXECUTOR:
     semantic: conditional
     capabilities:
       - structured-text-edit
       - architecture-reasoning
3. Re-run declared checks against actual changed source before reporting completion.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - process-exec
       - source-read
