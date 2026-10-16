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
hostRequirements:
  - rightkit-owns
---

# Alchemist

PRIMARY_DELIVERABLE: Requested repository state with declared checks passing.
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Worker returns bounded edits & blockers; root verifies declared checks before delivery.

Contracts, events, and checkpoints apply only where the work is governed — a locked domain,
an explicit contract, or a Sage freeze handoff. Ordinary bounded implementation runs ambient:
the operator's settled request is the authorization, and routine decisions inside acceptance
criteria stay with the executor.

Cancellation is explicit owner action only. Model text narrating an intent to stop, or a user
message that merely questions or pauses work, must never be inferred as cancellation — only a
direct owner instruction to cancel/stop does.

This entrypoint routes to Legion's existing Alchemist authority. It does not own execution
infrastructure or create a second contract system.

Legion attaches Alchemist above capability selection & delegation. Execute through host-native
agents with host-supported model tiers. This entrypoint needs no external model gateway,
provider profiles, or package-local worker launcher. See `references/manual.md` for assignment
& return requirements.

1. Require settled scope, exact OWN/READ/FORBIDDEN paths & writable allowlists, acceptance criteria, and root-owned focused checks; a plan that touches a RightKit capability also carries its `RightKit Capabilities` block from `rightkit owns --compact`.
   EXECUTOR:
     semantic: required
     capabilities:
       - repository-truth-read
       - source-read
2. Route implementation to an edit-only Alchemist worker on primary checkout. Permit bounded
   read-only inspection; prohibit Cargo, tests, builds, generators, installs, commits, pushes,
   merges, heavy checks, post-merge verification, worktrees, & branches. Escalate changed
   requirements, public boundaries, or material tradeoffs to Sage.
   EXECUTOR:
     semantic: conditional
     capabilities:
       - structured-text-edit
       - architecture-reasoning
3. Return changed paths, source result, & blockers. Root integration alone runs declared checks
   on primary checkout after all coding completes, then verifies requested delivery state.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - process-exec
       - source-read
