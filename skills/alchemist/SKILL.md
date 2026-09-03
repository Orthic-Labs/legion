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
  - omniroute
  - python-runtime
---

# Alchemist

PRIMARY_DELIVERABLE: Contract-conformant repository state with focused verification.
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Declared checks pass, or an exact blocker is reported.
POST_GREEN_DENIAL: RUN_COMPLETE_FINAL_REQUIRED

REQUIRES_HOST_CAPABILITY: omniroute (worker execution path only)

Declared checks passing ("green") is not itself completion — the final required run/render step
must still execute & be observed before the contract closes.

Cancellation is explicit owner action only: it transitions the run to the `CANCELLED` invocation
state, revokes tools, & renders that state. Model text narrating an intent to stop, or a user
message that merely questions or pauses work, must never be inferred as cancellation — only a
direct owner instruction to cancel/stop does.

This entrypoint routes to Legion's existing Alchemist authority. It does not own execution
infrastructure or create a second contract system.

The packaged worker scripts under `scripts/` are an **adapter** for one specific host: a local
OmniRoute gateway plus a Codex CLI profile set. They are not Legion's general execution path and
must not be treated as one. Probe for the `omniroute` capability before using them; if it is
absent, report Alchemist as unavailable on that path rather than returning an empty result. The
routing contract above holds regardless of which host executes it.

1. Require settled scope, ownership boundaries, acceptance criteria, and focused checks.
   EXECUTOR:
     semantic: required
     capabilities:
       - repository-truth-read
       - source-read
2. Route implementation to Alchemist; it applies bounded work and escalates undecided design,
   ownership, or boundary questions to Sage.
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
