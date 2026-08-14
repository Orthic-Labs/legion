---
name: alchemist
description: Execute a settled, bounded change through Legion's Alchemist authority. Use /alchemist after scope, ownership, checks, and acceptance are decided.
---

# Alchemist

MODE: EXECUTE
PRIMARY_DELIVERABLE: Contract-conformant repository state with focused verification.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write, focused_check, child_packet
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Declared checks pass, or an exact blocker is reported.

This entrypoint routes to Legion's existing Alchemist authority. It does not own execution
infrastructure or create a second contract system.

1. Require settled scope, ownership boundaries, acceptance criteria, and focused checks.
2. Route implementation to Alchemist; it applies bounded work and escalates undecided design,
   ownership, or boundary questions to Sage.
3. Re-run declared checks against actual changed source before reporting completion.
