---
name: compshop
description: Compare repositories from source through independent inventory, consolidation, and reconciliation passes. Use /compshop for a function-first comparison matrix.
---

# CompShop

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Source-grounded comparison matrix or reconciled report.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Requested stage produces its bounded comparison artifact.

This entrypoint routes to existing CompShop workflow; it does not create a parallel comparison
registry or certification system.

1. Select one stage: independent inventory, report-only consolidation, or source reconciliation.
2. Preserve uncertainty and unique findings; source alone proves reconciliation claims.
3. Return one function-first matrix and stop after an adversarial self-review.
