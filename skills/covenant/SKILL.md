---
name: covenant
description: Convene Legion's optional independent challenge chamber for a named decision, work artifact, blocker, or packet-only review preparation. Use /covenant.
kind: entrypoint
discoverability: explicit
target: challenge:covenant
operations:
  - analyze
  - evaluate
  - produce
effects:
  - source-read
hostRequirements: []
---

# Covenant

PRIMARY_DELIVERABLE: Digest-bound Covenant request, record, or packet-only artifact.
CHILD_AGENTS_MAX: 8
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

This entrypoint builds the review packet from `assets/external-review-packet-template.md`, shaped by
`lib/schemas/covenant-request-v1.schema.json` and `covenant-record-v1.schema.json`, and convenes seats
under `doctrine/covenant-seat.md`. The old Python and JS packet engine no longer exists; the one
native tool is `legion script covenant/validate-external-review-packet`, which validates an
external-review packet. It is advisory: it neither grants
product authorization nor closes Oracle findings.

1. Use decision challenge for a named decision or work artifact; use blocker consult for a named
   execution blocker. Covenant never creates a prerequisite authority route.
2. Keep independent seats read-only and isolate their views within each stage.
3. Revalidate source revision and packet digest at each gate; changed subjects stale prior verdicts.
