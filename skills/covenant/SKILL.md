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
hostRequirements:
  - legion
---

# Covenant

PRIMARY_DELIVERABLE: Digest-bound Covenant request, record, or packet-only artifact.
CHILD_AGENTS_MAX: 5
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

Covenant is Legion's optional independent challenge chamber. Its findings are advisory: they grant
no product authorization, seal nothing, and close no Oracle finding.

## Convener

The convener is the Legion main thread only. It convenes on the user's `/covenant`, or when Sage
returns a `COVENANT_REQUESTED: <decision>` line. No other agent, seat, or skill convenes Covenant,
and a seat never convenes a successor.

## Procedure

1. Build the request JSON per `lib/schemas/covenant-request-v1.schema.json`. Use DECISION_CHALLENGE
   for a named decision or work artifact, BLOCKER_CONSULT for a named execution blocker. Embed the
   real artifact and the user's verbatim request; Covenant never creates a prerequisite authority route.
2. Run `legion script covenant/digest <request.json|->` and store the printed digest as `packetDigest`.
3. Choose 3 seats (never more than 5). Give each seat exactly one lens from `references/lenses/`
   (index: `references/lenses/README.md`) and embed that lens text in the seat prompt.
4. Launch the seats in parallel as `subagent_type: legion:covenant-seat` with `fork_turns: "none"`.
   Each seat sees only the packet and its own lens, never another seat's output, and stays read-only.
5. Assemble the record per `lib/schemas/covenant-record-v1.schema.json`, then run
   `legion script covenant/validate-record <record.json> --request <request.json>`. Exit 0 is valid,
   1 is invalid, 2 is usage. Revalidate source revision and packet digest at each gate; a changed
   subject makes a prior verdict stale.
6. Return the record to the caller (the decision owner), who dispositions every finding and records
   each disposition. Covenant never dispositions its own findings.

## Degradation

If the `legion:covenant-seat` agent is unavailable, record DEGRADED and stop. Never simulate seats
inline, and never claim independence for a single-agent run.

## PACKET_ONLY

For packet-only review preparation, fill `assets/external-review-packet-template.md` and validate it
with `legion script covenant/validate-external-review-packet`. This mode runs no seats and produces
no record or outcome.
