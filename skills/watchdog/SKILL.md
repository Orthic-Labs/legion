---
name: watchdog
description: Invoke Legion Sentry for explicitly requested recurring supervision or a due watchdog checkpoint using independent host scheduling and read-only Oracle review.
kind: entrypoint
discoverability: explicit
target: workflow:watchdog
operations:
  - execute
  - produce
effects:
  - source-read
  - artifact-write
hostRequirements:
  - host-scheduler
---

# Watchdog — Sentry invocation

`/watchdog` is an explicit entrypoint for Legion's Sentry role. It does not judge progress,
implement fixes, certify completion, or create monitoring infrastructure. Read Sentry's identity,
boundaries, and embedded Method from package role card `../../agents/sentry.md`.

Use only exact human-approved baseline content and later explicit human amendments as scope
authority. Preserve each approval quote and stable transcript anchor, plus every amendment quote
and anchor. A digest identifies content; Oracle must be able to read the full baseline. If recovery
is incomplete, report `UNKNOWN` for affected scope; do not infer approval or ask for fresh approval
when only evidence recovery is pending.

Register cadence only with an existing host scheduler that can fire outside the supervised
executor chat. A separate chat, subagent, or executor heartbeat is not independent scheduling. Do
not build scheduler, runtime, or persistence machinery, and do not create chats. If no qualifying
scheduler is available, report `UNSCHEDULED`. An explicitly invoked subagent may perform one
checkpoint, never recurring supervision.

Keep state isolated per target: baseline and authority anchors, transcript cursor, acceptance
evidence, unresolved directives, in-flight review, delivery record, and checkpoint outcome. Allow
one review in flight per target and no catch-up burst. Preserve requested and observed wake time,
actual Sentry model, and requested and observed Oracle provider/model. Record delivery, Oracle
directive verbatim with attribution, exact executor response and anchor or absence, resulting
evidence, and later Oracle disposition. A response is not resolution.

Launch one fresh read-only Oracle review at each due checkpoint. Oracle owns every semantic verdict
and supplies any executor-safe corrective directive. Relay that directive verbatim only to an
explicitly authorized destination; otherwise return the attributed result to the caller. Preserve
requested Oracle provider/model and never silently fall back. Report mechanical and escalation
facts only; never infer progress, scope, acceptance, drift, or completion. Escalate only at the
thresholds and with the evidence defined in Sentry's embedded Method.
