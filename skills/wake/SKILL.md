---
name: wake
description: Schedule one bounded wakeup for an active job, external review, or goal-alignment check; inspect once per wake, stop polling, & continue only from observed state.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - analyze
  - execute
  - produce
effects:
  - source-read
  - artifact-write
hostRequirements: []
---

# Wake

`/wake` schedules one bounded later inspection. It is not polling, an implicit retry loop, or
permission to continue stopped work.

## Trigger & duration

Use for an active job, external review, or goal-alignment check when user wants a later inspection.
`wake N` means `N` minutes; bare `/wake` defaults to five minutes.

Do not schedule when target is missing or terminal, or after user stops, pauses, or revokes it.
Scope narrowing cancels only work outside remaining authorization; continue authorized in-scope work.

## Choose event or schedule

1. Use an existing completion/event wait for an active job when host can notify on state change.
2. Use a scheduled wake for a later time-based follow-up or alignment check.
3. Create/update exactly one next check bound to target & one question: what changed toward requested
   outcome, & what useful action remains authorized?
4. Report scheduler-observed next occurrence. Never claim timing, execution, or deadline enforcement
   that host has not exposed.

Reuse existing wake for same target. Never emulate scheduling with sleep or repeated short polls.

## Truthful scheduling

- Do not encode relative wake as timezone-less daily wall-clock rule.
- Do not treat `ACTIVE` status or rendered card as proof of a future occurrence.
- Do not promise exact wake timing from requested cadence; report observed execution time after it runs.
- A hard stop requires host-enforced timeout. Heartbeat prose does not enforce a deadline.

## One-inspection protocol

Each wake performs one inspection, takes one useful authorized action when needed, & stops. It never
polls again during same wake.

Inspect only evidence needed for next acceptance outcome or blocker: latest state/output, relevant
bounded diff/artifact/check evidence, & remaining work from current user scope. Compare prior wake.
If nothing changed, stay quiet when host supports non-notifying results.

| Observed state | Action |
| --- | --- |
| Still running | Use event wait or schedule next bounded wake only while unresolved; suppress unchanged notification. |
| Completed successfully | Verify requested acceptance, continue authorized workflow, & cancel wake when terminal. |
| Completed with failure | Retry only when transient, safe/idempotent, & within declared budget; otherwise report exact blocker. |
| Missing/stale/ambiguous | Preserve evidence; schedule one bounded recheck only while active & useful. |
| Stopped/paused/revoked | Cancel continuation. |
| Scope narrowed | Cancel excluded work; continue only work remaining inside authorization. |

Completion means observed success, not elapsed time, quota progress, or worker silence. Never retry
destructive or non-idempotent work without explicit safe retry rule. Never silently replace exhausted
retry budget. Notify only for completion, failure, divergence, blocker, or action-requiring change.

## Review & alignment

For external review, check that work remains active, bounded, & aligned. For goal alignment, compare
current plan/action with latest user instructions & exclusions. Carry corrections forward, cancel
divergent continuation, & perform bounded correction within remaining authority. Never invent scope.

## Result

Report only:

```text
observed_at: <timestamp>
change: <material observed change or none>
action: <useful authorized action taken or none>
blocker: <remaining blocker or none>
next_check: <scheduler-observed time, event wait, cancelled, or none>
```

Do not claim a future check happened. Scheduled heartbeat is continuation mechanism, not evidence.
