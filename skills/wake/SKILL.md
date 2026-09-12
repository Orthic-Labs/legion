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

`/wake` is a bounded scheduled check. It is not a polling loop, an implicit retry
loop, or permission to continue a stopped task.

## Trigger & duration

Use for an active job, an external review, or goal-alignment mode when the user
wants a later check. Natural language such as “check again later”, “wake me when
it finishes”, or “keep this aligned” routes here. A numeric `wake N` (or `/wake N`)
means `N` minutes. `N` must be a positive integer; preserve the thread's local
timezone when presenting the next check time. Bare `/wake` defaults to a
five-minute heartbeat. Goal-alignment heartbeats repeat at five-minute bounded
checks unless the user explicitly selects another cadence.

Do not schedule a wake when there is no identifiable target, when target state is
already terminal, or after a stop, pause, revoke, or scope-narrowing instruction.

## Schedule exactly one next check

1. Resolve one mode: `active-job`, `external-review`, or `goal-alignment`.
2. Read current target state, user scope, exclusions, owner, deadline, retry
   budget, idempotency status, and current `intent_epoch` plus
   `continuation_epoch` when available.
3. Create or update one scheduled heartbeat on the active thread for now + `N`
   minutes. Bind it to the resolved target, mode, epochs, and a bounded prompt
   that says what one inspection must decide.
4. Return the scheduled time, mode, target, terminal conditions, and next action.

Reuse or update an existing wake for the same target instead of creating a
duplicate. Never emulate scheduling with `wait_threads`, sleep, a timer, a
watcher, or repeated tool calls in the current turn.

## What not to do

- Do not encode a relative wake as a timezone-less daily `BYHOUR`/`BYMINUTE`
  rule. Hosts may interpret that wall clock differently, leave automation
  `ACTIVE`, and never run expected check.
- Do not treat `ACTIVE` status or a rendered automation card as proof that a
  future occurrence exists. Verify scheduler reports one future run.
- Do not use a relative `COUNT=1` rule when scheduler consumes immediate
  occurrence at creation. If host has no reliable one-shot primitive, schedule
  supported relative recurrence whose first instruction deletes itself before
  inspection, then create only next bounded wake after observing target state.
- Do not report wake as scheduled until target thread ID, next occurrence, and
  self-cancel behavior are all observable.

## One-inspection wake protocol

Each heartbeat performs one state inspection, records observed evidence, and then
chooses one outcome. It must not poll again during that wake.

### Evidence floor

A status label, worker state, or elapsed-time estimate alone is never an
inspection. Inspect only evidence needed to decide the next acceptance outcome
or blocking dependency:

1. The latest worker state, messages, receipts, failures, & completed outputs.
2. Relevant bounded diffs, artifacts, or command/test/build/delivery evidence
   for that acceptance outcome. Build a full changed-file inventory only when
   the acceptance criterion requires it.
3. Remaining work reconstructed from latest user requests, corrections,
   exclusions, active plan, & unresolved acceptance criteria.
4. Relevant host-visible desktop/task artifacts when available; record
   `unavailable` rather than infer unseen state.

Compare with the prior wake & name material deltas. If no evidence changed,
report that exact fact quietly; never substitute shallow `running`, `active`, or
`complete` labels for inspection.

| Observed state | Action |
| --- | --- |
| Still running | Schedule the next bounded wake only while the next acceptance outcome remains unresolved & target stays active; suppress unchanged-status notification, and stop. |
| Completed successfully | Check requested acceptance against evidence, continue the workflow, and cancel the wake if terminal. |
| Completed with failure | Retry only when failure is transient, retry is safe/idempotent, and declared budget remains; otherwise stop & report. A retry gets its own bounded next wake. |
| Missing, stale, or ambiguous | Do not claim completion. Preserve evidence, schedule one next check only while target remains active & within bounds, or report a blocker when it cannot safely continue. |
| Stopped, paused, revoked, or scope-narrowed | Cancel/suppress continuation immediately; preserve artifacts and do not reschedule. |

Completion means observed success, not merely elapsed time, quota progress, or
worker silence.
Never retry destructive or non-idempotent work without an explicit safe retry
rule. Never convert an exhausted retry budget into a new budget silently.
An unchanged running state is quiet: use the host's non-notifying heartbeat
result when available. Notify only for completion, failure, divergence, blocker,
or another state change that needs action.

## External-review mode

Inspect the review once for all three properties:

- **Active:** reviewer/worker exists, has an owner, and has observable current
  state or a valid bounded handoff.
- **Bounded:** scope, acceptance, deadline, retry limit, and next action are
  explicit; no open-ended “keep watching” instruction is enough.
- **Non-divergent:** work still serves the latest user request and exclusions;
  no unauthorized file, product, or policy scope has appeared.

If any property fails, stop automatic continuation, preserve evidence, and report
the exact failed property. Do not repair a divergent review by inventing scope.

## Goal-alignment mode

Compare latest user instructions (including corrections & exclusions) with
active plan, scheduled work, changes, & proposed next action. This is a user
compliance check, not a progress or quota estimate. Carry corrections forward
into the next inspection & act within existing authorization. If aligned, keep
the same bounded target. If divergent, self-correct within explicit scope:
cancel or suppress irrelevant continuation, retain useful artifacts, and set the
next action to the latest request. Do not resurrect a revoked goal or add a new
goal. If self-correction would change ownership, external effects, or acceptance,
stop & report the decision needed.

## Result contract

Return a compact `WAKE_RESULT` containing:

```text
mode: active-job | external-review | goal-alignment
observed_at: <timestamp>
state: running | succeeded | failed | ambiguous | stopped
evidence: <relevant paths, IDs, or user-confirmed observations>
changed_files: <relevant bounded delta or none; full inventory only when required>
agents: <new messages, outputs, failures, or unchanged>
completed_behavior: <current proof or none>
next_acceptance: <next outcome or blocking dependency>
remaining_work: <latest-scope acceptance items>
desktop_artifacts: <observed artifacts or unavailable>
action: <one action taken or explicitly none>
next_wake: <timestamp, cancelled, or none>
```

Do not claim a future check has happened. A scheduled heartbeat is a continuation
mechanism, not completion evidence.
