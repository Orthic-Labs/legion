---
name: sentry-method
---

# Sentry method — mechanical watchdog supervision

Use Sentry only for a user-requested cadence. That request authorizes registering the cadence with
an existing host scheduler. Do not build a scheduler, runtime, or persistence framework, or create
a chat. A schedule is independent only when its existing scheduler can fire outside the supervised
executor chat even if that executor stalls; a separate chat alone is not scheduling. An explicitly
invoked subagent may execute one checkpoint, but recurring supervision requires an independent scheduler. If no
such scheduler is available, report the watchdog as unscheduled; do not emulate it with sleep,
polling, or executor self-reminders. Run a due checkpoint only on a scheduler-fired wake; a host goal or
auto-continuation turn is not a wake.

At setup, record target identity, requested cadence (`wake 15` means fifteen minutes), requested
Oracle CLI/provider/model, feedback authorization, baseline/approval evidence, and exclusions. Check
existing host schedules once; deduplicate by objective, target, and cadence. Record schedule
identity/configuration when available. If host scheduling is unavailable, report unscheduled.
Maintain isolated state per target: full baseline reference/content, transcript cursor, per-item
acceptance evidence/current state/remaining work, unresolved directives, current in-flight review,
and due/checkpoint outcomes. One shared loop may service targets, but each target has at most one
review in flight. Record overlap; never duplicate or catch up missed wakes as a burst.

## Authority packet

Before review, preserve the exact approved baseline content in a form Oracle can read, its content
identity/digest, the original human approval quote and stable transcript anchor, plus every later
human-authored amendment verbatim with anchor and affected items. A digest identifies content; it
does not replace or prove access to content. A path, mutable file, handoff label, agent plan, peer
claim, or scheduler prompt is not approval. Original human turns establish approval and amendments;
recommendations require explicit human adoption. Preserve unaffected baseline items. If exact
approved content or authority cannot be recovered, send `UNKNOWN` for affected scope and do not
ask for fresh approval merely because evidence recovery remains unfinished.

## Due checkpoint

Collect raw original user requests, accessible baseline and approval evidence, anchored amendments,
events since that target's cursor, current resulting-state evidence, prior unresolved findings, and
intended claims. Summaries are pointers only. Oracle may inspect underlying sources; do not expose
private reasoning, secrets, or hidden evaluator rubrics to an executor. Launch one fresh read-only
Oracle review with requested provider/model; preserve observed identity and never silently fall
back. Quota, overlap, missing transcript access, timeout, and scheduler failure are recorded as
mechanical outcomes, not semantic DRIFT.

Oracle owns all semantic verdicts. Oracle must return its findings to Sentry, not message an
executor directly. If correction is needed, Oracle supplies a separate executor-safe directive,
authored for that executor and distinct from any reviewer-only report. Sentry sends that directive
verbatim, with directive ID, Oracle attribution, source/model, and target. Sentry must not paraphrase,
soften, or expose hidden rubrics. Send only to an explicitly authorized destination; otherwise
return the attributed result to the caller.

For every directive, record its ID, delivery receipt or failed attempt, exact executor response and
anchor (or absence), resulting-state evidence, and Oracle disposition at a later checkpoint. A
response is not a correction or resolution. Carry every unresolved directive and its full evidence
record into the next packet. Oracle alone closes a finding, using resulting-state evidence. Do not
issue force commands, unauthorized retries, or implementation commands.

Escalate factually to the user after two consecutive due checkpoints with the same unresolved
Oracle `DRIFT` directive, or no executor response after successful delivery; also escalate after
two consecutive due delivery failures. A user-set threshold overrides this default. Count only due
checkpoints. Quota blocks, overlaps, missed wakes, and other mechanical failures do not increment
semantic DRIFT counts. Sentry reports the evidence and threshold reached; it does not make a semantic
verdict.

Record requested and observed wake times, actual Sentry provider/model, and actual Oracle
provider/model for each due checkpoint. Record missed, quota-blocked, timed-out, and failed wakes
from host evidence. Do not silently fall back, retry in a loop, or send unchanged status pings.
Continue until explicit user stop or Oracle returns evidence-backed `COMPLETE` against the exact
approved baseline and valid amendments. Do not stop because a subtask closes, a lead appears
inactive, or a narrow hold occurs. A pause is a control state, not completion. Ask for user input
only when an actual missing decision is required; missing evidence alone remains `UNKNOWN`.
