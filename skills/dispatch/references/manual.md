# Dispatch manual

Default to one compact typed `direct` packet for bounded delegation. It carries objective,
authority sources, integration owner, model route, exact non-overlapping worker scopes, checks,
dependencies, bounded recovery, & return fields. Validate it in `authority` mode; no GoalRoute,
timing model, Minimize receipt, or author checklist is required for ambient bounded work.

Use legacy Markdown only when compatibility is explicitly requested. Locked or explicitly
contracted work uses its governing contract chain rather than enlarging an ambient dispatch
packet.

## Zero-context relay (lossless)

A dispatch packet must carry the full context an executor needs, verbatim — never a compressed
digest. Executor must succeed without chat history, dispatcher memory, or unstated judgment.

Iron law:

```text
NO AGENT TASK SHIPS UNTIL:
1. target can execute it from zero context;
2. every expected failure has a bounded next action;
3. completion is proven by named evidence;
4. TRUE_BLOCKER requires exhausted recovery + proof;
5. script-bearing work passes the execution-preflight tool with executable evidence;
6. validate-dispatch.py returns PASS.
```

Clear prose is not executable. A referenced plan is not transferred context. A command without
cwd, expected result, failure branch, & evidence path is incomplete.

## Step 0 — Decide whether dispatch should exist

Dispatch only when delegation adds useful parallelism, isolation, machine access, or focused
execution. Keep orchestration, architecture, synthesis, tiny edits, & user-reserved decisions in
current session. When the request explicitly asks for dispatch, create it. Compactness never
removes required fields.

## Step 1 — Ground task before writing

Read: user request (including granted authority & reserved decisions); nearest `AGENTS.md` /
workspace rules; exact source documents, plans, files, errors, & current state; relevant skill
bodies or runbooks the executor must follow; current scoped Git status for edit tasks; live
launcher/model/tool/API/environment config when routing can drift.

Never write "use existing context", "as discussed", "follow plan", or equivalent. Cite exact
accessible paths + required sections. Embed essential facts which exist only in chat.

## Step 2 — Design ownership & dependency graph

For each executor define: one outcome; `OWN` paths it may edit; `READ` paths it may inspect;
`FORBIDDEN` paths/actions; upstream inputs; downstream consumer; dependency position; whether
parallel-safe; integration owner.

Multiple agents receive separate complete dispatches. Never give overlapping `OWN` scopes.
Serialize shared-state edits, builds, installs, renders, deploys, migrations, paid calls, &
production writes. If independence is uncertain, investigate first. Do not dispatch ambiguity.

## Step 3 — Author from required template

Copy `assets/dispatch-template.md`. Fill every placeholder. Use exact paths, commands/tool
actions, cwd, expected outputs, checks, artifacts, & limits. Every execution step must answer:
why does this step exist; what exact inputs it consumes; where it runs; what exact command or tool
action runs; what stdout/state + exit/result proves success; what timeout + retry bound applies;
where outputs + evidence are stored; what happens for each failure. If command differs by OS,
provide both branches & selection rule.

## Step 4 — Build failure-complete recovery

Include all failure classes below, even when response is "not applicable — reason": path/input
missing; tool/dependency missing; auth/permission failure; transient external failure;
invalid input/schema; integrity/hash mismatch; deterministic command failure; dirty/conflicting
state; wrong producer/provenance; resource/capacity failure; ambiguous requirement;
unsafe/out-of-scope action; unknown failure. Each failure row needs: primary recovery branch;
second executable branch; degraded/independent continuation; retry/stop bound; exact proceed
condition; exact TRUE_BLOCKER threshold.

Recovery ladder, in order: re-read exact error & failing artifact; re-discover paths/config from
live workspace; re-run smallest deterministic reproduction; apply smallest in-scope correction;
retry transient failure within declared limit; use documented existing fallback with equivalent
acceptance criteria; split failed step so unaffected work continues; escalate only under
TRUE_BLOCKER law.

## Step 5 — Enforce TRUE_BLOCKER law

Executor may return `TRUE_BLOCKER` only when all are true: requested outcome cannot advance
safely; blocker is external or non-inferable (missing secret/private input, unavailable required
service/hardware, explicit user-reserved decision, unauthorized destructive/production action, or
unavoidable conflict with preserved user work); every applicable recovery action ran; all
independent safe work completed; blocker packet includes exact failed step, commands/actions
attempted, raw error, evidence paths, state preserved, single missing input, & exact resume
command.

If any condition is false, executor continues. `PARTIAL`, `NEEDS_CONTEXT`, & vague `BLOCKED` are
forbidden terminal statuses.

## Step 6 — Make acceptance executable

Map each requirement to: exact verification command/action; expected value, threshold, schema,
visual state, or hash; evidence artifact path; responsible owner. "Tests pass", "looks correct",
"reviewed", & "done" are not evidence without command/output or artifact. Delegated work is not
proof of completion; dispatcher/integrator reruns relevant final checks after integration.

## Step 7 — Zero-context simulation

Before dispatch, simulate a fresh executor encountering: source path missing; dirty checkout;
required tool absent; auth failure; transient timeout/rate limit; invalid schema/input;
hash/integrity mismatch; existing run from wrong producer; missing producer/provenance proof;
incomplete expected→started→terminal→delivery→value chain; direct closure/synthetic stand-in;
deterministic test failure; partial output/checkpoint; unsafe next action; conflicting
instructions; no safe degraded path. For each, the dispatch must identify next action, retry
bound, evidence, & escalation threshold without asking the dispatcher to reconstruct intent.

Any "no" means revise.

## Step 8 — Validate before sending

Write dispatch to a durable, named `.md` artifact before validation. Temporary-only & inline-only
dispatches are forbidden. Validate:

```bash
python3 skills/dispatch/scripts/validate-dispatch.py <dispatch.md> --write-receipt <dispatch.receipt.json>
```

Do not spawn/send until exit code is `0` and output begins `PASS:`. Receiver recomputes digest
before execution:

```bash
python3 skills/dispatch/scripts/validate-dispatch.py <dispatch.md> --verify-receipt <dispatch.receipt.json>
```

Embedded self-hash is forbidden (changing the document to add its hash changes the hash); the
sidecar binds exact bytes without circularity.

## Executor return & integration contract

Require exactly: `STATUS` (`COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER`), `SUMMARY`,
`ACCEPTANCE` (criterion → command/check → result → evidence path), `ARTIFACTS`, `CHANGES`,
`COMMANDS`, `RECOVERY`, `DEVIATIONS`, `BLOCKER`, `NEXT`.

`COMPLETE_WITH_NOTES` still requires every acceptance criterion to pass; notes are non-blocking
observations only.

## Worker output is untrusted

Delegated work is never proof of completion. The integrator reruns the relevant final checks in
the primary checkout after integration and requires a reachable canonical commit or
content-addressed patch before archive. Clean read-only tasks archive freely.

## Experiment / correction / lifecycle work

For a corrected objective: stop affected work, preserve old outputs as evidence-only, re-derive
from current authority, & reject incompatible resume. For a selection workload: use ordered
survivor stages, assign every fixture one stage, prohibit broad selectors, declare
`JOB_TOTAL_MAX` plus wall-time floor, run one trace before batch, & reconcile actual counts. A
`TRUE_BLOCKER` requires `RECOVERY_EXHAUSTED`, `INDEPENDENT_WORK_COMPLETE`, `RAW_EVIDENCE`,
`MISSING_INPUT`, & `RESUME_COMMAND`.

## Boundaries

Dispatch is an orchestration entrypoint, not peer domain expertise. It never delegates a
user-reserved decision, never ships a packet that depends on unseen chat, and never runs beside a
second executor for the same scope. The orchestration boundary belongs to `doctrine/legion.md`;
the deterministic mechanics belong to the dispatch validator and contracts runtime.
