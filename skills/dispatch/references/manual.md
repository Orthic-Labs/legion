# Dispatch manual

Default to one compact inline assignment for bounded delegation. It must carry
the current objective, authority, scope, exclusions, bounded worker paths or
modules, relevant evidence, expected result, & root integration action. Start workers
with `fork_turns: "none"`; pass bounded excerpts instead of full transcripts or
unbounded command output.

Use the durable contract path only when the user explicitly requests a contract
or when locked-domain/effect rules require it. Ordinary delegation does not
require a packet file or validator receipt. Oracle remains available for an
explicit review or a concrete outcome/safety risk.

## Decide whether dispatch helps

Dispatch only when delegation adds useful parallelism, isolation, machine
access, or focused execution. Keep tiny edits, orchestration, architecture,
synthesis, & user-reserved decisions in the current session. Do not delegate a
decision the user reserved.

## Build a bounded assignment

1. Read the current user request, applicable workspace/repository rules, exact
   source inputs, relevant errors, & scoped Git status. Pass only the excerpts
   the worker needs; never write “use existing context” or “as discussed.”
2. Define one end-to-end outcome per lane. Give lanes bounded non-overlapping
   file or module ownership. Use exact file allowlists, one-touch ledgers, &
   strict repair reassignment only when the governing contract requires them.
   Put independent lanes together & add dependencies only for concrete data,
   file, resource, or effect order.
3. State a repository-specific check policy. Workers inspect declared inputs &
   edit owned paths; they may run named focused checks when policy allows. In
   this public-CI run, workers are edit-only. They do not commit, push, merge,
   or perform unbounded/expensive checks unless accepted policy permits it.
4. Tell the integration owner to reconcile actual changed paths, integrate
   output, run required checkpoints, own final evidence, & repair or reassign
   within accepted scope. Governed contract work keeps strict allowlists & repair
   reassignment.

## Acceptance & authority

Name the actual acceptance surface, including requested platform, mode, install,
or user-facing readback when relevant. Shared compilation, input injection,
worker silence, or a relayed message is proxy evidence only. A relay carries
facts or results; it never grants user authority or expands scope. Re-check
authority against the current user request or governing contract before acting.

## Specialized experiment & lifecycle work

Apply these checks only when the assignment is an experiment, selection,
correction, or lifecycle run. Freeze State A/B, named decision metrics, provider,
dataset, mode, admission, pass, exclusions, workload, job ceiling, & value rule.
Use one canonical trace before batch work, ordered survivor stages with each
fixture assigned once, & reconcile actual launches against the ceiling. Bind
selected path, smoke, check, blast, ship, producer, lifecycle, delivery, &
user-value evidence when those stages are in scope.

Treat old progress, outputs, labels, paths, & producer claims as evidence only;
current authority decides. Reject incompatible runs, reset stale producers,
stop & globally rederive after a correction, remove inherited clauses with no
decision effect, reject invented ground truth or unrelated metrics, admit
downstream fixtures only after their stage, & treat runtime loadability as
runnability rather than behavioral qualification. Use a provider only when it
has a named acceptance metric. Offline logical work has no physical sleep. Full
comparison requires explicit authority.

## Recovery & blockers

For a failure, re-read the exact error, rediscover the relevant live path or
configuration, rerun the smallest deterministic reproduction, apply the
smallest in-scope correction, then retry only when safe and bounded. Continue
independent work when possible. A worker may return `TRUE_BLOCKER` only when the
requested outcome cannot safely advance because of an external or
non-inferable blocker, every applicable recovery ran, safe work is finished, &
the return names the failed action, raw error, evidence, preserved state, one
missing input, & exact resume action. `PARTIAL`, `NEEDS_CONTEXT`, & vague
`BLOCKED` are not completion statuses.

## Worker return & integration contract

Require a compact result with:

```text
finished: <requested work completed>
remaining: <acceptance items still open>
blocker: <none or exact bounded blocker>
evidence: <commands, outputs, or artifact paths>
commands: <actions run or none>
next: <root integration or reassignment action>
```

An incomplete or partial result is a handoff for continued work, not delivery.
The root agent reruns relevant checks after integration & verifies actual paths
against ownership before claiming completion.

## Durable contract path

When contract or locked-domain/effect rules apply, use the repository's
governing packet schema, validator, receipts, & review requirements. Keep exact
ownership, dependency order, worker boundary, bounded recovery, acceptance
evidence, & root integration ownership. Any packet edit requires its governing
validation and review to run again. Do not add those artifacts to ambient work.

Validate zero-context durable packets with `scripts/validate-dispatch.py <packet>`;
use `--write-receipt <receipt>` or `--verify-receipt <receipt>` when required.

Use `assets/dispatch-template.md` with `--packet-type legacy` only for explicit
legacy compatibility. Read `references/agent-routing.md` when authority routing
is needed. Never rely on unseen chat or delegate user-reserved decisions.
