---
name: tasklist
description: Create executable same-agent task lists, implementation plans, execution preflights, or automation plans. Use `/tasklist`; keep ordinary work inline. Use Dispatch for another agent & Handoff for a new chat.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - analyze
  - produce
  - execute
effects:
  - source-read
  - artifact-write
  - process-exec
hostRequirements:
  - legion
  - rightkit-owns
---

# Tasklist

The native `legion script` dispatcher remains its own interface. The `/script` skill alias selects this skill's **execution-preflight** mode.

The `legion script tasklist/validate-tasklist` route defaults to typed JSON `authority` or `worker` packets for governed work. Explicit `--packet-type legacy` validates historical Markdown timing before existing dispatch checks. This is not a validator for arbitrary inline plans; GoalRoute has its own validator. Do not require every `/tasklist` response to use a validator. See [validator scope](references/legacy-durable-workflow.md).

Select one mode from what the user requests. Modes compose when the work both needs a plan and will run a command or automation.

For every plan mode, resolve required inputs, setup, & decisions before dependent implementation;
show conditional dependencies on each step they can change; trace outputs into downstream inputs;
place final checks after all steps that contribute to them. Derive dependencies from consumed
outputs, shared write ownership, or required effect order; assistant-authored sequence adds no
permission gate. Independent ready work proceeds within real capacity, budget, ownership, &
safety limits, including coding while admitted builds queue or run.

## Inline tasklist mode

Use for ordinary same-agent work. Freeze the requested outcome, scope, constraints, & useful completion check, then give concise numbered actions. Each action names its dependency (`START` or a prior step) & an observable check when useful. Include exact paths when known; parallelize independent work. Start the first step when execution was requested.

Keep the list in chat unless persistence or a reusable record was requested. Ordinary work needs no packet, receipt, adversarial review, timing formula, line-rate estimate, or invented ETA. For explicit contract or locked-domain/effect work, follow [durable workflow](references/durable-workflow.md) & the governing typed-packet/receipt requirements. Inline Markdown is not natively validated.

## Execution-preflight mode (`/script` alias)

Use before running or handing over a nontrivial command, script, batch job, runner, or pipeline: anything scaled, long-running, remote, resource-intensive, paid, destructive, production-touching, or explicitly invoked with `/script` or “smoke it.” Skip this mode for a trivial read or known-safe one-line local action. The `/script` alias selects this mode; it does not replace or change the native `legion script` command dispatcher.

Before execution or handoff, inspect the exact intended environment and command path:

1. **Inputs & environment:** verify interpreter/tool versions, required dependencies, input existence/shape, output-directory writability, available space, required GPU or remote reachability, and required secret presence without revealing values. Check for an existing lock/process/progress state before starting a competing run.
2. **Exact-path smoke:** run the same entrypoint, working directory, environment, and relevant flags on a bounded sample, usually 2–5 items. Pick items that exercise useful boundaries where available. Show a real output example and check its content (schema, count, expected value, or equivalent), not mere process success. For destructive or production effects use a dry-run, sandbox, test data, or bounded safe canary; never damage live data as a smoke test.
3. **Effects & cost:** state relevant files read/written/deleted, network/services/accounts/datastores touched, and expected spend. Paid or resource-heavy work needs an enforceable hard cap or bounded limit before the run. Keep secrets out of command arguments and logs.
4. **Recovery & bounds:** set a timeout or wall-clock bound and visible progress/heartbeat for long work. For interrupted work, explain checkpoint/resume behavior; make retries idempotent or state how duplicate effects are prevented. Write outputs atomically when partial files could be mistaken for completed results. Distinguish retryable failures from fatal input/auth/schema/code failures.
5. **Efficiency:** check for avoidable duplicated work, safe overlap, and bounded concurrency when scale makes those relevant. Explain deliberate limits; do not add optimization ceremony to a trivial command.

If a required check cannot be performed, name missing evidence & withhold claims for affected
execution. Gate only affected operations & their actual dependents; continue unrelated authorized
work. Build admission still governs build launch, & final checks must verify their exact artifact.
A plan may identify next check. State only gates relevant to run risk & scale; this mode does not
require GoalRoute artifacts or receipts by default.

## Automation mode

Use when wiring recurring or event-driven work. First identify trigger, target, owner, steps/dependencies, command or pipeline, expected output, failure visibility, lifecycle evidence, and rollback/disable path. Inspect existing scheduler, hook, and pipeline owners and reuse their supported interfaces; do not invent a daemon, scheduler, CLI, or state store.

Before changing hook or automation configuration, read its current status through the owning status interface. Record the exact target, event/trigger, command, expected lifecycle evidence (including failure/skip state), and rollback/disable action. Smoke the supported path with a safe bounded input before enabling a recurring or broad effect. Apply execution-preflight checks for commands the automation will run, including bounds, effects, cost, resume, and idempotency when relevant. If no supported owner/tool is available, return a concrete design or manual procedure and say wiring was not performed.

## Implementation-plan mode

Use when asked for a plan from a spec or requirements. State the goal and acceptance checks, map exact files to their responsibilities, then write small tasks that can be checked independently. Name real dependencies, project-native checks, and expected outcomes; avoid file ownership overlap unless an explicit integration task owns it. Do not save a plan unless a durable artifact was requested. Self-review against the source for coverage, missing paths, placeholder steps, incompatible interfaces, and checks that do not prove the stated behavior. Route materially unresolved target design to Architect before treating the plan as settled.

## Boundaries

Keep direct same-agent scope. Route delegation to Dispatch, continuity to Handoff, and unresolved architecture to Architect. Ordinary inline work can adapt inside accepted scope; do not impose a ledger or repair ban. Durable contracts use only their governing records and validation path.
