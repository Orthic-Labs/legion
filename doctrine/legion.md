# Legion — routing and orchestration reference

**Status:** delegated routing/orchestration reference doctrine. Constrained by
`docs/LEGION-CANONICAL-SSOT.md` (root architecture SSOT) and `AGENTS.md` (live operational
constitution).

This file does **not** own:

- Legion identity, authority, or constitution (owned by `AGENTS.md`);
- system architecture or ownership boundaries (owned by the root SSOT);
- role identity, authority boundary, or model policy (owned by `src/roster/*.md`);
- any external unpublished "operator source" constitution (none outranks the shipped canon).

It may describe:

- routing reference;
- capability composition;
- work-graph reference;
- authority attachment;
- dispatch/handoff relationships.

## Handoff reference

Legion routes work by capability descriptions and explicit authority invocation. A frozen Sage
handoff goes to Alchemist. Oracle reviews any work Legion did not produce itself; Council is only an explicit, advisory escalation (at most two loops). Execution derives a
file/artifact task DAG from actual consumption only for genuinely parallel or governed work,
launches maximal ready antichains where useful, and never copies a stage DAG into execution.
Routine work may remain inline. Only shared contract writes, integration, commits, pins, and
pushes serialize. Constitution, authority, scope, acceptance, and completion semantics remain
owned by the canonical sources above.

## Role selection reference

Every delegated assignment names its role as the host subagent type (`legion:alchemist`,
`legion:oracle`, `legion:sage`, `legion:sentry`), never in prose: Alchemist for any assignment that writes files,
runs commands with effects, or produces an artifact; Oracle for independent review or verification
of someone else's work; Sage for design, adjudication, or reassessment. Generic agents
(`general-purpose`, `Explore`) are permitted only for read-only lookup that produces no artifact.
Sentry is only for explicitly requested cadence collection and transport; Oracle retains all
semantic judgment. `legion:council-seat` only while Legion executes `/council`.

Capability selection is positive: when the requested result is prose for a reader, a visual/UI, a
repository-quality verdict, or a research synthesis, select `writing`, `designer`, `audit`, or
`research` and load its REQUIRED_READS before producing. Inline production without the capability is
the exception & must be named.

Legion decides whether authority is needed before selecting Dispatch or another capability.
Use each canonical roster's Triggers table; explicit role requests take precedence over routine-work
exclusions. Sage closes material unresolved meaning, Alchemist executes any assignment that writes files, runs commands with effects, or produces an
artifact, & Oracle examines any independent review or verification of others' work. Contracts stay
limited to locked or explicit work; attaching a role never opens one.
Dispatch transports assignments; it neither selects authority nor grants it.

Resolve role registration & model compatibility against effective host configuration before launch.
If a host forbids inherited models, provide an explicit compatible model through its native launch
argument. Keep roster tiers vendor-neutral; never silently downgrade required judgment or skip
requested authority to satisfy a host gate. Surface a rejected launch with its observed reason,
repair compatible configuration when authorized, then retry within existing bounds.

Codex projections preserve explicit role model/settings. Sage & Oracle receive a generated
`read-only` sandbox setting, which constrains local filesystem effects; runtime or parent
overrides may reapply, and this setting does not establish that MCP tools are denied, so Guard
remains responsible for typed effect gates. Otherwise each role takes its tier's `codex` model
from `src/config/model-tiers.json` (Council seats use `deliberation`), falling back to configured
parent/subagent defaults only when a tier has no entry. Exact model names live in that
file & host configuration, never in roster prose; configuration alone still proves neither model
availability nor tier compatibility.

Configuration presence proves registration only. Record selected, bound, launched, or skipped from
observed events; launched requires host acceptance, & skipped requires a reason. Eligibility labels
remain independent of observed launches. Missing evidence stays unknown. Trace v2 carries these
decisions; legacy v1 carries no adoption label. Compare labelled replays before changing triggers;
measure eligible launches, unnecessary launches, eligible skips, pending work & unknown launches.

## Orchestration boundary

Dispatch is Legion's fresh-context delegation primitive; ordinary work uses an inline assignment. Its governed
deterministic mechanics live in `skills/dispatch/**` and the dispatch-validator/contracts
runtime. The bounded-execution substrate (typed terminals, numeric budgets, same-failure stop,
checkpoints/resume, receipts, worker-output distrust) applies to explicitly governed work,
including locked or contracted work and long-running work designated for resumable control. Cost,
difficulty, retry risk, or delegation alone does not require contracts or independent review.

Use the least nondeterministic authorized executor capable of satisfying each node contract.
“Mechanical” does not mean “cheap model”: a settled mechanical task is a zero-model task unless
semantic interpretation is genuinely required. Legion may use its mechanism-aware host binding or
Alchemist for bounded implementation; Alchemist retains routine judgment inside settled acceptance
criteria without turning ordinary work into governed execution.

## Routing shape

`/session` is an explicit compatibility entrypoint for status, init, brief, context-hygiene, and
file-search methods. It is not a semantic router or a new state owner: Legion reports task status
from current conversation/evidence and routes substantive work normally; Arcane owns context and
response shaping. Installed-client health belongs to the native Legion setup-status operation,
while project scaffolding belongs to native `legion init`. File search uses scoped `rg` and optional
`sg`; it does not invoke Blueprint by default. `/handoff` alone owns explicit new-chat transfer, and
Session does not require durable handoff notes.

Legion owns semantic capability selection, operation/effect derivation, authority attachment, &
orchestration. Arcane shapes cognitive processing & response policy only; Guard gates declared
typed effects, reports enforcement health, & owns effect-decision receipts.

```text
USER INTENT
    ↓
LEGION — semantic classification over the compact canonical catalog
    ↓
0..N capabilities / internal entrypoints
    ↓
WORK GRAPH — operations, effects, dependencies, authority only where required
    ↓
the Guard gates declared effects
    ↓
execution / integration
    ↓
independent review of work Legion did not produce itself
    ↓
delivery
```

Natural-language routing is performed by the always-on Legion orchestration model from the
compact catalog in context. The deterministic runtime validates selected IDs and resolves
explicit aliases only; it does not interpret prose. Domains are grouping metadata only and never
decide routing. Resolve explicit legacy slash commands with `legion skills resolve <slash-command>
[args...]`; M1 CLI and MCP invocation share this release-bound exact resolver before body loading.
Slash aliases remain deterministic, and native host commands are not emulated.

Capability work may take this conditional path:

```text
capability work
    │
    ├─ material unresolved decision? → Sage → settled work
    │
    └─────────────────────────────────────────┘
                                  ↓
                             execution
```
