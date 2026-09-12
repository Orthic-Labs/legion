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
handoff goes to Alchemist. Oracle review is used when explicitly requested or justified by concrete
outcome/safety risk; Covenant is only a one-shot advisory escalation. Execution derives a
file/artifact task DAG from actual consumption only for genuinely parallel or governed work,
launches maximal ready antichains where useful, and never copies a stage DAG into execution.
Routine work may remain inline. Only shared contract writes, integration, commits, pins, and
pushes serialize. Constitution, authority, scope, acceptance, and completion semantics remain
owned by the canonical sources above.

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
conditional independent review when explicitly requested or justified by concrete risk
    ↓
delivery
```

Natural-language routing is performed by the always-on Legion orchestration model from the
compact catalog in context. The deterministic runtime validates selected IDs and resolves
explicit aliases only; it does not interpret prose. Domains are grouping metadata only and never
decide routing. Slash aliases remain deterministic.

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
