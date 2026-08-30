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
handoff goes to Alchemist, then independent Oracle completion validation is required before every
successful final delivery; Covenant is only a one-shot advisory escalation. Execution derives a
file/artifact task DAG from actual consumption, launches the maximal ready antichain, & never
copies a stage DAG into execution. Only shared contract writes, integration, commits, pins, &
pushes serialize. Constitution, authority, scope, acceptance, & completion semantics remain owned
by the canonical sources above.

## Orchestration boundary

Dispatch is a Legion orchestration primitive for validated zero-context delegation packets. Its
deterministic mechanics live in `skills/dispatch/**` and the dispatch-validator/contracts
runtime. The bounded-execution substrate (typed terminals, numeric budgets, same-failure stop,
checkpoints/resume, receipts, worker-output distrust) applies where justified — dispatched,
governed, locked, contracted, expensive/retry-prone, or resumable long-running work — not to
ambient routine work.

Use the least nondeterministic authorized executor capable of satisfying each node contract.
“Mechanical” does not mean “cheap model”: a settled mechanical task is a zero-model task unless
semantic interpretation is genuinely required. Ambient cheap/mechanical execution belongs to
Legion’s mechanism-aware host binding, not to Alchemist, which stays the controlled
bounded-transformation authority.

## Routing shape

```text
USER INTENT
    ↓
LEGION — semantic classification over the compact canonical catalog
    ↓
0..N capabilities / internal entrypoints
    ↓
WORK GRAPH — operations, effects, dependencies, authority only where required
    ↓
Arcane gates declared effects
    ↓
execution / integration
    ↓
Oracle Completion Validation under current policy
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
