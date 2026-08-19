# Legion — role doctrine reference

> **Canon owner:** the operator's agent-rules source is the **sole source** for Legion identity, authority, routing & scope constitution (see `doctrine/architecture/canon-map.md` §37A). This file owns **role-routing reference** only — it references the constitution, never duplicates it. Do not edit constitution text here; edit that source and regenerate this file from it.

**Canonical source:** an operator-supplied agent-rules source, generated into `AGENTS.md`/`CLAUDE.md` by that operator's own tooling. This package ships neither the source nor the generator.

**This file's scope:** how Legion routes to Sage/Alchemist/Oracle/Arcane/Covenant per the constitution — no duplicated identity, scope, or invariant text. For full authority see the canonical source and `doctrine/architecture/canon-map.md`.

**Related map:** `doctrine/architecture/canon-map.md` — concept → source_owner, generated_consumers, runtime_producer, conformance_checks.

> **Historical:** prior version of this file duplicated the constitution verbatim — archived via this reference to eliminate dual ownership (Stage 1 S01-04).

## Handoff reference

Legion routes a frozen Sage handoff to Alchemist, then requires independent Oracle completion
validation before every successful final delivery; Covenant is only a one-shot
advisory escalation. It derives a file/artifact task DAG from actual consumption, launches the
maximal ready antichain, & never copies a stage DAG into execution. Only shared
contract writes, integration, commits, pins, & pushes serialize. Constitution, authority, scope,
acceptance, & completion semantics remain owned by canonical sources above.
