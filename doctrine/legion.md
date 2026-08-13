# Legion — role doctrine reference

> **Canon owner:** `docs/agent-rules/legion.md` is the sole source for Legion identity, authority, routing & scope constitution (see `doctrine/architecture/canon-map.md` §37A). This file owns **role-routing reference** only — it references the constitution, never duplicates it. Do not edit constitution text here; edit `docs/agent-rules/legion.md` and run `python3 tools/agent-rules/manage.py sync` if needed.

**Canonical source:** `docs/agent-rules/legion.md` + `docs/agent-rules/workspace.md` → generated `AGENTS.md`/`CLAUDE.md` via `tools/agent-rules/manage.py`.

**This file's scope:** how Legion routes to Sage/Alchemist/Oracle/Arcane/Covenant per the constitution — no duplicated identity, scope, or invariant text. For full authority see the canonical source and `doctrine/architecture/canon-map.md`.

**Related map:** `doctrine/architecture/canon-map.md` — concept → source_owner, generated_consumers, runtime_producer, conformance_checks.

> **Historical:** prior version of this file duplicated the constitution verbatim — archived via this reference to eliminate dual ownership (Stage 1 S01-04).

## Handoff reference

Legion routes a frozen Sage handoff to Alchemist, then an independent Oracle packet; Covenant is
only a one-shot advisory escalation. It derives a file/artifact task DAG from actual consumption,
launches the maximal ready antichain, & never copies a stage DAG into execution. Only shared
contract writes, integration, commits, pins, & pushes serialize. Constitution, authority, scope,
acceptance, & completion semantics remain owned by canonical sources above.
