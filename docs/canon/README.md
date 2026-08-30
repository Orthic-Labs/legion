# Legion atomic capability canons

Status: canonical capability-state index  
Updated: 2026-08-30

This directory is Legion's atomic product ledger. Each owned subsystem has one canon; this index contains no duplicate capability rows.

## Subsystem canons

| Subsystem | Canon | Owns |
|---|---|---|
| Legion | [legion.md](legion.md) | orchestration, integration, delivery, distribution |
| Sage | [sage.md](sage.md) | exceptional adjudication |
| Alchemist | [alchemist.md](alchemist.md) | controlled bounded transformation |
| Oracle | [oracle.md](oracle.md) | independent Completion Validation |
| Arcane | [arcane.md](arcane.md) | cognitive processing shape & response policy |
| Guard | [guard.md](guard.md) | deterministic effect enforcement |
| Covenant | [covenant.md](covenant.md) | bounded adversarial challenge |
| Skills | [skills.md](skills.md) | skill registry & projection infrastructure; each skill owns its semantics |

## Canon model

Only `COMMITTED` rows in each `Capability ledger` count as atoms. Every canon declares one required delivery boundary & keeps hierarchy, mechanisms, qualification, preservation, backlog, references, & exclusions outside capability totals.

Capability schema:

`ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence`

- `Parent` references a group ID from same canon.
- `Scope`: `COMMITTED`, `EXPLORATORY`, `BACKLOG`, `EXCLUDED`.
- `Implementation`: `MISSING`, `PARTIAL`, `DELIVERED`, `UNKNOWN`.
- `Verification`: `PENDING`, `FOCUSED_PASS`, `FAIL`, `STALE`, `UNKNOWN`.
- `Qualification`: `NOT_REQUIRED`, `PENDING`, `PASS`, `FAIL`, `STALE`, `UNKNOWN`.
- `Delivery`: `LOCAL`, `COMMITTED`, `PUSHED`, `RELEASED`, `UNKNOWN`.
- `Action`: planning metadata only; it never changes lifecycle state.
- `Evidence`: `PENDING` until an acceptance ID, exact material revision or receipt, & freshness marker exist.

Each canon also contains:

- a non-counted group ledger with explicit owner, scope, parent, & derived rollup;
- a non-counted implementation register whose targets must resolve to capabilities;
- a non-counted qualification ledger whose targets must resolve to capabilities;
- a non-counted decision register for `REFERENCE`, `EXCLUSION`, & `BACKLOG` dispositions.

Closure is derived only when implementation is `DELIVERED`, verification is `FOCUSED_PASS`, qualification is `PASS` or a recorded `NOT_REQUIRED`, delivery meets canon boundary, evidence is acceptance/revision/receipt/freshness bound, & no blocker contradicts row. Producer status never self-certifies closure.

## Ownership decisions

- Guard remains separate from Arcane. Guard owns typed effect enforcement & receipts; Arcane owns cognitive control.
- Five domains are Skills grouping metadata, not peer orchestrators or subsystems.
- Covenant seats are Covenant implementation, not independent subsystem owners.
- `src/packages/{context,contracts,kernel}` are implementation components under Legion-owned orchestration, not duplicate semantic owners.
- Public distribution & client integration remain Legion-owned.
- Historical deterministic-substrate & retired assurance-role planning names are provenance only; Oracle is current assurance owner.

## Derived pending work

[docs/pending/README.md](../../pending/README.md) is generated from open capability rows by `node scripts/check-atomic-canons.mjs --write`. Edit subsystem canons, never generated pending rows.

Historical pending inventory is preservation-mapped in [registers/preservation-map.md](registers/preservation-map.md). Any legacy row absent from this map, unresolved target, semantic ownership overlap, or stale evidence blocks reconciliation.
