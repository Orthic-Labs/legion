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
| Skills | [skills.md](skills.md) | packaged capabilities & entrypoints |

## Required capability schema

Only `Capability ledger` rows count as atoms. Every subsystem uses:

`ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence`

- `Parent` references a group ID from that file's non-counted group register.
- `Scope`: `COMMITTED`, `PROPOSED`, `EXCLUDED`.
- `Implementation`: `DELIVERED`, `PARTIAL`, `MISSING`, `UNKNOWN`.
- `Verification`: `FULL_PASS`, `FOCUSED_PASS`, `PENDING`, `FAILED`, `UNKNOWN`.
- `Qualification`: `PASS`, `NOT_REQUIRED`, `PENDING`, `FAILED`, `UNKNOWN`.
- `Delivery`: `DEPLOYED`, `INSTALLED`, `RELEASED`, `COMMITTED`, `LOCAL`, `UNKNOWN`.
- `Action`: `RETAIN`, `REPAIR_WIRE`, `EVIDENCE`, `ADD`, `REMOVE`, `SUPERSEDE`.

An atom is closed only when implementation is `DELIVERED`, verification is `FULL_PASS` or `FOCUSED_PASS`, qualification is `PASS` or `NOT_REQUIRED`, delivery meets its boundary, & evidence is exact. Closed state is derived; it is never stored.

## Ownership decisions

- Guard remains separate from Arcane. Guard owns typed effect enforcement & receipts; Arcane owns cognitive control.
- Five domains are Skills grouping metadata, not peer orchestrators or subsystems.
- Covenant seats are Covenant implementation, not independent subsystem owners.
- `src/packages/{context,contracts,kernel}` are implementation components under Legion-owned orchestration, not duplicate semantic owners.
- Public distribution & client integration remain Legion-owned.
- Historical deterministic-substrate & retired assurance-role planning names are provenance only; Oracle is current assurance owner.

## Derived pending work

[docs/pending/README.md](../../pending/README.md) is generated from open capability rows by `node scripts/check-atomic-canons.mjs --write`. Edit subsystem canons, never generated pending rows.
