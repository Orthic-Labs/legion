# Objective-lineage budgets

**Stage:** S02 · **Ledger:** S02-05 · **Owner:** Legion + Arcane doctrine. S03/S09 own counters, persistence, cancellation, & enforcement.

Every non-ambient engagement declares non-zero finite wall-clock, active-time, design-round, review-round, & contract-version ceilings before admission. Omitted duration, `UNBOUNDED`, & `AS_NEEDED` reject admission. One objective lineage carries them across packet, contract, agent, session, & resume IDs; a new identifier never resets a ceiling. Only later explicit user resume starts new lineage. Expiry reaches typed terminal state.

Defaults: specialist ≤1 round; optional Covenant ≤1; Oracle Completion Validation ≤1 plus one scoped recheck after material delta; sealed contract versions ≤2; architecture D1 ≤1, D2 ≤2, absolute tripwire 3. No agent/reviewer extends own budget. Concurrency is `min(independent ready work, slots, integration review capacity, shared-writer constraints, evidence/context merge budget)`; fan-out is never mandatory. Values beyond named defaults belong to calibrated capability tables, never permanent doctrine.
