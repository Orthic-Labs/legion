# Frozen acceptance ledger

**Stage:** S02 · **Ledger:** S02-01 · **Owner:** Legion architecture doctrine. This control owns task-level scope semantics; S03 owns persistence, S09 enforcement, S10 handoffs.

Before review, dispatch, or implementation, freeze one ledger from latest explicit user intent. Each immutable item has exactly one disposition: `REQUIRED` (must close now), `DEFERRED` (valid, not now; owner + revisit trigger), or `OUT_OF_SCOPE` (unauthorized or unnecessary). A required item names source, observable acceptance surface, verification method, owner, dependencies, result, `ledger_version`, `intent_epoch`, & `acceptance_fingerprint`.

Packets, contracts, milestones, & completion claims bind that fingerprint. Clarification may reduce scope without changing required semantics. Only later explicit user intent may add a required item or bring an item into scope; safety may deny an effect but never create product scope. An unauthorized required mutation is rejected & prior frozen fingerprint remains valid. This document defines no ledger store, mutation API, replay, or completion engine.
