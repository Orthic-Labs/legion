# Ownership disposition

**Stage:** S08 · **Owner:** Legion integration owner + Arcane state.

Every governed workload binds six distinct responsibilities: runtime owner, first-fix owner,
canonical owner, repository integration owner, shared-state writer, & evidence producer. One
identity may hold several roles, but each role has exactly one active owner. A mismatch records
`KEEP`, `TRANSFER`, `DELETE`, or `DEFER`, plus trigger & observed proof. Only integration owner
changes HEAD, index, canonical receipts, repository topology, or remotes; only shared-state writer mutates
acceptance ledger or producer contracts.

Closure requires every mismatch dispositioned, one active integration owner, one active writer per
shared state, & evidence from exact integrated state. Worker output alone never proves integration.
