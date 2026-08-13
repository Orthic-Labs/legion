# ADR admission

**Stage:** S02 · **Ledger:** S02-04 · **Owner:** Sage architecture doctrine. This control governs worthiness; S07 owns ADR schema/templates, S03 owns storage.

Create an ADR only when all predicates hold: decision is hard or costly to reverse; it would be surprising without retained context; & it resolves a real trade-off among credible alternatives. If all hold, admit ADR. If any fails, reject ADR & record decision in canonical architecture state or ordinary decision log; lack of ADR never means no decision record.

An admitted ADR retains decision/realization status separately, rationale, evidence, consequences, residual-risk authority, migration/coexistence, exit, ceiling, expiry/review trigger, ownership, & supersession lineage. Reversible local work following an accepted pattern is a negative case: no ADR. This control does not write records or alter decision lifecycle.
