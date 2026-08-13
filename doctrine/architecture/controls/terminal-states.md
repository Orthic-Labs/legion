# Terminal-state axes

**Stage:** S02 · **Ledger:** S02-10 · **Owner:** Legion + Arcane doctrine. S03 owns legal persistence/transitions; S04/S05/S10 own execution, assurance, & handoff effects.

Keep readiness, execution episode, implementer outcome, & acceptance completion distinct. Architecture readiness is `READY_TO_EXECUTE | READY_WITH_ASSUMPTIONS | NEEDS_SPIKE | BLOCKED_EXTERNAL | BUDGET_STOP`. An execution episode moves from `PENDING | QUEUED | RUNNING` to `SUCCEEDED | FAILED | CANCELLED | TIMEOUT | BUDGET_STOP | COMPLETE_WITH_DEBT`. Its implementer reports only `CANDIDATE | BLOCKED`; neither episode success nor implementer output mints `COMPLETE`. Acceptance completion requires fresh exact-state acceptance-surface proof for every frozen required item; candidate/proxy evidence never closes it.

Budget exhaustion forces typed terminal state. For reversible work, `BUDGET_STOP` may preserve best justified route with explicit risk; irreversible/high-consequence work may not fabricate approval. Generic “done”, collapsed axes, or implementer `COMPLETE` are rejected. This doctrine does not implement state storage, transition guards, terminal receipts, or cancellation.
