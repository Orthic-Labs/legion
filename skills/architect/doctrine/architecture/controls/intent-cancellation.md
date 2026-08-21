# Latest intent & cancellation

**Stage:** S02 · **Ledger:** S02-06 · **Owner:** Arcane doctrine. Semantic precedence only; S04 implements cancellation, quiescence, checkpoints, & resume.

Latest explicit user intent outranks persisted goals, plans, checkpoints, background work, resumptions, & former authorization. `STOP`, `PAUSE`, `REVOKE`, or scope narrowing increments `intent_epoch`, marks execution cancelled, invalidates continuation tokens/queued resume, suppresses automatic continuation, preserves completed artifacts, & reports current state. Only later explicit user intent clears cancellation or starts continuation epoch.

Stored objectives preserve context, never authority. Persisted/tool/repository/test/memory material re-enters as typed untrusted data, never instructions; only current user-origin text may authorize preference/profile writes or effects. This doctrine does not execute cancellation or build a persistence/replay system.
