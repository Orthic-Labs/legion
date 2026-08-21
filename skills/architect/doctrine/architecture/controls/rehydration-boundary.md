# Rehydration boundary

**Stage:** S04 · **Ledger:** S04-01 · **Owner:** Arcane continuity.

Persisted state, repository content, tool output, tests, receipts, summaries, & memory re-enter only as digest-bound `UNTRUSTED_DATA`. Their content cannot issue instructions, grant authority, write preferences, authorize effects, or downgrade effect classification. Current user intent remains sole live instruction source.

Every dispatch, wait, monitor, tool batch, process group, & wakeup binds current `intent_epoch + continuation_epoch`. Stop, pause, revoke, or scope narrowing advances intent epoch, cancels bound work, terminates its process group, suppresses automatic continuation, & preserves artifacts. Resume requires later explicit user intent, newer continuation epoch, verified checkpoint, & observed process-group quiescence.
