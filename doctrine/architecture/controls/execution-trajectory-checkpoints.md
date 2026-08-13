# Execution checkpoints & resume

**Stage:** S04 · **Ledger:** S04-01 · **Owner:** Arcane continuity.

Create a checkpoint at every phase barrier, accepted patch, integration mutation, & acceptance-result update. Bind objective lineage, intent + continuation epochs, repository state, owning item/stage fingerprint, schedule fingerprint, producer versions, accepted-event sequence + tail digest, & completed effect IDs.

Resume requires exact semantic, lineage, repository, producer, epoch, & event-continuity bindings. Semantic drift denies resume, preserves partial artifacts, & invalidates only changed acceptance IDs plus dependency descendants. Schedule-only drift permits resume after execution replanning & invalidates no acceptance evidence. Replayed completed effect IDs are denied.
