# Execution trajectory

Canonical `architecture-state.v4` is one persisted projection. Architecture phase & execution episode are independent closed axes; reducer permits only declared forward transitions. State fingerprint is canonical digest excluding only `state_fingerprint`, `execution.trajectory.replay_state_fingerprint`, & `execution.trajectory.last_event_digest`.

Only authenticated accepted trajectory events mutate projection. Proposals cannot own event ID, acceptance metadata, sequence, timestamps, authentication, predecessor, or resulting fingerprint. Caller first replays a declared initial state for its objective lineage, then acceptance compares exact state fingerprint before reduction. Rejected proposals mutate neither accepted history nor state; replay is pure & grants no authority. Checkpoint, resume, recovery effects, cancellation, & duplicate-effect defense remain Stage 4.

`BUDGET_SNAPSHOT_RECORDED` projects only an authenticated `budget_ref`, its content digest, & non-authoritative observed counters (`active_time_ms`, `excluded_wait_ms`, `retry_count`, `event_count`). Budget caps, amendments, stops, & authority remain exclusively in `BudgetGovernanceStore`; trajectory payloads carrying them are rejected.
