# Retry semantics

**Stage:** S02 · **Ledger:** S02-06 · **Owner:** Arcane doctrine. Taxonomy only: S04 cancellation/process control & S09 runtime enforcement remain excluded.

Classify failure before retry. Retry requires allowlisted retryable class, finite `max_retries`, finite subprocess timeout, sufficient remaining lineage budget, & material input, method, or state delta. Authentication, missing-resource, invalid-contract, & context-limit failures are non-retryable by default. Apply cheapest semantics-preserving repair first; preserve best reversible artifact at cap with precise partial/debt result.

Fingerprint binds normalized failure plus input. Second identical fingerprint terminates current approach; another ID, agent, or session cannot reset it. Attempts greater than three mismatch canonical policy and is doctrine-recorded drift only—this document authorizes no runtime repair. No retry lifts wall-clock or active-time exhaustion.
