# Migration cutover

**Stage:** S08 · **Owner:** Canonical owner + Legion integration owner.

Every migration selects exactly one mode. `HARD_CUT` requires one canonical path & observed absence
of losing imports, routes, runtime registrations, configuration keys, dependencies, tests,
documentation, & emitted protocol variants. `BOUNDED_COEXISTENCE` requires exact boundary, traffic
split, reconciliation invariant, telemetry, expiry, rollback, & cutover trigger.

Missing absence evidence or unbounded coexistence yields `INCOMPLETE`. Only exact integrated-state
evidence may yield `READY`; candidate files, worker branches, internal flags, & unit-only proof do not.
