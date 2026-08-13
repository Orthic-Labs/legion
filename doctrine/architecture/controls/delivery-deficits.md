# Delivery deficits & acknowledgements

**Stage:** S02 · **Ledger:** S02-07 · **Owner:** Legion architecture doctrine. S03 owns schemas/state; S08 owns live workload closure; S10 owns handoffs.

Execution incompleteness is a typed `delivery_deficit`, not hidden success. Record origin acceptance ID, kind, severity, lifecycle, owner, accepting authority where required, downstream tasks, prohibited claim levels, evidence, trigger, & expiry. Consumers acknowledge canonical deficit references as `compatible`, `workaround`, `blocked`, or `replan` with rationale; dispatch rejects unresolved dependency debt without acknowledgement.

`REQUIRED` acceptance, safety, privacy, security, correctness, data integrity, legal constraint, missing evidence, or missing authority never becomes debt automatically. `COMPLETE_WITH_DEBT` is limited to deferred, optional quality, or authority-accepted risk; `COMPLETE_WITH_NOTES` still requires every required item pass. This control neither stores deficits nor mints completion.
