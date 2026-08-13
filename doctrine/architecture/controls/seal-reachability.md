# Seal-time evidence reachability

**Stage:** S02 · **Ledger:** S02-08 · **Owner:** Legion + Arcane doctrine. S05 compiles/executes seals; S09 enforces; this control is semantic contract only.

Before seal, every required evidence class proves executable path: real producer → owned durable output → authenticated persistence → verifier → completion consumer → close path. It also proves positive lifecycle, substitution rejection, replay rejection, & recovery/close reachability when ordinary path fails. Caller-injected, generic-receipt, fixture-only, stale, unreachable, or self-attested paths fail as `UNSOUND_SEAL`.

External evidence declares machine readability, gateability, downloadability, trusted retrieval, trajectory binding, sensitivity, retention, & deletion ownership. Dashboard-only status is informational without trusted adapter. A schema field lacking reachable producer/consumer is an unsound seal defect, not a requirement. S05 compiles this lifecycle against existing Arcane seal & receipt primitives.
