# Gate validity

**Stage:** S02 · **Ledger:** S02-08 · **Owner:** Legion + Arcane doctrine. S05 owns gate implementation; S09 owns guard enforcement.

Every check declares inspected scope, discovery breadth, deterministic blocking filter, threshold, gate status, authority, & failure semantics. Discovery may retain all observations; only blocking filter may block. Zero eligible inspected items is `FAIL` or `INCONCLUSIVE`, never `PASS`; no inspection never supports CLEAN.

Blocking gates require known-good, known-bad, empty, & malformed fixtures before activation. Receipt records inspection count, fixture identity, matched rule, & rejection reason. Failed self-test disables blocking & records machinery defect, never product failure. Informational checks cannot block; blocking checks cannot silently degrade. This control defines neither gate store nor fixture runner.
