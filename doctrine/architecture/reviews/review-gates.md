# Review admission & scoped CLEAN

**Stage:** S02 · **Ledger:** S02-02 · **Owner:** Architect review method + Arcane deterministic admission. Oracle may consume resulting evidence for Completion Validation but does not own this evaluation method.

Every review module declares `when_to_use`, `when_not_to_use`, configured scope, eligibility filter, ordered gates, calibration-table version, claim language, & CLEAN bindings. Dismiss first: test `PROCESS → REACHABILITY → CONTROL → REAL_IMPACT → REPRODUCTION → BOUNDS → ENVIRONMENT`; first failed gate records decisive dismissal plus evidence. Assign severity only to survivors, then apply reviewer-scope mapping. Confidence never establishes blocker status without applicability, evidence, & mapping.

`CLEAN` means configured gates passed for declared scope, exact state, & freshness only; it never implies perfect or uninspected safety. Re-review covers prior blocking findings plus breakage introduced by fixes; new observations become debt, never another full loop. A module missing negative scope or admission gates cannot block. No runtime thresholds or review store are defined here.
