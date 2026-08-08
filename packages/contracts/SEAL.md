# WP2 Freeze — Coordinator Seal

**Sealed:** 2026-08-08, coordinator (Fable) after independent re-run of `node --test smoke.test.mjs` (42/42 pass) and digest verification against `FREEZE.md`.
**Status:** FROZEN. Wave-2 lanes build against this set. Changes require a coordinator amendment recorded here — no lane may edit `packages/contracts/`.

## Dispositions of FREEZE.md open questions

| Q | Disposition |
|---|---|
| 1 — `INVOCATION_STATE`/`CLAIM_BOUNDARY` values invented | **ACCEPT AS RESERVED.** Kernel lane (D) confirms or amends; treat as proposal, build against the shape (3 separate fields), not the specific values. |
| 2 — ExecutionTask vs Kernel task identity | **ACCEPT BRIDGE.** `kernelTaskId` stands; the Kernel lane owns the unification decision and files an amendment if it collapses them. |
| 3 — `RA-#`/`E-#`/`P-#`/`AR-#` unbound | **ACCEPT.** They are evidence-chain aliases, not schema subjects; no promotion needed for Wave 2. |
| 4 — `EFFECT_CLASS`/`MODEL_TIER` synthesized | **ACCEPT AS RESERVED.** Arcane lane (E) reconciles EFFECT_CLASS against its real broker; orchestrator work reconciles MODEL_TIER. Amend, don't fork. |
| 5 — `provisionalMappingRef` stays null | **CONFIRMED CORRECT.** Mapping is S01's deliverable (Arcane lane), never WP2's. |
| 6 — `AUTHENTICATION_METHOD` is a reserved slot | **ACCEPT AS RESERVED.** S03 (Arcane lane) owns the real authentication design and amends the enum. |

## Binding rule for Wave-2 lanes

Reserved items above are *shape-stable, value-provisional*: build code that treats the field as required and the enum as replaceable. An amendment to this package updates `FREEZE.md` digests and this seal; stale digests invalidate dependent lane evidence (G11).
