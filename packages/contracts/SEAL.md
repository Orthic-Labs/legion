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

## Amendment A-ER-1 — 2026-08-09, coordinator (Legion)

`effect-receipt-v1.contractId` and `.taskId` relaxed from required non-nullable
strings to `["string","null"]`, patterns retained (a pattern constrains only the
string case). Mirrors `evidence-capability-receipt-v1`'s pre-existing nullable
shape for the same two fields exactly — the nullability precedent already
shipped in this same freeze, proving it deliberate design, not oversight.

**Meaning of null:** an *ambient* observation — a host-observed effect in a
session bound to a run (real, host-minted `runId`) but not to a contract.
**Rationale (EC-5, disposed by Adrian):** evidence ≠ authorization. Recording an
uncontracted mutation is never a false clean; refusing to record it is itself a
coverage hole. Contracts gate *authorization* (the pre-effect gate); observation
must be universal or locked-domain completion gating cannot see ad-hoc work.
**Still refused, unchanged:** any post-effect event carrying no `runId` at all —
ambient is a typed tier, never a silent default.
**Additive:** no existing receipt changes meaning or validity; `schemaVersion`
stays 1. Verified: `smoke.test.mjs` 42/42 after amendment.
**Rejected alternative:** routing ambient mutations through
`evidence-capability-receipt-v1` (already nullable) — that schema models
verification evidence, and an unverified file write must never satisfy an
evidence-class prerequisite.

FREEZE.md digest for `effect-receipt-v1.schema.json` updated in place. Per G11,
lane evidence that pinned the old digest is invalidated by this amendment and
must reseal against the new one.
