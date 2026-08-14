---
name: covenant
description: Run Legion's typed independent challenge chamber for Sage decisions, Alchemist blockers, exceptional disputes, or packet-only review preparation.
---

# Covenant

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Digest-bound CovenantRequest, CovenantRecord, or packet-only artifact.
EFFECT_PROFILES: child_packet
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

Covenant is self-contained: canonical state, packet engine, & assets all live under this skill.

1. Construct canonical state through `lib/contracts.mjs`; never hand-author trusted digests.
2. Use `DECISION_CHALLENGE` only for Sage/user-owned decisions: isolated positions, synthesis, complete caller dispositions, revised subject, then unprimed fresh verdict.
3. Use `BLOCKER_CONSULT` only for Alchemist blockers; `CONTRACT_SAFE` requires every mechanical boundary check to remain false.
4. Use `PACKET_ONLY — DO_NOT_RUN_COVENANT` to prepare context without seats.
5. Keep seats read-only, isolated, concurrent within each stage, & explicit about provider degradation.
6. Treat verdicts as advisory evidence. Never emit `DECISION_SEALED`, `CONTROL_PASS`, product authorization, or closure of a Seer finding.
7. Revalidate source revision + packet digest at every gate query; changed subjects make prior verdicts stale.

Run: `node --test evals/covenant.test.mjs` & `py -3.11 scripts/test_validate_external_review_packet.py`.

