# Alchemist capability canon

Owner boundary: controlled bounded transformation of settled meaning.

Required delivery boundary: `PUSHED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| ALC-G01 | — | Alchemist | COMMITTED | contract admission |
| ALC-G02 | — | Alchemist | COMMITTED | bounded execution |
| ALC-G03 | — | Alchemist | COMMITTED | terminals & handoff |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| ALC-001 | ALC-G01 | Alchemist | COMMITTED | Activate only for locked, explicitly contracted, policy-controlled, or otherwise governed transformation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-002 | ALC-G01 | Alchemist | COMMITTED | Reject absent, stale, contradictory, or open-question contracts before effects. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-003 | ALC-G01 | Alchemist | COMMITTED | Bind execution to contract version, immutable acceptance IDs, owned paths, exclusions & declared checks. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-004 | ALC-G02 | Alchemist | COMMITTED | Execute one contract-bound mechanism within declared effects & acceptance. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-005 | ALC-G02 | Alchemist | COMMITTED | Mechanically repair failures only when behavior, architecture, public contract, acceptance & scope remain unchanged. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-006 | ALC-G02 | Alchemist | COMMITTED | Verify worker output locally & forward-test declared acceptance IDs plus downstream consumers. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-007 | ALC-G02 | Alchemist | COMMITTED | Stop identical failure fingerprints without material change instead of retrying unboundedly. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-008 | ALC-G03 | Alchemist | COMMITTED | Emit typed progress, repair, amendment, decision-block, scope, budget, contract-failure, or candidate-complete outcomes. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ALC-009 | ALC-G03 | Alchemist | COMMITTED | Escalate new semantics to Sage & send candidate result to Oracle without self-certification. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| ALC-I001 | ALC-001, ALC-002, ALC-003, ALC-004, ALC-005, ALC-006, ALC-007, ALC-008, ALC-009 | Roster, doctrine, entrypoint & typed outcomes | `src/roster/alchemist.md@c498a604`; `doctrine/alchemist.md@c498a604`; `skills/alchemist/SKILL.md@c498a604` | DIRECT_PORT | DELIVERED | Controlled transformation dispatch |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| ALC-Q001 | ALC-001, ALC-002, ALC-003, ALC-004, ALC-005, ALC-006, ALC-007, ALC-008, ALC-009 | Alchemist-AC-BOUNDARY-001: reconcile each observable through live consumer at PUSHED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| ALC-D001 | REFERENCE | ALC-001 | Ambient mutation remains Legion-owned; Alchemist activates only at controlled boundary. | Root SSOT | RECORDED |
