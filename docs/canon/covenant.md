# Covenant capability canon

Owner boundary: optional bounded packet-only adversarial challenge without authority.

Required delivery boundary: `PUSHED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| COV-G01 | — | Covenant | COMMITTED | packet & seat isolation |
| COV-G02 | — | Covenant | COMMITTED | challenge modes & disposition |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| COV-001 | COV-G01 | Covenant | COMMITTED | Convene only for named decision, artifact, blocker, or explicit packet preparation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-002 | COV-G01 | Covenant | COMMITTED | Freeze verbatim intent, actual artifact, caller question & assigned lens into immutable review packet. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-003 | COV-G01 | Covenant | COMMITTED | Isolate seats from repository, tools, browsing, other seats & state effects unless packet explicitly grants capability. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-004 | COV-G01 | Covenant | COMMITTED | Revalidate source revision & packet digest at each gate; stale verdicts after subject change. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-005 | COV-G02 | Covenant | COMMITTED | Challenge decision assumptions from assigned lens with evidence-grounded severity. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-006 | COV-G02 | Covenant | COMMITTED | Judge blocker proposal as CONTRACT_SAFE, AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-007 | COV-G02 | Covenant | COMMITTED | Label ungrounded objections speculation & missing actual artifact INSUFFICIENT_EVIDENCE. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| COV-008 | COV-G02 | Covenant | COMMITTED | Return advisory findings to caller; never authorize, dispose, remediate, certify, or gate release. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| COV-I001 | COV-001, COV-002, COV-003, COV-004, COV-005, COV-006, COV-007, COV-008 | Packet builder, isolated seats, lenses & disposition method | `skills/covenant/SKILL.md@c498a604`; `doctrine/covenant-seat.md@c498a604` | DIRECT_PORT | DELIVERED | Explicit Covenant invocation |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| COV-Q001 | COV-001, COV-002, COV-003, COV-004, COV-005, COV-006, COV-007, COV-008 | Covenant-AC-BOUNDARY-001: reconcile each observable through live consumer at PUSHED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| COV-D001 | EXCLUSION | COV-008 | Covenant never authorizes, remediates, certifies, or gates release. | Root SSOT | RECORDED |
