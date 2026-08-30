# Covenant capability canon

Owner boundary: optional bounded packet-only adversarial challenge without authority.

## Group register

| Group | Meaning |
|---|---|
| COV-G01 | packet & seat isolation |
| COV-G02 | challenge modes & disposition |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| COV-001 | COV-G01 | Covenant | COMMITTED | Convene only for named decision, artifact, blocker, or explicit packet preparation. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/covenant/SKILL.md@c498a604`; `doctrine/covenant-seat.md@c498a604` |
| COV-002 | COV-G01 | Covenant | COMMITTED | Freeze verbatim intent, actual artifact, caller question & assigned lens into immutable review packet. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/covenant/SKILL.md@c498a604`; `doctrine/covenant-seat.md@c498a604` |
| COV-003 | COV-G01 | Covenant | COMMITTED | Isolate seats from repository, tools, browsing, other seats & state effects unless packet explicitly grants capability. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/covenant-seat.md@c498a604`; `agents/covenant-seat.md@c498a604` |
| COV-004 | COV-G01 | Covenant | COMMITTED | Revalidate source revision & packet digest at each gate; stale verdicts after subject change. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/covenant/SKILL.md@c498a604` |
| COV-005 | COV-G02 | Covenant | COMMITTED | Challenge decision assumptions from assigned lens with evidence-grounded severity. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/covenant-seat.md@c498a604`; `doctrine/bundles/covenant-lenses/README.md@c498a604` |
| COV-006 | COV-G02 | Covenant | COMMITTED | Judge blocker proposal as CONTRACT_SAFE, AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/covenant-seat.md@c498a604` |
| COV-007 | COV-G02 | Covenant | COMMITTED | Label ungrounded objections speculation & missing actual artifact INSUFFICIENT_EVIDENCE. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/covenant-seat.md@c498a604` |
| COV-008 | COV-G02 | Covenant | COMMITTED | Return advisory findings to caller; never authorize, dispose, remediate, certify, or gate release. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `docs/LEGION-CANONICAL-SSOT.md@blob:61bcc163`; `doctrine/covenant-seat.md@c498a604` |

