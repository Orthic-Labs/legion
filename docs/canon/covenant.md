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
| COV-001 | COV-G01 | Covenant | COMMITTED | Convene only for named decision, artifact, blocker, or explicit packet preparation. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-002 | COV-G01 | Covenant | COMMITTED | Freeze verbatim intent, actual artifact, caller question & assigned lens into immutable review packet. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-003 | COV-G01 | Covenant | COMMITTED | Isolate seats from repository, tools, browsing, other seats & state effects unless packet explicitly grants capability. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-004 | COV-G01 | Covenant | COMMITTED | Revalidate source revision & packet digest at each gate; stale verdicts after subject change. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-005 | COV-G02 | Covenant | COMMITTED | Challenge decision assumptions from assigned lens with evidence-grounded severity. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-006 | COV-G02 | Covenant | COMMITTED | Judge blocker proposal as CONTRACT_SAFE, AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-007 | COV-G02 | Covenant | COMMITTED | Label ungrounded objections speculation & missing actual artifact INSUFFICIENT_EVIDENCE. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| COV-008 | COV-G02 | Covenant | COMMITTED | Return advisory findings to caller; never authorize, dispose, remediate, certify, or gate release. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| COV-I001 | COV-001, COV-002, COV-003, COV-004, COV-005, COV-006, COV-007, COV-008 | Packet builder, isolated seats, lenses & disposition method | `skills/covenant/SKILL.md@c498a604`; `doctrine/covenant-seat.md@c498a604` | DIRECT_PORT | DELIVERED | Explicit Covenant invocation |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| COV-Q001 | COV-001, COV-002, COV-003, COV-004, COV-005, COV-006, COV-007, COV-008 | COV-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at PUSHED boundary | PASS | Acceptance: COV-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| COV-D001 | EXCLUSION | COV-008 | Covenant never authorizes, remediates, certifies, or gates release. | Root SSOT | RECORDED |
