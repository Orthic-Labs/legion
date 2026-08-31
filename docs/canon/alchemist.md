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
| ALC-001 | ALC-G01 | Alchemist | COMMITTED | Activate only for locked, explicitly contracted, policy-controlled, or otherwise governed transformation. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-002 | ALC-G01 | Alchemist | COMMITTED | Reject absent, stale, contradictory, or open-question contracts before effects. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-003 | ALC-G01 | Alchemist | COMMITTED | Bind execution to contract version, immutable acceptance IDs, owned paths, exclusions & declared checks. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-004 | ALC-G02 | Alchemist | COMMITTED | Execute one contract-bound mechanism within declared effects & acceptance. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-005 | ALC-G02 | Alchemist | COMMITTED | Mechanically repair failures only when behavior, architecture, public contract, acceptance & scope remain unchanged. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-006 | ALC-G02 | Alchemist | COMMITTED | Verify worker output locally & forward-test declared acceptance IDs plus downstream consumers. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-007 | ALC-G02 | Alchemist | COMMITTED | Stop identical failure fingerprints without material change instead of retrying unboundedly. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-008 | ALC-G03 | Alchemist | COMMITTED | Emit typed progress, repair, amendment, decision-block, scope, budget, contract-failure, or candidate-complete outcomes. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ALC-009 | ALC-G03 | Alchemist | COMMITTED | Escalate new semantics to Sage & send candidate result to Oracle without self-certification. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| ALC-I001 | ALC-001, ALC-002, ALC-003, ALC-004, ALC-005, ALC-006, ALC-007, ALC-008, ALC-009 | Roster, doctrine, entrypoint & typed outcomes | `src/roster/alchemist.md@c498a604`; `doctrine/alchemist.md@c498a604`; `skills/alchemist/SKILL.md@c498a604` | DIRECT_PORT | DELIVERED | Controlled transformation dispatch |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| ALC-Q001 | ALC-001, ALC-002, ALC-003, ALC-004, ALC-005, ALC-006, ALC-007, ALC-008, ALC-009 | ALC-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at PUSHED boundary | PASS | Acceptance: ALC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| ALC-D001 | REFERENCE | ALC-001 | Ambient mutation remains Legion-owned; Alchemist activates only at controlled boundary. | Root SSOT | RECORDED |
