# Oracle capability canon

Owner boundary: independent read-only semantic Completion Validation.

Required delivery boundary: `PUSHED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| ORA-G01 | — | Oracle | COMMITTED | scope reconstruction |
| ORA-G02 | — | Oracle | COMMITTED | semantic validation |
| ORA-G03 | — | Oracle | COMMITTED | verdict & recheck |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| ORA-001 | ORA-G01 | Oracle | COMMITTED | Receive verbatim user requests, later corrections, actual artifact/diff, intended claims & exclusions. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-002 | ORA-G01 | Oracle | COMMITTED | Reconstruct current scope from raw user turns without trusting producer summary. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-003 | ORA-G02 | Oracle | COMMITTED | Inspect actual answer, source, diff, callers, configuration, docs & live consumers source-first. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-004 | ORA-G02 | Oracle | COMMITTED | Read tests only to clarify semantics; run no tests, probes, browsers, tools with effects, or evidence generation. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-005 | ORA-G02 | Oracle | COMMITTED | Remain structurally independent & never implement or certify its own repair. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-006 | ORA-G03 | Oracle | COMMITTED | Return PASS only when requested outcome is semantically satisfied. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-007 | ORA-G03 | Oracle | COMMITTED | BLOCK only incorrect requested behavior, regression, data loss, or concrete safety failure with exact source location. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ORA-008 | ORA-G03 | Oracle | COMMITTED | Permit one producer repair & one fresh recheck; return second block to user without recursion. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| ORA-I001 | ORA-001, ORA-002, ORA-003, ORA-004, ORA-005, ORA-006, ORA-007, ORA-008 | Roster, doctrine, entrypoint & host projection | `src/roster/oracle.md@c498a604`; `doctrine/oracle.md@c498a604`; `skills/oracle/SKILL.md@c498a604` | DIRECT_PORT | DELIVERED | Completion Validation dispatch |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| ORA-Q001 | ORA-001, ORA-002, ORA-003, ORA-004, ORA-005, ORA-006, ORA-007, ORA-008 | ORA-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at PUSHED boundary | PASS | Acceptance: ORA-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| ORA-D001 | EXCLUSION | ORA-001 | Retired `src/packages/oracle/**` package stays excluded; Oracle is an ephemeral authority role. | Legacy tracker item 23 | RECORDED |
