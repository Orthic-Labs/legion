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
| ORA-001 | ORA-G01 | Oracle | COMMITTED | Receive verbatim user requests, later corrections, actual artifact/diff, intended claims & exclusions. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-002 | ORA-G01 | Oracle | COMMITTED | Reconstruct current scope from raw user turns without trusting producer summary. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-003 | ORA-G02 | Oracle | COMMITTED | Inspect actual answer, source, diff, callers, configuration, docs & live consumers source-first. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-004 | ORA-G02 | Oracle | COMMITTED | Read tests only to clarify semantics; run no tests, probes, browsers, tools with effects, or evidence generation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-005 | ORA-G02 | Oracle | COMMITTED | Remain structurally independent & never implement or certify its own repair. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-006 | ORA-G03 | Oracle | COMMITTED | Return PASS only when requested outcome is semantically satisfied. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-007 | ORA-G03 | Oracle | COMMITTED | BLOCK only incorrect requested behavior, regression, data loss, or concrete safety failure with exact source location. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| ORA-008 | ORA-G03 | Oracle | COMMITTED | Permit one producer repair & one fresh recheck; return second block to user without recursion. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| ORA-I001 | ORA-001, ORA-002, ORA-003, ORA-004, ORA-005, ORA-006, ORA-007, ORA-008 | Roster, doctrine, entrypoint & host projection | `src/roster/oracle.md@c498a604`; `doctrine/oracle.md@c498a604`; `skills/oracle/SKILL.md@c498a604` | DIRECT_PORT | DELIVERED | Completion Validation dispatch |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| ORA-Q001 | ORA-001, ORA-002, ORA-003, ORA-004, ORA-005, ORA-006, ORA-007, ORA-008 | Oracle-AC-BOUNDARY-001: reconcile each observable through live consumer at PUSHED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| ORA-D001 | EXCLUSION | ORA-001 | Retired `src/packages/oracle/**` package stays excluded; Oracle is an ephemeral authority role. | Legacy tracker item 23 | RECORDED |
