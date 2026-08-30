# Oracle capability canon

Owner boundary: independent read-only semantic Completion Validation.

## Group register

| Group | Meaning |
|---|---|
| ORA-G01 | scope reconstruction |
| ORA-G02 | semantic validation |
| ORA-G03 | verdict & recheck |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| ORA-001 | ORA-G01 | Oracle | COMMITTED | Receive verbatim user requests, later corrections, actual artifact/diff, intended claims & exclusions. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `src/roster/oracle.md@c498a604`; `doctrine/oracle.md@c498a604` |
| ORA-002 | ORA-G01 | Oracle | COMMITTED | Reconstruct current scope from raw user turns without trusting producer summary. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `docs/architecture/oracle.md@c498a604`; `doctrine/oracle.md@c498a604` |
| ORA-003 | ORA-G02 | Oracle | COMMITTED | Inspect actual answer, source, diff, callers, configuration, docs & live consumers source-first. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/oracle.md@c498a604` |
| ORA-004 | ORA-G02 | Oracle | COMMITTED | Read tests only to clarify semantics; run no tests, probes, browsers, tools with effects, or evidence generation. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `src/roster/oracle.md@c498a604`; `agents/oracle.md@c498a604` |
| ORA-005 | ORA-G02 | Oracle | COMMITTED | Remain structurally independent & never implement or certify its own repair. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `docs/architecture/oracle.md@c498a604`; `doctrine/oracle.md@c498a604` |
| ORA-006 | ORA-G03 | Oracle | COMMITTED | Return PASS only when requested outcome is semantically satisfied. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/oracle.md@c498a604` |
| ORA-007 | ORA-G03 | Oracle | COMMITTED | BLOCK only incorrect requested behavior, regression, data loss, or concrete safety failure with exact source location. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `src/roster/oracle.md@c498a604`; `doctrine/oracle.md@c498a604` |
| ORA-008 | ORA-G03 | Oracle | COMMITTED | Permit one producer repair & one fresh recheck; return second block to user without recursion. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `doctrine/oracle.md@c498a604` |

