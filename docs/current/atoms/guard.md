# Guard capability canon

Owner boundary: deterministic typed effect enforcement & effect-decision receipts.

## Group register

| Group | Meaning |
|---|---|
| GRD-G01 | host interception & classification |
| GRD-G02 | policy & authorization |
| GRD-G03 | observation, receipts & health |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| GRD-001 | GRD-G01 | Guard | COMMITTED | Parse & validate versioned host lifecycle, pre-effect, post-effect, stop & CI-boundary frames. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |
| GRD-002 | GRD-G01 | Guard | COMMITTED | Classify explicit or inferred effects into canonical effect vocabulary without guessing unknown explicit classes. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |
| GRD-003 | GRD-G01 | Guard | COMMITTED | Match shell command segments for destructive file operations, dependency installs, commits, pushes & publication. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |
| GRD-004 | GRD-G02 | Guard | COMMITTED | Deny pre-effects when frame validation, classification, policy load, or authorization fails. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |
| GRD-005 | GRD-G02 | Guard | COMMITTED | Enforce hard destructive-command & history-rewrite-push refusals before native policy authorization. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `engine/bins/legion-hook/src/main.rs@c498a604`; `engine/crates/legion-host@c498a604` |
| GRD-006 | GRD-G02 | Guard | COMMITTED | Gate typed effects rather than capability labels, model roles, or route envelopes. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `docs/LEGION-CANONICAL-SSOT.md@blob:61bcc163`; `doctrine/guard.md@c498a604` |
| GRD-007 | GRD-G02 | Guard | COMMITTED | Load versioned native application policy from inline config, named path, or canonical repository default. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |
| GRD-008 | GRD-G03 | Guard | COMMITTED | Report typed enforcement health & keep mandatory authorization/security gates fail-closed. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/crates/legion-host@c498a604` |
| GRD-009 | GRD-G03 | Guard | COMMITTED | Record authenticated effect observations & dependency-bound evidence without accepting model self-report. | PARTIAL | PENDING | PENDING | COMMITTED | REPAIR_WIRE | `src/packages/arcane/lib/ingest.mjs@c498a604`; `src/packages/arcane/lib/receipt-auth.mjs@c498a604`; `doctrine/guard.md@c498a604` |
| GRD-010 | GRD-G03 | Guard | COMMITTED | Observe SubagentStop lifecycle without making dispatch itself an effect class. | MISSING | PENDING | NOT_REQUIRED | COMMITTED | ADD | `doctrine/guard.md@c498a604` |
| GRD-011 | GRD-G03 | Guard | COMMITTED | Classify MCP write, send & delete tools through same typed effect gate. | MISSING | PENDING | NOT_REQUIRED | COMMITTED | ADD | `doctrine/guard.md@c498a604`; `hooks/hooks.json@c498a604` |
| GRD-012 | GRD-G03 | Guard | COMMITTED | Apply proportional Stop verification & require Oracle receipt only when typed requirement demands it. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/guard.md@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` |

