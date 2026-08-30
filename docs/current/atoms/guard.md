# Guard capability canon

Owner boundary: deterministic typed effect enforcement & effect-decision receipts.

Required delivery boundary: `RELEASED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| GRD-G01 | — | Guard | COMMITTED | host interception & classification |
| GRD-G02 | — | Guard | COMMITTED | policy & authorization |
| GRD-G03 | — | Guard | COMMITTED | observation, receipts & health |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| GRD-001 | GRD-G01 | Guard | COMMITTED | Parse & validate versioned host lifecycle, pre-effect, post-effect, stop & CI-boundary frames. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-002 | GRD-G01 | Guard | COMMITTED | Classify explicit or inferred effects into canonical effect vocabulary without guessing unknown explicit classes. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-003 | GRD-G01 | Guard | COMMITTED | Match shell command segments for destructive file operations, dependency installs, commits, pushes & publication. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-004 | GRD-G02 | Guard | COMMITTED | Deny pre-effects when frame validation, classification, policy load, or authorization fails. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-005 | GRD-G02 | Guard | COMMITTED | Enforce hard destructive-command & history-rewrite-push refusals before native policy authorization. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-006 | GRD-G02 | Guard | COMMITTED | Gate typed effects rather than capability labels, model roles, or route envelopes. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-007 | GRD-G02 | Guard | COMMITTED | Load versioned native application policy from inline config, named path, or canonical repository default. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-008 | GRD-G03 | Guard | COMMITTED | Report typed enforcement health & keep mandatory authorization/security gates fail-closed. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-009 | GRD-G03 | Guard | COMMITTED | Record authenticated effect observations & dependency-bound evidence without accepting model self-report. | PARTIAL | PENDING | PENDING | COMMITTED | REPAIR_WIRE | PENDING |
| GRD-010 | GRD-G03 | Guard | COMMITTED | Observe SubagentStop lifecycle without making dispatch itself an effect class. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-011 | GRD-G01 | Guard | COMMITTED | Classify MCP write, send & delete tools through same typed effect gate. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| GRD-012 | GRD-G03 | Guard | COMMITTED | Apply proportional Stop verification & require Oracle receipt only when typed requirement demands it. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| GRD-I001 | GRD-009 | Authenticated observations & dependency-bound evidence | `src/lib/verification/arcane/ingest.mjs@LOCAL`; `src/lib/guard/compat/audit/receipt-auth.mjs@LOCAL` | ADAPT | PARTIAL | Guard receipt ingestion |
| GRD-I002 | GRD-010 | SubagentStop observation-only lifecycle support | `hooks/hooks.json@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` | DIRECT_PORT | DELIVERED | legion-hook SubagentStop dispatch |
| GRD-I003 | GRD-011 | MCP write/send/delete effect classification | `hooks/hooks.json@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` | DIRECT_PORT | DELIVERED | legion-hook PreToolUse gate |
| GRD-I004 | GRD-001, GRD-002, GRD-003, GRD-004, GRD-007, GRD-009 | P0.5 relocation of Guard host, effect, policy, rule & audit modules | `docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json@LOCAL` | DIRECT_PORT | DELIVERED | `src/lib/guard/compat` plus CLI & host imports |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| GRD-Q001 | GRD-001, GRD-002, GRD-003, GRD-004, GRD-005, GRD-006, GRD-007, GRD-008, GRD-009, GRD-010, GRD-011, GRD-012 | Guard-AC-BOUNDARY-001: reconcile each observable through live consumer at RELEASED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| GRD-D001 | REFERENCE | GRD-001 | Guard owns deterministic effect enforcement & receipts; Arcane owns cognitive policy. | Root SSOT | RECORDED |
| GRD-D002 | BACKLOG | — | Final public Guard naming remains deferred & does not change owner boundary. | Legacy tracker | DEFERRED |
