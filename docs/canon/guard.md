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
| GRD-001 | GRD-G01 | Guard | COMMITTED | Parse & validate versioned host lifecycle, pre-effect, post-effect, stop & CI-boundary frames. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-002 | GRD-G01 | Guard | COMMITTED | Classify explicit or inferred effects into canonical effect vocabulary without guessing unknown explicit classes. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-003 | GRD-G01 | Guard | COMMITTED | Match shell command segments for destructive file operations, dependency installs, commits, pushes & publication. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-004 | GRD-G02 | Guard | COMMITTED | Deny pre-effects when frame validation, classification, policy load, or authorization fails. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-005 | GRD-G02 | Guard | COMMITTED | Enforce hard destructive-command & history-rewrite-push refusals before native policy authorization. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-006 | GRD-G02 | Guard | COMMITTED | Gate typed effects rather than capability labels, model roles, or route envelopes. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-007 | GRD-G02 | Guard | COMMITTED | Load versioned native application policy from inline config, named path, or canonical repository default. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-008 | GRD-G03 | Guard | COMMITTED | Report typed enforcement health & keep mandatory authorization/security gates fail-closed. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-009 | GRD-G03 | Guard | COMMITTED | Record authenticated effect observations & dependency-bound evidence without accepting model self-report. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-UNRESOLVED-CLOSURE-001; Revision: 044ae8f157d001d8633a771e1b15f99a53240cb9; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@2e8a925780c1ff1ce8b939a3646f0304b7a80117353c6ea60e621a1545e8051a; Freshness: 2026-08-31 |
| GRD-010 | GRD-G03 | Guard | COMMITTED | Observe SubagentStop lifecycle without making dispatch itself an effect class. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-011 | GRD-G01 | Guard | COMMITTED | Classify MCP write, send & delete tools through same typed effect gate. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-012 | GRD-G03 | Guard | COMMITTED | Apply proportional Stop verification & require Oracle receipt only when typed requirement demands it. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| GRD-013 | GRD-G02 | Guard | COMMITTED | Expose provider credentials only inside authorized execution scope & keep credential material out of public receipts. | DELIVERED | FOCUSED_PASS | PASS | RELEASED | RETAIN | Acceptance: GRD-AC-UNRESOLVED-CLOSURE-001; Revision: 044ae8f157d001d8633a771e1b15f99a53240cb9; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@2e8a925780c1ff1ce8b939a3646f0304b7a80117353c6ea60e621a1545e8051a; Freshness: 2026-08-31 |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| GRD-I001 | GRD-009 | Authenticated observations, dependency freshness & invalidation | `src/lib/verification/arcane/ingest.mjs@044ae8f1`; `src/lib/verification/arcane/invalidation.mjs@044ae8f1`; `src/lib/guard/compat/audit/receipt-auth.mjs@044ae8f1` | ADAPT | DELIVERED | Guard receipt ingestion & host invalidation consumer |
| GRD-I002 | GRD-010 | SubagentStop observation-only lifecycle support | `hooks/hooks.json@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` | DIRECT_PORT | DELIVERED | legion-hook SubagentStop dispatch |
| GRD-I003 | GRD-011 | MCP write/send/delete effect classification | `hooks/hooks.json@c498a604`; `engine/bins/legion-hook/src/main.rs@c498a604` | DIRECT_PORT | DELIVERED | legion-hook PreToolUse gate |
| GRD-I004 | GRD-001, GRD-002, GRD-003, GRD-004, GRD-007, GRD-009 | P0.5 relocation of Guard host, effect, policy, rule & audit modules | `docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json@LOCAL` | DIRECT_PORT | DELIVERED | `src/lib/guard/compat` plus CLI & host imports |
| GRD-I005 | GRD-013 | Provider credential allowlist, scoped environment injection & public evidence redaction | `engine/crates/legion-provider-sdk/src/auth.rs@044ae8f1`; `engine/crates/legion-provider-sdk/src/http_client.rs@044ae8f1`; `engine/crates/legion-provider-sdk/src/inference.rs@044ae8f1` | ORIGINAL | DELIVERED | Native provider execution boundary |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| GRD-Q001 | GRD-009, GRD-013 | GRD-AC-UNRESOLVED-CLOSURE-001: reconcile each observable through live consumer at RELEASED boundary | PASS | Acceptance: GRD-AC-UNRESOLVED-CLOSURE-001; Revision: 044ae8f157d001d8633a771e1b15f99a53240cb9; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@2e8a925780c1ff1ce8b939a3646f0304b7a80117353c6ea60e621a1545e8051a; Freshness: 2026-08-31 | 044ae8f157d001d8633a771e1b15f99a53240cb9 |
| GRD-Q002 | GRD-001, GRD-002, GRD-003, GRD-004, GRD-005, GRD-006, GRD-007, GRD-008, GRD-010, GRD-011, GRD-012 | GRD-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at RELEASED boundary | PASS | Acceptance: GRD-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| GRD-D001 | REFERENCE | GRD-001 | Guard owns deterministic effect enforcement & receipts; Arcane owns cognitive policy. | Root SSOT | RECORDED |
| GRD-D002 | BACKLOG | — | Final public Guard naming remains deferred & does not change owner boundary. | Legacy tracker | DEFERRED |
| GRD-D003 | REFERENCE | GRD-013 | Dual blind Foundation inventories identified execution-scoped credential isolation as distinct from generic effect classification. | `docs/foundation/2026-08-31/legion-reconciliation.md` | RECORDED |
