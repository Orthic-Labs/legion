# Arcane capability canon

Owner boundary: bounded cognitive control plane; never effect authorization or receipts.

Required delivery boundary: `PUSHED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| ARC-G01 | — | Arcane | COMMITTED | route envelope |
| ARC-G02 | — | Arcane | COMMITTED | cognitive controls |
| ARC-G03 | — | Arcane | COMMITTED | response policy |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| ARC-001 | ARC-G01 | Arcane | COMMITTED | Compile minimum sufficient context, cognition, grounding, compute, challenge, verification & response policy. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-UNRESOLVED-CLOSURE-001; Revision: 0d6016c864cffebd480bc72d2b1a46529b0cf3da; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@8c0d04dd33e0bfc86a135362c7aea95cb7185c207bc83e92258d876820197706; Freshness: 2026-08-31 |
| ARC-002 | ARC-G01 | Arcane | COMMITTED | Resolve trivial default route with no model call & near-empty envelope. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-UNRESOLVED-CLOSURE-001; Revision: 0d6016c864cffebd480bc72d2b1a46529b0cf3da; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@8c0d04dd33e0bfc86a135362c7aea95cb7185c207bc83e92258d876820197706; Freshness: 2026-08-31 |
| ARC-004 | ARC-G02 | Arcane | COMMITTED | Add cognitive machinery only when it improves task outcome; never create self-justifying ceremony. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ARC-005 | ARC-G02 | Arcane | COMMITTED | Run at most one evidence-directed bounded falsification pass with KEEP, NARROW, or REVISE result. | PARTIAL | PENDING | PENDING | PUSHED | REPAIR_WIRE | Oracle recheck BLOCK: `src/lib/host/arcane/host-runtime.mjs:461` returns caller-supplied result without evaluating evidence. |
| ARC-006 | ARC-G02 | Arcane | COMMITTED | Escalate routing uncertainty to stronger working model without creating workflow ritual. | PARTIAL | PENDING | PENDING | PUSHED | REPAIR_WIRE | Oracle recheck BLOCK: `src/lib/host/arcane/host-runtime.mjs:449` & `engine/bins/legion-hook/src/main.rs:154` emit escalation metadata without executing stronger model. |
| ARC-007 | ARC-G03 | Arcane | COMMITTED | Apply Brief/Minimize & ending-shape discipline without managing work state. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ARC-008 | ARC-G03 | Arcane | COMMITTED | Keep cognitive route ephemeral & emit no effect authorization or effect receipt. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| ARC-009 | ARC-G03 | Arcane | COMMITTED | Degrade unavailable optional cognitive machinery while preserving useful permitted work. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: ARC-AC-UNRESOLVED-CLOSURE-001; Revision: 0d6016c864cffebd480bc72d2b1a46529b0cf3da; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@8c0d04dd33e0bfc86a135362c7aea95cb7185c207bc83e92258d876820197706; Freshness: 2026-08-31 |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| ARC-I001 | ARC-001, ARC-002, ARC-009 | Cognitive route-envelope, host policy injection & degradation continuity | `src/lib/cognitive/arcane/route-envelope.mjs@0d6016c8`; `src/lib/cognitive/arcane/host/policy-inject.mjs@0d6016c8`; `src/lib/host/arcane/host-runtime.mjs@0d6016c8` | ADAPT | DELIVERED | Live host cognitive-route producer & continuity ledger |
| ARC-I002 | ARC-004, ARC-007, ARC-008 | Brief/Minimize, ending-shape & anti-ceremony doctrine | `doctrine/arcane.md@c498a604`; `src/lib/cognitive/arcane/minimize.mjs@LOCAL` | DIRECT_PORT | DELIVERED | SessionStart/Stop cognitive policy surface |
| ARC-I003 | LEG-008 | Legacy deterministic-executor selection behavior formerly counted as ARC-003 | `docs/canon/registers/preservation-map.md@LOCAL` (original citation `docs/current/atoms/arcane.md@d47d3a08` no longer exists in-repo) | ABSORB_REFERENCE | UNKNOWN | Legion executor binding |
| ARC-I004 | ARC-001, ARC-007 | P0.5 relocation of Arcane cognitive-plane modules from mixed package | `docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json@LOCAL` | DIRECT_PORT | DELIVERED | `src/lib/cognitive/arcane` plus CLI & host imports |
| ARC-I005 | ARC-005, ARC-006 | Bounded falsification & stronger-model escalation execution | `src/lib/host/arcane/host-runtime.mjs@0d6016c8`; `engine/bins/legion-hook/src/main.rs@0d6016c8` | ADAPT | PARTIAL | Host path records caller-supplied challenge/escalation metadata; evidence evaluation & stronger-model execution remain unwired |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| ARC-Q001 | ARC-001, ARC-002, ARC-009 | ARC-AC-UNRESOLVED-CLOSURE-001: reconcile each observable through live consumer at PUSHED boundary | PASS | Acceptance: ARC-AC-UNRESOLVED-CLOSURE-001; Revision: 0d6016c864cffebd480bc72d2b1a46529b0cf3da; Receipt: docs/foundation/2026-08-31/unresolved-closure-receipt.json@8c0d04dd33e0bfc86a135362c7aea95cb7185c207bc83e92258d876820197706; Freshness: 2026-08-31 | 0d6016c864cffebd480bc72d2b1a46529b0cf3da |
| ARC-Q002 | ARC-004, ARC-007, ARC-008 | ARC-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at PUSHED boundary | PASS | Acceptance: ARC-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |
| ARC-Q003 | ARC-005, ARC-006 | Execute evidence-directed falsification & stronger-model escalation in live production consumer | FAIL | Oracle Completion Validation recheck BLOCK at release revision `0d6016c864cffebd480bc72d2b1a46529b0cf3da`. | 0d6016c864cffebd480bc72d2b1a46529b0cf3da |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| ARC-D001 | REFERENCE | LEG-008 | Arcane compiles cognitive policy only; Legion binds executor. | Canon reconciliation | RECORDED |
| ARC-D002 | BACKLOG | ARC-002 | Resident micro-router remains deferred until behavioral qualification exists. | Legacy Arcane proposal §29 | DEFERRED |
| ARC-D003 | REFERENCE | LEG-008 | ARC-003 is retired from capability totals; Legion owns executor binding. | Canon reconciliation migration | RECORDED |
| ARC-D004 | REFERENCE | ARC-007, ARC-008 | Stop-shape/ending-shape logic exists twice: JS `src/lib/cognitive/arcane/stop-shape.mjs` (SessionStart projection) & an independent Rust reimplementation in `engine/bins/legion-hook/src/main.rs` (the wired Stop hook). Rust is the enforced surface; parity between the two is unverified. | Canon reconciliation 2026-08-30 | RECORDED |
| ARC-D005 | BACKLOG | ARC-005, ARC-006 | Replace caller-supplied falsification result with evidence evaluation & execute selected stronger model rather than emitting metadata only. | Oracle Completion Validation recheck at `0d6016c8` | DEFERRED |
