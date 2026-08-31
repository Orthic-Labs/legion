# Legion capability canon

Owner boundary: orchestration, work compilation, integration, delivery & public distribution.

Required delivery boundary: `PUSHED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| LEG-G01 | — | Legion | COMMITTED | intent & routing |
| LEG-G02 | — | Legion | COMMITTED | work graph & execution coordination |
| LEG-G03 | — | Legion | COMMITTED | evidence & delivery |
| LEG-G04 | — | Legion | COMMITTED | distribution & host projection |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| LEG-001 | LEG-G01 | Legion | COMMITTED | Classify each request as answer, design, implementation, or artifact with smallest reversible reading. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-002 | LEG-G01 | Legion | COMMITTED | Treat latest explicit user scope as authority while preventing prompts, memory, or hooks from expanding it. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-003 | LEG-G01 | Legion | COMMITTED | Select zero, one, or many capabilities semantically from flat compact catalog; keep explicit aliases deterministic. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-004 | LEG-G01 | Legion | COMMITTED | Attach Sage, Alchemist, or Oracle only when authority boundary requires it. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-005 | LEG-G02 | Legion | COMMITTED | Compile non-trivial work into dependency-aware work units with capabilities, operations, effects & authority state. | PARTIAL | PENDING | PENDING | COMMITTED | REPAIR_WIRE | PENDING |
| LEG-006 | LEG-G02 | Legion | COMMITTED | Execute ordinary explicit reversible mutations ambiently when Guard policy permits. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-007 | LEG-G02 | Legion | COMMITTED | Parallelize independent implementation while assigning one integration owner per repository. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-008 | LEG-G02 | Legion | COMMITTED | Bind each work unit to least nondeterministic authorized executor without escalating denied semantic execution. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-009 | LEG-G02 | Legion | COMMITTED | Treat worker output as untrusted until primary-checkout verification & durable handoff evidence exist. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-010 | LEG-G03 | Legion | COMMITTED | Require evidence before claims & report produced, verified, completion-validated, committed, pushed & deployed separately. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-011 | LEG-G03 | Legion | COMMITTED | Require fresh independent Oracle Completion Validation before successful delivery. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-012 | LEG-G03 | Legion | COMMITTED | Preserve unrelated changes, avoid false-clean claims, bound retries & stop on repeated unchanged failure. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-013 | LEG-G04 | Legion | COMMITTED | Generate host-specific role & hook projections one-way from canonical host-neutral sources. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-014 | LEG-G04 | Legion | COMMITTED | Package collision-safe reversible client integrations without transferring canonical semantic ownership to adapters. | DELIVERED | FOCUSED_PASS | PASS | PUSHED | RETAIN | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 |
| LEG-015 | LEG-G04 | Legion | COMMITTED | Publish exact signed native candidates only after hosted signing & installed qualification gates. | PARTIAL | PENDING | PENDING | LOCAL | REPAIR_WIRE | PENDING |
| LEG-016 | LEG-G03 | Legion | COMMITTED | Emit signed & sealed audit plans with SARIF, execution receipts & Blueprint generation pinning. | PARTIAL | PENDING | PENDING | LOCAL | REPAIR_WIRE | PENDING |
| LEG-017 | LEG-G02 | Legion | COMMITTED | Resume interrupted execution from fingerprinted durable state without repeating completed effects. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-018 | LEG-G02 | Legion | COMMITTED | Pause at named planning or execution decisions & resume with captured operator direction. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-019 | LEG-G02 | Legion | COMMITTED | Enforce per-run step, call, spend & wall-time limits while terminating descendant processes on timeout or cancellation. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-020 | LEG-G02 | Legion | COMMITTED | Replan remaining dependency work from failure evidence while preserving completed outputs. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-021 | LEG-G02 | Legion | COMMITTED | Normalize executor actions & return explicit malformed-output guidance for bounded correction. | MISSING | PENDING | PENDING | LOCAL | BEHAVIORAL_REIMPLEMENT | PENDING |
| LEG-022 | LEG-G03 | Legion | COMMITTED | Preserve an inspectable execution trajectory with parent, dependency, terminal & submission state. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-023 | LEG-G03 | Legion | COMMITTED | Attribute model calls, tokens & cost to executions and work units for operator inspection. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-024 | LEG-G02 | Legion | COMMITTED | Start bound workflows from schedules or external events while preserving trigger metadata. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-025 | LEG-G02 | Legion | COMMITTED | Stop accepting work & drain active operations before runtime shutdown. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-026 | LEG-G03 | Legion | COMMITTED | Forward execution observations with bounded batching, dead-letter retention & explicit redrive. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |
| LEG-027 | LEG-G04 | Legion | COMMITTED | Publish capability metadata with verifiable identity when available & explicit unavailable trust state otherwise. | UNKNOWN | PENDING | PENDING | LOCAL | RECONCILE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| LEG-I001 | LEG-005 | Work-unit execution requirements & compiler wiring | `engine/crates/legion-contracts/src/plan.rs@c498a604`; `engine/crates/legion-runtime/src/plan.rs@c498a604` | ADAPT | PARTIAL | Legion runtime plan builder |
| LEG-I002 | LEG-013 | Role & hook host projections | `scripts/generate-host-projection.mjs@c498a604`; `scripts/generate-catalogs.mjs@c498a604` | DIRECT_PORT | DELIVERED | Host projection generator |
| LEG-I003 | LEG-015 | Signed-candidate & publication pipeline | Active release working tree; not durable evidence | ADAPT | PARTIAL | RightKit release pipeline |
| LEG-I004 | LEG-004, LEG-005, LEG-006, LEG-010, LEG-014 | P0.5 relocation of Legion-owned contracts, governance, host & verification modules | `docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json@LOCAL` | DIRECT_PORT | DELIVERED | `src/lib/contracts`, `src/lib/cli/commands/governance`, `src/lib/host` & `src/lib/verification` consumers |
| LEG-I005 | LEG-001, LEG-002, LEG-003, LEG-004, LEG-006 | Hand-maintained routing/scope doctrine injected at SessionStart (`SESSION_START_CONTEXT`); not produced by `scripts/generate-host-projection.mjs` | `engine/bins/legion-hook/src/main.rs@LOCAL`; `hooks/hooks.json@LOCAL` | ORIGINAL | DELIVERED | legion-hook SessionStart additionalContext |
| LEG-I006 | LEG-016 | Plan seal/signature, SARIF writer & Blueprint generation pinning | `tools/audit/audit-run.mjs@LOCAL`; `tools/audit/audit-plan.mjs@LOCAL`; `tools/audit/audit-finalize.mjs@LOCAL`; `src/lib/cli/commands/audit.mjs@LOCAL` | ORIGINAL | PARTIAL | Reachable from package JavaScript `legion audit`; installed native composition remains partial until release parity |
| LEG-I007 | LEG-021 | Executor-neutral parse → normalize → validate loop with bounded malformed-output correction before effects | `swe-agent__swe-agent/sweagent/agent/agents.py@3ea751c087f32b16e039a2233dd6eefecef325d5`; `docs/foundation/2026-08-31/legion-stage5-gap-handoff.md` | BEHAVIORAL_REIMPLEMENT | MISSING | Executor adapter boundary; not yet wired |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| LEG-Q001 | LEG-005, LEG-015, LEG-016, LEG-017, LEG-018, LEG-019, LEG-020, LEG-021, LEG-022, LEG-023, LEG-024, LEG-025, LEG-026, LEG-027 | Legion-AC-BOUNDARY-001: reconcile each observable through live consumer at PUSHED boundary | PENDING | NONE | LOCAL |
| LEG-Q002 | LEG-001, LEG-002, LEG-003, LEG-004, LEG-006, LEG-007, LEG-008, LEG-009, LEG-010, LEG-011, LEG-012, LEG-013, LEG-014 | LEG-AC-IMPLEMENTED-CLOSURE-001: qualify delivered observables at PUSHED boundary | PASS | Acceptance: LEG-AC-IMPLEMENTED-CLOSURE-001; Revision: d495db78b8d63be58f288e73a8d0660197791253; Receipt: docs/foundation/2026-08-31/implemented-closure-receipt.json@7da910ed92772c5bca53b8d7eb68c1c2561979078d5df4d2df88bbb8dacc4800; Freshness: 2026-08-31 | d495db78b8d63be58f288e73a8d0660197791253 |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| LEG-D001 | REFERENCE | LEG-013 | Skill projection remains SKL-003-owned; LEG-013 retains role & hook projection only. | Canon reconciliation | RECORDED |
| LEG-D002 | BACKLOG | LEG-005 | Fact-derived work state & supervision remain deferred outside LEG-MR-0..5. | Legacy proposal §16.1 | DEFERRED |
| LEG-D003 | EXCLUSION | LEG-015 | Homebrew/WinGet metadata is not an active release gate; aliases remain optional derived consumers. | Distribution doctrine | RECORDED |
| LEG-D004 | REFERENCE | LEG-016 | Package JavaScript CLI now reaches complete `tools/audit` provider runner; installed native CLI remains explicit partial compatibility coverage & cannot support full-Audit claims. | Live-path repair, 2026-08-31 | RECORDED |
| LEG-D005 | REFERENCE | LEG-017, LEG-018, LEG-019, LEG-020, LEG-021, LEG-022, LEG-023, LEG-024, LEG-025, LEG-026, LEG-027 | Dual blind Foundation inventories promoted these missed contracts; implementation, verification & delivery remain unproven until target reconciliation. | `docs/foundation/2026-08-31/legion-reconciliation.md` | RECORDED |
| LEG-D006 | REFERENCE | LEG-021 | Dual Stage 3 comparison resolved 106 dirty rows & proved one material implementation deficit; no new observable atom was required. | `docs/foundation/2026-08-31/legion-foundation-receipt.json`; `docs/foundation/2026-08-31/legion-stage3-reconciliation.md` | RECORDED |
