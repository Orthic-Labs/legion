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
| LEG-001 | LEG-G01 | Legion | COMMITTED | Classify each request as answer, design, implementation, or artifact with smallest reversible reading. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-002 | LEG-G01 | Legion | COMMITTED | Treat latest explicit user scope as authority while preventing prompts, memory, or hooks from expanding it. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-003 | LEG-G01 | Legion | COMMITTED | Select zero, one, or many capabilities semantically from flat compact catalog; keep explicit aliases deterministic. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-004 | LEG-G01 | Legion | COMMITTED | Attach Sage, Alchemist, or Oracle only when authority boundary requires it. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-005 | LEG-G02 | Legion | COMMITTED | Compile non-trivial work into dependency-aware work units with capabilities, operations, effects & authority state. | PARTIAL | PENDING | PENDING | COMMITTED | REPAIR_WIRE | PENDING |
| LEG-006 | LEG-G02 | Legion | COMMITTED | Execute ordinary explicit reversible mutations ambiently when Guard policy permits. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-007 | LEG-G02 | Legion | COMMITTED | Parallelize independent implementation while assigning one integration owner per repository. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-008 | LEG-G02 | Legion | COMMITTED | Bind each work unit to least nondeterministic authorized executor without escalating denied semantic execution. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-009 | LEG-G02 | Legion | COMMITTED | Treat worker output as untrusted until primary-checkout verification & durable handoff evidence exist. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-010 | LEG-G03 | Legion | COMMITTED | Require evidence before claims & report produced, verified, completion-validated, committed, pushed & deployed separately. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-011 | LEG-G03 | Legion | COMMITTED | Require fresh independent Oracle Completion Validation before successful delivery. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-012 | LEG-G03 | Legion | COMMITTED | Preserve unrelated changes, avoid false-clean claims, bound retries & stop on repeated unchanged failure. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-013 | LEG-G04 | Legion | COMMITTED | Generate host-specific role & hook projections one-way from canonical host-neutral sources. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-014 | LEG-G04 | Legion | COMMITTED | Package collision-safe reversible client integrations without transferring canonical semantic ownership to adapters. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| LEG-015 | LEG-G04 | Legion | COMMITTED | Publish exact signed native candidates only after hosted signing & installed qualification gates. | PARTIAL | PENDING | PENDING | LOCAL | REPAIR_WIRE | PENDING |
| LEG-016 | LEG-G03 | Legion | COMMITTED | Emit signed & sealed audit plans with SARIF, execution receipts & Blueprint generation pinning. | PARTIAL | PENDING | PENDING | LOCAL | REPAIR_WIRE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| LEG-I001 | LEG-005 | Work-unit execution requirements & compiler wiring | `engine/crates/legion-contracts/src/plan.rs@c498a604`; `engine/crates/legion-runtime/src/plan.rs@c498a604` | ADAPT | PARTIAL | Legion runtime plan builder |
| LEG-I002 | LEG-013 | Role & hook host projections | `scripts/generate-host-projection.mjs@c498a604`; `scripts/generate-catalogs.mjs@c498a604` | DIRECT_PORT | DELIVERED | Host projection generator |
| LEG-I003 | LEG-015 | Signed-candidate & publication pipeline | Active release working tree; not durable evidence | ADAPT | PARTIAL | RightKit release pipeline |
| LEG-I004 | LEG-004, LEG-005, LEG-006, LEG-010, LEG-014 | P0.5 relocation of Legion-owned contracts, governance, host & verification modules | `docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json@LOCAL` | DIRECT_PORT | DELIVERED | `src/lib/contracts`, `src/lib/cli/commands/governance`, `src/lib/host` & `src/lib/verification` consumers |
| LEG-I005 | LEG-001, LEG-002, LEG-003, LEG-004, LEG-006 | Hand-maintained routing/scope doctrine injected at SessionStart (`SESSION_START_CONTEXT`); not produced by `scripts/generate-host-projection.mjs` | `engine/bins/legion-hook/src/main.rs@LOCAL`; `hooks/hooks.json@LOCAL` | ORIGINAL | DELIVERED | legion-hook SessionStart additionalContext |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| LEG-Q001 | LEG-001, LEG-002, LEG-003, LEG-004, LEG-005, LEG-006, LEG-007, LEG-008, LEG-009, LEG-010, LEG-011, LEG-012, LEG-013, LEG-014, LEG-015 | Legion-AC-BOUNDARY-001: reconcile each observable through live consumer at PUSHED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| LEG-D001 | REFERENCE | LEG-013 | Skill projection remains SKL-003-owned; LEG-013 retains role & hook projection only. | Canon reconciliation | RECORDED |
| LEG-D002 | BACKLOG | LEG-005 | Fact-derived work state & supervision remain deferred outside LEG-MR-0..5. | Legacy proposal §16.1 | DEFERRED |
| LEG-D003 | EXCLUSION | LEG-015 | Homebrew/WinGet metadata is not an active release gate; aliases remain optional derived consumers. | Distribution doctrine | RECORDED |
