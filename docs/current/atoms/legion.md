# Legion capability canon

Owner boundary: orchestration, work compilation, integration, delivery & public distribution.

## Group register

| Group | Meaning |
|---|---|
| LEG-G01 | intent & routing |
| LEG-G02 | work graph & execution coordination |
| LEG-G03 | evidence & delivery |
| LEG-G04 | distribution & host projection |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| LEG-001 | LEG-G01 | Legion | COMMITTED | Classify each request as answer, design, implementation, or artifact with smallest reversible reading. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604` |
| LEG-002 | LEG-G01 | Legion | COMMITTED | Treat latest explicit user scope as authority while preventing prompts, memory, or hooks from expanding it. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604` |
| LEG-003 | LEG-G01 | Legion | COMMITTED | Select zero, one, or many capabilities semantically from flat compact catalog; keep explicit aliases deterministic. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/legion.md@c498a604` |
| LEG-004 | LEG-G01 | Legion | COMMITTED | Attach Sage, Alchemist, or Oracle only when authority boundary requires it. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `docs/LEGION-CANONICAL-SSOT.md@blob:61bcc163` |
| LEG-005 | LEG-G02 | Legion | COMMITTED | Compile non-trivial work into dependency-aware work units with capabilities, operations, effects & authority state. | PARTIAL | PENDING | NOT_REQUIRED | COMMITTED | REPAIR_WIRE | `docs/LEGION-CANONICAL-SSOT.md@blob:61bcc163`; `src/packages/contracts@c498a604` |
| LEG-006 | LEG-G02 | Legion | COMMITTED | Execute ordinary explicit reversible mutations ambiently when Guard policy permits. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `doctrine/legion.md@c498a604` |
| LEG-007 | LEG-G02 | Legion | COMMITTED | Parallelize independent implementation while assigning one integration owner per repository. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604` |
| LEG-008 | LEG-G02 | Legion | COMMITTED | Bind each work unit to least nondeterministic authorized executor without escalating denied semantic execution. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `doctrine/legion.md@c498a604`; `engine/crates/legion-contracts/src/plan.rs@c498a604` |
| LEG-009 | LEG-G02 | Legion | COMMITTED | Treat worker output as untrusted until primary-checkout verification & durable handoff evidence exist. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `skills/dispatch/SKILL.md@c498a604` |
| LEG-010 | LEG-G03 | Legion | COMMITTED | Require evidence before claims & report produced, verified, completion-validated, committed, pushed & deployed separately. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604` |
| LEG-011 | LEG-G03 | Legion | COMMITTED | Require fresh independent Oracle Completion Validation before successful delivery. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `doctrine/oracle.md@c498a604` |
| LEG-012 | LEG-G03 | Legion | COMMITTED | Preserve unrelated changes, avoid false-clean claims, bound retries & stop on repeated unchanged failure. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `AGENTS.md@c498a604`; `doctrine/legion.md@c498a604` |
| LEG-013 | LEG-G04 | Legion | COMMITTED | Generate host-specific role, skill & hook projections one-way from canonical host-neutral sources. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `scripts/generate-host-projection.mjs@c498a604`; `scripts/generate-catalogs.mjs@c498a604` |
| LEG-014 | LEG-G04 | Legion | COMMITTED | Package collision-safe reversible client integrations without transferring canonical semantic ownership to adapters. | DELIVERED | FOCUSED_PASS | PENDING | COMMITTED | EVIDENCE | `docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md@c498a604`; `scripts/qualify-clean-environment.mjs@c498a604` |
| LEG-015 | LEG-G04 | Legion | COMMITTED | Publish exact signed native candidates only after hosted signing & installed qualification gates. | PARTIAL | PENDING | PENDING | LOCAL | REPAIR_WIRE | `right-release.config.mjs@working-tree`; `.github/workflows/release-candidate.yml@working-tree` |

