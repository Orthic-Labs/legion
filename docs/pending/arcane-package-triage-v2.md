# Arcane package triage v2 — consumer-grounded

**Tracker:** P0.5  
**Scope:** every file under `src/packages/arcane/` (235 files).  
**Action:** disposition only. This document moves, deletes, or edits nothing.

## Result before disposition

The consumer bands are the execution order:

| Band | Meaning | Files |
|---|---|---:|
| 1 | No live source consumer found anywhere in the repository | **84** |
| 2 | Consumers found only inside `src/packages/arcane/` | **94** |
| 3 | At least one consumer outside `src/packages/arcane/` | **57** |

Thus **151 files are not actionable by deletion/move alone today**; they have package-internal or external consumers. Only the 84 Band-1 entries can be safely considered without first preserving a consumer. A Band-3 entry is never `RETIRE`; its consumer must migrate before its old location can disappear.

### Method and coverage

I read the correction at the bottom of `docs/pending/arcane-package-triage.md` first. I then enumerated the live tree and grepped the whole repository (excluding `.git`, `dist`, and `node_modules`) for each module path, its relative import path, its exported symbol names, and for data assets their exact path/value references. The source search covered `src/`, `tests/`, `tools/`, `engine/`, `docs/`, `doctrine/`, `package.json`, and `MANIFEST.package.json`; binary build outputs were not treated as consumers.

**Coverage:** 235/235 files were path-checked. Consumer status was established by grep for **187/235 code modules** and **48/235 JSON/Markdown/rules assets**: **235/235 consumer-verified, 0/235 consumer-inferred**. **0/235 dispositions are inferred solely from filename.** “No live consumers found” below is a grep result, not an architectural assumption. A test runner is not counted as a source-module consumer; a root test or CLI that imports an Arcane file is counted. Documentation mentions and archived evidence are recorded only when relevant, but are not live consumers.

`Consumers: none found` means no live consumer was found outside the file itself (or, for an implementation, outside its own test-only references). Every row still has a disposition and a consumer-based reason.

### Dispositions and concrete landing owners

- **PORT** — move/implement the behavior in the existing Guard crates: `engine/crates/legion-policy/src`, `engine/crates/legion-contracts/src`, `engine/crates/legion-effects/src`, `engine/crates/legion-host/src`, or `engine/crates/legion-audit/src`, as named per row.
- **RESTORE** — retain the cognitive Brief/Minimize/ending-shape behavior at the existing host/Arcane boundary.
- **MOVE** — move to the existing owner named per row. `src/lib/cli/commands/governance/delivery.mjs`, `src/lib/cli/commands/governance/execution.mjs`, `src/lib/cli/commands/governance/judgment.mjs`, `src/lib/verification/`, and `src/lib/host/` are existing destinations. Where no suitable destination exists, the row says **blocked: destination not built** rather than inventing “Legion” as an owner.
- **RETIRE** — only no live consumer was found and the asset is dead ceremony/obsolete documentation; this is not used for live policy, CLI, host, or test dependencies.
- **SPLIT** — the named portions have separate owners; consumer migration must preserve both portions.

## Band 1 — no live source consumers found (84)

### Package and policy assets

- `src/packages/arcane/INTERFACES.md` — **Consumers:** none found. **RETIRE.** No live reader exists; it is package ceremony rather than a consumed runtime contract.
- `src/packages/arcane/KEY-CUSTODY.md` — **Consumers:** none found as a live source reader; the key implementation and provisioning modules refer to it only as documentation. **PORT** its custody contract to `engine/crates/legion-host/src`; no source consumer needs migration.
- `src/packages/arcane/index.mjs` — **Consumers:** none found. **SPLIT (PORT/MOVE/RESTORE).** No importer uses the barrel; its exported portions can be separated without breaking a discovered consumer.
- `src/packages/arcane/policy/README.md` — **Consumers:** none found. **RETIRE.** No live reader uses this historical-bundle explanation.

### Arcane tests

Each test below has **Consumers: none found** outside the test runner. Its disposition follows the behavior it directly tests; the absence of an importer does not make the tested production module dead.

- `src/packages/arcane/tests/adversarial-ai-reconstruction.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and its assertions belong to the existing verification owner.
- `src/packages/arcane/tests/adversarial-migration-distributed.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and its migration-assurance assertions belong there.
- `src/packages/arcane/tests/adversarial-ownership-economics.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and its ownership assurance belongs there.
- `src/packages/arcane/tests/adversarial-proportionality.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and its proportionality assurance belongs there.
- `src/packages/arcane/tests/advisory-certification.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and certification assertions belong to verification.
- `src/packages/arcane/tests/advisory-effect-classification.test.mjs` — **PORT** to `engine/crates/legion-policy/src`; no consumer needs migration, and the tested effect vocabulary is Guard behavior.
- `src/packages/arcane/tests/advisory-judgment.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and judgment assertions belong there.
- `src/packages/arcane/tests/advisory-profile.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and profile assertions belong there.
- `src/packages/arcane/tests/authority-binding-store.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and authority-binding assertions belong there.
- `src/packages/arcane/tests/authority-invocation-proof.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and proof assertions belong there.
- `src/packages/arcane/tests/budget-governance.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; no consumer needs migration, and budget-governance assertions belong to execution governance.
- `src/packages/arcane/tests/calibration-convergence-policy.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and calibration assertions belong there.
- `src/packages/arcane/tests/chain-bootstrap.test.mjs` — **SPLIT (PORT/MOVE)** between `engine/crates/legion-policy/src` and `src/lib/verification/`; no consumer needs migration, and the test crosses Guard bootstrap and runtime bootstrap.
- `src/packages/arcane/tests/claude-code-adapter.test.mjs` — **PORT** to `engine/crates/legion-host/src`; no consumer needs migration, and it tests host-to-Guard normalization.
- `src/packages/arcane/tests/codex-adapter.test.mjs` — **PORT** to `engine/crates/legion-host/src`; no consumer needs migration, and it tests host-to-Guard normalization.
- `src/packages/arcane/tests/codex-escalation.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and the ceremony is host lifecycle rather than cognition.
- `src/packages/arcane/tests/command-verifier.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and command-result verification belongs there.
- `src/packages/arcane/tests/completion-state.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and completion-state assertions belong there.
- `src/packages/arcane/tests/contract-lifecycle.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and lifecycle assertions belong to delivery governance.
- `src/packages/arcane/tests/contract-seal-store.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and seal assertions belong to delivery governance.
- `src/packages/arcane/tests/current-user-risk-acceptance.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and risk-acceptance assertions belong to assurance.
- `src/packages/arcane/tests/current-user-scope-amendment.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; no consumer needs migration, and scope-amendment assertions belong there.
- `src/packages/arcane/tests/deficit-governance.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; no consumer needs migration, and deficit assertions belong to judgment governance.
- `src/packages/arcane/tests/delivery-continuity-bindings.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and continuity-binding assertions belong there.
- `src/packages/arcane/tests/delivery-guard.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and delivery assertions belong there.
- `src/packages/arcane/tests/denial-circuit.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and bounded retry assertions belong to host runtime.
- `src/packages/arcane/tests/discipline-controls.test.mjs` — **SPLIT (PORT/MOVE)** between `engine/crates/legion-effects/src` and `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and effect refusal and commit discipline have different owners.
- `src/packages/arcane/tests/dispatch-scheduler.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and dispatch assertions belong to delivery governance.
- `src/packages/arcane/tests/durable-capability-store.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and capability assertions belong to Guard effects.
- `src/packages/arcane/tests/eval-candidate-quality.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evaluator assertions belong there.
- `src/packages/arcane/tests/eval-concurrency-convergence.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evaluator assertions belong there.
- `src/packages/arcane/tests/eval-handoff-negative.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evaluator assertions belong there.
- `src/packages/arcane/tests/eval-review-security.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evaluator assertions belong there.
- `src/packages/arcane/tests/evidence-authority.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evidence-authority assertions belong there.
- `src/packages/arcane/tests/evidence-lifecycle.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evidence lifecycle belongs there.
- `src/packages/arcane/tests/execution-governance.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; no consumer needs migration, and retry/continuity assertions belong there.
- `src/packages/arcane/tests/finding-lifecycle.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; no consumer needs migration, and finding assertions belong there.
- `src/packages/arcane/tests/governance-state-binding.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and governance-binding assertions belong there.
- `src/packages/arcane/tests/h13-codex-registered-parity.acceptance.test.mjs` — **PORT** to `engine/crates/legion-host/src`; no consumer needs migration, and parity assertions cover Guard host registration.
- `src/packages/arcane/tests/hook-adapter-core.test.mjs` — **SPLIT (PORT/MOVE/RESTORE)** between `engine/crates/legion-host/src`, `src/lib/host/`, and the cognitive response owner; no consumer needs migration, and the test crosses all three planes.
- `src/packages/arcane/tests/host-runtime-output.test.mjs` — **SPLIT (PORT/MOVE)** between `engine/crates/legion-host/src` and `src/lib/verification/`; no consumer needs migration, and output transport and completion result assertions differ.
- `src/packages/arcane/tests/m7-state-replay.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and replay assertions belong to architecture verification.
- `src/packages/arcane/tests/minimize.test.mjs` — **RESTORE** at the Arcane cognitive boundary; no consumer needs migration, and it preserves Minimize posture tests.
- `src/packages/arcane/tests/policy-compiler.test.mjs` — **PORT** to `engine/crates/legion-rules/src`; no consumer needs migration, and it tests the policy compiler rather than a dead file.
- `src/packages/arcane/tests/policy-inject.test.mjs` — **RESTORE** at the Arcane host boundary; no consumer needs migration, and it tests Brief/Minimize injection.
- `src/packages/arcane/tests/preeffect-correlation.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and correlation is Guard effect evidence.
- `src/packages/arcane/tests/recovery-migration-lifecycle.test.mjs` — **SPLIT (MOVE/RETIRE)** between `src/lib/host/` and `src/lib/verification/`; no consumer needs migration, and only generic control-lifecycle ceremony is retired.
- `src/packages/arcane/tests/review-disposition-policy.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and review disposition belongs there.
- `src/packages/arcane/tests/runtime-binding.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and runtime binding belongs to host integration.
- `src/packages/arcane/tests/runtime-schema.test.mjs` — **MOVE** to `src/lib/contracts/`; no consumer needs migration, and schema assertions belong to contracts.
- `src/packages/arcane/tests/s01-bridge.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and compatibility bridge assertions belong to migration compatibility.
- `src/packages/arcane/tests/s02-policy.test.mjs` — **PORT** to `engine/crates/legion-policy/src`; no consumer needs migration, and its live policy assertions belong to Guard.
- `src/packages/arcane/tests/s03-keys.test.mjs` — **PORT** to `engine/crates/legion-host/src`; no consumer needs migration, and key custody is Guard receipt infrastructure.
- `src/packages/arcane/tests/s03-receipt-auth.test.mjs` — **PORT** to `engine/crates/legion-audit/src`; no consumer needs migration, and it tests authenticated receipts.
- `src/packages/arcane/tests/s03-receipt-store.test.mjs` — **PORT** to `engine/crates/legion-audit/src`; no consumer needs migration, and it tests receipt persistence.
- `src/packages/arcane/tests/s03-replay.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and replay refusal is Guard safety.
- `src/packages/arcane/tests/s04-host-event.test.mjs` — **SPLIT (PORT/MOVE)** between `engine/crates/legion-host/src` and `src/lib/verification/`; no consumer needs migration, and effect normalization and observation qualification differ.
- `src/packages/arcane/tests/s04-ingest.test.mjs` — **SPLIT (PORT/MOVE)** between `engine/crates/legion-audit/src` and `src/lib/verification/`; no consumer needs migration, and receipt ingestion and evidence invalidation differ.
- `src/packages/arcane/tests/s05-evidence-envelope.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evidence-envelope assertions belong there.
- `src/packages/arcane/tests/s05-invalidation.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and invalidation belongs there.
- `src/packages/arcane/tests/s05-migration.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and migration assertions belong there.
- `src/packages/arcane/tests/s06-preeffect-gate.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and pre-effect refusal is Guard behavior.
- `src/packages/arcane/tests/s07-gate2-integration.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and the integration tests the effect gate.
- `src/packages/arcane/tests/s08-capability-mint.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and capability minting is Guard behavior.
- `src/packages/arcane/tests/s09-completion-gate.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and completion claims belong to verification.
- `src/packages/arcane/tests/s11-authority-review-bindings.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and authority review belongs there.
- `src/packages/arcane/tests/s11-eval-adr-canon-clarify.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and ADR evaluation belongs there.
- `src/packages/arcane/tests/s11-eval-adversarial.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and adversarial evaluation belongs there.
- `src/packages/arcane/tests/s11-evidence-closure-bindings.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and evidence closure belongs there.
- `src/packages/arcane/tests/s11-m1-m6-bindings.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and M1–M6 evaluation belongs there.
- `src/packages/arcane/tests/s11-m7-bindings.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and M7 replay evaluation belongs there.
- `src/packages/arcane/tests/semantic-health.test.mjs` — **MOVE** to `src/lib/verification/`; no consumer needs migration, and health probes belong to host verification.
- `src/packages/arcane/tests/session-binding-e2e.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and session binding belongs to host integration.
- `src/packages/arcane/tests/session-binding.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and session binding belongs there.
- `src/packages/arcane/tests/source-revision.test.mjs` — **MOVE** to `src/lib/host/`; no consumer needs migration, and source revision is host evidence.
- `src/packages/arcane/tests/stale-open-atomicity.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; no consumer needs migration, and stale-open behavior belongs to delivery governance.
- `src/packages/arcane/tests/stop-disposition-integration.test.mjs` — **SPLIT (RESTORE/MOVE)** between the cognitive boundary and `src/lib/verification/`; no consumer needs migration, and Stop shape and completion disposition differ.
- `src/packages/arcane/tests/task-budget-seal.test.mjs` — **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; no consumer needs migration, and budget-seal assertions belong to execution governance.
- `src/packages/arcane/tests/user-approval.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and target-bound approval is Guard behavior.
- `src/packages/arcane/tests/vcs-rewrite-approval.test.mjs` — **PORT** to `engine/crates/legion-effects/src`; no consumer needs migration, and VCS rewrite approval is an effect boundary.

## Band 2 — consumers only inside Arcane (94)

### Host and library modules

- `src/packages/arcane/host/codex-adapter.mjs` — **Consumers:** `host/preeffect-correlation.mjs`, `lib/s09-runtime-executor.mjs`, `lib/semantic-health.mjs`, and Arcane adapter/parity/runtime tests. **PORT** to `engine/crates/legion-host/src`; those internal consumers must migrate together.
- `src/packages/arcane/host/hook-adapter-core.mjs` — **Consumers:** `host/claude-code-adapter.mjs`, `host/codex-adapter.mjs`, `host/host-runtime.mjs`, `lib/ingest.mjs`, and Arcane hook/Stop tests. **SPLIT (PORT/MOVE/RESTORE)**; preserve these internal consumers while separating Guard ingress, host lifecycle, and response shape.
- `src/packages/arcane/host/host-runtime-output.mjs` — **Consumers:** `host/host-runtime.mjs`, `index.mjs`, and `tests/host-runtime-output.test.mjs`. **SPLIT (PORT/MOVE)**; those internal consumers require transport preservation while runtime results move.
- `src/packages/arcane/host/policy-inject.mjs` — **Consumers:** `host/host-runtime.mjs` and `tests/policy-inject.test.mjs`. **RESTORE** at the cognitive host boundary because both live consumers inject Brief/Minimize.
- `src/packages/arcane/host/provision-keys.mjs` — **Consumers:** `host/claude-code-adapter.mjs`. **PORT** to `engine/crates/legion-host/src`; the adapter is a live internal consumer of key provisioning.
- `src/packages/arcane/host/source-revision.mjs` — **Consumers:** `host/hook-adapter-core.mjs` and `tests/source-revision.test.mjs`; the similarly named `src/lib/qualification/source-revision.mjs` is a different module. **MOVE** to `src/lib/host/`; only internal consumers need migration.

- `src/packages/arcane/lib/validate.mjs` — **Consumers:** `index.mjs`, `lib/host-event.mjs`, `lib/pending-terminal-operation-store.mjs`, `lib/policy.mjs`, `lib/runtime-schema.mjs`, and Arcane tests. **MOVE** to `src/lib/contracts/`; those consumers need a shared validator.
- `src/packages/arcane/lib/replay.mjs` — **Consumers:** `host/host-runtime.mjs` and Arcane adapter/gate tests. **PORT** to `engine/crates/legion-effects/src`; the internal runtime depends on replay refusal.
- `src/packages/arcane/lib/capability-store.mjs` — **Consumers:** `host/host-runtime.mjs`, `index.mjs`, and capability tests. **PORT** to `engine/crates/legion-effects/src`; those consumers require capability state.
- `src/packages/arcane/lib/kernel-binding.mjs` — **Consumers:** `index.mjs` only. **MOVE** blocked: destination not built; the barrel is the only live consumer and no Kernel binding landing owner exists.
- `src/packages/arcane/lib/legacy-bridge.mjs` — **Consumers:** `index.mjs`, `tests/s01-bridge.test.mjs`, and the Forge map. **MOVE** to `src/lib/host/`; those internal migration consumers need the compatibility bridge.
- `src/packages/arcane/lib/host-event.mjs` — **Consumers:** host adapters, hook core, ingest, `index.mjs`, and Arcane host/ingest tests. **SPLIT (PORT/MOVE)**; Guard event consumers must remain while observation helpers move.
- `src/packages/arcane/lib/ingest.mjs` — **Consumers:** `host/hook-adapter-core.mjs`, `index.mjs`, and `tests/s04-ingest.test.mjs`. **SPLIT (PORT/MOVE)**; receipt consumers need the Guard portion and evidence consumers need the verification portion.
- `src/packages/arcane/lib/preeffect-gate.mjs` — **Consumers:** `host/host-runtime.mjs`, `index.mjs`, and gate/bootstrap tests. **PORT** to `engine/crates/legion-effects/src`; the runtime is a live internal consumer.
- `src/packages/arcane/lib/preeffect-correlation.mjs` — **Consumers:** `host/host-runtime.mjs`, `index.mjs`, host correlation tests, and fixture worker. **PORT** to `engine/crates/legion-effects/src`; all listed consumers require the correlation store.
- `src/packages/arcane/lib/user-approval.mjs` — **Consumers:** `host/host-runtime.mjs`, `index.mjs`, and approval/capability tests. **PORT** to `engine/crates/legion-effects/src`; target-bound approval remains live.
- `src/packages/arcane/lib/runtime-schema.mjs` — **Consumers:** host output/runtime, `index.mjs`, and runtime-schema tests. **MOVE** to `src/lib/contracts/`; the runtime and tests consume the schema set.
- `src/packages/arcane/lib/state-paths.mjs` — **Consumers:** `index.mjs` and `tests/runtime-schema.test.mjs`. **MOVE** to `src/lib/contracts/`; both consumers use generic state addressing.
- `src/packages/arcane/lib/evidence-migration.mjs` — **Consumers:** `index.mjs` and `tests/s05-migration.test.mjs`. **MOVE** to `src/lib/verification/`; migration consumers must move first.
- `src/packages/arcane/lib/invalidation.mjs` — **Consumers:** `lib/host-event.mjs`, `index.mjs`, and S04/S05 tests. **MOVE** to `src/lib/verification/`; invalidation is live evidence machinery.
- `src/packages/arcane/lib/stop-disposition.mjs` — **Consumers:** host runtime, hook core, and Stop integration tests. **MOVE** to `src/lib/host/`; those internal Stop consumers need termination semantics.
- `src/packages/arcane/lib/review-disposition-policy.mjs` — **Consumers:** `tests/review-disposition-policy.test.mjs`. **MOVE** to `src/lib/verification/`; the test is a live consumer of review policy.
- `src/packages/arcane/lib/current-user-risk-acceptance.mjs` — **Consumers:** `tests/current-user-risk-acceptance.test.mjs`. **MOVE** to `src/lib/verification/`; the acceptance test must migrate with it.
- `src/packages/arcane/lib/decision-envelope.mjs` — **Consumers:** host runtime/output and their tests. **SPLIT (PORT/MOVE)**; refusal transport is live in host consumers while completion fields move.
- `src/packages/arcane/lib/denial-circuit.mjs` — **Consumers:** `host/host-runtime.mjs` and `tests/denial-circuit.test.mjs`. **MOVE** to `src/lib/host/`; both consumers use bounded denial retry.
- `src/packages/arcane/lib/discipline-controls.mjs` — **Consumers:** hook core, host runtime, and discipline tests. **SPLIT (PORT/MOVE)**; effect refusal and commit discipline have live internal consumers.
- `src/packages/arcane/lib/codex-escalation.mjs` — **Consumers:** `host/hook-adapter-core.mjs` and `tests/codex-escalation.test.mjs`. **MOVE** blocked: destination not built; the hook-core consumer proves it cannot be RETIRE.
- `src/packages/arcane/lib/adversarial-ai-reconstruction.mjs` — **Consumers:** `lib/s11-runtime-executor.mjs` and its paired test. **MOVE** to `src/lib/verification/`; the runtime consumer must migrate first.
- `src/packages/arcane/lib/adversarial-migration-distributed.mjs` — **Consumers:** `lib/s11-runtime-executor.mjs` and its paired test. **MOVE** to `src/lib/verification/`; the runtime consumer must migrate first.
- `src/packages/arcane/lib/adversarial-ownership-economics.mjs` — **Consumers:** `lib/s11-runtime-executor.mjs` and its paired test. **MOVE** to `src/lib/verification/`; the runtime consumer must migrate first.
- `src/packages/arcane/lib/adversarial-proportionality.mjs` — **Consumers:** `lib/s11-runtime-executor.mjs` and its paired test. **MOVE** to `src/lib/verification/`; the runtime consumer must migrate first.
- `src/packages/arcane/lib/advisory-certification.mjs` — **Consumers:** `index.mjs`, `lib/completion-gate.mjs`, and its paired test. **MOVE** to `src/lib/verification/`; completion consumers must migrate first.
- `src/packages/arcane/lib/calibration-convergence-policy.mjs` — **Consumers:** S11 runtime and its paired test. **MOVE** to `src/lib/verification/`; both consumers are assurance machinery.
- `src/packages/arcane/lib/s11-bindings/advisory-judgment.mjs` — **Consumers:** `lib/s11-runtime-executor.mjs` and `tests/advisory-judgment.test.mjs`. **MOVE** to `src/lib/verification/`; the internal runtime/test pair is live.
- `src/packages/arcane/lib/s11-bindings/authority-review.mjs` — **Consumers:** S11 runtime and authority-review test. **MOVE** to `src/lib/verification/`; review consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/delivery-continuity.mjs` — **Consumers:** S11 runtime and delivery-continuity test. **MOVE** to `src/lib/verification/`; continuity consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-adr-canon-clarify.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-adversarial.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-candidate-quality.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-concurrency-convergence.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-handoff-negative.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/eval-review-security.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/evidence-closure.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; evidence-closure consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/governance-state.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; governance consumers need an existing owner.
- `src/packages/arcane/lib/s11-bindings/m1-m6-production.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; production evaluator consumers must migrate first.
- `src/packages/arcane/lib/s11-bindings/m7-production.mjs` — **Consumers:** S11 runtime and paired test. **MOVE** to `src/lib/verification/`; replay evaluator consumers must migrate first.

### Forge compatibility data

- `src/packages/arcane/compatibility/forge/legacy-semantic-inventory.json` — **Consumers:** Forge migration dry-run, operation/parity/schema maps, `lib/host-event.mjs`, `lib/invalidation.mjs`, and S01/S04 tests. **MOVE** blocked: destination not built; those internal consumers must migrate first.
- `src/packages/arcane/compatibility/forge/migration-dry-run.json` — **Consumers:** all twelve Forge fixture files. **MOVE** blocked: destination not built; the fixture aggregate is live data for those consumers.
- `src/packages/arcane/compatibility/forge/operation-map.json` — **Consumers:** Forge fixtures, `lib/legacy-bridge.mjs`, and migration tests. **MOVE** blocked: destination not built; compatibility consumers remain live.
- `src/packages/arcane/compatibility/forge/parity-report.json` — **Consumers:** `legacy-semantic-inventory.json` and migration tooling references. **MOVE** blocked: destination not built; parity evidence has live map consumers.
- `src/packages/arcane/compatibility/forge/policy-threshold-map.json` — **Consumers:** `operation-map.json` and policy migration references. **MOVE** blocked: destination not built; the map is live migration input.
- `src/packages/arcane/compatibility/forge/schema-map.json` — **Consumers:** `lib/legacy-bridge.mjs`, `lib/host-event.mjs`, `lib/invalidation.mjs`, and S01/S04 tests. **MOVE** blocked: destination not built; these consumers must migrate first.
- `src/packages/arcane/compatibility/forge/fixtures/01-assess-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/02-checkpoint-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/03-checkpoint-failure-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/04-checkpoint-host-check-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/05-verify-signoff-blocked-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/06-verify-high-risk-blocked-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: destination not built; the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/07-close-blocked-response.json` — **Consumers:** `migration-dry-run.json` and `operation-map.json`. **MOVE** blocked: both maps read this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/08-store-snapshot-scoped.json` — **Consumers:** `migration-dry-run.json`, `lib/legacy-bridge.mjs`, and S01 test. **MOVE** blocked: these compatibility consumers remain live.
- `src/packages/arcane/compatibility/forge/fixtures/09-resolve-session-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/10-verify-signoff-passing-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/11-close-success-response.json` — **Consumers:** `migration-dry-run.json`. **MOVE** blocked: the dry-run reads this fixture.
- `src/packages/arcane/compatibility/forge/fixtures/12-close-idempotent-response.json` — **Consumers:** `migration-dry-run.json` and `operation-map.json`. **MOVE** blocked: both maps read this fixture.

### Policy and schema assets

- `src/packages/arcane/policy/arcane-policy-v1.rules` — **Consumers:** `lib/policy-compiler.mjs` and `tests/policy-compiler.test.mjs`. **PORT** to `engine/crates/legion-rules/src`; the compiler/test consumers are live.
- `src/packages/arcane/policy/inject/brief-policy.md` — **Consumers:** `host/policy-inject.mjs` and policy-inject tests. **RESTORE** because the host has live Brief consumers.
- `src/packages/arcane/policy/inject/ccx-gateway-directive.md` — **Consumers:** `host/policy-inject.mjs`. **SPLIT (RESTORE/RETIRE)**; preserve any text consumed by the host directive path, retire only unused ceremony.
- `src/packages/arcane/policy/policy-bundle-v1.schema.json` — **Consumers:** `lib/policy.mjs` and policy compiler tests. **PORT** to `engine/crates/legion-policy/src`; schema consumers must migrate with the Node policy.

### Package schemas

- `src/packages/arcane/schemas/advisory-artifact-receipt-v1.schema.json` — **Consumers:** no external consumers; `advisory-certification.mjs`/tests use the receipt shape. **MOVE** blocked: destination not built; retain until its internal assurance consumer moves.
- `src/packages/arcane/schemas/advisory-certification-receipt-v1.schema.json` — **Consumers:** no external consumers; advisory certification tests use it. **MOVE** blocked: destination not built; its internal assurance consumer is live.
- `src/packages/arcane/schemas/advisory-judgment-v1.schema.json` — **Consumers:** advisory judgment modules/tests. **MOVE** blocked: destination not built; judgment consumers must migrate first.
- `src/packages/arcane/schemas/arcane-decision-envelope-v1.schema.json` — **Consumers:** host runtime/output and tests. **SPLIT (PORT/MOVE)**; refusal fields have live transport consumers while completion fields move.
- `src/packages/arcane/schemas/authority-binding-v1.schema.json` — **Consumers:** authority-binding store/tests. **MOVE** blocked: destination not built; its binding consumer is live.
- `src/packages/arcane/schemas/authority-invocation-proof-v1.schema.json` — **Consumers:** authority-proof issuer/tests. **MOVE** blocked: destination not built; its proof consumer is live.
- `src/packages/arcane/schemas/authority-proof-transition-v1.schema.json` — **Consumers:** authority-proof lifecycle modules/tests. **MOVE** blocked: destination not built; transition consumers are live.
- `src/packages/arcane/schemas/budget-governance-v1.schema.json` — **Consumers:** budget-governance store/tests. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; the existing governance owner must migrate first.
- `src/packages/arcane/schemas/capability-grant-v1.schema.json` — **Consumers:** capability store and Guard tests. **PORT** to `engine/crates/legion-effects/src`; capability consumers are live.
- `src/packages/arcane/schemas/capability-transition-v1.schema.json` — **Consumers:** capability store and Guard tests. **PORT** to `engine/crates/legion-effects/src`; transition consumers are live.
- `src/packages/arcane/schemas/contract-seal-v1.schema.json` — **Consumers:** contract-seal store/tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; seal consumers are live.
- `src/packages/arcane/schemas/contract-transition-receipt-v1.schema.json` — **Consumers:** contract-lifecycle store/tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; transition consumers are live.
- `src/packages/arcane/schemas/current-user-risk-acceptance-v1.schema.json` — **Consumers:** risk-acceptance module/tests. **MOVE** to `src/lib/verification/`; assurance consumers are live.
- `src/packages/arcane/schemas/current-user-scope-amendment-v1.schema.json` — **Consumers:** scope-amendment module/tests. **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; judgment consumers are live.
- `src/packages/arcane/schemas/host-event-ledger-record-v1.schema.json` — **Consumers:** host-event ledger/tests. **MOVE** blocked: destination not built; the ledger consumer is live.
- `src/packages/arcane/schemas/host-runtime-output-v1.schema.json` — **Consumers:** host runtime output/tests. **SPLIT (PORT/MOVE)**; effect output and runtime result consumers differ.
- `src/packages/arcane/schemas/host-runtime-result-v1.schema.json` — **Consumers:** host runtime/output/tests. **SPLIT (PORT/MOVE)**; effect decision transport is live while completion fields move.
- `src/packages/arcane/schemas/pending-terminal-operation-v1.schema.json` — **Consumers:** pending-terminal store/tests. **MOVE** to `src/lib/verification/`; completion consumers are live.
- `src/packages/arcane/schemas/task-budget-seal-v1.schema.json` — **Consumers:** task-budget store/tests. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; execution consumers are live.
- `src/packages/arcane/schemas/terminal-operation-transition-v1.schema.json` — **Consumers:** pending-terminal store/tests. **MOVE** to `src/lib/verification/`; completion consumers are live.
- `src/packages/arcane/schemas/user-approval-v1.schema.json` — **Consumers:** user-approval module/tests. **PORT** to `engine/crates/legion-effects/src`; Guard approval consumers are live.

### Race fixtures

- `src/packages/arcane/tests/fixtures/authority-binding-race-worker.mjs` — **Consumers:** `tests/authority-binding-store.test.mjs`. **MOVE** blocked: destination not built; the paired test is a live consumer.
- `src/packages/arcane/tests/fixtures/capability-race-worker.mjs` — **Consumers:** `tests/durable-capability-store.test.mjs`. **PORT** to `engine/crates/legion-effects/src`; the paired Guard test consumes it.
- `src/packages/arcane/tests/fixtures/contract-seal-race-worker.mjs` — **Consumers:** `tests/contract-seal-store.test.mjs`. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the paired seal test consumes it.
- `src/packages/arcane/tests/fixtures/preeffect-correlation-race-worker.mjs` — **Consumers:** `tests/preeffect-correlation.test.mjs`. **PORT** to `engine/crates/legion-effects/src`; the paired Guard test consumes it.
- `src/packages/arcane/tests/fixtures/session-binding-race-worker.mjs` — **Consumers:** `tests/session-binding.test.mjs`. **MOVE** to `src/lib/host/`; the paired host test consumes it.

## Band 3 — external consumers requiring migration (57)

The paths below are the external consumers found by grep. These entries cannot be retired in place; their named consumers must migrate first.

### Host and root library modules

- `src/packages/arcane/host/claude-code-adapter.mjs` — **Consumers:** `src/lib/cli/commands/doctor-host.mjs` and `tests/contract-seal-producer.test.mjs`, plus internal host/tests. **PORT** to `engine/crates/legion-host/src`; both external consumers must migrate.
- `src/packages/arcane/host/host-runtime.mjs` — **Consumers:** `tests/contract-seal-producer.test.mjs`, plus internal host/runtime tests. **MOVE** to `src/lib/host/`; the root integration test must migrate first.

- `src/packages/arcane/lib/errors.mjs` — **Consumers:** `src/lib/cli/commands/contract.mjs`, `src/lib/cli/commands/governance/execution.mjs`, and internal modules/tests. **MOVE** to `src/lib/contracts/`; shipped CLI consumers must migrate.
- `src/packages/arcane/lib/canonical.mjs` — **Consumers:** CLI contract/completion commands, governance tests, root CLI/contract tests, and many internal modules. **MOVE** to `src/lib/contracts/`; all listed consumers must migrate.
- `src/packages/arcane/lib/ids.mjs` — **Consumers:** `src/lib/cli/commands/run.mjs`, root CLI tests, and internal modules/tests. **MOVE** to `src/lib/contracts/`; the shipped run command must migrate.
- `src/packages/arcane/lib/receipt-auth.mjs` — **Consumers:** completion/contract CLI commands and root CLI/contract tests, plus internal modules/tests. **PORT** to `engine/crates/legion-audit/src`; external receipt consumers must migrate.
- `src/packages/arcane/lib/receipt-store.mjs` — **Consumers:** completion/contract/governance/run CLI commands and root CLI/contract tests, plus internal modules/tests. **PORT** to `engine/crates/legion-audit/src`; external receipt consumers must migrate.
- `src/packages/arcane/lib/policy.mjs` — **Consumers:** `src/lib/cli/commands/run.mjs`, `tests/cli.test.mjs`, and internal host/policy tests. **PORT** to `engine/crates/legion-policy/src`; the correction specifically proves these consumers block RETIRE.
- `src/packages/arcane/lib/policy-compiler.mjs` — **Consumers:** `src/lib/cli/commands/rules.mjs` and `tests/policy-compiler.test.mjs`. **PORT** to `engine/crates/legion-rules/src`; the shipped rules command must migrate.
- `src/packages/arcane/lib/host-event-ledger.mjs` — **Consumers:** completion/contract/governance/host-events/run CLI commands, root CLI/contract tests, and internal host/tests. **MOVE** to `src/lib/host/`; all external ledger consumers must migrate.
- `src/packages/arcane/lib/authority.mjs` — **Consumers:** contract and governance execution CLI commands, provider modules, root governance tests, and internal modules/tests. **MOVE** to `src/lib/contracts/`; external authority consumers must migrate.
- `src/packages/arcane/lib/authority-binding-store.mjs` — **Consumers:** contract/governance CLI commands, governance tests, naming checks, root contract tests, and internal modules/tests. **MOVE** to `src/lib/contracts/`; external binding consumers must migrate.
- `src/packages/arcane/lib/authority-invocation-proof.mjs` — **Consumers:** completion/contract/run CLI commands, root CLI tests, and internal modules/tests. **MOVE** to `src/lib/contracts/`; external proof consumers must migrate.
- `src/packages/arcane/lib/advisory-profile.mjs` — **Consumers:** `src/lib/cli/commands/completion.mjs`, root completion tests, and internal modules/tests. **MOVE** to `src/lib/verification/`; completion must migrate first.
- `src/packages/arcane/lib/advisory-judgment.mjs` — **Consumers:** `src/lib/cli/commands/governance/judgment.mjs`, `tests/stage11-advisory-judgment.test.mjs`, and internal modules/tests. **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; those live consumers name the owner.
- `src/packages/arcane/lib/provider-capability.mjs` — **Consumers:** `tests/stage5-evidence-gates.test.mjs` and internal evidence tests. **MOVE** to `src/lib/verification/`; the root assurance test must migrate.
- `src/packages/arcane/lib/architecture-router.mjs` — **Consumers:** `tests/stage3-architecture-conformance.test.mjs` and internal architecture/S11 modules/tests. **MOVE** to `src/lib/verification/`; the root conformance test must migrate.
- `src/packages/arcane/lib/architecture-state.mjs` — **Consumers:** `tests/stage3-architecture-conformance.test.mjs` and internal runtime/S11 modules/tests. **MOVE** to `src/lib/verification/`; the root conformance test must migrate.
- `src/packages/arcane/lib/architecture-event-store.mjs` — **Consumers:** `tests/stage3-architecture-conformance.test.mjs` and internal runtime/S11 modules/tests. **MOVE** to `src/lib/verification/`; the root conformance test must migrate.
- `src/packages/arcane/lib/architecture-fingerprints.mjs` — **Consumers:** `tests/stage3-architecture-conformance.test.mjs` and internal architecture modules/tests. **MOVE** to `src/lib/verification/`; the root conformance test must migrate.
- `src/packages/arcane/lib/assurance-packet.mjs` — **Consumers:** `tests/stage5-evidence-gates.test.mjs` and internal authority-review code. **MOVE** to `src/lib/verification/`; the root assurance test must migrate.
- `src/packages/arcane/lib/evidence-authority.mjs` — **Consumers:** `src/lib/cli/commands/governance/execution.mjs`, `tests/cli-execution-governance.test.mjs`, and internal S11/tests. **MOVE** to `src/lib/verification/`; execution governance must migrate first.
- `src/packages/arcane/lib/evidence-envelope.mjs` — **Consumers:** `src/lib/cli/commands/completion.mjs`, root CLI tests, and internal evidence/tests. **MOVE** to `src/lib/verification/`; completion consumers must migrate first.
- `src/packages/arcane/lib/evidence-registry.mjs` — **Consumers:** `tests/stage5-evidence-gates.test.mjs` and internal S09/S11/evidence tests. **MOVE** to `src/lib/verification/`; root assurance consumers must migrate.
- `src/packages/arcane/lib/seal-reachability.mjs` — **Consumers:** `src/lib/cli/commands/contract.mjs` and internal contract tests. **MOVE** to `src/lib/verification/`; the contract command must migrate.
- `src/packages/arcane/lib/completion-evidence.mjs` — **Consumers:** `src/lib/cli/commands/completion.mjs`, `tests/cli.test.mjs`, and internal completion tests. **MOVE** to `src/lib/verification/`; root CLI consumers must migrate.
- `src/packages/arcane/lib/completion-gate.mjs` — **Consumers:** `src/lib/cli/commands/run.mjs`, root CLI tests, and internal host/S09/tests. **MOVE** to `src/lib/verification/`; the shipped run command must migrate.
- `src/packages/arcane/lib/completion-state.mjs` — **Consumers:** completion/run CLI commands, root CLI tests, and internal runtime/tests. **MOVE** to `src/lib/verification/`; shipped completion consumers must migrate.
- `src/packages/arcane/lib/pending-terminal-operation-store.mjs` — **Consumers:** `src/lib/cli/commands/completion.mjs` and internal host/Stop tests. **MOVE** to `src/lib/verification/`; the completion command must migrate.
- `src/packages/arcane/lib/task-budget-seal-store.mjs` — **Consumers:** budget/contract/run CLI commands, root CLI/contract tests, and internal runtime/tests. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; shipped budget consumers must migrate.
- `src/packages/arcane/lib/budget-governance-store.mjs` — **Consumers:** budget/contract/run CLI commands, root CLI/contract tests, and internal runtime/S11/tests. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; those commands are live consumers.
- `src/packages/arcane/lib/contract-seal-store.mjs` — **Consumers:** contract/run CLI commands, root contract tests, and internal host/tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the shipped contract command must migrate.
- `src/packages/arcane/lib/contract-lifecycle.mjs` — **Consumers:** `src/lib/cli/commands/run.mjs`, Arcane lifecycle tests, and internal host/tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the run command must migrate.
- `src/packages/arcane/lib/session-binding.mjs` — **Consumers:** `src/lib/cli/commands/completion.mjs`, `src/lib/cli/commands/run.mjs`, root CLI tests, and internal host/tests. **MOVE** to `src/lib/host/`; shipped session consumers must migrate.
- `src/packages/arcane/lib/continuity.mjs` — **Consumers:** `tests/stage4-continuity.test.mjs` and internal host/S11/tests. **MOVE** to `src/lib/host/`; the root continuity test must migrate.
- `src/packages/arcane/lib/scoped-acceptance.mjs` — **Consumers:** `tests/scoped-acceptance.test.mjs`. **MOVE** to `src/lib/verification/`; the root test is a live consumer.
- `src/packages/arcane/lib/dispatch-scheduler.mjs` — **Consumers:** `src/lib/cli/commands/governance/delivery.mjs` and internal dispatch tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the existing delivery owner is concrete.
- `src/packages/arcane/lib/execution-governance.mjs` — **Consumers:** `src/lib/cli/commands/governance/execution.mjs` and internal execution/S11 tests. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; the existing execution owner is concrete.
- `src/packages/arcane/lib/delivery-guard.mjs` — **Consumers:** `src/lib/cli/commands/run.mjs` and internal delivery/dispatch tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the run command must migrate.
- `src/packages/arcane/lib/deficit-governance.mjs` — **Consumers:** `src/lib/cli/commands/governance/judgment.mjs` and internal judgment/S11 tests. **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; the existing judgment owner is concrete.
- `src/packages/arcane/lib/finding-lifecycle.mjs` — **Consumers:** governance judgment CLI/tests and internal judgment tests. **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; external governance consumers must migrate.
- `src/packages/arcane/lib/gate-validity.mjs` — **Consumers:** `tests/stage5-evidence-gates.test.mjs` and internal security tests. **MOVE** to `src/lib/verification/`; the root test must migrate.
- `src/packages/arcane/lib/command-verifier.mjs` — **Consumers:** `src/lib/cli/commands/governance/execution.mjs` and internal verifier test. **MOVE** to `src/lib/cli/commands/governance/execution.mjs`; execution governance is the existing owner.
- `src/packages/arcane/lib/current-user-scope-amendment.mjs` — **Consumers:** `src/lib/cli/commands/governance/judgment.mjs` and internal tests. **MOVE** to `src/lib/cli/commands/governance/judgment.mjs`; judgment is the existing owner.
- `src/packages/arcane/lib/minimize.mjs` — **Consumers:** `src/lib/cli/commands/minimize.mjs` and Arcane Minimize tests. **RESTORE** at the cognitive boundary; the shipped CLI consumer must remain compatible.
- `src/packages/arcane/lib/migration-cutover.mjs` — **Consumers:** `src/lib/cli/commands/governance/delivery.mjs`, S11 migration bindings, and internal tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; delivery governance is the existing owner.
- `src/packages/arcane/lib/control-recovery.mjs` — **Consumers:** `src/lib/cli/commands/governance/delivery.mjs` and recovery tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the shipped governance command must migrate.
- `src/packages/arcane/lib/control-lifecycle.mjs` — **Consumers:** `src/lib/cli/commands/governance/delivery.mjs`, `lib/completion-gate.mjs`, and lifecycle tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the correction specifically identifies the CLI consumer, so RETIRE is forbidden.
- `src/packages/arcane/lib/s09-runtime-executor.mjs` — **Consumers:** `tests/stage9-runtime-executor.test.mjs` and internal host/S09 modules/tests. **MOVE** to `src/lib/verification/`; the root stage-9 test must migrate.
- `src/packages/arcane/lib/s11-runtime-executor.mjs` — **Consumers:** `tests/stage11-runtime-executor.test.mjs` and internal S11 modules/tests. **MOVE** to `src/lib/verification/`; the root stage-11 test must migrate.
- `src/packages/arcane/lib/semantic-health.mjs` — **Consumers:** `src/lib/cli/commands/doctor.mjs`, internal host adapters, and health tests. **MOVE** to `src/lib/verification/`; the shipped doctor command must migrate.
- `src/packages/arcane/lib/user-intent.mjs` — **Consumers:** `src/packages/arcane/host/host-runtime.mjs`, `tests/user-intent.test.mjs`, and internal runtime tests. **RESTORE** at the cognitive boundary; the root test and host runtime are live consumers.
- `src/packages/arcane/lib/stop-shape.mjs` — **Consumers:** `src/packages/arcane/host/host-runtime.mjs`, `tests/stop-shape.test.mjs`, and internal runtime tests. **SPLIT (PORT/RESTORE)**; Guard delivery and root response-shape consumers must survive separately.

### External tests and policy assets

- `src/packages/arcane/lib/keys.mjs` — **Consumers:** `src/lib/cli/commands/budget.mjs`, `completion.mjs`, `contract.mjs`, `governance.mjs`, `host-events.mjs`, and `run.mjs`, plus root CLI/contract tests and internal modules. **PORT** to `engine/crates/legion-host/src`; all external key consumers must migrate.
- `src/packages/arcane/policy/arcane-policy-v1.json` — **Consumers:** `tests/cli.test.mjs` plus internal `lib/policy.mjs` and policy tests. **PORT** to `engine/crates/legion-policy/src`; the root CLI test must migrate first.
- `src/packages/arcane/policy/minimize-policy.md` — **Consumers:** `src/lib/cli/commands/minimize.mjs` plus internal host and tests. **RESTORE** because the shipped Minimize command reads it.
- `src/packages/arcane/tests/fixtures/runtime-binding-contract.mjs` — **Consumers:** `tests/cli.test.mjs`, `tests/contract-seal-producer.test.mjs`, and internal contract/runtime tests. **MOVE** to `src/lib/cli/commands/governance/delivery.mjs`; the root tests must migrate first.

## Explicitly not counted as live consumers

The following were found by grep but are not live source consumers: the superseded triage document, archived provenance/audit prose, comments, generated dispatch evidence, and binary files under `engine/target`. They do not change the bands. Conversely, the following are live and intentionally counted: `src/lib/cli/commands/run.mjs`, `rules.mjs`, `governance/delivery.mjs`, `tests/cli.test.mjs`, root stage tests, and the direct schema/data readers listed above.

## Intended later verification (not run in this lane)

Integration owner review is required. Execution is a separate lane. After migration decisions are implemented, preserve the current green baseline: **1359 tests and all three CI runners green**. No tests, builds, generators, installs, commits, or pushes were run for this document.
