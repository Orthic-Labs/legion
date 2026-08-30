# Arcane package triage

**Tracker item:** P0.5 from `docs/pending/PENDING-WORK-2026-08-29.md`  
**Scope:** `src/packages/arcane/` only  
**Action:** disposition only; this document moves or deletes nothing.

## Method and disposition vocabulary

The tree contains **235 files**: 187 `.mjs`, 41 `.json`, 6 `.md`, and 1 `.rules`. I enumerated every file with the live tree, read the authority documents and the package entry/interface files, content-read the principal host, policy, Guard, receipt, evidence, completion, and routing implementations, and structurally inspected all remaining source/test files through their imports, exports, headers, and paired tests. The 235-file inventory below is complete; files whose full bodies were not content-read are explicitly treated as **structurally inspected**, not silently assumed from their names.

**Inspection counts:** 235/235 files inspected for disposition evidence; 0/235 inferred solely from filename; 0/235 unresolved. The inventory is therefore an inspected count, while the full-body-read subset is not presented as a false precision metric. No file is left unclassified.

The four dispositions are semantic:

- **PORT** — deterministic effect/safety, policy, authentication, correlation, and receipt mechanisms whose owner is the Guard.
- **RESTORE** — the original cognitive Arcane posture: Brief/Minimize injection and bounded response/ending discipline.
- **MOVE** — work, authority, evidence, completion, orchestration, supervision, host-runtime, or migration machinery owned by Legion, the host, or another subsystem. Completion-gate material specifically moves toward P2.16.
- **RETIRE** — dead compatibility/ceremony or obsolete duplicate architecture, including its tests.

A **SPLIT** is recorded where one file crosses an ownership boundary; each named portion has one of the four dispositions. This is intentional and follows the tracker’s `stop-shape.mjs` example. `UNRESOLVED` is not used: no remaining ownership call was materially ambiguous after applying `doctrine/arcane.md` and `doctrine/guard.md`.

## Boundary decisions

- `doctrine/arcane.md` makes Arcane cognitive-only: it may shape cognition and response, but does not own effects, task DAGs, authority stores, executor binding, or durable supervision.
- `doctrine/guard.md` makes the Guard deterministic and effect-focused: classification, policy, hard safety gates, approval-boundary refusals, enforcement health, and effect receipts belong there.
- `stop-shape.mjs` **SPLITS**: effect/safety and laundering checks PORT; ending-shape, anti-caveat, no-permission-ending, and bounded postflight discipline RESTORE.
- `host-runtime.mjs` and `hook-adapter-core.mjs` **SPLIT**: canonical effect ingress and Guard delivery PORT; host lifecycle, contracts, completion, architecture trajectory, and orchestration MOVE; postflight injection/ending behavior RESTORE.
- `host-runtime-output.mjs`, `decision-envelope.mjs`, `host-event.mjs`, `ingest.mjs`, `discipline-controls.mjs`, `policy-inject.mjs`, and `receipt-auth.mjs` likewise contain explicit mixed-plane portions rather than being forced into one bucket.
- The Node policy bundle is explicitly historical in `src/packages/arcane/policy/README.md`; its rule content is already superseded by the Rust canonical Guard policy. The duplicate Node policy implementation and artifacts RETIRE, while Brief/Minimize assets RESTORE.

## Inventory

### Package root — 3 files

- **RETIRE** `src/packages/arcane/INTERFACES.md` — package-internal S03/S04/S05 seam contract and lane ceremony; ownership must move to the receiving Guard/Legion contracts rather than remain a package-wide control document. **Evidence:** `src/packages/arcane/INTERFACES.md`, `doctrine/arcane.md` Boundaries.
- **PORT** `src/packages/arcane/KEY-CUSTODY.md` — documents host-held signing-key custody for authenticated Guard receipts and explicitly separates it from cognitive Arcane. **Evidence:** `src/packages/arcane/KEY-CUSTODY.md`, `doctrine/guard.md` Receipts.
- **SPLIT (PORT/MOVE/RESTORE/RETIRE)** `src/packages/arcane/index.mjs` — one barrel exports Guard primitives, Legion work machinery, and cognitive injection/stop behavior; decompose exports by owner, retain only the Guard surface, restore cognitive assets, and remove dead exports. **Evidence:** `src/packages/arcane/index.mjs`, `doctrine/arcane.md` Boundaries.

### Host adapters — 8 files

- **MOVE** `src/packages/arcane/host/claude-code-adapter.mjs` — Claude-native payload normalization and process wiring are host integration; Guard consumes the canonical event rather than owning a Claude adapter. **Evidence:** file header and `doctrine/guard.md` Hook event surface.
- **MOVE** `src/packages/arcane/host/codex-adapter.mjs` — Codex-native identity and patch parsing belong to the host/Legion binding layer, not cognitive Arcane or the Guard policy engine. **Evidence:** file header and `doctrine/guard.md` Seed implementation.
- **SPLIT (PORT/MOVE/RESTORE)** `src/packages/arcane/host/hook-adapter-core.mjs` — signing/ingestion and destructive-effect refusal PORT; host lifecycle/contract/completion orchestration MOVE; Stop ending-shape postflight RESTORE. **Evidence:** exports and imports in file; `doctrine/guard.md` Guard and Arcane; `doctrine/arcane.md` §14/§16.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/host/host-runtime-output.mjs` — typed effect refusal rendering PORT; completion/certification and generic host runtime result shaping MOVE. **Evidence:** `renderHostRuntimeOutput`; `doctrine/guard.md` Definition and `doctrine/arcane.md` Boundaries.
- **SPLIT (PORT/MOVE/RESTORE)** `src/packages/arcane/host/host-runtime.mjs` — pre-effect dispatch and Guard refusal path PORT; lifecycle, authority binding, budgets, completion, architecture trajectory MOVE; policy injection and Stop shape RESTORE. **Evidence:** `createHostRuntime`; `doctrine/guard.md` Seed implementation; `doctrine/arcane.md` §11/§14.
- **RESTORE** `src/packages/arcane/host/policy-inject.mjs` — reconstructs Brief/Minimize and bounded gotcha context injection at the host boundary; the CCX sub-branch is separately retired below. **Evidence:** file header and `src/packages/arcane/policy/inject/brief-policy.md`.
- **PORT** `src/packages/arcane/host/provision-keys.mjs` — deterministic host key provisioning is Guard receipt/key custody, not model routing. **Evidence:** file header and `src/packages/arcane/KEY-CUSTODY.md`.
- **MOVE** `src/packages/arcane/host/source-revision.mjs` — filesystem/git revision lookup is host evidence and repository-state binding used by runtime/Legion, not cognitive policy. **Evidence:** file header and `doctrine/guard.md` Receipts.

### Core library — 79 files

#### Guard primitives and shared seams

- **MOVE** `src/packages/arcane/lib/errors.mjs` — shared error/decision vocabulary is a contract seam consumed by several owners, not Guard policy itself; move to the shared Legion/contract layer while preserving Guard codes. **Evidence:** exports and `doctrine/guard.md` Fail closed and enforcement health.
- **MOVE** `src/packages/arcane/lib/canonical.mjs` — canonical serialization is shared signing/contract infrastructure, not effect authorization; centralize with shared Legion contracts and let Guard import it. **Evidence:** file header and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/ids.mjs` — identifier grammar/allocation is a shared Kernel/Legion concern; Guard may consume IDs but does not own the allocator. **Evidence:** file header and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/validate.mjs` — generic frozen-contract/schema loading belongs with shared contracts, not the Guard’s semantic effect decision. **Evidence:** imports/exports and `doctrine/guard.md` Definition.
- **PORT** `src/packages/arcane/lib/keys.mjs` — host key custody and fail-closed key lookup authenticate Guard event/effect receipts; the derived authority-proof use is a Legion consumer of the same custody seam. **Evidence:** file header and `KEY-CUSTODY.md`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/lib/receipt-auth.mjs` — explicit-bound-field HMAC verification PORTs for Guard receipts; generic authority-proof domains and Legion evidence authentication MOVE with the consuming owner. **Evidence:** `EFFECT_RECEIPT_BOUND_FIELDS`, `AUTHORITY_PROOF` consumers; `doctrine/guard.md` Receipts.
- **PORT** `src/packages/arcane/lib/receipt-store.mjs` — append-only authenticated effect-receipt persistence, chain verification, and capability state are deterministic Guard evidence mechanisms. **Evidence:** file header and `doctrine/guard.md` Receipts.
- **PORT** `src/packages/arcane/lib/replay.mjs` — nonce, sequence, freshness, and bounded replay refusal are deterministic effect/event safety controls. **Evidence:** file header and `doctrine/guard.md` Guard invariants.
- **PORT** `src/packages/arcane/lib/capability-store.mjs` — single-use effect capability binding, expiry, revocation, and target checks belong to the deterministic Guard boundary. **Evidence:** exports and `doctrine/guard.md` Definition.
- **MOVE** `src/packages/arcane/lib/kernel-binding.mjs` — binds Arcane to the Kernel substrate and explicitly defers durable identity/event authority to Lane D/Legion. **Evidence:** file header and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/legacy-bridge.mjs` — shape-only legacy-predecessor compatibility bridge and migration dry-run; move to Legion compatibility, preserving its refusal of legacy trust claims. **Evidence:** file header and this package's own compatibility operation map.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/lib/host-event.mjs` — closed host-event normalization and effect identity PORT; observation qualification beyond effect safety MOVE to Legion evidence/verification. **Evidence:** `HOST_EVENT_SCHEMA`, `classifyObservation`, `doctrine/guard.md` Hook event surface.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/lib/ingest.mjs` — authenticated host/effect receipt construction PORT; evidence invalidation and check/observation qualification MOVE. **Evidence:** `HostIngestor`, `DependencyLedger` call, `doctrine/guard.md` Receipts.
- **RETIRE** `src/packages/arcane/lib/policy.mjs` — Node policy engine is the historical duplicate explicitly superseded by Rust `canonical_default_policy_pack`; no Node rule content needs porting. **Evidence:** `src/packages/arcane/policy/README.md`, tracker P0.4, `doctrine/guard.md` Canonical default policy.
- **RETIRE** `src/packages/arcane/lib/policy-compiler.mjs` — compiles the superseded Node `.rules` artifact and has no live Guard owner after P0.4. **Evidence:** `src/packages/arcane/policy/README.md`, file imports.
- **PORT** `src/packages/arcane/lib/preeffect-gate.mjs` — deterministic effect class, path scope, contract ceiling, authority, capability, latitude, and fail-closed pre-effect checks are Guard behavior. **Evidence:** file header and `doctrine/guard.md` Effect classification/Hard safety gates.
- **PORT** `src/packages/arcane/lib/preeffect-correlation.mjs` — carries the host pre-effect reservation to post-effect receipt correlation without semantic inference. **Evidence:** file header and `doctrine/guard.md` Receipts.
- **PORT** `src/packages/arcane/lib/user-approval.mjs` — host-derived, target-bound approval evidence releases reserved effects only through the deterministic Guard boundary. **Evidence:** file header and `doctrine/guard.md` Approval boundary.
- **MOVE** `src/packages/arcane/lib/runtime-schema.mjs` — aggregates broad contract, budget, authority, and completion schemas; it is shared runtime/Legion schema machinery, not a Guard-only policy mechanism. **Evidence:** `FILES` list and `doctrine/arcane.md` Boundaries.
- **MOVE** `src/packages/arcane/lib/state-paths.mjs` — generic durable state addressing for many Legion stores, not effect authorization. **Evidence:** exports and `doctrine/arcane.md` §1.3.
- **MOVE** `src/packages/arcane/lib/host-event-ledger.mjs` — authenticated lifecycle/authority trajectory storage is host/Legion supervision; Guard may receive effect facts but does not own architecture trajectory. **Evidence:** exports and `doctrine/arcane.md` §16.

#### Legion authority, work, evidence, completion, and delivery machinery

- **MOVE** `src/packages/arcane/lib/authority.mjs` — per-turn authority assertion and model-claim refusal are Legion authority attachment, not effect policy. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/authority-binding-store.mjs` — persistent Legion/Sage/Alchemist/Oracle binding observation is authority infrastructure. **Evidence:** `AuthorityBindingStore`; `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/authority-invocation-proof.mjs` — authenticated authority invocation proofs are Legion authority records, not Guard effect decisions. **Evidence:** `AuthorityInvocationProofIssuer`; `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/advisory-profile.mjs` — advisory capability/profile binding belongs to Legion capabilities and host manifests. **Evidence:** exports and `doctrine/arcane.md` §3 Legion.
- **MOVE** `src/packages/arcane/lib/advisory-certification.mjs` — advisory certification is authority/evidence completion machinery, not deterministic effect safety. **Evidence:** exports and `doctrine/arcane.md` §13 Oracle.
- **MOVE** `src/packages/arcane/lib/advisory-judgment.mjs` — advisory judgment records belong to Legion’s capability/authority plane. **Evidence:** exports and `doctrine/arcane.md` §3.
- **MOVE** `src/packages/arcane/lib/provider-capability.mjs` — provider capability and external-host binding are Legion/host resolution concerns. **Evidence:** `ProviderCapabilityRegistry`; `doctrine/arcane.md` §3 and §18.
- **MOVE** `src/packages/arcane/lib/architecture-router.mjs` — domain/architecture routing is capability judgment; Arcane may route but must not own the architecture decision machinery. **Evidence:** `routeArchitecture`; `doctrine/arcane.md` §1.3 and §15.
- **MOVE** `src/packages/arcane/lib/architecture-state.mjs` — durable architecture state, transitions, revisions, and execution episodes are Legion work-state supervision. **Evidence:** `ARCHITECTURE_STATE_SCHEMA_ID`; `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/architecture-event-store.mjs` — authenticated accepted-event trajectory and replay are Legion durable supervision. **Evidence:** `ArchitectureEventStore`; `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/architecture-fingerprints.mjs` — architecture/event/retry/evidence fingerprints belong to the Legion work graph and receipts. **Evidence:** exports and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/assurance-packet.mjs` — independent assurance packet compilation belongs to Oracle/Legion completion assurance. **Evidence:** `buildAssurancePacket`; `doctrine/arcane.md` §13 Oracle.
- **MOVE** `src/packages/arcane/lib/evidence-authority.mjs` — host-authorized latency/technology constraints are Legion evidence and capability facts. **Evidence:** `EvidenceAuthorityRegistry`; `doctrine/arcane.md` Membrane/Legion boundaries.
- **MOVE** `src/packages/arcane/lib/evidence-envelope.mjs` — evidence-capability receipts, dependency dimensions, and legacy trust status are Legion evidence infrastructure, not Guard effect receipts. **Evidence:** file header and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/evidence-migration.mjs` — batch legacy evidence migration is Legion migration/evidence work and explicitly never upgrades trust. **Evidence:** file header and `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/lib/evidence-registry.mjs` — acceptance evidence lifecycle and independent verification belong to Legion/Oracle completion assurance. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/invalidation.mjs` — transitive evidence dependency invalidation is Legion evidence/work-state machinery; it is not effect authorization. **Evidence:** file header and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/seal-reachability.mjs` — evidence lifecycle reachability is completion-contract validation. **Evidence:** file header and tracker P2.16.
- **MOVE** `src/packages/arcane/lib/completion-evidence.mjs` — reconstructs Oracle evidence for completion claims and belongs to P2.16/Legion. **Evidence:** file header and tracker P2.16.
- **MOVE** `src/packages/arcane/lib/completion-gate.mjs` — completion claim levels, acceptance evidence, stale evidence, and release prerequisites are explicitly P2.16 Legion completion machinery. **Evidence:** file header and tracker P2.16; `doctrine/arcane.md` §13 Oracle.
- **MOVE** `src/packages/arcane/lib/completion-state.mjs` — integrated repository state and material-change freshness are Legion delivery/completion identity. **Evidence:** exports and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/stop-disposition.mjs` — termination versus certification is completion/runtime semantics, not cognitive ending shape or Guard authorization. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/pending-terminal-operation-store.mjs` — pending completion operations and Stop claims belong to Legion completion contracts. **Evidence:** `PendingTerminalOperationStore`; tracker P2.16.
- **MOVE** `src/packages/arcane/lib/task-budget-seal-store.mjs` — task budget seals are Legion plan/execution contracts. **Evidence:** `TaskBudgetSealStore`; `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/budget-governance-store.mjs` — active-time, retry, progress-deadline, and budget event governance belong to Legion work execution. **Evidence:** `BudgetGovernanceStore`; `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/contract-seal-store.mjs` — executable contract sealing and scope/acceptance binding are Legion work compilation. **Evidence:** `ContractSealStore`; `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/contract-lifecycle.mjs` — suspend/supersede transition journaling is durable Legion contract lifecycle. **Evidence:** `ContractLifecycle`; `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/session-binding.mjs` — session-to-run/task/contract binding is host/Legion runtime identity. **Evidence:** file header and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/continuity.mjs` — checkpoints, epochs, cancellation, rehydration, and process-group continuity are Legion supervision. **Evidence:** exports and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/scoped-acceptance.mjs` — acceptance schedules and dependency-cone diffs belong to Legion plans/contracts. **Evidence:** exports and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/dispatch-scheduler.mjs` — capacity, phase admission, packet replay, handoff, and realization are Legion orchestration. **Evidence:** file header and `doctrine/arcane.md` §3 Legion.
- **MOVE** `src/packages/arcane/lib/execution-governance.mjs` — retry, stale continuation, rehydration, and bounded execution governance are Legion work supervision. **Evidence:** file header and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/delivery-guard.mjs` — repository integration ownership, leases, archives, and close are delivery orchestration, not effect Guard policy. **Evidence:** exports and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/deficit-governance.mjs` — acceptance debt and completion outcome classification belong to Legion completion contracts. **Evidence:** file header and tracker P2.16.
- **MOVE** `src/packages/arcane/lib/finding-lifecycle.mjs` — finding identity, closure, thresholds, and scoped rechecks belong to Oracle/Legion assurance. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/gate-validity.mjs` — blocking-gate self-tests and inspected-scope evidence are completion/verification machinery. **Evidence:** file header and tracker P2.16.
- **MOVE** `src/packages/arcane/lib/command-verifier.mjs` — structured command-result verification is Legion evidence/verification, not permission to execute. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/review-disposition-policy.mjs` — review, exploit-chain, and handoff dispositions are Legion assurance policy. **Evidence:** file header and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/current-user-risk-acceptance.mjs` — current-user risk acceptance is a Legion completion/authority record, not a Guard effect rule. **Evidence:** exports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/current-user-scope-amendment.mjs` — scope expansion evidence and user-turn binding belong to Legion contract amendment. **Evidence:** exports and `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/lib/decision-envelope.mjs` — effect denial presentation PORTs, but certification, missing evidence, remediation, and termination fields are Legion completion semantics. **Evidence:** `createDecisionEnvelope`; `doctrine/guard.md` Definition and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/denial-circuit.mjs` — bounded repeated-denial termination and retry signatures are host/Legion conversational execution governance, not authorization. **Evidence:** file header and `doctrine/arcane.md` Anti-ceremony invariants.
- **MOVE** `src/packages/arcane/lib/discipline-controls.mjs` — commit receipt/minimize and commit identity belong delivery/Legion; only the narrow no-verify/generated-lock effect refusal SPLITs to PORT. **Evidence:** `preEffectDiscipline` and `commitReceiptRequirement`; `doctrine/guard.md` Hard safety gates.
- **MOVE** `src/packages/arcane/lib/minimize.mjs` — staged-tree review/decision/commit receipts are delivery governance, not Brief/Minimize response posture; move to Legion delivery while restoring the policy asset separately. **Evidence:** file header and `src/packages/arcane/policy/minimize-policy.md`.
- **RETIRE** `src/packages/arcane/lib/codex-escalation.mjs` — a two-self-attempt escalation gate is process ceremony and has no role in the bounded cognitive-plane v0 or Guard effect policy. **Evidence:** file header; `doctrine/arcane.md` Anti-ceremony invariants.
- **MOVE** `src/packages/arcane/lib/migration-cutover.mjs` — migration absence/coexistence assessment is subsystem migration machinery, not Arcane cognition. **Evidence:** exports and `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/lib/control-recovery.mjs` — authenticated control-state repair/quarantine is host/Legion recovery and supervision. **Evidence:** file header and `doctrine/arcane.md` §16.
- **RETIRE** `src/packages/arcane/lib/control-lifecycle.mjs` — generic control retirement assessment is Arcane self-governance ceremony; the cognitive plane must not preserve process whose primary purpose is proving control lifecycle. **Evidence:** file header and `doctrine/arcane.md` Anti-ceremony invariants.
- **MOVE** `src/packages/arcane/lib/s09-runtime-executor.mjs` — stage-9 probes compose contracts, budgets, gates, continuity, and host runtime; this is Legion qualification/runtime orchestration. **Evidence:** file header and `doctrine/arcane.md` §11/§16.
- **MOVE** `src/packages/arcane/lib/s11-runtime-executor.mjs` — S11 production binding execution and evaluator dispatch are Legion assurance/runtime machinery. **Evidence:** imports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/adversarial-ai-reconstruction.mjs` — adversarial architecture evaluator is Legion assurance, not cognitive response shaping. **Evidence:** file header and exports.
- **MOVE** `src/packages/arcane/lib/adversarial-migration-distributed.mjs` — migration-selection adversarial evaluator belongs to Legion work/migration assurance. **Evidence:** file header and exports.
- **MOVE** `src/packages/arcane/lib/adversarial-ownership-economics.mjs` — ownership/economics evaluator is Legion architecture assurance. **Evidence:** file header and exports.
- **MOVE** `src/packages/arcane/lib/adversarial-proportionality.mjs` — proportionality evaluator is Legion assurance. **Evidence:** file header and exports.
- **MOVE** `src/packages/arcane/lib/calibration-convergence-policy.mjs` — calibration/convergence evaluator is work/assurance policy, not Arcane’s bounded cognitive primitive. **Evidence:** file header and exports.
- **MOVE** `src/packages/arcane/lib/semantic-health.mjs` — host/runtime enforcement-health probes belong to Legion/host supervision; Guard remains the source of deterministic health refusal. **Evidence:** file exports and `doctrine/guard.md` Enforcement health.

#### Cognitive response pieces

- **RESTORE** `src/packages/arcane/lib/user-intent.mjs` — authenticated reading of the latest genuine user instruction supports the original no-permission-ending and response discipline, with host integration kept outside the cognitive owner. **Evidence:** file header and `doctrine/arcane.md` §14/§17.
- **SPLIT (PORT/RESTORE)** `src/packages/arcane/lib/stop-shape.mjs` — `isPushGateLaundering` and reserved effect/safety discrimination PORT; anti-caveat, no-permission-ending, continue-intent, work-left, deferred-defect, and bounded ending judgment RESTORE as Arcane postflight through the Guard Stop event. **Evidence:** file header, `evaluateStopShape`, tracker P0.5/P1.10, `doctrine/arcane.md` §14.

### S11 binding library — 13 files

All S11 binding modules are production/evaluation architecture machinery rather than cognitive Arcane primitives; they MOVE to Legion assurance/runtime owners.

- **MOVE** `src/packages/arcane/lib/s11-bindings/advisory-judgment.mjs` — advisory judgment binding; **evidence:** file exports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/s11-bindings/authority-review.mjs` — authority review binding; **evidence:** imports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/s11-bindings/delivery-continuity.mjs` — delivery continuity binding; **evidence:** imports and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-adr-canon-clarify.mjs` — ADR/canonical-owner clarification evaluator; **evidence:** exports and `doctrine/arcane.md` §15.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-adversarial.mjs` — adversarial architecture evaluator; **evidence:** exports and `doctrine/arcane.md` §15.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-candidate-quality.mjs` — candidate-quality evaluator; **evidence:** imports and `doctrine/arcane.md` §15.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-concurrency-convergence.mjs` — concurrency/convergence evaluator; **evidence:** imports and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-handoff-negative.mjs` — handoff-negative evaluator; **evidence:** imports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/s11-bindings/eval-review-security.mjs` — review-security evaluator; **evidence:** imports and `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/lib/s11-bindings/evidence-closure.mjs` — evidence closure binding; **evidence:** imports and tracker P2.16.
- **MOVE** `src/packages/arcane/lib/s11-bindings/governance-state.mjs` — governance state binding; **evidence:** imports and `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/lib/s11-bindings/m1-m6-production.mjs` — M1–M6 production evaluator; **evidence:** imports and exports.
- **MOVE** `src/packages/arcane/lib/s11-bindings/m7-production.mjs` — M7 production replay evaluator; **evidence:** imports and `doctrine/arcane.md` §16.

### Compatibility/Forge tree — 18 files

All Forge compatibility maps, migration reports, and captured fixtures are historical migration inputs/outputs. The bridge and its data are owned by Legion migration compatibility, not Arcane cognition or Guard authorization.

- **MOVE** `src/packages/arcane/compatibility/forge/legacy-semantic-inventory.json` — historical source inventory for Legion migration; **evidence:** JSON `schema` and `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/compatibility/forge/migration-dry-run.json` — non-destructive migration result; **evidence:** JSON `deliverable: S01`, `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/compatibility/forge/operation-map.json` — legacy-to-Legion operation mapping; **evidence:** JSON `canonicalOperationId`, `doctrine/arcane.md` §11.
- **MOVE** `src/packages/arcane/compatibility/forge/parity-report.json` — compatibility parity evidence; **evidence:** JSON `totals`, `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/compatibility/forge/policy-threshold-map.json` — historical Forge-to-claim mapping; **evidence:** JSON `target`, tracker P0.4/P2.16.
- **MOVE** `src/packages/arcane/compatibility/forge/schema-map.json` — legacy schema disposition map; **evidence:** JSON `dispositionVocabulary`, `doctrine/arcane.md` §1.4.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/01-assess-response.json` — captured legacy run-open fixture; **evidence:** fixture `legacyOperation: assess`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/02-checkpoint-response.json` — captured legacy checkpoint fixture; **evidence:** fixture `legacyOperation: checkpoint`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/03-checkpoint-failure-response.json` — captured legacy failed-checkpoint fixture; **evidence:** fixture `legacyOperation: checkpoint`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/04-checkpoint-host-check-response.json` — captured legacy host-check fixture; **evidence:** fixture `legacyOperation: checkpoint`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/05-verify-signoff-blocked-response.json` — captured legacy blocked-signoff fixture; **evidence:** fixture `legacyOperation: verify`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/06-verify-high-risk-blocked-response.json` — captured legacy high-risk fixture; **evidence:** fixture `legacyOperation: verify`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/07-close-blocked-response.json` — captured legacy blocked-close fixture; **evidence:** fixture `legacyOperation: close`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/08-store-snapshot-scoped.json` — captured legacy store snapshot; **evidence:** fixture `kind: store-snapshot`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/09-resolve-session-response.json` — captured session-resolution fixture; **evidence:** fixture `legacyOperation: resolveSession`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/10-verify-signoff-passing-response.json` — captured legacy passing-signoff fixture; **evidence:** fixture `legacyOperation: verify`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/11-close-success-response.json` — captured legacy successful-close fixture; **evidence:** fixture `legacyOperation: close`.
- **MOVE** `src/packages/arcane/compatibility/forge/fixtures/12-close-idempotent-response.json` — captured legacy idempotent-close fixture; **evidence:** fixture `legacyOperation: close`.
### Policy tree — 7 files

- **RETIRE** `src/packages/arcane/policy/README.md` — explicitly records this entire Node policy bundle as historical and says no rule content needs porting. **Evidence:** file text; tracker P0.4.
- **RETIRE** `src/packages/arcane/policy/arcane-policy-v1.json` — superseded duplicate Node policy artifact. **Evidence:** `src/packages/arcane/policy/README.md`.
- **RETIRE** `src/packages/arcane/policy/arcane-policy-v1.rules` — source form of the superseded duplicate policy artifact. **Evidence:** `src/packages/arcane/policy/README.md`.
- **RESTORE** `src/packages/arcane/policy/inject/brief-policy.md` — original Brief response discipline payload. **Evidence:** file text and `doctrine/arcane.md` §14.
- **SPLIT (RESTORE/RETIRE)** `src/packages/arcane/policy/inject/ccx-gateway-directive.md` — the bounded gateway directive is a legacy host-specific gateway ceremony, not v0 cognitive Arcane; retain only any text explicitly reused as Brief/Minimize posture, otherwise retire. **Evidence:** file text and `doctrine/arcane.md` §17.
- **RESTORE** `src/packages/arcane/policy/minimize-policy.md` — original Minimize posture payload; restore as cognitive policy, not as the old commit gate. **Evidence:** file text and `doctrine/arcane.md` §14/§15.
- **RETIRE** `src/packages/arcane/policy/policy-bundle-v1.schema.json` — schema for the historical Node policy bundle, already superseded by the Rust Guard `PolicyPack`. **Evidence:** `src/packages/arcane/policy/README.md` and tracker P0.4.

### Package schemas — 21 files

The schemas below describe authority, budgets, contracts, evidence, completion, and runtime records; they MOVE with their Legion/host owners. The two response schemas explicitly split their Guard transport fields from Legion completion fields.

- **MOVE** `src/packages/arcane/schemas/advisory-artifact-receipt-v1.schema.json` — advisory artifact evidence; **evidence:** schema `$id`, `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/schemas/advisory-certification-receipt-v1.schema.json` — advisory certification evidence; **evidence:** schema `$id`, `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/schemas/advisory-judgment-v1.schema.json` — advisory judgment record; **evidence:** schema `$id`, `doctrine/arcane.md` §13.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/schemas/arcane-decision-envelope-v1.schema.json` — Guard refusal envelope fields PORT; completion/certification/remediation fields MOVE. **Evidence:** schema required fields and `decision-envelope.mjs`.
- **MOVE** `src/packages/arcane/schemas/authority-binding-v1.schema.json` — authority binding; **evidence:** schema `$id`, `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/schemas/authority-invocation-proof-v1.schema.json` — authority proof; **evidence:** schema `$id`, `doctrine/arcane.md` §13.
- **MOVE** `src/packages/arcane/schemas/authority-proof-transition-v1.schema.json` — authority proof lifecycle; **evidence:** schema `$id`, `doctrine/arcane.md` §16.
- **MOVE** `src/packages/arcane/schemas/budget-governance-v1.schema.json` — budget governance; **evidence:** schema `$id`, `budget-governance-store.mjs`.
- **PORT** `src/packages/arcane/schemas/capability-grant-v1.schema.json` — deterministic Guard capability grant; **evidence:** schema `$id`, `doctrine/guard.md` Definition.
- **PORT** `src/packages/arcane/schemas/capability-transition-v1.schema.json` — deterministic Guard capability consume/revoke transition; **evidence:** schema `$id`, `capability-store.mjs`.
- **MOVE** `src/packages/arcane/schemas/contract-seal-v1.schema.json` — Legion executable contract seal; **evidence:** schema `$id`, `contract-seal-store.mjs`.
- **MOVE** `src/packages/arcane/schemas/contract-transition-receipt-v1.schema.json` — Legion contract lifecycle receipt; **evidence:** schema `$id`, `contract-lifecycle.mjs`.
- **MOVE** `src/packages/arcane/schemas/current-user-risk-acceptance-v1.schema.json` — Legion user-risk acceptance; **evidence:** schema `$id`, `current-user-risk-acceptance.mjs`.
- **MOVE** `src/packages/arcane/schemas/current-user-scope-amendment-v1.schema.json` — Legion scope amendment; **evidence:** schema `$id`, `current-user-scope-amendment.mjs`.
- **MOVE** `src/packages/arcane/schemas/host-event-ledger-record-v1.schema.json` — host/Legion lifecycle trajectory record; **evidence:** schema `$id`, `host-event-ledger.mjs`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/schemas/host-runtime-output-v1.schema.json` — typed Guard effect output PORT; completion/runtime result fields MOVE. **Evidence:** schema required fields and `host-runtime-output.mjs`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/schemas/host-runtime-result-v1.schema.json` — effect decision transport PORT; certification, termination, and remediation MOVE. **Evidence:** schema required fields and `host-runtime.mjs`.
- **MOVE** `src/packages/arcane/schemas/pending-terminal-operation-v1.schema.json` — completion claim operation; **evidence:** schema `$id`, tracker P2.16.
- **MOVE** `src/packages/arcane/schemas/task-budget-seal-v1.schema.json` — Legion task budget seal; **evidence:** schema `$id`, `task-budget-seal-store.mjs`.
- **MOVE** `src/packages/arcane/schemas/terminal-operation-transition-v1.schema.json` — completion operation transition; **evidence:** schema `$id`, tracker P2.16.
- **PORT** `src/packages/arcane/schemas/user-approval-v1.schema.json` — target-bound Guard approval record; **evidence:** schema `$id`, `doctrine/guard.md` Approval boundary.

### Tests — 80 files

Tests follow the disposition of the behavior they exercise. RETIRE tests are retired with dead architecture; SPLIT tests must be separated when the implementation is split.

#### PORT tests

- **PORT** `src/packages/arcane/tests/advisory-effect-classification.test.mjs` — tests host effect classification/Guard vocabulary; **evidence:** imports `claude-code-adapter.mjs`, `codex-adapter.mjs`, and `contracts/enums.mjs`.
- **PORT** `src/packages/arcane/tests/claude-code-adapter.test.mjs` — Guard-facing Claude event normalization and effect mapping; **evidence:** imports host adapter and `host-event.mjs`.
- **PORT** `src/packages/arcane/tests/codex-adapter.test.mjs` — Guard-facing Codex event/effect mapping; **evidence:** imports host adapter, `host-event.mjs`, replay, and receipt store.
- **SPLIT (PORT/MOVE/RESTORE)** `src/packages/arcane/tests/hook-adapter-core.test.mjs` — shared Guard ingress, host runtime, and Stop postflight assertions; **evidence:** imports `hook-adapter-core.mjs` and host event modules.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/tests/host-runtime-output.test.mjs` — effect refusal output PORT, runtime/completion envelope MOVE; **evidence:** imports `host-runtime-output.mjs`, `decision-envelope.mjs`, and runtime schemas.
- **PORT** `src/packages/arcane/tests/s03-keys.test.mjs` — key custody; **evidence:** imports `keys.mjs`.
- **PORT** `src/packages/arcane/tests/s03-receipt-auth.test.mjs` — HMAC bound-field verification; **evidence:** imports `receipt-auth.mjs`.
- **PORT** `src/packages/arcane/tests/s03-receipt-store.test.mjs` — append-only receipt chain; **evidence:** imports `receipt-store.mjs`.
- **PORT** `src/packages/arcane/tests/s03-replay.test.mjs` — replay defense; **evidence:** imports `replay.mjs`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/tests/s04-host-event.test.mjs` — effect event schema PORT, observation qualification MOVE; **evidence:** imports `host-event.mjs`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/tests/s04-ingest.test.mjs` — authenticated effect ingestion PORT, invalidation/observation semantics MOVE; **evidence:** imports `ingest.mjs`, `host-event.mjs`, and policy.
- **PORT** `src/packages/arcane/tests/s06-preeffect-gate.test.mjs` — pre-effect Guard gate; **evidence:** imports `preeffect-gate.mjs`.
- **PORT** `src/packages/arcane/tests/s07-gate2-integration.test.mjs` — Guard gate integration; **evidence:** imports `preeffect-gate.mjs` and policy/authority.
- **PORT** `src/packages/arcane/tests/s08-capability-mint.test.mjs` — Guard capability minting; **evidence:** imports `preeffect-gate.mjs`.
- **PORT** `src/packages/arcane/tests/preeffect-correlation.test.mjs` — Guard pre/post correlation; **evidence:** imports correlation store.
- **PORT** `src/packages/arcane/tests/user-approval.test.mjs` — target-bound user approval; **evidence:** imports `user-approval.mjs`.
- **PORT** `src/packages/arcane/tests/vcs-rewrite-approval.test.mjs` — Guard VCS rewrite refusal/approval boundary; **evidence:** imports `hook-adapter-core.mjs` push classification.
- **PORT** `src/packages/arcane/tests/durable-capability-store.test.mjs` — durable Guard capability grants/transitions; **evidence:** imports `capability-store.mjs`.

#### RESTORE tests

- **RESTORE** `src/packages/arcane/tests/minimize.test.mjs` — preserve only tests for the Minimize policy/decision posture; move commit-gate tests with delivery owner. **Evidence:** imports `minimize.mjs`; `policy/minimize-policy.md`.
- **RESTORE** `src/packages/arcane/tests/policy-inject.test.mjs` — Brief/Minimize injection behavior; **evidence:** imports `host/policy-inject.mjs`.
- **SPLIT (PORT/RESTORE/MOVE)** `src/packages/arcane/tests/stop-disposition-integration.test.mjs` — Stop delivery, cognitive shape, and completion disposition must separate; **evidence:** imports hook core, pending terminal store, and keys.

#### MOVE tests

- **MOVE** `src/packages/arcane/tests/adversarial-ai-reconstruction.test.mjs` — Legion architecture evaluator; **evidence:** imports matching adversarial module.
- **MOVE** `src/packages/arcane/tests/adversarial-migration-distributed.test.mjs` — Legion migration evaluator; **evidence:** imports matching module.
- **MOVE** `src/packages/arcane/tests/adversarial-ownership-economics.test.mjs` — Legion ownership evaluator; **evidence:** imports matching module.
- **MOVE** `src/packages/arcane/tests/adversarial-proportionality.test.mjs` — Legion proportionality evaluator; **evidence:** imports matching module.
- **MOVE** `src/packages/arcane/tests/advisory-certification.test.mjs` — advisory certification; **evidence:** imports `advisory-certification.mjs`.
- **MOVE** `src/packages/arcane/tests/advisory-judgment.test.mjs` — advisory judgment; **evidence:** imports `advisory-judgment.mjs`.
- **MOVE** `src/packages/arcane/tests/advisory-profile.test.mjs` — advisory profile; **evidence:** imports `advisory-profile.mjs`.
- **MOVE** `src/packages/arcane/tests/authority-binding-store.test.mjs` — authority binding; **evidence:** imports binding store.
- **MOVE** `src/packages/arcane/tests/authority-invocation-proof.test.mjs` — authority proof; **evidence:** imports proof issuer.
- **MOVE** `src/packages/arcane/tests/budget-governance.test.mjs` — budget execution; **evidence:** imports budget store.
- **MOVE** `src/packages/arcane/tests/calibration-convergence-policy.test.mjs` — convergence policy; **evidence:** imports calibration module.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/tests/chain-bootstrap.test.mjs` — Guard bootstrap assertions PORT, runtime/contract bootstrap MOVE; **evidence:** imports authority binding, pre-effect gate, runtime schema.
- **MOVE** `src/packages/arcane/tests/command-verifier.test.mjs` — structured verification; **evidence:** imports `command-verifier.mjs`.
- **MOVE** `src/packages/arcane/tests/completion-state.test.mjs` — completion state; **evidence:** imports `completion-state.mjs`.
- **MOVE** `src/packages/arcane/tests/contract-lifecycle.test.mjs` — contract lifecycle; **evidence:** imports `contract-lifecycle.mjs`.
- **MOVE** `src/packages/arcane/tests/contract-seal-store.test.mjs` — contract seal; **evidence:** imports `contract-seal-store.mjs`.
- **MOVE** `src/packages/arcane/tests/current-user-risk-acceptance.test.mjs` — risk acceptance; **evidence:** imports risk acceptance and completion gate.
- **MOVE** `src/packages/arcane/tests/current-user-scope-amendment.test.mjs` — scope amendment; **evidence:** imports scope amendment and host ledger.
- **MOVE** `src/packages/arcane/tests/deficit-governance.test.mjs` — acceptance debt; **evidence:** imports deficit governance.
- **MOVE** `src/packages/arcane/tests/delivery-continuity-bindings.test.mjs` — delivery continuity; **evidence:** imports S11 delivery binding.
- **MOVE** `src/packages/arcane/tests/delivery-guard.test.mjs` — delivery ownership/lease; **evidence:** imports `delivery-guard.mjs`.
- **MOVE** `src/packages/arcane/tests/denial-circuit.test.mjs` — bounded retry termination; **evidence:** imports `denial-circuit.mjs`.
- **SPLIT (PORT/MOVE)** `src/packages/arcane/tests/discipline-controls.test.mjs` — narrow effect refusal PORT, commit/delivery discipline MOVE; **evidence:** imports discipline controls and host runtime.
- **MOVE** `src/packages/arcane/tests/dispatch-scheduler.test.mjs` — Legion dispatch; **evidence:** imports scheduler and delivery guard.
- **MOVE** `src/packages/arcane/tests/eval-candidate-quality.test.mjs` — S11 quality evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/eval-concurrency-convergence.test.mjs` — S11 convergence evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/eval-handoff-negative.test.mjs` — S11 handoff evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/eval-review-security.test.mjs` — S11 security evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/evidence-authority.test.mjs` — evidence authority; **evidence:** imports `evidence-authority.mjs`.
- **MOVE** `src/packages/arcane/tests/evidence-lifecycle.test.mjs` — evidence registry/provider lifecycle; **evidence:** imports `evidence-registry.mjs`.
- **MOVE** `src/packages/arcane/tests/execution-governance.test.mjs` — retry/continuity governance; **evidence:** imports execution governance and architecture event store.
- **MOVE** `src/packages/arcane/tests/finding-lifecycle.test.mjs` — finding lifecycle; **evidence:** imports finding module.
- **MOVE** `src/packages/arcane/tests/governance-state-binding.test.mjs` — S11 governance state; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/h13-codex-registered-parity.acceptance.test.mjs` — host registration parity; **evidence:** imports Codex adapter and host event.
- **MOVE** `src/packages/arcane/tests/m7-state-replay.test.mjs` — architecture state replay; **evidence:** imports architecture state/event store.
- **SPLIT (MOVE/RETIRE)** `src/packages/arcane/tests/recovery-migration-lifecycle.test.mjs` — recovery and migration assertions MOVE with their owners; generic control-lifecycle retirement assertions RETIRE with dead ceremony. **Evidence:** paired imports and `control-lifecycle.mjs`.
- **MOVE** `src/packages/arcane/tests/review-disposition-policy.test.mjs` — review disposition; **evidence:** imports review policy.
- **MOVE** `src/packages/arcane/tests/runtime-binding.test.mjs` — host runtime binding; **evidence:** imports `host-runtime.mjs`.
- **MOVE** `src/packages/arcane/tests/runtime-schema.test.mjs` — runtime schema set; **evidence:** imports runtime schema/state paths.
- **MOVE** `src/packages/arcane/tests/s01-bridge.test.mjs` — Forge compatibility bridge; **evidence:** imports `legacy-bridge.mjs`.
- **MOVE** `src/packages/arcane/tests/s05-evidence-envelope.test.mjs` — Legion evidence envelope; **evidence:** imports evidence envelope.
- **MOVE** `src/packages/arcane/tests/s05-invalidation.test.mjs` — Legion dependency invalidation; **evidence:** imports invalidation.
- **MOVE** `src/packages/arcane/tests/s05-migration.test.mjs` — Legion evidence migration; **evidence:** imports evidence migration.
- **MOVE** `src/packages/arcane/tests/s09-completion-gate.test.mjs` — completion gate P2.16; **evidence:** imports completion gate.
- **MOVE** `src/packages/arcane/tests/s11-authority-review-bindings.test.mjs` — S11 authority review; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/s11-eval-adr-canon-clarify.test.mjs` — S11 ADR evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/s11-eval-adversarial.test.mjs` — S11 adversarial evaluator; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/s11-evidence-closure-bindings.test.mjs` — S11 evidence closure; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/s11-m1-m6-bindings.test.mjs` — S11 M1–M6; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/s11-m7-bindings.test.mjs` — S11 M7; **evidence:** imports matching binding.
- **MOVE** `src/packages/arcane/tests/semantic-health.test.mjs` — runtime/host health probes; **evidence:** imports `semantic-health.mjs`.
- **MOVE** `src/packages/arcane/tests/session-binding-e2e.test.mjs` — host session binding; **evidence:** imports Claude adapter/session binding.
- **MOVE** `src/packages/arcane/tests/session-binding.test.mjs` — session binding store; **evidence:** imports session binding.
- **MOVE** `src/packages/arcane/tests/source-revision.test.mjs` — host repository revision; **evidence:** imports source revision.
- **MOVE** `src/packages/arcane/tests/stale-open-atomicity.test.mjs` — runtime/contract stale-state atomicity; **evidence:** imports CLI run and runtime fixture.
- **MOVE** `src/packages/arcane/tests/task-budget-seal.test.mjs` — task budget seal; **evidence:** imports task budget store.
#### RETIRE tests

- **RETIRE** `src/packages/arcane/tests/s02-policy.test.mjs` — duplicate Node policy API test is retired with the historical policy bundle; **evidence:** imports `policy.mjs`, `policy/README.md`.
- **RETIRE** `src/packages/arcane/tests/policy-compiler.test.mjs` — dead duplicate Node policy compiler and its test are retired together; **evidence:** `policy/README.md`.
- **RETIRE** `src/packages/arcane/tests/codex-escalation.test.mjs` — dead escalation ceremony and test are retired together; **evidence:** `codex-escalation.mjs`, `doctrine/arcane.md` Anti-ceremony invariants.
### Test fixtures — 6 files

- **MOVE** `src/packages/arcane/tests/fixtures/authority-binding-race-worker.mjs` — Legion authority binding race fixture; **evidence:** filename plus authority-binding imports in paired tests.
- **PORT** `src/packages/arcane/tests/fixtures/capability-race-worker.mjs` — Guard capability race fixture; **evidence:** paired durable capability test.
- **MOVE** `src/packages/arcane/tests/fixtures/contract-seal-race-worker.mjs` — Legion contract seal race fixture; **evidence:** paired contract-seal test.
- **PORT** `src/packages/arcane/tests/fixtures/preeffect-correlation-race-worker.mjs` — Guard correlation race fixture; **evidence:** paired preeffect-correlation test.
- **MOVE** `src/packages/arcane/tests/fixtures/runtime-binding-contract.mjs` — Legion runtime contract fixture; **evidence:** paired runtime/stale-open tests.
- **MOVE** `src/packages/arcane/tests/fixtures/session-binding-race-worker.mjs` — host/Legion session binding race fixture; **evidence:** paired session-binding tests.

## Unresolved decisions

None. The only apparent mixed cases are recorded as SPLITs with an explicit receiving owner. In particular, Guard delivery of a Stop event does not transfer ownership of ending-shape cognition to the Guard; the postflight discipline remains Arcane-owned and RESTOREs to the cognitive plane.

## Integration-owner hand checks

1. Review every row against the current tree and preserve the listed SPLIT boundaries when extracting code.
2. Keep Guard PORTs deterministic and receipt-owning; do not port cognitive response rules into Guard policy.
3. Move completion/evidence/authority/runtime machinery together with its tests; completion-gate material is part of P2.16.
4. Restore only Brief/Minimize injection and bounded ending-shape behavior; retire duplicate Node policy and escalation ceremony.
5. After merge, run the package’s existing `pnpm test` and confirm no test/CLI/output/exit-code regression.

**Verification status for this lane:** inspection only; no tests, builds, generators, installs, commits, or pushes were run.
