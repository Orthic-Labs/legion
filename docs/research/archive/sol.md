# Legion external-practices comparison & recommendations

**Date:** 2026-08-13  
**Baseline:** current Legion checkout + [final architecture improvements book](./2026-08-12-legion-architecture-book-final.md)  
**Corpus:** 18 local repository snapshots, commit-pinned below  
**Decision:** implement final book first; add five narrow control families; improve four existing contracts; reject unsafe imported anti-patterns.

## Executive verdict

Legion already has stronger constitutional boundaries than any single supplied repository: latest-intent authority, proportional routing, explicit Sage/Alchemist/Oracle separation, ambient-by-default work, one integration owner, evidence-before-claim, bounded governed runs, authenticated receipts, independent assurance, & exact delivery-state reporting.

Final book already absorbs most broadly useful practices in corpus: acceptance freeze, scoped consumptive review, severity-gated reopening, representative-workload-first execution, intent cancellation, cross-ID budgets, local invalidation, decision finality, risk-first spikes, canonical state, outcome-surface proof, evidence reachability, shared-writer serialization, & machinery-defect isolation.

Main risk is therefore **implementation gap**, not idea gap. Adding more doctrine before adoption would recreate ceremony final book is designed to remove.

Five genuinely net-new additions remain worthwhile:

1. **Correlated execution trajectory + deterministic resume/replay view.** Arcane has authenticated host events, budget events, receipts, & replay defense, but no unified task trajectory joining user intent, dispatch, tool results, checkpoints, acceptance items, findings, costs, retries, & terminal reason.
2. **Typed incomplete/debt propagation.** `DECIDE_WITH_DEBT` exists for design, but execution lacks a dependency-aware record showing which optional deficit propagates to which downstream tasks & final delivery.
3. **Stable cross-round finding identity.** Final book types findings, but does not fully define stable fingerprint, first/last observed, anchors, supersession, duplicate detection, or resolution transitions.
4. **Ownership-role split + cutover proof.** “One canonical owner” should distinguish runtime owner, first-fix owner, long-term owner, integration owner, shared-state writer, & evidence producer. Migrations should choose hard cut or bounded coexistence & prove losing-path absence where hard cut applies.
5. **Evidence-artifact envelope.** Representative workload should bind environment tuple, artifact sensitivity, retention, gateability, failure signature, matrix rationale, & external-provider result semantics.

Four improvements should modify existing final-book contracts rather than add more top-level laws:

- checkpoint/resume semantics inside canonical execution state;
- assurance confidence separated from severity, with reachability/controllability/impact/negative evidence;
- attention-budgeted concurrency instead of universal or fixed-width fan-out;
- retry taxonomy with cheapest valid repair first, changed-input proof, & exact cross-layer stop constants.

## Comparison rules

### Status meanings

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | Behavior exists in current doctrine/runtime with inspectable enforcement or test evidence. |
| `DOCTRINE_ONLY` | Current authoritative rule exists, but broad mechanical enforcement is absent or partial. |
| `PLAN_ONLY` | Final book specifies behavior; adoption sequence shows it remains implementation work. |
| `PARTIAL` | Pieces exist, but end-to-end invariant is not closed. |
| `MISSING` | Neither current system nor final book defines control sufficiently. |
| `REJECT` | External practice conflicts with Legion authority, scope, safety, or convergence rules. |

### Evidence discipline

- Repository prose proves what repository documents or instructs, not production effectiveness.
- Source code, executable schemas, & tests outrank README claims.
- Design proposals remain `PLAN`, even when detailed.
- Catalogs are discovery indexes only; entry count is not implementation evidence.
- Duplicate `agent-field-swe-af-snapshot` was excluded.
- Comparison used local commit snapshots; no moving web pages were needed.

## What current Legion already does well

| Practice | Current evidence | External reinforcement | Verdict |
|---|---|---|---|
| Latest explicit intent controls authority | [legion.md](/workspace/docs/agent-rules/legion.md:7), [workspace.md](/workspace/docs/agent-rules/workspace.md:4) | gstack decision finality; final book stop precedence | `IMPLEMENTED` constitutionally |
| Proportional depth; ambient default | [legion.md](/workspace/docs/agent-rules/legion.md:31) | Addy skips planning for obvious scope; Matt Pocock reserves heavy diagnosis | `IMPLEMENTED` |
| Sage decides; Alchemist transforms; Oracle certifies | [legion.md](/workspace/docs/agent-rules/legion.md:19) | NeoLab judge separation; Superpowers spec then quality review | `IMPLEMENTED` & stronger than corpus defaults |
| Evidence before completion claim | [legion.md](/workspace/docs/agent-rules/legion.md:12), [completion-gate.mjs](/workspace/tools/skills/legion/packages/arcane/lib/completion-gate.mjs:91) | Superpowers fresh verification; TestDino command-backed conclusions | `IMPLEMENTED/PARTIAL`: receipt prerequisites exist; task acceptance ledger does not |
| One integration owner | [legion.md](/workspace/docs/agent-rules/legion.md:10), [workspace.md](/workspace/docs/agent-rules/workspace.md:8) | Instructa canonical ownership; SWE-AF barriers | `DOCTRINE_ONLY`: owner lease/active-writer enforcement remains planned |
| Bounded governed-run budgets | [budget-governance-store.mjs](/workspace/tools/skills/legion/packages/arcane/lib/budget-governance-store.mjs:33) | SWE-agent episode budgets; SWE-AF nested caps | `IMPLEMENTED` after seal; admission/pre-seal gap remains |
| Changed-input retry rule | [alchemist.md](/workspace/tools/skills/legion/doctrine/alchemist.md:36) | Addy/Superpowers/NeoLab/SWE-AF stuck-loop controls | `IMPLEMENTED` doctrine; runtime constant drifts |
| Authenticated evidence, replay defense, event continuity | [replay.mjs](/workspace/tools/skills/legion/packages/arcane/lib/replay.mjs:1), [host-event-ledger.mjs](/workspace/tools/skills/legion/packages/arcane/lib/host-event-ledger.mjs:7) | AgentField correlation; gstack atomic partial results | `IMPLEMENTED` primitives; unified trajectory missing |
| Missing evidence never passes | [oracle.md](/workspace/tools/skills/legion/doctrine/oracle.md:17) | Trail of Bits verification chain; LambdaTest gateability boundary | `IMPLEMENTED` |
| Out-of-scope findings do not become opportunistic fixes | [alchemist.md](/workspace/tools/skills/legion/doctrine/alchemist.md:28), [legion.md](/workspace/docs/agent-rules/legion.md:35) | Addy scope discipline; NeoLab judge cannot create criteria | `IMPLEMENTED` doctrine |
| Exact delivery-state language | [legion.md](/workspace/docs/agent-rules/legion.md:51) | SWE-agent typed exits; mini-SWE-agent flow exceptions | `IMPLEMENTED` |
| No recursive assurance | [oracle.md](/workspace/tools/skills/legion/doctrine/oracle.md:44) | Superpowers scoped final review | `IMPLEMENTED` |
| Durable runtime truth; Markdown as export | [workspace.md](/workspace/docs/agent-rules/workspace.md:27) | gstack append-only decisions; SWE-agent trajectories | `IMPLEMENTED` principle |

## Strong practices already present in final book, but not fully implemented

Final book explicitly calls itself an adoption sequence at [Part XVI](./2026-08-12-legion-architecture-book-final.md#part-xvi--adoption-sequence). These controls should not be re-designed from corpus; they should be implemented & evaluated.

| Planned control | Book location | Current state | Required implementation |
|---|---|---|---|
| Frozen acceptance ledger with IDs, dispositions, surfaces, owners, dependencies, fingerprint | [G-A19](./2026-08-12-legion-architecture-book-final.md#g-a19--frozen-acceptance-ledger) | `PLAN_ONLY`; worker capsules have rich acceptance records, but no universal task ledger | Schema, state store, user-intent compiler, immutable lineage, mutation guard |
| Reviewer cannot create requirements | [G-A20](./2026-08-12-legion-architecture-book-final.md#g-a20--review-cannot-create-requirements) | `DOCTRINE_ONLY/PARTIAL` | Finding-to-acceptance/invariant/safety mapping enforced before blocker status |
| Representative workload before theoretical hardening | [G-A21](./2026-08-12-legion-architecture-book-final.md#g-a21--representative-workload-before-hardening) | `PLAN_ONLY` globally; used in some worker capsules | Workload schema, forward-workload state, hardening deferral guard |
| Latest intent cancels persistence | [G-A22](./2026-08-12-legion-architecture-book-final.md#g-a22--latest-intent-cancels-persistence) | `PARTIAL`: host events & stop classification exist; no complete epoch-bound cancellation | Intent/continuation epochs across dispatch, waits, monitors, tools, goals |
| Hard time/round boundaries across objective lineage | [G-A23](./2026-08-12-legion-architecture-book-final.md#g-a23--hard-time-and-round-boundaries) | `PARTIAL`: sealed active/progress/contract caps exist; pre-seal design/review counters do not | Dispatch-bound counters, cross-ID lineage, typed expiry |
| One integration owner + one active shared-state writer | [G-A24](./2026-08-12-legion-architecture-book-final.md#g-a24--one-integration-owner-one-shared-state-writer) | `DOCTRINE_ONLY` | Owner/writer lease, conflict denial, return-only worker protocol |
| Acceptance-surface completion | [G-A25](./2026-08-12-legion-architecture-book-final.md#g-a25--outcome-closure-requires-acceptance-surface-evidence) | `PARTIAL`: claim-level receipt gate exists, not per-required-item closure | Exact state identity + integration identity + per-item observed proof |
| Seal-time evidence reachability | [G-A26](./2026-08-12-legion-architecture-book-final.md#g-a26--seal-time-evidence-reachability) | `PARTIAL`: producer checks/replay defense exist; no producer→store→verifier→consumer→close compiler | Reachability graph, positive lifecycle, substitution/replay tests, recovery path |
| Machinery defect isolation | [G-A27](./2026-08-12-legion-architecture-book-final.md#g-a27--gate-defects-do-not-replace-delivery) | `DOCTRINE_ONLY` | Typed defect record + required-evidence/safety impact test + sanctioned continuation |
| `OBJECTIVE × DEPTH × RIGOR` router | [Part IV](./2026-08-12-legion-architecture-book-final.md#part-iv--routing-objective--depth--rigor) | `PLAN_ONLY` as canonical machine state | Router schema, dispatch binding, objective non-upgrade guard |
| Decision/evidence/review-packet fingerprints | [Part V](./2026-08-12-legion-architecture-book-final.md#part-v--canonical-architecture-state) | `PARTIAL`: contract/retry digests exist, not architecture-state fingerprints | Canonical fingerprint producer + delta classifier |
| Cause + scope invalidation | [G-A9](./2026-08-12-legion-architecture-book-final.md#g-a9--invalidation-is-cause-plus-scope) | `PLAN_ONLY` for architecture | Typed invalidation record + dependent-cone computation |
| Decision finality + governed reopening | [G-A8](./2026-08-12-legion-architecture-book-final.md#g-a8--decision-finality) | `DOCTRINE_ONLY/PARTIAL` | Frozen decision state, admissible reopen evidence, supersession lineage |
| Consumptive scoped review | [G-A13](./2026-08-12-legion-architecture-book-final.md#g-a13--review-is-consumptive) | `DOCTRINE_ONLY` | Round packet, prior-blocker scope, new-observation deferral, one scoped re-audit |
| Canonical architecture state + terminal states | [Part V](./2026-08-12-legion-architecture-book-final.md#part-v--canonical-architecture-state), [Part VII](./2026-08-12-legion-architecture-book-final.md#part-vii--readiness-convergence-and-terminal-states) | `PLAN_ONLY` | Durable state, legal transitions, resume rules, terminal receipts |
| Dominance, failure stories, minimum-sufficient selection | [G-A16–G-A18](./2026-08-12-legion-architecture-book-final.md#g-a16--every-viable-candidate-carries-a-failure-story-restored) | `PLAN_ONLY` for canonical Architect route | Templates, phase logic, candidate-quality evals |
| Progressive disclosure + canonical concept owners | [Part X](./2026-08-12-legion-architecture-book-final.md#part-x--progressive-disclosure-and-canonical-ownership) | `PARTIAL`: skill routing exists; architecture package not yet reorganized | Compact root, phase modules, material-lens loading, generated-reference cleanup |

### Concrete current contradiction

Alchemist doctrine says “same fingerprint twice → stop,” while current Arcane budget runtime stops only when identical-attempt count becomes greater than three: [alchemist.md](/workspace/tools/skills/legion/doctrine/alchemist.md:38) vs [budget-governance-store.mjs](/workspace/tools/skills/legion/packages/arcane/lib/budget-governance-store.mjs:58). Final book says constants were aligned, but checkout is not aligned. Treat this as implementation drift, not a new policy decision.

## Net-new additions

### N1 — Unified execution trajectory & replay projection

**Priority:** P1, immediately after final-book state producers.

AgentField distinguishes a correlated durable execution event stream from raw process logs; gstack retains atomic partial eval output across interruption; SWE-agent & mini-SWE-agent keep versioned trajectories with typed terminal states. Current Arcane has separate host, budget, receipt, capability, & completion records, but no unified task projection.

Add `execution-trajectory-event.v1` as an append-only, authenticated envelope:

```yaml
event_id: stable unique ID
sequence: strict per execution
occurred_at: monotonic + wall-clock binding
objective_lineage_id: cross-session budget lineage
intent_epoch: current authority epoch
execution_id: current task/run execution
parent_execution_id: dispatch parent
repository_id: canonical checkout identity
actor_role: legion | sage | alchemist | oracle | covenant | worker | host
phase: route | decide | dispatch | execute | verify | integrate | close
event_type: typed lifecycle event
acceptance_ids: immutable required/deferred/out-of-scope references
decision_ids: affected frozen decisions
finding_ids: opened/changed/closed findings
input_fingerprint: evidence-bearing input state
output_refs: content-addressed artifacts or receipts
checkpoint_ref: resumable projection snapshot
cost_delta: tokens/time/external calls where available
retry_class: none | mechanical | changed-input | changed-method | external
terminal_reason: typed reason when terminal
privacy_class: content-free | metadata | sensitive | restricted
```

Requirements:

- Keep raw logs separate; trajectory answers lifecycle questions, logs answer debugging detail.
- Build read models from events; do not make agent-authored summary source of truth.
- Checkpoint after phase barriers & each durable acceptance advance.
- Resume from last verified checkpoint; never rerun completed work unless invalidated.
- Preserve full event chain for bounded retention; redact payloads while retaining hashes, IDs, classifications, & evidence refs.
- Provide deterministic `inspect`, `timeline`, `why-stopped`, `acceptance-progress`, `retry-history`, & `replay-plan` views.
- Do not confuse receipt anti-replay with episode replay. One rejects reused evidence; other reconstructs execution.

Evidence: [AgentField RFC](/tmp/legion-practices-sources.GtrSei/agent-field-agentfield/docs/design/execution-observability-rfc.md:59), [gstack architecture](/tmp/legion-practices-sources.GtrSei/garrytan-gstack/ARCHITECTURE.md:410), [SWE-agent types](/tmp/legion-practices-sources.GtrSei/swe-agent/sweagent/types.py:44), [mini-SWE-agent control flow](/tmp/legion-practices-sources.GtrSei/swe-agent-mini/docs/advanced/control_flow.md:94).

### N2 — Typed incomplete/debt propagation

**Priority:** P1.

Final book has architecture `DECIDE_WITH_DEBT`, residual debt ledger, & strict outcome completion. SWE-AF contributes useful execution behavior: incomplete or accepted-debt states remain explicit & propagate downstream instead of disappearing behind a successful stage label.

Add `delivery-deficit.v1`:

```yaml
deficit_id: stable ID
origin_acceptance_id: required/deferred item or null
kind: optional_gap | accepted_risk | external_blocker | degraded_evidence | machinery_defect
severity: blocker | required_this_slice | follow_up | advisory
status: open | accepted | mitigated | resolved | superseded
owner: named accountable owner
accepting_authority: required for accepted risk
affected_tasks: dependency-aware downstream set
affected_claim_levels: claims that cannot be made
evidence: exact current proof
trigger: observable reopen/review condition
expiry: optional date/event
```

Rules:

- `COMPLETE_WITH_NOTES` means every required item passed; notes are non-blocking.
- `COMPLETE_WITH_DEBT` is legal only when deficit maps to `DEFERRED`, optional quality, or authority-accepted risk.
- Required acceptance, safety, privacy, security, correctness, data integrity, legal constraint, or missing authority can never be auto-relaxed into debt.
- Downstream work receives affected-claim restrictions; it cannot claim stronger completion than inherited deficit permits.
- Final user report lists unresolved deficits without turning them into hidden new work.
- Budget expiry yields typed terminal state, never auto-approval.

Evidence: [SWE-AF architecture](/tmp/legion-practices-sources.GtrSei/agent-field-swe-af/docs/ARCHITECTURE.md:217), [final book G-A7](./2026-08-12-legion-architecture-book-final.md#g-a7--bounded-deliberation).

### N3 — Stable finding identity & lifecycle

**Priority:** P1.

Final book defines finding kind, severity, blocking criteria, & scoped rereview. CodeRabbit shows practical persistence: thread identity, resolution state, severity, anchors, & independent validation survive remediation. Legion needs cross-round identity so a renamed or reworded observation cannot masquerade as a new blocker.

Extend `architecture-review-finding` & Oracle finding records with:

```yaml
finding_id: stable across reruns
fingerprint: control + subject + normalized condition + acceptance/invariant ID
first_observed_at: timestamp + state identity
last_observed_at: timestamp + state identity
anchors: file/range, runtime span, receipt, screenshot, trace, or external artifact
status: open | addressed_candidate | verified_closed | refuted | accepted_risk | superseded
resolution_reason: typed disposition
caused_by: upstream finding IDs
supersedes: prior finding IDs
retest_scope: changed surface + affected dependency cone
negative_evidence: proof supporting refutation/non-applicability
```

Rules:

- Same fingerprint updates existing finding; it does not consume another review round as “new.”
- Fix author may mark `addressed_candidate`; only fresh verifier marks `verified_closed`.
- New observations during scoped rereview become deferred unless fix-introduced breakage or G-A20 blocker.
- Line movement does not mint new identity; anchors are evidence, not identity.
- Refuted findings remain queryable to suppress rediscovery & calibrate reviewers.

Evidence: [CodeRabbit autofix](/tmp/legion-practices-sources.GtrSei/coderabbitai-skills/skills/autofix/SKILL.md:171), [final book G-A13](./2026-08-12-legion-architecture-book-final.md#g-a13--review-is-consumptive).

### N4 — Ownership roles + migration cutover contract

**Priority:** P1.

Current doctrine correctly assigns one integration owner, but “owner” still spans distinct responsibilities. Instructa’s useful distinction is immediate repair vs runtime responsibility vs canonical long-term direction. Its hard-cut skill also makes losing-path deletion a first-class acceptance check.

Define separate roles:

| Role | Authority |
|---|---|
| Runtime owner | Accountable for operating behavior & incidents. |
| First-fix owner | Repairs present defect within current slice; may differ from long-term owner. |
| Canonical long-term owner | Owns intended boundary/source of truth after migration. |
| Integration owner | Alone mutates HEAD/index/receipts/pins/remotes for task. |
| Shared-state writer | Alone mutates one shared schema/ledger/contract while lease is active. |
| Evidence producer | Produces named evidence class; has no implied semantic or risk authority. |

Every migration chooses:

- `HARD_CUT`: one canonical path after change; delete old path, adapters, flags, fallback, tests, docs, config, & dependency unless external compatibility obligation proves retention.
- `BOUNDED_COEXISTENCE`: exact external boundary, owner, traffic split, reconciliation invariant, telemetry, expiry, rollback, & cutover trigger.

Acceptance proof adds `absence_checks` for old imports, routes, configuration keys, runtime registrations, dependencies, tests, docs, & emitted protocol variants.

Evidence: [architecture ownership](/tmp/legion-practices-sources.GtrSei/instructa-agent-skills/skills/architecture-ownership/SKILL.md:28), [hard cut](/tmp/legion-practices-sources.GtrSei/instructa-agent-skills/skills/hard-cut/SKILL.md:10).

### N5 — Evidence-artifact envelope

**Priority:** P2.

Final book requires representative workloads & executable evidence lifecycle. TestDino & LambdaTest add operational details necessary for remote/browser evidence: traces can be sensitive/untrusted; environment matrices should expand by risk; dashboard-visible results may not be machine-gateable; remote status defaults can misrepresent outcome unless set explicitly.

Extend `representative-workload.v1` & external evidence manifest:

```yaml
environment:
  os: exact
  runtime: exact
  browser_or_device: exact or null
  locale_timezone_network: declared when material
artifact:
  kind: trace | log | screenshot | video | report | receipt | dataset
  sensitivity: public | internal | sensitive | restricted
  trust: trusted | untrusted_input | generated_diagnostic
  retention: duration + deletion owner
  digest: content address
result:
  status: passed | failed | blocked | inconclusive
  machine_readable: true | false
  gateable: true | false
  downloadable: true | false
  correlation_id: execution trajectory binding
  failure_signature: normalized cluster key
matrix:
  rationale: risk/usage/contract source
  pr_subset: fast required cells
  release_set: full required cells
```

Rules:

- Dashboard-only output cannot satisfy a machine gate unless a trusted adapter retrieves & binds it.
- Retry after failure only when configuration, environment, input, or method materially changed.
- First retry captures trace/diagnostics; repeated “retry until green” is not evidence.
- Passing retry does not erase flake; cluster & root-cause it.
- Start with smallest representative cell; expand matrix from user distribution, risk, contract, or observed failure.

Evidence: [TestDino trace analysis](/tmp/legion-practices-sources.GtrSei/testdino-playwright-skill/core/trace-analysis.md:21), [LambdaTest Playwright](/tmp/legion-practices-sources.GtrSei/lambdatest-agent-skills/playwright-skill/SKILL.md:134), [LambdaTest accessibility](/tmp/legion-practices-sources.GtrSei/lambdatest-agent-skills/accessibility-skill/SKILL.md:23).

## Improvements to existing final-book controls

### I1 — Add checkpoint/resume to canonical execution state

SWE-AF checkpoints each phase; gstack writes partial results atomically; Superpowers maintains durable per-plan task status; SWE-agent serializes trajectory & exit status.

Change final book:

- Add `execution_checkpoint` to canonical state after every phase barrier, accepted patch, integration mutation, & acceptance-result update.
- Bind checkpoint to `intent_epoch`, objective lineage, repository state, acceptance fingerprint, producer versions, & last trajectory sequence.
- On resume, verify all bindings; invalidate smallest changed cone; never silently rerun completed effects.
- Treat partial artifacts as candidates until verified, but preserve them for recovery.
- Add crash-after-each-phase evals.

### I2 — Separate finding confidence from severity

Final book already separates kind from severity. Add independent confidence & exploitability/applicability chain:

```text
confidence: confirmed | high | medium | low | unknown
reachability: reachable | conditionally_reachable | unreachable | unknown
control: attacker_or_user_controlled | internal_only | unknown
impact: demonstrated | modeled | speculative | none
disposition: valid | false_positive | defense_in_depth | not_applicable | unknown
```

Only strong evidence plus G-A20 mapping makes a blocker. Security provider should execute deeper Trail of Bits verification; global architecture doctrine should only require typed fields & route specialist analysis when triggered.

Evidence: [Trail of Bits standard verification](/tmp/legion-practices-sources.GtrSei/trailofbits-skills/plugins/fp-check/skills/fp-check/references/standard-verification.md:26), [variant triage](/tmp/legion-practices-sources.GtrSei/trailofbits-skills/plugins/variant-analysis/skills/variant-analysis/references/triage.md:28), [Anthropic reviewer](/tmp/legion-practices-sources.GtrSei/anthropics-claude-code/plugins/feature-dev/agents/code-reviewer.md:23).

### I3 — Replace fixed concurrency with attention budget

NeoLab proposes controller width targets; useful insight is coordination cost, not fixed number. Legion should compute concurrency from integration & context load.

```text
concurrency = min(
  independent_ready_tasks,
  available_agent_slots,
  integration_owner_review_capacity,
  shared-state-writer constraints,
  context/evidence merge budget
)
```

Rules:

- Parallelize independent discovery & disjoint implementation.
- Serialize semantic decisions, shared state, repository delivery, & final disposition.
- Batch tiny same-shape tasks when isolation cost exceeds work.
- Workers receive task briefs, not whole session history.
- Bounded waits should release controller for useful local work.
- No universal “always use agents” rule.

Evidence: [NeoLab team lead](/tmp/legion-practices-sources.GtrSei/neolab-context-engineering-kit/agents/team-lead.md:50), [Superpowers SDD](/tmp/legion-practices-sources.GtrSei/obra-superpowers/skills/subagent-driven-development/SKILL.md:223).

### I4 — Normalize retry taxonomy & constants

Use one cross-layer rule:

1. Classify failure: mechanical, schema/format, evidence gap, environment, transient external, semantic defect, architecture blocker, authority/access, or unknown.
2. Apply cheapest valid repair that preserves acceptance semantics.
3. Record material delta: code, method, input, evidence, contract, or relevant environment.
4. Retry only after material delta.
5. Same normalized fingerprint twice stops current approach; route split/change-method/spike/escalate.
6. Budget caps never imply pass.

Repair order for structured-output failure:

```text
local deterministic normalization
→ same-session constrained repair
→ one full regeneration when semantics may be lost
→ typed failure
```

Do not adopt retry counts from individual repos wholesale. Final book’s objective-lineage ceiling remains authority. Align actual Arcane constant with doctrine & cover drift with test.

Evidence: [AgentField harness proposal](/tmp/legion-practices-sources.GtrSei/agent-field-agentfield/docs/design/harness-v2-design.md:307), [Alchemist retry discipline](/workspace/tools/skills/legion/doctrine/alchemist.md:36).

## Remove, reject, or constrain

| External practice | Action | Reason |
|---|---|---|
| Universal fresh reviewer after every task/change | `REJECT` as default | Conflicts with proportionality; creates endless criticism surface. Review only by risk/scope trigger. |
| “Repeat until clean” without round/time cap | `REJECT` | Violates Progress Invariant & objective-lineage budgets. |
| Auto-approve when architecture-review budget expires | `REJECT` | Missing or unresolved critical evidence never becomes pass. SWE-AF contains this unsafe fallback. |
| Continue after coordinator/replanner crash by default | `REJECT` | Control-plane failure may invalidate plan/safety. Resume only from verified checkpoint or typed block. |
| Unlimited Ralph-style same-prompt loop | `REJECT` | Same prompt/evidence is identical retry; max iteration remains too permissive unless bounded by changed-state fingerprint & acceptance proof. |
| Fixed “always use subagents” or fixed universal width | `REJECT` | Violates ambient default & attention-budgeted coordination. |
| Human approval after every plan/spec slice | `REJECT` unless user or risk policy requires it | Invents authority gates & delays reversible ambient work. |
| Punitive/threatening persona instructions | `REMOVE` | They add prompt noise, distort reporting, & provide no control evidence. |
| Catalog entry count or “battle-tested” label as quality evidence | `REJECT` | Discovery lead only; inspect original source, implementation, tests, & currentness. |
| Stale implementation spec as permanent source of truth | `REMOVE` from canon after delivery | Durable decisions belong in ADR/invariants; transient task spec becomes history. |
| Old & new codepaths kept “just in case” | `REJECT` by default | Require proven external compatibility obligation or explicit bounded-coexistence contract. |
| Timeout increases, forced clicks, assertion loosening, blind retries, baseline updates as first response | `REJECT` | Masks test/system failure & corrupts acceptance evidence. |
| Reviewer-authored acceptance criteria | `REJECT` | Violates G-A20 & user authority. |
| Model confidence alone as finding truth | `REJECT` | Confidence is triage metadata; actual applicability/evidence decides. |

## Repository-by-repository ledger

### 1. addyosmani/agent-skills — `be42637`

**Strongest practices:** vertical slices; risky/uncertain work first; scope discipline; green verification after each increment; smallest reviewable unit; reviewers return data rather than verdict; bounded doubt cycles.

**Legion status:** risk-first spike, representative slice, scope hold, Progress Invariant, bounded review, & evidence-before-claim are already in final book. Current ambient routing is stronger than repository’s more universal review posture.

**Recommendation:** no new top-level law. Add risk ordering to execution decomposition: first slice should maximize uncertainty retired per unit cost while still producing a testable acceptance advance.

**Reject:** universal fresh-review/human-approval requirements.

Evidence: [planning](/tmp/legion-practices-sources.GtrSei/addy-agent-skills/skills/planning-and-task-breakdown/SKILL.md:57), [incremental implementation](/tmp/legion-practices-sources.GtrSei/addy-agent-skills/skills/incremental-implementation/SKILL.md:77), [doubt-driven development](/tmp/legion-practices-sources.GtrSei/addy-agent-skills/skills/doubt-driven-development/SKILL.md:170).

### 2. obra/superpowers — `b36e082`

**Strongest practices:** scoped task brief; per-plan durable ledger; small-task batching; bounded waits; explicit `DONE`, `DONE_WITH_CONCERNS`, `BLOCKED`; no identical retry; scoped re-review + one final broad review.

**Legion status:** final book already absorbed consumptive review, scoped rereview, bounded loops, ledger-backed acceptance, worker isolation, & fresh verification.

**Recommendation:** reuse checkpoint/task-state ideas in N1; keep review trigger proportional. Do not mandate fresh worker or two reviews for every task.

Evidence: [subagent-driven development](/tmp/legion-practices-sources.GtrSei/obra-superpowers/skills/subagent-driven-development/SKILL.md:132), [verification before completion](/tmp/legion-practices-sources.GtrSei/obra-superpowers/skills/verification-before-completion/SKILL.md:17), [condition waits](/tmp/legion-practices-sources.GtrSei/obra-superpowers/skills/systematic-debugging/condition-based-waiting.md:5).

### 3. garrytan/gstack — `d078622`

**Strongest practices:** append-only decision memory; explicit supersession; context-health loop detection; user-origin preference memory; operational learnings after failures; real-session E2E evals; atomic partial result persistence.

**Legion status:** decision finality & explicit reopening exist in final book; Crypt/Membrane own memory. Full execution trajectory remains incomplete.

**Recommendation:** absorb atomic checkpoint/event behavior into N1. Preference promotion must remain user-origin, evidence-qualified, reversible, & never grant authority.

Evidence: [context save](/tmp/legion-practices-sources.GtrSei/garrytan-gstack/context-save/SKILL.md:639), [architecture](/tmp/legion-practices-sources.GtrSei/garrytan-gstack/ARCHITECTURE.md:410).

### 4. mattpocock/skills — `84fdeff`

**Strongest practices:** specs preserve decisions rather than reopen them; prototype when a question is empirically answerable; retain ADR rationale while discarding transient implementation plans; reference durable docs instead of copying them into handoffs.

**Legion status:** final book covers spikes, decision finality, durable rejection reasons, architecture/implementation boundary, & canonical ownership.

**Recommendation:** add explicit artifact lifecycle labels: `EPHEMERAL_TASK`, `DURABLE_DECISION`, `EXECUTION_RECEIPT`, `REFERENCE`. Automatically demote completed task specs from active context after durable facts migrate.

**Reject:** unbounded grilling frontier; final book’s hard question/time/revision caps win.

Evidence: [to spec](/tmp/legion-practices-sources.GtrSei/mattpocock-skills/docs/engineering/to-spec.md:5), [prototype](/tmp/legion-practices-sources.GtrSei/mattpocock-skills/docs/engineering/prototype.md:3), [handoff](/tmp/legion-practices-sources.GtrSei/mattpocock-skills/docs/productivity/handoff.md:34).

### 5. NeoLabHQ/context-engineering-kit — `8539779`

**Strongest practices:** smallest high-signal context; fresh contexts for isolated tasks; judge consumes criteria rather than inventing them; expected result drafted before implementation inspection; dependency-first parallelism; context-decay awareness.

**Legion status:** reviewer non-expansion, progressive disclosure, shared-writer control, & proportional routing exist in final book.

**Recommendation:** implement I3 attention budget; add pre-observation expected-result hash for high-risk independent assurance where hindsight bias matters.

**Reject:** “always use agents,” fixed width as universal law, punitive language, & new rules for one-off context failures.

Evidence: [concepts](/tmp/legion-practices-sources.GtrSei/neolab-context-engineering-kit/docs/concepts.md:7), [judge](/tmp/legion-practices-sources.GtrSei/neolab-context-engineering-kit/agents/judge.md:188), [team lead](/tmp/legion-practices-sources.GtrSei/neolab-context-engineering-kit/agents/team-lead.md:50).

### 6. instructa/agent-skills — `dff3284`

**Strongest practices:** runtime/first-fix/canonical-owner separation; hard-cut migrations; duplicate-ownership detection; explicit external-boundary exceptions; deletion of losing path.

**Legion status:** one integration owner & one canonical concept owner exist, but ownership roles & cutover proof are underspecified.

**Recommendation:** adopt N4.

Evidence: [architecture ownership](/tmp/legion-practices-sources.GtrSei/instructa-agent-skills/skills/architecture-ownership/SKILL.md:28), [hard cut](/tmp/legion-practices-sources.GtrSei/instructa-agent-skills/skills/hard-cut/SKILL.md:10), [duplicate ownership](/tmp/legion-practices-sources.GtrSei/instructa-agent-skills/skills/find-duplicate-ownership/SKILL.md:23).

### 7. trailofbits/skills — `304c81a`

**Strongest practices:** suspected finding verification; dismissal-first skepticism; attacker-control/reachability/impact chain; severity separate from confidence; false-positive records; explicit “when not to use”; diff/history blast-radius analysis.

**Legion status:** Oracle already requires actual-state evidence & pass/fail/unknown/not-applicable. Final book separates finding kind/severity but not full applicability chain.

**Recommendation:** adopt I2 inside security/assurance provider contracts; keep deep exploit analysis out of always-loaded Legion doctrine.

Evidence: [fp-check](/tmp/legion-practices-sources.GtrSei/trailofbits-skills/plugins/fp-check/skills/fp-check/SKILL.md:3), [standard verification](/tmp/legion-practices-sources.GtrSei/trailofbits-skills/plugins/fp-check/skills/fp-check/references/standard-verification.md:26), [triage](/tmp/legion-practices-sources.GtrSei/trailofbits-skills/plugins/variant-analysis/skills/variant-analysis/references/triage.md:77).

### 8. coderabbitai/skills — `aa49953`

**Strongest practices:** review scope & severity; untrusted feedback handling; persistent thread identity/resolution/anchors; independent fix validation.

**Legion status:** final book has typed findings & scoped rereview; stable cross-round identity remains missing.

**Recommendation:** adopt N3.

**Reject:** “repeat until only informational” unless objective-lineage round cap & changed-input rule apply.

Evidence: [code review](/tmp/legion-practices-sources.GtrSei/coderabbitai-skills/skills/code-review/SKILL.md:98), [autofix](/tmp/legion-practices-sources.GtrSei/coderabbitai-skills/skills/autofix/SKILL.md:171).

### 9. testdino-hq/playwright-skill — `d3be9ca`

**Strongest practices:** traces first after reproduction; artifact sensitivity/untrusted-input handling; cross-channel evidence; passing-vs-failing diff; failure clustering; anti-fix rejection; command-backed conclusions.

**Legion status:** representative workload & acceptance-surface proof are planned; artifact governance is incomplete.

**Recommendation:** adopt N5. Route visual conclusions through actual rendered artifacts; never treat trace viewer availability as machine-readable proof by itself.

Evidence: [trace analysis](/tmp/legion-practices-sources.GtrSei/testdino-playwright-skill/core/trace-analysis.md:3), [skill](/tmp/legion-practices-sources.GtrSei/testdino-playwright-skill/SKILL.md:29).

### 10. LambdaTest/agent-skills — `0491a3a`

**Strongest practices:** explicit environment matrix; no hard waits; diagnostics on failure; remote job status must reflect test result; scale only after one successful run; dashboard-vs-machine-gate distinction.

**Legion status:** final book has workload & evidence-reachability concepts but not external-provider evidence capabilities.

**Recommendation:** adopt N5; add provider capability manifest with `machine_readable`, `gateable`, `downloadable`, `correlatable`, `freshness`, & `status_semantics`.

Evidence: [Playwright](/tmp/legion-practices-sources.GtrSei/lambdatest-agent-skills/playwright-skill/SKILL.md:94), [HyperExecute](/tmp/legion-practices-sources.GtrSei/lambdatest-agent-skills/hyperexecute-skill/SKILL.md:30), [accessibility](/tmp/legion-practices-sources.GtrSei/lambdatest-agent-skills/accessibility-skill/SKILL.md:23).

### 11. VoltAgent/awesome-agent-skills — `bb272b6`

**Strongest use:** capability-family discovery & upstream-source finding.

**Legion status:** progressive disclosure & specialist routing already cover capability taxonomy.

**Recommendation:** use only as periodic omission scan. Every candidate capability must resolve to original source, current commit, implementation/test evidence, authority boundary, & duplication check before adoption.

**Reject:** count, popularity, badge, or curation claim as evidence.

Evidence: [README](/tmp/legion-practices-sources.GtrSei/voltagent-awesome-agent-skills/README.md:10).

### 12. EricGrill/agents-skills-plugins — `43a037f`

**Strongest use:** packaging/taxonomy survey & discovery of copied/forked skill families.

**Legion status:** many entries duplicate upstream systems already inspected directly.

**Recommendation:** deduplicate by upstream origin; never count fork plus source as independent convergence evidence.

Evidence: [README](/tmp/legion-practices-sources.GtrSei/ericgrill-agents-skills-plugins/README.md:75).

### 13. ArabelaTso/Coding-Skills-Collection — `e66a625`

**Strongest use:** SDLC omission scan—requirements, traceability, design, implementation, testing, verification, deployment, maintenance.

**Legion status:** routing tree already spans these stages through engineering/advisory domains & specialized skills.

**Recommendation:** use category coverage as discovery input only. Claims link outward, so inspect original implementation before any decision.

Evidence: [README](/tmp/legion-practices-sources.GtrSei/arabelatso-coding-skills-collection/README.md:45).

### 14. SWE-agent/mini-swe-agent — `a83fcae`

**Strongest practices:** minimal linear loop; typed flow exceptions; versioned output; explicit cost/time/repeated-format limits; complete history/config/metadata artifact.

**Legion status:** Legion is necessarily broader, but lacks a deliberately minimal baseline for ceremony cost.

**Recommendation:** create a “shadow harness” eval: solve representative bounded tasks with minimal ambient loop vs full routed system. Track outcome, latency, tokens, tool calls, reviewer rounds, & coordination overhead. Legion must justify added machinery by risk or outcome improvement.

Evidence: [README](/tmp/legion-practices-sources.GtrSei/swe-agent-mini/README.md:26), [control flow](/tmp/legion-practices-sources.GtrSei/swe-agent-mini/docs/advanced/control_flow.md:59), [output files](/tmp/legion-practices-sources.GtrSei/swe-agent-mini/docs/usage/output_files.md:17).

### 15. swe-agent/swe-agent — `3ea751c`

**Strongest practices:** explicit trajectory steps; exit status/submission; configurable history compression; replay tooling; budget/cost visibility.

**Legion status:** budgets & receipts exist, but coherent episode trajectory/replay view is missing.

**Recommendation:** adopt N1; preserve raw evidence references when compressing context so summary never becomes sole proof.

Evidence: [types](/tmp/legion-practices-sources.GtrSei/swe-agent/sweagent/types.py:44), [history processor](/tmp/legion-practices-sources.GtrSei/swe-agent/docs/reference/history_processor_config.md:3), [replay runner](/tmp/legion-practices-sources.GtrSei/swe-agent/sweagent/run/run_replay.py:1).

### 16. Agent-Field/SWE-AF — `1ae2913`

**Strongest practices:** exact phase checkpoints; hierarchical retry/split/replan/debt actions; stuck-loop detection; structured barriers; incomplete/debt propagation; mutable remaining DAG; crash recovery.

**Legion status:** final book covers caps, progress delta, terminal states, local invalidation, & design debt. Execution propagation & phase resume remain missing.

**Recommendation:** adopt N2 + I1.

**Reject:** auto-approve after review exhaustion & continue after replanner crash. Both violate no-false-clean & verified-resume invariants.

Evidence: [architecture](/tmp/legion-practices-sources.GtrSei/agent-field-swe-af/docs/ARCHITECTURE.md:28), [skill](/tmp/legion-practices-sources.GtrSei/agent-field-swe-af/docs/SKILL.md:178).

### 17. Agent-Field/agentfield — `a6dd3f3`

**Strongest practices:** durable queues; crash/restart resume; execution timeline; correlation IDs; explicit cost cap; multi-layer output recovery; lifecycle events separate from raw logs; bounded event retention.

**Legion status:** Arcane already has strong authenticated primitives, but no unified trajectory. AgentField’s observability RFC is a design proposal, not implemented-performance evidence.

**Recommendation:** adopt N1 using Arcane identity/authentication rather than importing distributed platform complexity.

Evidence: [README](/tmp/legion-practices-sources.GtrSei/agent-field-agentfield/README.md:230), [observability RFC](/tmp/legion-practices-sources.GtrSei/agent-field-agentfield/docs/design/execution-observability-rfc.md:22), [harness proposal](/tmp/legion-practices-sources.GtrSei/agent-field-agentfield/docs/design/harness-v2-design.md:307).

### 18. anthropics/claude-code — `be90077`

**Strongest practices:** confidence-gated review; review starts from explicit diff scope; decisive architecture output; stop-hook iteration supports max bound & cancellation; clear “not good for” scope.

**Legion status:** final book’s severity/confidence floor, decisive selection, bounded iteration, & scope routing are stronger. Native hook lifecycle is useful compatibility evidence.

**Recommendation:** preserve host-native stop/cancel semantics while layering Arcane intent epochs. Use reviewer confidence for triage only. Never copy Ralph’s unlimited default or exact-string completion as proof.

Evidence: [code reviewer](/tmp/legion-practices-sources.GtrSei/anthropics-claude-code/plugins/feature-dev/agents/code-reviewer.md:23), [code architect](/tmp/legion-practices-sources.GtrSei/anthropics-claude-code/plugins/feature-dev/agents/code-architect.md:13), [Ralph](/tmp/legion-practices-sources.GtrSei/anthropics-claude-code/plugins/ralph-wiggum/README.md:50).

## Exact changes to final book

Do not add five more constitutional G-A laws. Extend existing canonical concepts so root doctrine stays small.

| Book area | Change |
|---|---|
| Part V canonical state | Add execution identity, last trajectory sequence, checkpoint ref, unresolved deficit IDs, open finding IDs, ownership-role map, artifact-envelope refs. |
| G-A6 Progress Invariant | Define retry material delta against normalized execution fingerprint; require explicit retry class. |
| G-A7 bounded deliberation | Clarify design debt vs delivery deficit; no automatic acceptance relaxation. |
| G-A13 review consumptive | Add stable finding fingerprint/lifecycle, negative evidence, first/last observed, scoped dependency cone. |
| G-A15 lifecycle governance | Split ownership roles; add hard-cut/bounded-coexistence selection & exit proof. |
| G-A21 representative workload | Add environment/matrix/artifact envelope, machine gateability, sensitivity/retention, failure signature. |
| G-A23 boundaries | Align identical retry constant across doctrine/runtime/tests. Add concurrency attention budget. |
| G-A24 integration owner | Add active-writer lease + distinct runtime/first-fix/long-term/evidence-producer roles. |
| G-A25 outcome closure | Apply inherited deficit claim ceiling; require absence proof for hard cuts. |
| G-A26 evidence reachability | Add external-provider capability manifest & trajectory correlation. |
| Architecture review template | Add finding identity, applicability chain, confidence, negative evidence, supersession. |
| Representative workload template | Add N5 envelope fields. |
| Convergence receipt | Add last event digest, checkpoint digest, deficit/finding sets, ownership lease IDs. |
| Adoption sequence stage 3 | Build trajectory schema alongside canonical state; avoid later parallel telemetry system. |
| Adoption sequence stage 7 | Add finding lifecycle, migration cutover, artifact envelope templates. |
| Adoption sequence stage 11 | Add replay/resume, finding dedupe, deficit propagation, owner-role, artifact-handling, minimal-baseline evals. |

## Recommended implementation order

1. **Execute final book stages 1–2 unchanged.** Canon & convergence first.
2. **At stage 3, add N1 state/event envelope.** Reuse Arcane IDs, MACs, event continuity, receipts, & budget lineage.
3. **At stage 4, bind cancellation & checkpoints to intent epoch.** Prove stale resume denial.
4. **At stage 5, compile evidence lifecycle + external provider capability.** This absorbs N5 without separate control plane.
5. **At stages 7–8, add N2/N3/N4 schemas & handoffs.** Keep root doctrine compact.
6. **At stage 9, enforce owner leases, finding dedupe, deficit claim ceilings, retry constants, & trajectory continuity in Arcane.**
7. **At stage 11, ship evals before more features.**
8. **At stage 12, compare minimal ambient baseline vs governed route on real tasks.** Remove controls whose cost lacks demonstrated risk/outcome benefit.

## Required evals

| Eval | Expected result |
|---|---|
| Crash after each workflow phase | Resume from last verified checkpoint; no duplicate effect; exact event continuity. |
| Stop during wait, dispatch, tool batch, monitor, goal wakeup | Current intent epoch cancels continuation; later stale wakeup denied. |
| Same finding reworded or line-shifted | Existing finding updated; review round not reset. |
| Fix closes blocker & reveals unrelated nit | Blocker scoped recheck closes; nit deferred; no full review loop. |
| Optional acceptance item deferred | Delivery may complete with visible owned deficit when required items pass. |
| Required/safety item proposed as debt | Denied; terminal state remains blocked/candidate. |
| Downstream task inherits deficit | Claim level is mechanically capped; deficit remains visible. |
| Hard-cut migration leaves old import/config/route | Acceptance fails on absence check. |
| Bounded coexistence lacks expiry/owner/reconciliation | Architecture readiness fails. |
| Two integration owners or shared writers | Second lease denied before mutation. |
| First-fix owner differs from canonical owner | Local repair succeeds without rewriting long-term ownership. |
| Dashboard-only remote report | Cannot satisfy machine gate without trusted retrieval adapter. |
| Sensitive trace artifact | Retention/cleanup required; unsafe publication denied. |
| Retry with identical normalized fingerprint twice | `BUDGET_STOP`; no third identical attempt. |
| Schema error repair | Deterministic normalization attempted before full regeneration. |
| Minimal reversible task | Ambient baseline wins; no Sage/Oracle/trajectory ceremony beyond cheap host events. |
| High-risk irreversible task | Routed system supplies stronger acceptance, authority, & evidence closure than minimal baseline. |
| Catalog-only capability claim | Remains discovery lead until original source & implementation evidence are inspected. |

## Success metrics

Measure outcomes, not number of rules:

- acceptance success on exact requested surface;
- time to first complete representative slice;
- wall time & active time to verified delivery;
- architecture/review rounds per objective lineage;
- identical-fingerprint stop rate;
- resumed work duplicated effects: target zero;
- stale continuation after stop: target zero;
- duplicate findings reminted across reruns: target zero;
- required items silently converted to debt: target zero;
- hard-cut losing paths remaining: target zero;
- completion claims missing per-item proof: target zero;
- coordination/tool/token overhead vs minimal baseline;
- false-positive rate by finding family & reviewer;
- external evidence marked gateable but not machine retrievable: target zero;
- artifact retention violations: target zero.

## Final recommendation

**Keep current Legion authority architecture. Implement final book before broadening it.** Corpus validates book’s central design more than it challenges it.

Add N1–N5 as extensions to canonical state, review records, workload evidence, & ownership contracts. Improve checkpoints, assurance calibration, concurrency, & retry semantics. Reject imported practices that make review universal, iteration unbounded, budget exhaustion equivalent to approval, coordination failure safe by default, catalogs evidentiary, or agents inherently mandatory.

Result should be **less ceremony with stronger state**, not more skills: one frozen acceptance surface, one correlated trajectory, one owner per mutation domain, one identity per finding, explicit debt, bounded recovery, & proof from actual outcome.

## Snapshot index

| Repository | Commit | Evidence role |
|---|---:|---|
| addyosmani/agent-skills | `be42637` | implementation workflow |
| Agent-Field/agentfield | `a6dd3f3` | orchestration/observability design + code |
| Agent-Field/SWE-AF | `1ae2913` | multi-stage harness |
| anthropics/claude-code | `be90077` | official host/plugin examples |
| ArabelaTso/Coding-Skills-Collection | `e66a625` | catalog only |
| coderabbitai/skills | `aa49953` | review workflow |
| EricGrill/agents-skills-plugins | `43a037f` | catalog/fork collection |
| garrytan/gstack | `d078622` | workflow, persistence, evals |
| instructa/agent-skills | `dff3284` | ownership/migration skills |
| LambdaTest/agent-skills | `0491a3a` | remote testing workflows |
| mattpocock/skills | `84fdeff` | decision/spec/prototype workflows |
| NeoLabHQ/context-engineering-kit | `8539779` | context/judge/orchestration workflows |
| obra/superpowers | `b36e082` | development/review lifecycle |
| swe-agent/swe-agent | `3ea751c` | mature agent harness |
| SWE-agent/mini-swe-agent | `a83fcae` | minimal harness baseline |
| testdino-hq/playwright-skill | `d3be9ca` | browser evidence workflow |
| trailofbits/skills | `304c81a` | security verification |
| VoltAgent/awesome-agent-skills | `bb272b6` | catalog only |
