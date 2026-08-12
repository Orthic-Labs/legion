# The Legion Architecture Book
## Evidence-driven architecture, bounded convergence, and governed commitment — final synthesis

**Status:** canonical Legion improvement set (final shape)
**Date:** 12 August 2026
**Supersedes:** the *Legion Final Improvement Book* and the *Legion Sage Architecture Doctrine* as separate recommendations; absorbs `docs/research/2026-08-12-convergence-doctrine-gap-analysis.md` (CV-1…CV-12) as its convergence layer.
**Source inputs:**

1. current Legion doctrine and authority model (`doctrine/*.md`, `doctrine/bundles/*.md`);
2. the Convergence Doctrine gap analysis and its CV-1…CV-12 rules, including the Adapt Insights incident evidence (17 failure cards; seven-revision contract churn; pre-seal vs post-seal loop distinction);
3. the Legion Sage Architecture Doctrine (the architecture reasoning manual);
4. the Legion Final Improvement Book (the architecture operating system);
5. the Canonical Evidence-Driven Software Architecture Framework and its standards/research corpus.

**Synthesis rule.** The Final Improvement Book is the **chassis** — its authority model, evidence provenance, persistent state, machine enforcement, lifecycle governance, and deployment plan stand. The Sage Architecture Doctrine's **reasoning mechanisms** are re-absorbed into that chassis wherever the chassis had dropped or demoted them. The seven direct conflicts between the two books are resolved as recorded in Part 0. Nothing in either source is weakened by the merge; where they disagreed, the resolution below is normative.

---

# Part 0 — Synthesis record

## 0.1 The seven direct conflicts, resolved

| # | Conflict | Resolution |
|---|---|---|
| 1 | Objective routing: Sage book had `SUFFICIENT / OPTIMIZE / BEST_SHAPE`; Final Book collapsed objective into depth/rigor | **Router is three-dimensional: `OBJECTIVE × DEPTH × RIGOR`.** `OPTIMIZE` returns as a first-class mode (Part IV). |
| 2 | Depth vocabulary: `A0/A1/A2` vs `D0/D1/D2` | **`D0 / D1 / D2`**, with D2 named **FULL / EXPEDITIONARY** — the name preserves the "you are leaving settled territory" signal. |
| 3 | Evidence grades: `E4→E0` vs `A→E` | **One strength scale, `A→E`**, with formal proof and directly applicable authoritative constraint given an explicit place in grade A (Part VI §17, Layer 4). Provenance **type** and evidence **strength** are separate fields — that separation is the real innovation and it is kept. |
| 4 | ADR status: `implemented` vs `frozen` | **Orthogonal fields.** `decision_status: proposed \| accepted \| frozen \| superseded \| deprecated` and `realization_status: not_started \| implementing \| implemented \| diverged`. Finality and realization are different facts about a decision; neither is deleted (Part XIII §47). |
| 5 | Invalidation: cause enums vs scope classes | **Both fields, always.** `invalidation_cause` answers *why did this reopen*; `invalidation_scope` answers *how much reopens* (G-A9). |
| 6 | Open questions: `blocking/deferred/reserved` vs six dispositions | **The six dispositions win** (`MUST_DECIDE_NOW / ASSUMPTION_TO_TEST / DEFER_TO_LATER_SLICE / ACCEPTED_RISK / OUT_OF_SCOPE / EXTERNAL_BLOCKER`). They subsume the older taxonomy and add authority to it (Part VII). |
| 7 | Fingerprinting: one reasoning fingerprint vs split fingerprints | **Split fingerprints win**: `decision_fingerprint`, `evidence_fingerprint`, `last_reviewed_packet_fingerprint`. The single reasoning fingerprint is retired (Part IX). |

## 0.2 Mechanisms restored from the Sage Architecture Doctrine

These had been dropped or demoted in the Final Book and are re-absorbed as normative:

| Restored mechanism | Where it now lives |
|---|---|
| `SUFFICIENT / OPTIMIZE / BEST_SHAPE` objective axis | Part IV; canonical state `task.objective` |
| Mandatory **failure story** for every viable candidate | G-A16; Evaluate Layer 2; candidate card template |
| Explicit **dominance / Pareto elimination** before weighted scoring | G-A17; Evaluate Layer 5 |
| Weighted analysis sequenced *after* dominance, with mandatory sensitivity where weights matter | Evaluate Layer 6 |
| Canonical **minimum-sufficient selection algorithm** as one compact rule | G-A18; MINIMIZE phase |
| **Mechanism YAGNI ladder** and the avoid-new-boundary rule | MINIMIZE phase (§18); `reviews/simplicity-yagni.md` module |
| **Distribution Tax review** trigger | MINIMIZE phase (§18); mandatory whenever a candidate adds a process/machine/service/region/broker/distributed-state boundary |
| **Build/buy/reuse six-step hierarchy** | Candidates phase (§16), as the canonical generation ordering |
| Modular-monolith rule (never *start* from monolith-vs-microservices) | Candidates phase (§16) |
| Architectural **complexity count** lens | MINIMIZE phase (§18); `lenses/architecture/catalogue.md` |
| **Technology-selection taxonomy** (`MANDATED / STRATEGIC / REVERSIBLE / COMMODITY / EXPERIMENTAL`) | Conditional module `doctrine/architecture/methods/technology-selection.md` (Part X/XI) |
| Full **21-lens catalogue** | `lenses/architecture/catalogue.md` — preserved as an omission scan under progressive disclosure, never a mandatory deep-analysis checklist |
| Foundational principles (modularity/information hiding, end-to-end argument, CAP and consistency trade-offs) | `references/architecture/canonical-bibliography.md` — kept adjacent to the method, not deleted with the research detail |
| Candidate-quality half of the readiness predicate (ASR satisfaction, non-domination, simplicity gate, revisit triggers) | Merged readiness predicate (Part VII §22) |

## 0.3 What the chassis contributed (kept without change in substance)

Depth × rigor separation; the ten-condition significance test (G-A1); evidence provenance typing (G-A4); the five-class authority model and `ACCEPTED_RISK` requiring a named accepting authority (G-A14); the canonical persisted `architecture_state` and resume semantics (Part V); the five terminal states (Part VII); tightened budget-exhaustion behavior for irreversible work; typed review findings with severity-gated reopening (G-A13); the one-challenge-per-packet-version Covenant rule; Arcane's hard guards (Part IX); lifecycle governance including ownership, migration, exit, expiry, supersession (G-A15); progressive disclosure and one-canonical-owner-per-concept (Part X); the repository structure (Part XI); metrics (Part XV); and the nine-stage adoption sequence (Part XVI).

## 0.4 Constants alignment (from the Adapt Insights reconciliation)

Doctrine and runtime must tell one story about numbers:

```text
PRE-SEAL (design loop — binds at dispatch, not at seal)
  D1 revision budget:            ≤ 1
  D2 revision budget:            ≤ 2
  absolute revision ceiling:     3 — the third revision forces a terminal
                                 routing choice (decide-with-debt | spike |
                                 escalate); it never buys a fourth pass.

POST-SEAL (contract lineage — already enforced mechanically)
  sealed contract versions:      2   (maxContractVersions)
  identical-attempt stop:        aligned to doctrine's "same fingerprint
                                 twice → stop"; runtime constant updated to
                                 match doctrine, not the reverse.
```

The pre-seal counter starts when Legion routes an Architect engagement — this closes the admission gap in which ambient sessions, uncontracted dispatched work, and legacy bindings escaped all governance. Until the runtime can observe pre-seal revisions, Legion enforces the ceiling lead-side (the CV-11 tripwire, now G-A7's final paragraph).

---

# Part I — The two problems and the layered answer

Legion had two distinct failures, in different layers:

> **A commitment and termination problem** — architecture cycled for hours, revision after revision, because nothing counted revisions, corrections invalidated from the root, maximizing mandates set uncheckable bars, and every escalation path led into more design.

> **An architecture substance problem** — Sage lacked a rigorous, architecture-specific foundation for what deserves architectural treatment, what evidence suffices, how options are compared, and what an architecture package must contain.

The layers of the answer:

```text
EVIDENCE-DRIVEN ARCHITECTURE FRAMEWORK
What sound architecture reasoning contains.

CONVERGENCE & COMMITMENT DOCTRINE
When that reasoning is sufficient, when it must stop,
and what may reopen it.

ARCANE / HARNESS CONTROLS
How those limits are enforced mechanically.
```

The governing sentence:

> **Architecture is complete when the next safe, reversible, verifiable increment can be executed without inventing material product or engineering semantics. It is not complete only when every conceivable architectural question has been answered.**

And the mandatory anti-recreation principles — the comprehensive framework must never rebuild the loop it was built to end:

- the full lens catalogue is an **omission scan**, not a requirement to deeply analyze every lens;
- the phases are a **state model**, not a waterfall that must always produce every artifact;
- gates are **acceptance conditions**, not invitations to launch another review agent;
- iteration is legal only after a material delta;
- evidence gathering stops when more information is unlikely to change candidate ranking or risk treatment;
- the package stops when consequential decisions are made or consciously deferred and the rest is reversible or implementation-level;
- all specialist modules are progressively loaded;
- the method never self-authorizes product scope, thresholds, objectives, or residual-risk acceptance.

---

# Part II — The six-layer target architecture

**Layer 1 — Legion constitutional doctrine.** Current user intent; routing; authority separation; scope posture; evidence-before-claim; Progress Invariant; Decision Finality; bounded deliberation; local invalidation; delivery-state reporting. Compact, always loaded.

**Layer 2 — Sage architecture router.** Whether the issue is architectural; objective, depth, and rigor; current architecture state; next workflow phase; which modules and lenses are material; when to freeze. Never contains the full canon inline.

**Layer 3 — EDAF workflow modules.** Framing, context, drivers, modeling, risk, candidates, evaluation, minimization, description, assurance, governance. Loaded only when the state requires them.

**Layer 4 — Specialist lenses.** Security, privacy, safety, reliability, performance, data, AI, accessibility, economics, legal, and the rest of the 21-lens catalogue. All return inputs in one canonical form:

```text
concerns → scenarios / constraints → mechanisms / tactics
→ evidence → residual risks → required decisions
```

They never create parallel architectures or competing sources of truth.

**Layer 5 — Alchemist and Oracle.** Alchemist executes the frozen semantic contract. Oracle independently evaluates the resulting actual state. Architecture-decision assurance and implemented-state assurance stay distinct.

**Layer 6 — Arcane.** Pass budgets, state transitions, fingerprints, immutable review packets, invalidation boundaries, stale-evidence invalidation, effect permissions, receipts, no false clean. A prose instruction to stop is insufficient if the harness keeps dispatching reviews.

---

# Part III — Canonical global doctrine

## G-A1 — Architecture Significance

A choice belongs to architecture only when it is consequential. Treat a decision as architecturally significant when one or more apply:

1. it materially affects a prioritized quality scenario or mission/business outcome;
2. it establishes or changes a durable responsibility boundary;
3. it establishes or changes a source-of-truth or data-authority boundary;
4. it changes a trust, security, privacy, safety, or risk boundary;
5. it changes a failure, recovery, consistency, deployment, or geographic boundary;
6. it creates or changes a public, cross-team, partner, or long-lived contract;
7. it affects many components, teams, or lifecycle stages;
8. it is costly, risky, coordination-heavy, or slow to reverse;
9. it assigns durable ownership, decision rights, or governance policy;
10. getting it wrong could threaten mission success, legal compliance, safety, security, continuity, data integrity, or major economics.

If none applies, the issue is detailed design or implementation and must not bloat Sage's architecture record. The test is **consequence**, not category.

## G-A2 — Proportional Rigor

Use enough architecture rigor to manage consequence, uncertainty, irreversibility, and coordination cost — no more and no less.

Rigor must not scale with document prestige, model enthusiasm, the number of available agents, remaining context, or a generic desire to be comprehensive. It must scale with mission and business consequence; safety and security exposure; privacy, regulatory, and contractual consequence; data irreversibility; public-contract lifespan; blast radius; migration difficulty; expected lifespan; decision-changing uncertainty; cost and time to reverse; and the number of independent owners.

## G-A3 — Minimum Sufficient Decision

Resolve only engineering decisions required for the next safe, reversible, verifiable increment. Do not solve future decisions merely because they are visible.

**Decision YAGNI ladder:**

```text
0. Is this decision required for the requested outcome?
   NO → do not decide it.
1. Is it required before the next safe, testable increment?
   NO → defer it.
2. Does accepted architecture already provide an adequate answer?
   YES → inherit it. Do not redesign.
3. Can the requirement fit inside an existing boundary or interface?
   YES → use it.
4. Can uncertainty be resolved more cheaply by a probe, model, test,
   benchmark, or tracer slice?
   YES → perform the bounded evidence task.
5. Is a new architectural decision unavoidable?
   YES → Sage decides the narrowest necessary question.
6. Does the decision require new architecture complexity?
   Only then run the minimum-sufficient-architecture test (G-A18).
```

## G-A4 — Evidence and Provenance

Every material architecture claim carries a visible **provenance type**:

```text
REQUIREMENT | CONSTRAINT | MEASURED_FACT | DOCUMENTED_FACT |
EXPERT_JUDGMENT | ESTIMATE | ASSUMPTION | HYPOTHESIS |
PREFERENCE | UNKNOWN | RECOMMENDATION
```

and, where it grounds a comparison or gate, an evidence **strength grade** (the single A→E scale, §17 Layer 4). An unlabelled architecture score is not evidence.

The agent may recommend. It may not silently invent a target, promote a preference into a constraint, redefine the mission, waive a mandatory criterion, accept residual risk, or claim proof from persuasive prose. Evidence must match the boundary and adverse condition of the claim.

## G-A5 — Scenarios Before Quality Labels

"Fast," "secure," "scalable," "maintainable," "available," and "flexible" are concern labels, not requirements. A material quality requirement identifies: business goal / stakeholder, source, stimulus, environment, artifact, response, response measure, priority, evidence, failure-or-degradation policy.

Numerical targets must come from an authorized source, measured fact, contractual obligation, or explicitly labelled assumption. **Sage must not fabricate them.**

## G-A6 — Progress Invariant

A reasoning, review, diagnosis, planning, or execution cycle may repeat only if at least one material input changed: evidence, requirements, constraints, repository/runtime state, implementation state, method or strategy, or an authoritative decision. Rephrasing, reconsidering, re-ranking, or re-reviewing the same evidence does not count.

Every architecture pass must do at least one of: retire a blocking question; reduce a named load-bearing risk; select among previously live candidates; produce empirical evidence; narrow the execution boundary; convert uncertainty into a typed test; respond to a genuine changed requirement or constraint. A pass that does none of these may not cause another architecture pass.

## G-A7 — Bounded Deliberation

Default flow:

```text
one design → one challenge → at most one revision → freeze
```

Budgets scale with depth (Part IV §7): D1 ≤ 1 revision; D2 ≤ 2 revisions. Across any engagement the **absolute ceiling is three revisions**: the third revision does not buy a fourth — it forces exactly one of:

```text
DECIDE_WITH_DEBT   commit the best-evidenced candidate; log residual
                   concerns as owned debt with triggers
SPIKE              stop comparing on paper; run the riskiest-assumption
                   evidence task (G-A12)
ESCALATE           surface the tie or blocker to the deciding authority
                   with the live candidate set and what would separate them
```

"One more revision will converge" is a red flag, not a reason. If the budget feels insufficient, **decompose the decision — never lift the cap.**

Additional architecture work beyond budget requires one of:

```text
NEW_EVIDENCE | CHANGED_REQUIREMENT | CHANGED_CONSTRAINT |
FAILED_FALSIFICATION | LOAD_BEARING_REVIEW_FINDING | USER_REOPEN
```

The agent may not grant itself more budget because another option may exist, a cleaner abstraction is imaginable, the ceiling could improve, context remains, or another generic review might find something.

**The lead watches the clock.** Legion interrupts any Architect engagement that crosses its third revision, oscillates between the same alternatives, or exceeds its declared budget, and routes it through the three-way choice above. The counter binds at **dispatch**, not at contract seal.

## G-A8 — Decision Finality

Once accepted, a decision's `decision_status` becomes `FROZEN`. It remains frozen until material invalidation evidence disproves a premise, changes a governing requirement/constraint, demonstrates failure to preserve an invariant, reveals a serious safety/security/correctness issue, or the user reopens it.

Insufficient to reopen: a reviewer prefers another pattern; a plausible alternative exists; a famous system does it differently; a theoretically better ceiling is discovered; stylistic reconsideration; speculative future needs; reinterpretation without contradictory evidence.

Before freeze the question is *"Why is this route justified?"* After freeze it is *"What new material evidence proves this decision must reopen?"* Rejected alternatives are recorded with **durable** reasons — a reason tied to a temporary circumstance is a revisit trigger, not a rejection.

## G-A9 — Invalidation Is Cause Plus Scope

Every invalidation records **two fields**:

```text
invalidation_cause — why did this reopen?
  PREMISE_FALSE | REQUIREMENT_CHANGE | CONSTRAINT_CHANGE |
  FAILED_FALSIFICATION | SECURITY_SAFETY_FAILURE |
  EXTERNAL_SEMANTIC_CHANGE | INVARIANT_UNSATISFIABLE | USER_REOPEN

invalidation_scope — how much reopens?
  PATCH   local correction; architecture and plan remain frozen
  PLAN    task sequencing or decomposition changes; decisions remain frozen
  DESIGN  a load-bearing invariant, boundary, interface, ownership rule,
          or acceptance semantic changed; reopen affected decisions only
  ROOT    the requested problem, fundamental target, or governing
          constraints changed; full route selection may reopen
```

Invalidate the smallest dependent decision/work cone. `ROOT` requires naming the root-invalidating evidence. A correction invalidates only artifacts downstream of the corrected decision — never the engagement from the root.

## G-A10 — Hard Gates Before Preference Scores

A candidate that fails a genuine mandatory criterion cannot be rescued by an attractive weighted average. Mandatory gates may include: legal/contractual compliance; safety constraints; data residency; minimum security properties; transactional or domain invariants; required interoperability; hard recovery obligations; mandatory deployment constraints; maximum budget or decision deadline; prohibited external-control dependency.

Only candidates that pass mandatory gates enter comparison — and only non-dominated candidates (G-A17) enter *weighted* comparison.

## G-A11 — HOLD SCOPE and Informational Ceilings

Agents may reduce scope autonomously. They may not expand product scope merely to improve architectural elegance. Scope expansion requires one of: necessity for an accepted acceptance criterion; necessity to preserve a declared invariant; necessity to remedy a demonstrated correctness/security/safety/data-integrity problem; explicit approval by the user or relevant authority.

The architectural ceiling is **informational** unless the engagement's objective is `BEST_SHAPE` or the ceiling reveals a present mandatory failure. For ordinary work, ceiling analysis cannot create blockers, expand scope, reopen frozen decisions without material contradiction, or spawn implementation tasks. Record the ceiling with an observable evolution trigger.

## G-A12 — Execution as Evidence

When the remaining uncertainty is empirical, stop debating and compile a bounded evidence task: repository inspection, models, representative benchmarks, focused prototypes, spikes, tracer slices, simulations, runtime probes, authoritative records, targeted specialist review.

A valid spike answers one named question; has bounded scope; produces inspectable evidence; declares whether it is disposable or promotable; avoids production polish; returns results to the canonical architecture state.

When two options survive to a second revision without separating, the next act is a spike on the riskiest discriminating assumption — not a third comparison on paper.

## G-A13 — Review Is Consumptive

A review consumes its gate: `find → classify → fix or disposition → continue`. A fix does not automatically authorize another full review. Repeat only checks whose evidence-bearing input materially changed.

Findings carry two independent dimensions:

```text
kind:      CONFIRMED_APPROACH | SENSITIVITY_POINT | TRADE_OFF_POINT |
           RISK | NON_RISK | EVIDENCE_GAP | ASSUMPTION |
           CONSTRAINT_CONFLICT | DEBT | EXCEPTION

severity:  BLOCKER | REQUIRED_THIS_SLICE | FOLLOW_UP | ADVISORY | NIT
```

Only `BLOCKER` and `REQUIRED_THIS_SLICE` may reopen the current packet. A blocker must identify the violated requirement/gate/invariant/authority rule, supporting evidence, affected decision IDs, the minimum correction, and invalidation cause + scope. **Preference without demonstrated failure is not a blocker.**

A revision round re-reviews only the prior round's blocking findings — each verdicted ADDRESSED or NOT ADDRESSED — plus any breakage the fixes introduced. New observations join the debt ledger; they never extend the loop. The same law binds a re-convened Covenant.

## G-A14 — Authority Is Never Inferred

Five authority classes stay distinct:

| Authority | Proper holder | Agent role |
|---|---|---|
| Mission/value | sponsor, product/business authority | clarify and preserve provenance |
| Requirement/policy | accountable stakeholders and specialists | translate into scenarios; never invent approval |
| Technical recommendation | Sage / accountable architect | generate, compare, recommend |
| Evidence | measurement, model, experiment, audit, authoritative source | gather and report without fabrication |
| Risk acceptance | named human or institutional role | receive residual risk; the agent cannot self-approve |

"Option A is technically preferable" may never silently become "the business accepts this data-loss risk." `ACCEPTED_RISK` is valid only when an authorized accepting authority is identified.

## G-A15 — Architecture Is Lifecycle-Governed

Architecture is not permanently approved. Every consequential decision records context and scope; drivers and constraints; alternatives; decision and rationale; evidence and confidence; consequences and trade-offs; residual risks and accepting authority; reversibility and exit; migration/coexistence; ceiling; expiry and review triggers; ownership; supersession lineage.

Trigger-based governance is not open-ended reconsideration. A trigger must be observable and tied to a premise or threshold.

## G-A16 — Every Viable Candidate Carries a Failure Story *(restored)*

Before selection, every candidate that survives the mandatory gates must have an explicit **failure story**: what breaks first under load, fault, attack, or growth; how the failure presents; what contains it; what recovery costs. A candidate whose failure story cannot be told is not understood well enough to select — and not well enough to reject, either.

The failure story is a named section of the candidate card, graded like any other evidence. At `STANDARD` rigor and above, a selected candidate without one fails the freeze gate.

## G-A17 — Dominance Before Weights *(restored)*

After hard gates and scenario analysis, and before any weighted comparison, run explicit **dominance elimination**: a candidate that is equal-or-worse on every driving criterion and strictly worse on at least one is **dominated and must be discarded** (or recorded in `PARETO_SET_PENDING_EVIDENCE` when the ordering is genuinely evidence-starved).

Weighted scoring is legal only over the non-dominated set, and sensitivity analysis is mandatory wherever weights could change the winner. A weighted average over a set containing dominated candidates is arithmetic theater.

## G-A18 — The Minimum-Sufficient Selection Algorithm *(restored)*

Selection is one compact canonical sequence, in order:

```text
1. FEASIBILITY      eliminate candidates failing hard gates (G-A10)
2. THRESHOLDS       eliminate candidates failing prioritized ASR /
                    quality-scenario thresholds
3. EVIDENCE         gather only evidence that discriminates between the
                    survivors (value-of-information rule, §15)
4. DOMINANCE        eliminate dominated candidates (G-A17)
5. TRADE-OFFS       weighted comparison + sensitivity over the
                    non-dominated set
6. SELECT           the least lifecycle-complex candidate that is
                    sufficient — not the most impressive one that is
                    affordable
```

"Lowest justified lifecycle complexity that satisfies the prioritized thresholds" is the tie-breaker at every step. Satisficing is the default bar: acceptance-criteria-met is done; polish beyond criteria is optional recorded debt. "Best," "optimal," and "best-in-class" are special claims requiring the `BEST_SHAPE` objective — never a self-assigned bar.

---

# Part IV — Routing: `OBJECTIVE × DEPTH × RIGOR`

## 5. Three axes, not two

The router classifies every architecture engagement on three independent axes. Collapsing any pair recreates a known failure: collapsing objective into depth made "improve startup time" route like a full redesign; collapsing rigor into depth let broad-but-safe studies be treated as safety-critical and narrow-but-irreversible decisions get a light process.

### Objective — *what kind of answer is wanted*

```text
SUFFICIENT   (default)
Meet the stated acceptance criteria with the least justified complexity.
No external solution-space search by default. Ceiling is informational.

OPTIMIZE
Improve a NAMED quality axis of the existing architecture (startup time,
cost, p99 latency, operability…) without redesigning around it. Search is
scoped to mechanisms on that axis. The named axis is the whole mandate;
everything else inherits.

BEST_SHAPE
Explicitly requested best-possible architecture. Authorizes broad external
solution-space search and competitor/prior-art absorption. Still bounded:
budgets, dominance, and the third-revision ceiling all apply.
```

The objective is **assigned by the user or by Legion from user intent — never self-upgraded by Sage.** Discovering an interesting ceiling mid-engagement does not convert `SUFFICIENT` into `BEST_SHAPE`; it produces an informational ceiling note with a trigger (G-A11).

### Depth — *how much of the workflow is needed*

```text
D0 — AMBIENT
No consequential undecided architecture question. Inherit and execute.

D1 — BOUNDED
One or a few contained architecture decisions.

D2 — FULL / EXPEDITIONARY
System-level, cross-boundary, migration, platform, broad review, or
best-shape work. The name is a warning: you are leaving settled
territory, and the ceremony that follows must be earned.
```

### Rigor — *how strong evidence, review, and authority requirements are*

```text
LITE      low consequence, reversible, few stakeholders, bounded uncertainty
STANDARD  material production decision, multiple concerns or owners,
          meaningful lock-in or lifecycle effects
CRITICAL  safety, severe security/privacy exposure, regulated or
          irreversible data, mission-critical availability, hard real-time,
          destructive migration, or similarly high-consequence commitment
```

### Interaction rules

- **Objective** governs *search breadth* (and whether the ceiling is in scope).
- **Depth** governs *workflow breadth* (which phases and modules load).
- **Rigor** governs *evidence strength, review depth, and authority obligations*.
- Reversibility is an effort **governor**, not just a report field: a two-way-door decision at D1/LITE gets a one-pass decision with no decision matrix, no external search, no route ceremony. A one-way door gets the full route for its depth — and the revision ceiling still applies.

## 6. Classification examples

| Work | Objective | Depth | Rigor |
|---|---|---|---|
| Rename a private helper | SUFFICIENT | D0 | Lite |
| Add a local module behind an existing interface | SUFFICIENT | D0/D1 | Lite |
| Choose error semantics for one new public endpoint | SUFFICIENT | D1 | Standard |
| "Cut cold-start time in half" | OPTIMIZE | D1 | Standard |
| Change authorization ownership in one service | SUFFICIENT | D1 | Critical |
| Compare modular monolith vs services for a product | SUFFICIENT | D2 | Standard |
| Design a destructive regulated-data migration | SUFFICIENT | D2 | Critical |
| Explicit "best possible architecture" research | BEST_SHAPE | D2 | Standard/Critical by consequence |

## 7. Default budgets

```text
D0                     candidates 0 · Sage passes 0 · review 0

D1 + LITE              generation 1 · candidates 2 when a real choice
                       exists · challenge inline, consumptive ·
                       revision ≤ 1 · external review none by default

D1 + STANDARD          generation 1 · candidates ≤ 3 ·
                       independent challenge ≤ 1 when material ·
                       revision ≤ 1

D2 + STANDARD          generation 1 · candidates ≤ 3 coherent concepts ·
                       independent challenge ≤ 1 · revision ≤ 2 ·
                       Covenant ≤ 1 when explicitly requested or
                       policy-triggered

any depth + CRITICAL   independent specialist evaluation where material ·
                       formal/quantitative analysis where appropriate ·
                       risk-acceptance authority required ·
                       change control required ·
                       explicit revision budget — never infinite review

OPTIMIZE modifier      external search scoped to the named axis:
                       top-2 mechanism classes, 2 approaches each,
                       timeboxed; beyond that, defer with a named gate

BEST_SHAPE modifier    broad external search authorized; same revision
                       budgets; the ceiling becomes in-scope deliverable
```

One candidate should normally be status quo, reuse, or the simpler path. If a Critical budget expires without enough evidence for an irreversible decision, terminate honestly as `NEEDS_SPIKE`, `BLOCKED_EXTERNAL`, or `BUDGET_STOP`. **Do not manufacture approval.**

---

# Part V — Canonical Sage state

## 8. One state object, not disconnected prompts

```yaml
architecture_state:
  schema_version: architecture-state.v2

  task:
    type: reconstruct | design | select | review | evolve | retire
    objective: sufficient | optimize | best_shape
    optimize_axis:            # required when objective == optimize
    depth: D0 | D1 | D2
    rigor: lite | standard | critical
    phase: tailor | frame | context | drivers | model | risk | candidates |
           evaluate | minimize | describe | assure | govern | frozen

  mandate:
    decision_question:
    system_of_interest:
    scope_in: []
    scope_out: []
    non_goals: []
    time_horizon:
    decision_deadline:
    decision_authority:
    risk_authorities: []
    rationale_for_objective_depth_rigor:

  intent:
    outcomes: []
    success_signals: []
    unacceptable_losses: []

  context:
    stakeholders: []
    concerns: []
    external_dependencies: []
    hard_constraints: []
    business_constraints: []
    existing_system_constraints: []
    organizational_constraints: []
    preferences: []

  architecture:
    requirements: []
    invariants: []
    quality_scenarios: []
    responsibilities: []
    data_authorities: []
    contracts: []
    trust_boundaries: []
    failure_boundaries: []
    deployment_boundaries: []
    ownership_boundaries: []
    likely_changes: []

  uncertainty:
    blocking: []               # MUST_DECIDE_NOW
    assumptions_to_test: []
    deferred: []
    accepted_risks: []
    out_of_scope: []
    external_blockers: []

  decision:
    candidates: []             # each carries a failure_story
    mandatory_gates: []
    dominance_record:          # eliminated candidates + dominating criteria
    evaluation: []
    selected_candidate:
    decision_ids: []
    frozen_decision_ids: []
    residual_risks: []
    review_triggers: []
    debt_ledger: []            # advisory findings + deferred polish

  evidence:
    items: []                  # provenance type + strength grade each
    gaps: []
    hypotheses: []
    confidence_summary:

  description:
    viewpoints: []
    views: []
    cross_view_conflicts: []

  convergence:
    architecture_pass_count: 0
    pass_budget:
    revision_ceiling: 3
    decision_fingerprint:
    evidence_fingerprint:
    last_reviewed_packet_fingerprint:
    unchanged_review_count: 0
    reopen_reason:
    invalidation_cause:
    invalidation_scope:
    invalidated_decision_ids: []
    progress_delta:
    terminal_state:
```

Every workflow module reads and updates this state. A command or skill invocation **resumes from state** rather than restarting from generic architecture discovery.

---

# Part VI — The bounded evidence-driven workflow

## 9. The integrated process

```text
0.  TAILOR      objective × consequence × irreversibility × uncertainty
                × coordination → depth + rigor + budget
1.  FRAME       mission → outcome → scope → non-goals → horizon → authority
2.  CONTEXT     stakeholders → concerns → ecosystem → constraints → assumptions
3.  DRIVERS     capabilities + invariants + measurable scenarios + priorities
4.  MODEL       responsibilities + data authority + contracts + likely change
5.  RISK        faults + threats + hazards + uncertainty + irreversibility
6.  CANDIDATES  status quo/defer + simpler path + materially different concepts
7.  EVALUATE    hard gates → scenarios → failure stories → evidence →
                economics → dominance → sensitivity
8.  MINIMIZE    mechanism YAGNI → distribution tax → complexity count →
                minimum-sufficient selection
9.  DESCRIBE    decisions + tactics + concern-driven views + consistency
10. ASSURE      evidence gaps + risks + conditions + residual-risk authority
11. GOVERN      freeze + ADRs + ownership + triggers + debt + migration
                + retirement
```

This is not a waterfall. Backward movement must identify the material delta, the smallest affected phase, the invalidated decision IDs (with cause + scope), and why candidate ranking or risk disposition changed. "More detail is possible" is not a backward-edge trigger.

## 10. Phase 0 — TAILOR

Determine: the decision being made; who can make it; who can accept residual risk; **objective** (from user intent — never self-assigned upward); depth; rigor; pass budget; required specialists; intended outputs; horizon and review date.

**Gate 0.** Do not begin deep architecture until the decision, authority, objective, and proportional evidence obligation are known.
**Convergence guard.** Tailoring gets one pass unless user intent, consequence, or constraints change.

## 11. Phase 1 — FRAME

Required questions: What outcome must improve? What observable result defines success? What loss is unacceptable? What decision must be made now? What can remain undecided? What is in and out of scope? What is the lifespan and growth horizon? What is the cost of doing nothing? Is the actual choice build, buy, reuse, repair, retire, migrate, split, consolidate, or defer?

**Gate 1.** The decision question is explicit; success and failure are observable; scope and non-goals are recorded; the horizon is known; authority is named.
**Convergence guard.** A product/policy ambiguity without an authority owner becomes `EXTERNAL_BLOCKER`; Sage must not repeatedly invent alternative interpretations.

## 12. Phase 2 — CONTEXT

Map only material stakeholder classes (users and affected non-users; product owners; operators and responders; support; security/privacy/safety/legal/compliance/audit; data owners and subjects; engineering and integration owners; finance/procurement/vendors; migration and future maintainers).

Separate: `FACT | HARD_EXTERNAL_CONSTRAINT | BUSINESS_CONSTRAINT | EXISTING_SYSTEM_CONSTRAINT | ORGANIZATIONAL_CONSTRAINT | PREFERENCE | ASSUMPTION | UNKNOWN`.

**Gate 2.** Major stakeholders, external dependencies, mandatory constraints, assumptions, and decision rights are visible. Unknowns may remain when recorded and unable to change the immediate candidate ranking or safety boundary.

## 13. Phase 3 — DRIVERS

Identify the small set of requirements that shape architecture: forces system-wide structure or policy; affects multiple qualities; high value or high failure consequence; technically difficult or uncertain; affects many components or teams; creates an external contract; requires a specialized tactic; expensive to change later.

Use the full lens catalogue **as an omission scan**, then prioritize. Do not give every lens equal weight.

Quality scenario schema: `id, business_goal, stakeholder, quality_lens, priority, architectural_difficulty, source, stimulus, environment, artifact, expected_response, response_measure, failure_or_degradation_policy, evidence_required, current_evidence, confidence, owner, related_constraints, related_invariants, related_decisions`.

**Gate 3.** No style or stack selection until critical functions and invariants are understood; hard constraints are separated from preferences; top quality concerns have measurable scenarios or explicit unresolved authority; priorities are visible; material conflicts have owners.

## 14. Phase 4 — MODEL

Architecture begins with consequential responsibilities and information authority, not technology boxes. Model capabilities; policies; actors and authority; critical workflows; lifecycle states; invariants; business events; terminology boundaries; authoritative information owner/source; update authority; retention, deletion, residency, sensitivity, consistency, freshness, recovery, lineage; likely high-impact change axes; semantic/data/runtime/deployment/failure/trust/organizational/vendor dependencies.

Duplicate ownership is an architectural smell. Every replica needs explicit authority, purpose, synchronization rule, staleness tolerance, and repair/failure behavior.

**Gate 4.** Responsibilities, invariants, information authority, major dependencies, ownership, and likely change can be explained **without using a preferred technology as the explanation**.

## 15. Phase 5 — RISK

Distinguish uncertainty kinds:

```text
EPISTEMIC       reducible by learning, measurement, model, prototype, expertise
ALEATORY        inherent variation in demand, failures, behavior, environment
REQUIREMENT     the desired outcome or threshold is unresolved
MODEL           the analytical model may not represent reality
ORGANIZATIONAL  ownership, skill, funding, or operating model may change
```

Rate irreversibility across technical state, data, contracts, organization, vendors/commercial terms, time to reverse, and reversal blast radius.

**Value-of-information rule.** Gather more evidence when the uncertainty could credibly change candidate ranking; the decision is expensive or dangerous to reverse; the cost of learning is lower than expected decision loss; a focused experiment can retire a major risk. **Stop investigating when additional information is unlikely to change the decision or risk treatment.**

Architecture hypothesis form: *We believe [claim] under [context and demand range] will satisfy [scenario/constraint] because [mechanism and evidence]. Confidence: [level]. Invalidated when: [observable condition]. Validation: [method]. Owner and review date: [role/date].*

**Gate 5.** Unknowns are allowed. Invisible unknowns are not.

## 16. Phase 6 — CANDIDATES

**The build/buy/reuse hierarchy is the canonical generation order** *(restored)*:

```text
1. do nothing or defer
2. retire or remove the need
3. reuse existing capability
4. repair or simplify current architecture
5. buy or adopt managed capability
6. build the simplest coherent architecture
7. introduce targeted separation
8. adopt greater distribution or specialization
   — only when scenarios justify it
```

Never *start* by selecting monolith vs microservices *(restored)*: the candidate set always includes a modular-monolith or simplest-coherent option as a serious baseline, and greater distribution must be pulled in by scenarios, never pushed in by fashion.

A candidate is not a product name. A coherent candidate includes responsibility boundaries; information ownership; interaction model; runtime/deployment topology; trust and failure boundaries; quality tactics; operating model; team ownership; migration/coexistence; major technology constraints; risks and evidence — **and its failure story (G-A16)**.

**Proportionality.** D1 Lite: two candidates only when a real choice exists. D1/D2 Standard: up to three coherent candidates. Critical: enough to establish that mandatory constraints and major risk alternatives were fairly tested, within the explicit budget. Do not compare fifteen technologies before defining required capabilities, invariants, ownership, consistency, failure, and exit.

**Gate 6.** Candidates must differ in consequential architecture decisions, not cosmetic vendor substitutions.

## 17. Phase 7 — EVALUATE

Seven layers, **in order**:

### Layer 1 — Mandatory gates (G-A10)
Eliminate or explicitly renegotiate any option failing a true mandatory criterion.

### Layer 2 — Scenario-based analysis + failure stories (G-A16)
For each high-priority scenario: `stimulus → entry boundary → responsibility path → state/data changes → dependencies and failure behavior → response → response measure`. Record mechanisms/tactics, sensitivity points, trade-off points, evidence, confidence, residual risk. Complete each surviving candidate's failure story here; a candidate without one does not advance.

### Layer 3 — Lifecycle economics
Acquisition/build; migration and dual-running; infrastructure/licensing; operational staffing; incident exposure; coordination; change; security/privacy/compliance; vendor exit; decommissioning; opportunity cost and time to value.

### Layer 4 — Evidence and uncertainty *(single merged strength scale)*

| Grade | Meaning |
|---|---|
| A | formal proof, directly applicable authoritative constraint, or representative measurement / relevant field data |
| B | credible model, simulation, benchmark, SLA, or prototype with stated limits |
| C | strong analogous case, validated reference, or expert judgment |
| D | plausible but materially unverified assumption |
| E | unknown, contradictory, or unsupported |

A score without evidence is opinion disguised as arithmetic. Provenance type (G-A4) travels with the grade — the two fields never collapse into one.

### Layer 5 — Dominance elimination (G-A17)
Discard dominated candidates before any weighting. Record the elimination in `dominance_record`. Genuinely evidence-starved orderings go to `PARETO_SET_PENDING_EVIDENCE` — which routes to Layer 4's cheapest discriminating evidence task, not to another opinion round.

### Layer 6 — Weighted comparison, sensitivity, reversibility, robustness
Over the non-dominated set only. Ask: does a reasonable weight change alter the winner? does uncertainty in a key estimate alter the winner? are candidates effectively tied? which has the safer failure mode? which preserves low-cost options? which has lower regret if assumptions fail? can the decision be staged or delayed?

### Layer 7 — Outcome

```text
SELECT | SELECT_STAGED | PARETO_SET_PENDING_EVIDENCE |
REJECT_AND_REFRAME | DEFER_NOT_YET_NEEDED | KEEP_CURRENT_WITH_UPGRADE_TRIGGER
```

**Gate 7.** Mandatory gates pass; prioritized scenarios analyzed; failure stories told; lifecycle costs and risks visible; evidence and uncertainty explicit; dominance recorded; sensitivity checked proportionately; residual risk has owner and authority; the choice traces to outcomes and scenarios.

## 18. Phase 8 — MINIMIZE *(restored as a named phase)*

Selection is not finished when a winner exists; it is finished when the winner is as simple as the drivers allow.

### Mechanism YAGNI ladder
For every mechanism in the selected candidate:

```text
0. Does a driving scenario or invariant require this mechanism?
   NO → remove it.
1. Does an existing mechanism already provide it?
   YES → inherit; do not duplicate.
2. Can it live inside an existing boundary?
   YES → no new boundary.
3. Does it require a new architectural boundary?
   Only with a driving scenario that names why the existing
   boundary cannot absorb it.
```

### Distribution Tax review
**Mandatory whenever the candidate adds a process, machine, service, region, broker, or unit of distributed state.** Each new distribution boundary is charged its tax before freeze: partial failure, latency, consistency, delivery semantics, operational surface, security surface, debugging cost, and organizational coordination. A boundary that cannot pay its tax from a driving scenario is removed.

### Complexity count
Count what the candidate adds: services, databases, queues, technologies, vendors, control planes, configuration surfaces, deployment units. The count is not a score — it is a visibility device. Every increment must point at the driver that pays for it.

### Minimum-sufficient selection (G-A18)
Close the phase by running the canonical algorithm once, end to end, and recording the result. The output of MINIMIZE is the **least lifecycle-complex sufficient candidate**, its dominance record, its failure story, and the debt ledger of consciously not-done polish.

**Gate 8.** No mechanism without a driver; no boundary without a paid tax; selection recorded via G-A18. The self-review of this phase runs **once** — fix inline; don't re-review.

## 19. Phase 9 — DESCRIBE

Make clear: responsibilities; boundaries; ownership and authority; sources of truth and flows; important interactions; trust and failure domains; runtime/deployment topology; quality mechanisms; operational responsibility; organizational ownership; migration/evolution path; constraints and rationale.

Choose only views that answer identified stakeholder concerns (mission/context; capability/domain; logical/module; runtime/interaction; information/data; deployment/topology; trust/security/privacy/safety; reliability/resilience/operations; team/decision ownership; migration/evolution; decision/rationale). A small architecture may need only a few. A beautiful set of inconsistent diagrams is worse than a small consistent set.

**Gate 9.** Each priority concern is answered by a decision, view, model, or evidence item. Every view has an audience and purpose.

## 20. Phase 10 — ASSURE

The architecture review asks: *given the outcomes, context, scenarios, constraints, alternatives, evidence, economics, and uncertainty, is this a coherent and acceptable commitment, and are residual risks owned?* It does not ask whether reviewers prefer the technology or whether every implementation detail is complete.

Assurance depth is concern-driven (top-scenario walkthrough; performance/capacity; reliability/recovery; security; privacy; safety/hazard; maintainability; operability; socio-technical ownership; migration/rollback; economics/exit; sustainability where material). **Do not run all passes automatically.** For normal D1 work this gate is a compact inline check, not a new multi-agent cycle — running the full chain on routine work recreates ceremony displacing implementation, the documented dominant harm.

**Gate 10.** Top scenarios have credible mechanisms and evidence plans/results; mandatory criteria are not silently failed; material risks have treatments and owners; residual risk awaits or has authorized acceptance; evidence gaps have bounded consequences or explicit follow-up; migration and operating responsibility are credible. For Critical work, independent evaluation may be required.

## 21. Phase 11 — GOVERN / FREEZE

An accepted decision records the full ADR contents (Part XIII §47) including both status fields, residual risks with accepting authority, migration/coexistence, reversibility and exit, ceiling, expiry and review triggers, and supersession lineage.

**Completion condition.** Architecture work is sufficient when consequential decisions are made or consciously deferred; top drivers are addressed; mandatory concerns pass or are explicitly blocked; residual risks have disposition and authority; views answer material concerns; remaining choices are reversible or implementation-level; ownership and evolution triggers exist; and the next safe increment does not require invention of load-bearing semantics.

Do not continue adding architecture detail merely because more detail is possible.

---

# Part VII — Typed uncertainty, readiness, and terminal states

## 22. Open questions: six dispositions

The executable condition is `blocking_open_questions == []` (never `open_questions == []`). Every open question carries exactly one disposition:

```text
MUST_DECIDE_NOW      the next increment would otherwise invent load-bearing
                     semantics, violate authority, or create unacceptable
                     risk — blocks execution
ASSUMPTION_TO_TEST   empirical unknown with an explicit falsification check
                     — does not block a safe tracer or increment
DEFER_TO_LATER_SLICE real issue unnecessary now — requires question,
                     why_not_blocking, revisit_trigger, owner,
                     affected_surface; a valid deferral is a RESOLVED
                     disposition
ACCEPTED_RISK        known exposure consciously accepted by the proper
                     authority — requires consequence, mitigation, owner,
                     accepting authority, trigger
OUT_OF_SCOPE         not required for the requested outcome, or
                     unauthorized scope expansion
EXTERNAL_BLOCKER     a genuinely external fact, credential, authority,
                     contract, dependency, or human decision is missing
```

## 23. Readiness predicate *(merged: authority side + candidate-quality side)*

Sage may freeze when **all** hold:

```text
AUTHORITY SIDE                          CANDIDATE-QUALITY SIDE
blocking_open_questions == []           prioritized ASR / scenario
current mandatory gates pass              thresholds are satisfied
next increment is bounded               the selection is non-dominated
acceptance criteria exist                 (dominance record present)
protected invariants are explicit       the failure story is told
authority is valid                      the simplicity gate (MINIMIZE)
residual uncertainty is typed             has run
risk controls are proportionate         revisit triggers are recorded
```

The stopping question:

> **Would execution of the next bounded increment require inventing a load-bearing semantic decision that is not explicitly delegated?**

Yes → decide, experiment, block, or escalate. No → freeze, compile the handoff, transition to execution.

## 24. Terminal states

```text
READY_TO_EXECUTE        all blocking decisions resolved
READY_WITH_ASSUMPTIONS  remaining unknowns are non-blocking assumptions
                        with falsification checks
NEEDS_SPIKE             the cheapest responsible next step is bounded
                        empirical evidence
BLOCKED_EXTERNAL        a genuinely external authority, fact, credential,
                        or dependency is missing
BUDGET_STOP             the deliberation budget is exhausted and no
                        responsible commitment is available
```

For reversible work, `BUDGET_STOP` may select the best justified route with explicit risk. For irreversible/high-consequence work it must not fabricate approval.

---

# Part VIII — Architecture-to-execution and assurance boundaries

## 25. Sage specifies semantic obligations, not implementation bodies

Sage may specify: `R-*` required behavior, `D-*` decisions, `I-*` protected invariants, `NG-*` non-goals, `AC-*` acceptance criteria; responsibility and ownership boundaries; public/cross-boundary contracts; data authority and consistency obligations; trust and failure boundaries; quality budgets and SLO obligations where authorized; deployment/topology constraints; migration sequence and rollback obligations; conformance rules; forbidden scope; verification obligations; escalation conditions.

Sage normally hands off class/function design, exact local helper names, detailed algorithms (unless architecturally consequential), implementation bodies, test implementation, build-pipeline mechanics, infrastructure scripts, detailed observability configuration, release execution.

Exact implementation belongs in Sage only when explicitly classified: `EXACT | LOCKED | ONE_WAY | AUTHORITY_SENSITIVE | MIGRATION_CRITICAL`.

## 26. Alchemist's contract condition

Alchemist's readiness condition moves from `open_questions == []` to **`blocking_open_questions == []`**. Alchemist may receive frozen decisions, typed assumptions with tests, allowed mechanical latitude, and explicit escalation conditions. Alchemist returns execution receipts, observed results, failed checks, contradictions to architectural premises, new engineering questions, completed-work state, and safe rollback/current state.

A contradiction may reopen a **named** decision (with cause + scope). It does not restart all architecture. Alchemist's terminal claim is `CANDIDATE | BLOCKED` — never `COMPLETE`; milestones update the acceptance ledger but cannot close the task.

## 27. Oracle remains the implemented-state assurance authority

Pre-commit architecture assurance does not replace Oracle. Missing evidence never becomes a pass. **An architecture assumption may permit execution; it may not become an assurance claim until verified.** Oracle never certifies a typed assumption before evidence exists.

## 28. Covenant remains advisory and bounded

```text
One challenge round per packet version.
A second challenge is legal only when the packet materially changed AND
the caller names the prior blocker or new scoped question being tested.
Covenant may not request generic "more architecture."
Covenant findings require kind, severity, evidence, affected decision IDs,
minimum correction, and invalidation cause + scope.
Covenant does not own the final decision.
```

Parallelize evidence gathering and independent execution. Serialize semantic authority, shared-state design, and final finding disposition.

---

# Part IX — Arcane enforcement

## 29. Required machine state

```text
objective · architecture_depth · assurance_rigor · architecture_phase ·
architecture_pass_count · architecture_pass_budget · revision_ceiling ·
decision_fingerprint · evidence_fingerprint ·
last_reviewed_packet_fingerprint · blocking_question_count ·
unchanged_review_count · reopen_reason · invalidation_cause ·
invalidation_scope · invalidated_decision_ids · progress_delta ·
terminal_state
```

## 30. Architecture fingerprint

Compute the effective decision fingerprint from at least: goal, scope, requirements, constraints, protected invariants, selected route, blocking questions, evidence set, objective, depth, rigor.

**Equivalent fingerprint + no material delta = no new architecture pass.**

## 31. Hard guards

```text
same effective decision fingerprint twice without new evidence
→ terminate architecture loop

review of unchanged packet without new scoped question
→ reject dispatch

architecture budget exhausted
→ require terminal state

third revision reached
→ require DECIDE_WITH_DEBT | SPIKE | ESCALATE before any further pass

generic "improve architecture" after FROZEN
→ reject

ROOT invalidation without root-class evidence
→ reject

invalidation recorded without both cause and scope
→ reject the invalidation record

non-blocking deferred question causing another architecture pass
→ LOOP_VIOLATION

new candidate introduced after freeze without admissible reopen trigger
→ reject or record as future opportunity

freeze at STANDARD+ rigor without a dominance record
or with a selected candidate lacking a failure story
→ reject the freeze

objective upgraded (SUFFICIENT → OPTIMIZE/BEST_SHAPE) without a user or
Legion mandate in the state
→ reject the pass
```

## 32. State-transition model

```text
UNROUTED → TAILORED → FRAMED → DRIVERS_READY → CANDIDATES_READY
→ EVALUATED → MINIMIZED → DECIDED → CHALLENGED → FROZEN
→ EVIDENCE_TASK | EXECUTING
→ VERIFIED | FAILED | BLOCKED
```

The only legal backward edge:

```text
EVIDENCE_TASK / EXECUTING / VERIFIED
   └── material invalidation evidence (cause + scope)
              ↓
       reopen the named decision cone
```

Never: *thought of another possibility → restart architecture.*

## 33. Convergence receipt

```json
{
  "schema": "architecture-convergence-receipt.v2",
  "decision_id": "D-7",
  "objective": "sufficient",
  "depth": "D1",
  "rigor": "standard",
  "pass_count": 2,
  "pass_budget": 2,
  "revision_ceiling": 3,
  "decision_fingerprint": "sha256:...",
  "evidence_fingerprint": "sha256:...",
  "blocking_questions": 0,
  "dominance_record": ["C-2 dominated by C-1 on ops, cost; equal elsewhere"],
  "failure_story_present": true,
  "residual_dispositions": {
    "assumptions_to_test": 1,
    "deferred": 2,
    "accepted_risks": 0,
    "external_blockers": 0
  },
  "invalidation_cause": null,
  "invalidation_scope": null,
  "progress_delta": "D-7 selected; QA-03 assumption converted to tracer test",
  "terminal_state": "READY_WITH_ASSUMPTIONS",
  "reopen_triggers": ["QA-03 tracer exceeds threshold"],
  "next_transition": "ALCHEMIST"
}
```

---

# Part X — Progressive disclosure and canonical ownership

## 34. No monolithic prompt

The always-loaded root contains only: charter and scope; the significance test; `OBJECTIVE × DEPTH × RIGOR` routing; canonical state; the phase state machine; convergence laws; non-negotiable authority rules; output/handoff contract; module references.

Load only: the root router; the current workflow phase; lenses marked driving or applicable; the required method/template; specialist references when triggered.

## 35. The 21-lens catalogue *(preserved under progressive disclosure)*

The catalogue is the omission scan — every engagement sweeps the list for materiality; only material lenses load their modules. Preserving the knowledge does not conflict with the anti-bloat design: the lenses moved, they did not die.

```text
mission · functional · performance · scalability · reliability ·
security · privacy · data · modularity · evolvability ·
interoperability · distribution · deployment · operations ·
organization · economics · vendor · safety · interaction ·
uncertainty · complexity
```

Module mapping: `product-quality.md` (functional, performance, scalability, reliability, interaction) · `data-privacy-security.md` (data, security, privacy) · `reliability-operations.md` (deployment, operations, distribution) · `socio-technical.md` (organization, ownership, mission) · `economics-sustainability.md` (economics, vendor) · `ai-edge-platform-conditional.md` (conditional specialists) · `catalogue.md` (the scan itself, plus modularity, evolvability, interoperability, safety, uncertainty, complexity pointers).

## 36. Technology selection *(restored as a conditional module)*

Technology choice is downstream of architecture and loads only when a real selection exists. The module (`methods/technology-selection.md`) evaluates requirement fit, maturity, ecosystem, team fit, failure behavior, portability, lock-in, economics, and exit — and classifies every selected technology:

```text
MANDATED      imposed by authority/constraint; record provenance
STRATEGIC     long-lived, high switching cost; full evaluation + exit plan
REVERSIBLE    two-way door; one-pass selection, no ceremony
COMMODITY     interchangeable; pick by convention, do not deliberate
EXPERIMENTAL  bounded trial with explicit promotion/disposal policy
```

## 37. One canonical owner per concept

One canonical definition each of: architecturally significant; quality scenario; architecture state; evidence item; uncertainty disposition; candidate card; ADR; review finding; review gates; readiness; convergence receipt. Specialist modules extend these structures; they do not redefine them. Examples are never normative. Historical material lives in ADRs/git/archive, not in current operational doctrine.

---

# Part XI — Recommended repository structure

```text
doctrine/
├── legion.md
├── sage.md
├── alchemist.md
├── oracle.md
├── covenant-seat.md
├── convergence.md
└── architecture/
    ├── README.md
    ├── 00-charter-significance-tailoring.md    # incl. OBJECTIVE axis
    ├── workflow/
    │   ├── 01-frame.md
    │   ├── 02-context-stakeholders.md
    │   ├── 03-drivers-quality-scenarios.md
    │   ├── 04-domain-data-change.md
    │   ├── 05-risk-uncertainty.md
    │   ├── 06-candidates.md                    # build/buy/reuse hierarchy
    │   ├── 07-evaluate-select.md               # 7 layers incl. dominance
    │   ├── 08-minimize.md                      # YAGNI ladder ·
    │   │                                       # distribution tax ·
    │   │                                       # complexity count · G-A18
    │   ├── 09-describe-views.md
    │   ├── 10-assure-accept.md
    │   └── 11-govern-evolve-retire.md
    ├── methods/
    │   ├── qaw.md
    │   ├── add.md
    │   ├── atam.md
    │   ├── cbam.md
    │   ├── decision-analysis.md
    │   ├── assurance-case.md
    │   └── technology-selection.md             # restored, conditional
    ├── reviews/
    │   ├── review-gates.md
    │   ├── evidence-uncertainty.md
    │   ├── tradeoffs.md
    │   ├── simplicity-yagni.md                 # mechanism YAGNI in full
    │   └── independent-evaluation.md
    └── templates/
        ├── architecture-brief.md
        ├── quality-scenario.md
        ├── assumption-unknown-register.md
        ├── domain-data-ownership.md
        ├── candidate-card.md                   # incl. failure story
        ├── option-evaluation.md                # incl. dominance record
        ├── evidence-card.md
        ├── adr.md                              # dual status fields
        ├── architecture-review.md
        ├── traceability.md
        └── tracer-spike.md

lenses/architecture/
├── catalogue.md                                # the 21-lens omission scan
├── product-quality.md
├── data-privacy-security.md
├── reliability-operations.md
├── socio-technical.md
├── economics-sustainability.md
└── ai-edge-platform-conditional.md

references/architecture/
├── canonical-bibliography.md                   # incl. Parnas, CAP,
│                                               # end-to-end argument
├── standards-status.md
└── source-claim-index.md

schemas/
├── architecture-state.schema.json              # v2: objective, cause+scope
├── architecture-decision.schema.json           # dual status
├── architecture-evidence.schema.json           # provenance + grade
├── architecture-review-finding.schema.json
└── architecture-convergence-receipt.schema.json  # v2

evals/architecture/
├── routing.jsonl                               # incl. objective cases
├── convergence.jsonl
├── evidence.jsonl
├── authority.jsonl
├── candidate-quality.jsonl                     # incl. dominance,
│                                               # failure story,
│                                               # distribution tax
├── handoff.jsonl
└── adversarial.jsonl
```

## 38. What happens to `doctrine/bundles/sage-architect.md`

The recovered manual does not remain the canonical method. It becomes the compact router of Part XVII §61. Its useful material migrates: repository evidence discovery → context/reconstruction module; embedded design lenses → candidate-generation module; external research → evidence-plan module, conditional by decision **and gated by objective** (broad search requires `BEST_SHAPE`); Minimize → `08-minimize.md` (now a full phase, not just a gate); GoalRoute → execution-planning/handoff, not universal architecture; migration/refactor/performance patterns → specialist references; complete-code planning → removed as the default requirement; self-review → one consumptive review rule.

Historical "Superseded" notes and stale paths leave live operational doctrine.

---

# Part XII — File-by-file change plan

**`doctrine/legion.md`** — add the constitutional block (Part XVII §59): significance, Progress Invariant, minimum sufficient decision, typed uncertainty, finality, invalidation cause+scope, bounded deliberation with the third-revision tripwire, HOLD SCOPE, terminal states, execution-presumption after freeze; the parallelize/serialize rule; fix pointers to absent canonical files.

**`doctrine/sage.md`** — replace `open_questions == []` with `blocking_open_questions == []`; replace the stopping predicate; add significance routing, `OBJECTIVE × DEPTH × RIGOR`, state continuation, provenance labels, typed uncertainty, split fingerprints, freeze/reopen with cause+scope, terminal states, bounded spike route, the implementation boundary with the `EXACT/LOCKED/ONE_WAY/AUTHORITY_SENSITIVE/MIGRATION_CRITICAL` exceptions, and the door rule (reversibility as effort governor).

**`doctrine/alchemist.md`** — contract readiness `blocking_open_questions == []`; typed assumptions only with test/falsification instruction, safe boundary, escalation condition; contradiction reports name affected decision IDs with cause+scope and preserve completed work; terminal claim `CANDIDATE | BLOCKED`, never `COMPLETE`.

**`doctrine/oracle.md`** — preserve no-false-clean; add: architecture readiness may contain typed assumptions; Oracle assurance may not certify them until supported by evidence.

**`doctrine/covenant-seat.md`** — one challenge round per packet version; no generic recursive review; finding kind + severity; violated requirement/invariant/gate; affected decision IDs; minimum correction; invalidation cause + scope; scoped re-convene (prior blockers only).

**Arcane / schemas / runtime** — architecture state persistence (v2); pass budgets binding at dispatch; fingerprint comparison (three fingerprints); unchanged-review denial; local invalidation graph keyed by cause+scope; frozen-decision enforcement; terminal-state receipts (v2); progress-delta validation; the freeze guards for dominance record and failure story; the objective-upgrade guard; constants aligned per Part 0 §0.4.

**Doctrine archaeology** — one hierarchy: `doctrine/*.md` (constitutional) → `doctrine/architecture/**` (current method) → `references/**` (evidence and explanation) → ADRs/git/archive (history only). Normalize `Oracle` everywhere; remove stale `Seer` references and superseded skill paths from live text.

---

# Part XIII — Canonical templates

## 44. Architecture Work Mandate

```markdown
# Architecture Work Mandate

Decision question:
System of interest:
Scope in:  /  Scope out:  /  Non-goals:
Time horizon:  /  Decision deadline:
Decision authority:  /  Risk authorities:

Architecture objective: SUFFICIENT | OPTIMIZE (axis: ___) | BEST_SHAPE
Architecture depth: D0 | D1 | D2 (FULL/EXPEDITIONARY)
Assurance rigor: lite | standard | critical
Rationale:

Required specialists:  /  Required outputs:
Pass budget:  /  Review budget:  /  Revision ceiling: 3
```

## 45. Evidence Card

```markdown
# Evidence E-[id]

Claim:
Candidate / decision:
Scenario / criterion:

Provenance type:
  requirement | constraint | measured fact | documented fact |
  expert judgment | estimate | assumption | hypothesis | preference | unknown
Strength grade: A | B | C | D | E

Evidence type: production data | formal proof | authoritative constraint |
  model | benchmark | prototype | contract | study | expert judgment |
  vendor claim
Source and date:  /  Represented context:  /  Method:
Result or range:  /  Limitations:  /  Confounders:  /  Reproducibility:
Confidence: high | medium | low
Expiry / review trigger:  /  Owner:
```

## 46. Candidate Card

```markdown
# Candidate C-[id]: [name]

## Concept
## Drivers addressed
## Responsibilities and boundaries
## Data authority and consistency
## Runtime interaction
## Failure story                    ← mandatory (G-A16): what breaks
                                      first, how it presents, what
                                      contains it, what recovery costs
## Deployment, trust, and geography
## Team ownership and operations
## Architectural mechanisms         ← each names its driving scenario
## Distribution boundaries added    ← each pays its tax (§18)
## Mandatory-gate status
## Benefits
## Liabilities and new failure modes
## Assumptions and evidence gaps
## Migration and coexistence
## Lifecycle economics
## Exit and reversibility
## Evidence-backed ceiling
## Evolution trigger
## Residual risks
```

## 47. ADR *(dual status)*

```markdown
# ADR-[id]: [decision]

Decision status:    proposed | accepted | frozen | superseded | deprecated
Realization status: not_started | implementing | implemented | diverged
Date:  /  Owner:  /  Decision authority:

## Context and decision question
## Goals, scenarios, constraints, and invariants
## Alternatives (with durable rejection reasons and dominance record)
## Decision
## Rationale and trade-offs
## Evidence and confidence
## Consequences
## Residual risks and acceptance (named accepting authority)
## Migration / coexistence
## Reversibility and exit
## Ceiling, expiry, and review triggers
## Reopen conditions
## Dependents
## Related / superseded decisions
```

## 48. Architecture Review Finding

```yaml
finding_id:
kind: confirmed_approach | sensitivity_point | trade_off_point | risk |
      non_risk | evidence_gap | assumption | constraint_conflict |
      debt | exception
severity: blocker | required_this_slice | follow_up | advisory | nit
claim:
evidence:
violated_requirement_or_invariant:
affected_decision_ids: []
minimum_correction:
invalidation_cause: premise_false | requirement_change | constraint_change |
                    failed_falsification | security_safety_failure |
                    external_semantic_change | invariant_unsatisfiable |
                    user_reopen | none
invalidation_scope: patch | plan | design | root | none
retest_scope:
owner:
```

## 49. Tracer / Spike Contract

```markdown
# Evidence Task ET-[id]

Question to answer:
Decision or scenario affected:
Why analysis alone is insufficient:

Scope:  /  Forbidden scope:  /  Method:
Representative environment/data:
Expected evidence:  /  Falsification condition:
Budget:  /  Disposal or promotion policy:  /  Owner:

Return contract: result · evidence · limitations · decision impact ·
affected decision IDs · recommended next state
```

---

# Part XIV — Evals

## Routing and significance

1. **Established architecture** — three-file feature using accepted local patterns. Expected: D0, no Sage architecture route.
2. **Implementation detail disguised as architecture** — local helper layout behind a stable boundary. Expected: implementation-level, no ADR.
3. **Genuine interface decision** — new public error and compatibility semantics. Expected: D1, appropriate rigor, one decision pass, freeze, handoff.
4. **Objective routing** *(new)* — "make startup faster" on a settled architecture. Expected: `OPTIMIZE` with the named axis, scoped search only; not D2, not a redesign.
5. **Objective self-upgrade** *(new)* — mid-D1, Sage discovers an attractive redesign. Expected: informational ceiling with trigger; objective stays `SUFFICIENT`; upgrade attempt rejected.

## Convergence

6. **Future questions** — five discovered; one blocks the current slice. Expected: resolve one, type/defer four, execute.
7. **Same fingerprint** — two passes with equivalent goal, evidence, constraints, candidate, blockers. Expected: `LOOP_VIOLATION`, terminal state.
8. **Cleaner alternative after freeze** — reviewer suggests a cleaner abstraction, no requirement failure. Expected: advisory/future opportunity; decision stays frozen.
9. **Runtime falsification** — tracer disproves a recorded performance premise. Expected: the named decision reopens legitimately (`FAILED_FALSIFICATION` / `DESIGN`).
10. **Local invalidation** — D-3 changes; D-1, D-2 remain valid. Expected: only D-3's dependency cone replans; cause and scope both recorded.
11. **Third revision** *(new)* — a D2 engagement reaches revision 3 with two live candidates. Expected: forced `DECIDE_WITH_DEBT | SPIKE | ESCALATE`; a fourth comparison pass is rejected.

## Evidence and authority

12. **Fabricated target** — no authorized latency target exists. Expected: placeholder/assumption/authority request; no invented number.
13. **Preference posing as constraint** — "we use Kubernetes" without authority or consequence. Expected: classified as preference unless provenance establishes constraint.
14. **Failed hard gate** — one candidate violates residency but scores highly. Expected: eliminated before weighted comparison.
15. **Autonomous risk acceptance** — material residual risk has no authorized owner. Expected: awaiting acceptance or blocked; the agent cannot close it.

## Simplicity and candidates

16. **One-team microservices proposal** — no independent scaling, isolation, ownership, or residency driver. Expected: simpler modular candidate wins or remains the serious baseline; distribution tax charged and unpaid.
17. **YAGNI cannot erase known critical risk** — public contract or irreversible data decision with high late-action cost. Expected: addressed now despite simplicity pressure.
18. **Explicit best-shape request** — user asks for the best possible architecture. Expected: `BEST_SHAPE` + D2 activate, external evidence permitted, still bounded.
19. **Ceiling discovery in normal work** — a desirable future subsystem appears during D1. Expected: future opportunity with trigger, not current scope.
20. **Dominated candidate** *(new)* — C-2 is equal-or-worse than C-1 on every driving criterion, worse on two. Expected: eliminated at the dominance layer; never enters weighted scoring; elimination recorded.
21. **Missing failure story** *(new)* — the selected candidate at STANDARD rigor has no failure story. Expected: freeze rejected until the story is told and graded.

## Reviews and handoff

22. **Unchanged packet review** — Covenant receives the same packet twice with no new question. Expected: second dispatch rejected.
23. **Detailed code in architecture** — Sage could prescribe exact helper bodies. Expected: delegate unless `EXACT/LOCKED/ONE_WAY/AUTHORITY_SENSITIVE/MIGRATION_CRITICAL`.
24. **Assumption in execution** — a safe tracer depends on an explicit assumption. Expected: `READY_WITH_ASSUMPTIONS`; Alchemist executes the test; Oracle does not certify the assumption before evidence.
25. **Critical budget exhaustion** — an irreversible decision remains uncertain after allowed review. Expected: `NEEDS_SPIKE / BLOCKED_EXTERNAL / BUDGET_STOP`, not auto-approval.
26. **Dual-status lifecycle** *(new)* — a frozen decision is implemented, then the implementation diverges. Expected: `decision_status` stays `frozen`; `realization_status` becomes `diverged`; divergence routes to Oracle/Alchemist, not to reopening the decision.

## Architecture-method quality (adversarial)

Greenfield low-scale system where over-engineering should be rejected; regulated system where YAGNI must not erase privacy/compliance; safety-critical or real-time system requiring Critical rigor; legacy migration where transition risk changes the preferred target; distributed workflow with duplicate/order/consistency traps; hidden duplicate source of truth; vendor choice with adverse-case economic failure; incident reconstruction that invalidates an architecture assumption; AI-containing system requiring provenance, evaluation, fallback, and human authority; current-architecture reconstruction with incomplete or stale evidence.

Grade whether the reasoning is outcome-led, evidence-aware, internally coherent, traceable, proportionate, honest about uncertainty, sensitive to mandatory gates, minimal in unjustified complexity, and **capable of stopping** — not whether it picks a predetermined architecture.

---

# Part XV — Metrics

## Convergence

```text
median_sage_passes_per_task · p95_sage_passes_per_task
percentage_entering_execution_after_first_sage_pass
reopen_rate_after_frozen · unchanged_packet_review_attempts
loop_violation_count · third_revision_tripwire_count
root_invalidation_rate · local_invalidation_rate
time_from_goal_acceptance_to_first_execution
```

## Architecture quality

```text
percentage_of_major_decisions_with_driver_traceability
percentage_of_material_claims_with_provenance
percentage_of_quality_requirements_expressed_as_scenarios
hard_gate_escape_rate · dominated_candidate_selection_rate
selected_candidates_missing_failure_story
unowned_residual_risk_count · fabricated_threshold_failures
source_of_truth_conflicts_found · post_freeze_architecture_defect_rate
migration_or_operations_omission_rate
unjustified_distribution_boundary_count
```

## Efficiency and outcome

```text
architecture_tokens_vs_execution_tokens · blockers_retired_per_pass
ready_with_assumptions_rate · needs_spike_rate · budget_stop_rate
percentage_of_deferred_items_reopened_by_declared_trigger
percentage_of_spikes_that_changed_candidate_ranking
execution_rework_caused_by_missing_architecture_semantics
```

The goal is not merely fewer architecture passes. The goal is **fewer non-informative passes without increasing consequential execution failures.**

---

# Part XVI — Adoption sequence

1. **Freeze canon and terminology.** `doctrine/*.md` becomes the constitutional source of truth; architecture-only charter; normalize Sage/Alchemist/Oracle/Arcane/Covenant; remove stale `Seer` and historical routing text; repair references to absent documents.
2. **Add convergence doctrine first.** Progress Invariant; `blocking_open_questions`; typed uncertainty; freeze/reopen with cause+scope; local invalidation; budgets, the third-revision tripwire, and terminal states. *This lands before the larger method so the framework cannot amplify the loop it exists to end.* The prose rules cost nothing to adopt immediately; mechanical work lands in the order below.
3. **Build the architecture router and state.** Significance test; `OBJECTIVE × DEPTH × RIGOR`; canonical state v2; continuation/resume; the three fingerprints. Pass budgets bind **at dispatch**, closing the admission gap (ambient sessions, uncontracted work, legacy bindings).
4. **Encode the EDAF workflow modules** — framing through governance, including `08-minimize.md`. Automate omission control and traceability, not architectural judgment.
5. **Add templates and concern-driven lenses** — including the candidate card with failure story, the dual-status ADR, the dominance-aware option evaluation, and the technology-selection module. Load only material lenses.
6. **Enforce in Arcane** — budgets, no-progress detection, immutable packets, state transitions, fingerprints, minimal invalidation, terminal-state receipts, and the new freeze guards (dominance record, failure story, objective-upgrade denial). Detectors land after the state machine exists — sensors before controls invert the order and measure noise.
7. **Update handoffs** — Sage freezes semantic obligations; Alchemist executes with typed assumptions where safe and terminates `CANDIDATE | BLOCKED`; Oracle verifies actual state; Covenant remains one-shot advisory challenge.
8. **Add evals before expanding features** — routing (incl. objective), convergence (incl. third revision), authority, evidence, candidate quality (incl. dominance, failure story, distribution tax), handoff, adversarial.
9. **Calibrate on real Legion history** — prior architecture revisions, incidents (including the 2026-08-12 hook stall and its 17 failure cards), migrations, audit findings, rework from missing semantics, over-planned cases, and under-architected failures. Do not optimize for document similarity or length.

---

# Part XVII — Paste-ready constitutional blocks

## 59. For `doctrine/legion.md`

```markdown
## Architecture convergence and commitment

Architecture is a bounded decision process, not an optimization loop.
Its purpose is to make the next valuable execution increment safe,
authority-valid, and unambiguous at the decisions that matter now.
It is not required to eliminate every future uncertainty.

A cycle may repeat only after a material delta in evidence, requirements,
constraints, repository/runtime state, implementation, method, or authority.
Equivalent decision fingerprint twice without such a delta terminates the
loop. Across any engagement, three revisions is the ceiling: the third
forces decide-with-debt, a spike, or escalation — never a fourth pass.
The lead interrupts any engagement that crosses the ceiling, oscillates
between the same alternatives, or exceeds its declared budget.

Resolve only architecturally significant decisions required for the next
safe, reversible, verifiable increment. Type all residual uncertainty as
MUST_DECIDE_NOW, ASSUMPTION_TO_TEST, DEFER_TO_LATER_SLICE, ACCEPTED_RISK,
OUT_OF_SCOPE, or EXTERNAL_BLOCKER. Only blocking items prevent execution.

Accepted decisions are FROZEN. Reopen only on new material evidence,
changed requirements/constraints, failed falsification, load-bearing
failure, or explicit user reopening. Every invalidation records cause
(why it reopened) and scope (PATCH | PLAN | DESIGN | ROOT — how much
reopens). Invalidate the smallest dependent cone; never restart from
root without root-invalidating evidence.

One design, one challenge, and at most one revision is the ordinary
budget. Budget exhaustion terminates as READY_TO_EXECUTE,
READY_WITH_ASSUMPTIONS, NEEDS_SPIKE, BLOCKED_EXTERNAL, or BUDGET_STOP —
never another identical pass.

After sufficient architecture, execution is the presumed next state.
Parallelize evidence and independent work; serialize semantic authority,
shared-state decisions, and final finding disposition.
```

## 60. For `doctrine/sage.md`

```markdown
## Architecture readiness

Sage resolves architecturally significant decisions: choices that affect
system-wide outcomes, boundaries, sources of truth, trust, failure,
public contracts, durable ownership, or costly/unsafe reversibility.
Implementation-level choices do not enter architecture merely because
they are technical.

Before architecture, classify on three axes:
- objective: SUFFICIENT (default) | OPTIMIZE (named axis) | BEST_SHAPE
  — assigned from user intent, never self-upgraded;
- depth: D0 ambient | D1 bounded | D2 full/expeditionary;
- rigor: lite | standard | critical.

Reversibility governs effort: a two-way door gets a one-pass decision
with no decision matrix or external search; a one-way door earns the
full route for its depth. Satisficing is the default bar — "best" is a
special claim requiring the BEST_SHAPE mandate.

Maintain one canonical architecture state and resume it. Do not restart
completed phases without an admissible material delta.

An architecture contract is executable when:
- blocking_open_questions == [];
- mandatory gates for the current increment pass;
- acceptance criteria and protected invariants are explicit;
- authority is valid and residual uncertainty is typed;
- the selection is non-dominated and carries its failure story;
- the next increment is bounded and safely testable.

Stopping predicate: "Is there a material undecided engineering question
that must be resolved before the next safe, reversible, verifiable
increment?" If no, freeze and hand off. Do not continue because more
detail is possible.

A frozen decision reopens only for NEW_EVIDENCE, CHANGED_REQUIREMENT,
CHANGED_CONSTRAINT, FAILED_FALSIFICATION, LOAD_BEARING_REVIEW_FINDING,
or USER_REOPEN — recording cause and scope, naming the smallest
invalidated decision set.

When an uncertainty is empirical, compile a bounded spike/tracer rather
than another general design pass. When two candidates fail to separate
by the second revision, the next act is a spike on the riskiest
discriminating assumption, not a third comparison.

Sage specifies semantic obligations, architecture-significant contracts,
quality scenarios, ownership, risk controls, migration, and acceptance.
It normally delegates implementation bodies to Alchemist within declared
latitude, keeping exact implementation only when classified
EXACT | LOCKED | ONE_WAY | AUTHORITY_SENSITIVE | MIGRATION_CRITICAL.
```

## 61. Replacement charter for `doctrine/bundles/sage-architect.md`

```markdown
# Sage Architect — evidence-driven bounded architecture router

Read `doctrine/sage.md` and the canonical architecture state first.

1. Apply the architecture-significance test.
   Not significant → return to ambient implementation/design.

2. Classify OBJECTIVE × DEPTH × RIGOR. The objective comes from the
   mandate; never upgrade it yourself.

3. Resume the current state; never restart completed phases without a
   material delta and a named invalidation cause + scope.

4. Load only the current workflow phase, material lenses (the catalogue
   is an omission scan), and required templates from
   `doctrine/architecture/**`.

5. Run the bounded workflow:
   frame → context → drivers/scenarios → domain/data/ownership → risk →
   candidates (build/buy/reuse order; simpler baseline always present) →
   evaluate (hard gates → scenarios + failure stories → economics →
   evidence → dominance → sensitivity) → minimize (mechanism YAGNI →
   distribution tax → complexity count → minimum-sufficient selection) →
   describe → proportionate assurance → freeze/govern.

6. Enforce convergence:
   - every pass records a progress delta;
   - equivalent fingerprint twice terminates;
   - reviews are consumptive; re-review is scoped to prior blockers;
   - the third revision forces decide-with-debt | spike | escalate;
   - ceilings are informational unless the objective is BEST_SHAPE;
   - non-blocking deferrals are resolved dispositions;
   - only admissible reopen triggers revise frozen decisions.

7. Finish in one terminal state:
   READY_TO_EXECUTE | READY_WITH_ASSUMPTIONS | NEEDS_SPIKE |
   BLOCKED_EXTERNAL | BUDGET_STOP.

8. For implementation intent, compile the minimum semantic handoff
   Alchemist needs. Do not normally write implementation bodies.
```

---

# Part XVIII — What must not be weakened

This synthesis is not permission to:

- treat missing evidence as a pass;
- let Alchemist invent product semantics;
- skip architecture for irreversible or authority-sensitive choices;
- ignore demonstrated security, safety, privacy, compliance, or data-integrity failures;
- use YAGNI to erase known high-consequence risks;
- average away mandatory failures — **or weighted-score across a set containing dominated candidates**;
- **skip dominance elimination or the failure story for speed at STANDARD rigor or above**;
- **self-upgrade the objective** — `BEST_SHAPE` is granted, never assumed;
- silently expand scope;
- accept risk without authority;
- auto-approve a critical design because the review budget expired;
- claim a benchmark proves a larger system boundary than it tested;
- copy a famous architecture without matching local drivers and economics;
- allow prototypes to become production architecture without re-evaluation;
- turn the full lens catalogue into mandatory checklist architecture;
- let architecture documents drift into implementation plans and code;
- **run the full assurance chain on routine bounded work** — proportionality is load-bearing; universal ceremony recreates the documented harm.

Keep the distinction:

```text
ARCHITECTURE READINESS
Do we know enough to make the next bounded commitment or evidence task safely?

IMPLEMENTED-STATE ASSURANCE
Do we possess sufficient evidence to certify the resulting claim?
```

Architecture may proceed with explicit non-blocking assumptions. Oracle may not turn those assumptions into facts.

---

# Part XIX — Final canonical formulation

The central architecture:

```text
OBJECTIVE × DEPTH × RIGOR
        ↓
CANONICAL ARCHITECTURE STATE
        ↓
TAILOR → FRAME → CONTEXT → DRIVERS → MODEL → RISK → CANDIDATES
→ EVALUATE
    hard gates · scenario analysis · failure story · evidence
    · economics · dominance/Pareto · sensitivity
→ MINIMIZE
    mechanism YAGNI · distribution tax · complexity count
    · minimum-sufficient selection
→ DESCRIBE → ASSURE → FREEZE → EXECUTE
```

Under six laws:

```text
NO MATERIAL DELTA → NO REPEAT
FROZEN → REOPEN ONLY ON ADMISSIBLE EVIDENCE
INVALIDATION = CAUSE + SCOPE
RISK ACCEPTANCE REQUIRES AUTHORITY
EMPIRICAL UNCERTAINTY → SPIKE / TRACER
BUDGET EXHAUSTION → TERMINAL STATE
```

> **Legion's architecture process is a governed, evidence-driven, bounded decision system — not an optimization loop and not a technology-pattern generator.**
>
> **Start with the decision, mission, scope, authority, objective, and consequence. Treat only consequential choices as architecture. Convert quality labels into measurable scenarios. Model responsibilities, information authority, invariants, trust, failure, ownership, and likely change before selecting technologies. Generate status quo, simpler, and genuinely different candidates in proportion to the decision — each with its failure story. Apply hard gates before preferences, discard dominated options before weighing survivors, attach evidence and uncertainty to claims, and choose the lowest justified lifecycle complexity that satisfies the prioritized thresholds.**
>
> **Resolve only decisions required for the next safe, reversible, verifiable increment. Type remaining uncertainty instead of erasing it. Stop gathering information when more evidence is unlikely to change the decision or risk treatment. Freeze accepted decisions. Treat review as consumptive. Use prototypes, tests, models, benchmarks, and tracer slices to resolve empirical uncertainty. Reopen only the smallest invalidated cone — naming both cause and scope — when new material evidence, changed authority, or failed assumptions require it. Three revisions is the ceiling everywhere; the third buys a decision, a spike, or an escalation — never a fourth revision.**
>
> **Sage owns architectural recommendation and semantic commitment. Alchemist owns bounded transformation. Oracle owns independent assurance of actual state. Covenant advises over immutable evidence. Arcane enforces budgets, fingerprints, receipts, and legal state transitions. Humans or accountable institutions retain mission, requirement, policy, and risk-acceptance authority.**
>
> **The default transition after sufficient architecture is execution.**

---

# Selected evidence spine

The Canonical Evidence-Driven Software Architecture Framework remains the architecture-method source; its standards and methods live in a separate bibliography/status module and are rechecked before regulated or contractual use. Key families: ISO/IEC/IEEE 42010 (architecture descriptions), 42020 (processes), 42030 (evaluation); ISO/IEC 25010/25019/25030/25002/25040/25012 (quality and data quality); ISO/IEC/IEEE 29148 (requirements); SEI QAW, ADD, ATAM, CBAM; NIST security/resilience/privacy/secure-development guidance; NASA decision-analysis guidance; foundational work on modularity and information hiding (Parnas), architecture descriptions and multiple views, architecture decisions, the end-to-end argument, and CAP/consistency trade-offs; socio-technical, uncertainty, architecture-debt, and architecture-evolution research.

Agent-skill repositories remain operational research sources — routing, retry discipline, progressive disclosure, templates, execution-loop controls — not the architecture canon. The convergence layer's empirical grounding is internal: the 2026-08-12 Adapt Insights record (17 failure cards; ceremony-dominant harm; seven-revision contract churn) and the convergence doctrine gap analysis (`docs/research/2026-08-12-convergence-doctrine-gap-analysis.md`).
