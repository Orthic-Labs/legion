# Legion Semantic Decision Ledger — Phase A v1.1

**Status:** FINAL PHASE A — semantic freeze before mechanical migration  
**Repository:** `Orthic-Labs/legion`  
**Baseline:** `57d00b1f`  
**Purpose:** remove all architectural, ownership, capability, authority, routing, and policy ambiguity before Phase B produces a file-by-file migration manifest.

This ledger merges the broader live-repository review in `LEGION-SEMANTIC-DECISION-LEDGER.md` with the previously agreed Legion architecture decisions and closes the remaining ambiguity around executable-contract authorship and capability taxonomy.

## Authority of this artifact

This is a **migration decision artifact**, not the permanent Legion root SSOT.

During Phase B:

- these decisions are frozen;
- the executor may not reinterpret them;
- unexpected contradictions become `SEMANTIC_BLOCKER`, not invitations to redesign Legion;
- useful method is migrated before superseded owners are retired;
- generated projections are regenerated from canonical sources rather than hand-edited.

After Phase B, these decisions are folded into the final root SSOT and this ledger becomes provenance.

---

# A. Root, constitution, and ownership

## D-001 — Final root SSOT

**CURRENT CONFLICT**  
`docs/LEGION-CANONICAL-SSOT-v2.md`, `docs/architecture.md`, and `doctrine/architecture/canon-map.md` currently make overlapping architecture/authority claims.

**FROZEN TARGET**  
Legion has one permanent root system-architecture source of truth:

```text
docs/LEGION-CANONICAL-SSOT.md
```

`docs/LEGION-CANONICAL-SSOT-v2.md` is input to the migration, not a filename or version that must remain canonical after adoption.

The root SSOT owns:

- system architecture;
- ownership boundaries;
- global invariants;
- orchestration semantics;
- capability/authority/effect relationships;
- canonical-owner delegation;
- globally binding architectural decisions.

It delegates specialist method rather than duplicating it.

**CANONICAL OWNER**  
`docs/LEGION-CANONICAL-SSOT.md`

**CONSEQUENCES**  
No other file may co-own “Legion architecture”.

**COMPATIBILITY**  
The v2 draft may remain as migration provenance after adoption but must leave active normative loading paths.

**EVIDENCE**  
`docs/LEGION-CANONICAL-SSOT-v2.md`; `docs/architecture.md`; `doctrine/architecture/canon-map.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-002 — Legion operational constitution

**CURRENT CONFLICT**  
`AGENTS.md` presents itself as the live Legion constitution while other doctrine claims an external operator source owns identity and routing.

**FROZEN TARGET**  
`AGENTS.md` owns Legion's live operational constitution:

- Legion identity;
- orchestration mandate;
- live scope rules;
- package-level invariants;
- delivery behavior;
- global operational policy.

It is constrained by the root SSOT.

**CANONICAL OWNER**  
`AGENTS.md`

**CONSEQUENCES**  
No external unpublished “operator source” may outrank the shipped constitution.

**COMPATIBILITY**  
Generated overlays may project `AGENTS.md`; they do not become owners.

**EVIDENCE**  
`AGENTS.md`; `doctrine/legion.md`; `doctrine/architecture/canon-map.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-003 — `doctrine/legion.md` is delegated routing reference

**CURRENT CONFLICT**  
`doctrine/legion.md` currently says an operator-supplied agent-rules source is the sole source for Legion identity, authority, routing and scope, conflicting with `AGENTS.md` and the intended in-repo ownership model.

**FROZEN TARGET**  
`doctrine/legion.md` is delegated routing/reference doctrine only.

It may explain:

- routing reference;
- role engagement;
- handoff relationships;
- orchestration reference patterns.

It does not own or generate Legion identity, authority or constitution.

**CANONICAL OWNER**  
Delegated under `AGENTS.md` and the root SSOT.

**CONSEQUENCES**  
External-source supremacy claims and phantom ownership references are retired.

**COMPATIBILITY**  
The file may remain as a compact routing reference.

**EVIDENCE**  
`doctrine/legion.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-004 — Canon map is derived, never normative

**CURRENT CONFLICT**  
`doctrine/architecture/canon-map.md` declares authority while containing old Sage ownership and stale pre-`src/` Arcane paths.

**FROZEN TARGET**  
`canon-map.md` is not an architecture authority.

If retained, it is a derived conformance/projection artifact recording:

- concept;
- canonical owner location;
- generated consumers;
- runtime producer;
- checks;
- fingerprints.

Its meaning is derived from canonical owners.

**CANONICAL OWNER**  
Root SSOT for system ownership; specialist owners for delegated method.

**CONSEQUENCES**  
A stale canon-map row can never override its source owner.

Phase B may retain, generate, shrink, or retire this file according to actual consumers, but may not preserve it merely because it exists.

**COMPATIBILITY**  
Existing drift checks may continue consuming a derived canon map.

**EVIDENCE**  
`doctrine/architecture/canon-map.md`; `src/packages/arcane/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-005 — Role identity and role method are separate owners

**CURRENT CONFLICT**  
Roster files, doctrine files and recovered bundles duplicate role identity, authority, method and model policy.

**FROZEN TARGET**  

```text
src/roster/sage.md
src/roster/alchemist.md
src/roster/oracle.md
```

own:

- role identity;
- authority boundary;
- trigger boundary;
- model-policy tier.

Delegated doctrine owns detailed operating method only.

**CANONICAL OWNER**  
`src/roster/*.md` for identity/authority; `doctrine/*.md` for delegated method.

**CONSEQUENCES**  
Doctrine must not recreate a second role identity.

**COMPATIBILITY**  
Detailed method remains in doctrine where useful.

**EVIDENCE**  
`src/roster/README.md`; `src/roster/*.md`; `doctrine/{sage,alchemist,oracle}.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-006 — Specialist method delegation

**CURRENT CONFLICT**  
Historical global architecture and role bundles contain still-useful specialist method alongside obsolete ownership claims.

**FROZEN TARGET**  
Useful method is re-homed to the specialist that actually owns it before the old owner is retired.

Examples:

```text
architecture method      → architect / doctrine/architecture/**
diagnostic method        → debugger
audit method             → audit
visual capture/QA method → qa / audit-visual as appropriate
dispatch worker method   → Legion orchestration / dispatch
```

**CANONICAL OWNER**  
The selected specialist capability or orchestration concern.

**CONSEQUENCES**  
Retirement is never delete-first.

**COMPATIBILITY**  
Historical documents may remain archived as provenance.

**EVIDENCE**  
`docs/architecture.md`; `doctrine/bundles/*`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# B. Orchestration, capability, and authority

## D-007 — Legion is the only always-on orchestrator

**CURRENT CONFLICT**  
Historical routing language makes engineering roles and peer domains resemble parallel orchestration layers.

**FROZEN TARGET**  
Legion is the only always-on orchestrator.

Sage, Alchemist, Oracle, Covenant, Audit, Architect, Debugger, Arcane and all other components are selected/attached concerns, not peer orchestrators.

**CANONICAL OWNER**  
Root SSOT + `AGENTS.md`

**CONSEQUENCES**  
No second routing/control hierarchy may form around a role or domain.

**COMPATIBILITY**  
Deterministic slash aliases may invoke internal concerns without changing ownership.

**EVIDENCE**  
`AGENTS.md`; `docs/LEGION-CANONICAL-SSOT-v2.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-008 — Work units/work graphs are the primary orchestration abstraction

**CURRENT CONFLICT**  
Historical stage/mode/domain routing encodes process through role or domain identity rather than explicit work semantics.

**FROZEN TARGET**  
Legion decomposes non-trivial work into a work graph of work units.

A work unit expresses:

```text
capabilities
operations
effects
dependencies
authority state only where required
bounds/checkpoints only where required
```

**CANONICAL OWNER**  
Legion orchestration.

**CONSEQUENCES**  
Work is modeled by what must happen, not by which role name matched first.

**COMPATIBILITY**  
Simple requests may execute directly without durable work-unit artifacts.

**EVIDENCE**  
Draft SSOT work-unit sections; current dispatch/contracts machinery.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-009 — Capability and authority are orthogonal

**CURRENT CONFLICT**  
Current Architect→Sage, Debugger→Sage and mutation→Alchemist routes infer authority from capability/operation.

**FROZEN TARGET**  
A capability answers:

> What expertise, method, contextual procedure, or reusable workflow is required?

Authority answers:

> Does this particular work require exceptional adjudication, controlled transformation, or independent assurance?

Capability identity never statically determines authority.

**CANONICAL OWNER**  
Root SSOT.

**CONSEQUENCES**  
Authority attaches to work, not to a domain tree or skill parent.

**COMPATIBILITY**  
Explicit authority invocation remains possible.

**EVIDENCE**  
`skills/architect/SKILL.md`; `skills/debugger/SKILL.md`; roster doctrine.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-010 — Capabilities own routine domain judgment

**CURRENT CONFLICT**  
Historical role routing moves normal architecture and diagnosis decisions to Sage.

**FROZEN TARGET**  
A capability owns the routine judgment required by its own valid method.

Examples:

- Architect decides routine architecture trade-offs.
- Debugger evaluates routine root-cause hypotheses.
- Designer decides routine design hierarchy and craft.
- Research selects routine evidence methods.
- Marketing makes routine marketing strategy decisions.
- Audit adjudicates findings inside its method.

**CANONICAL OWNER**  
Each capability's canonical method owner.

**CONSEQUENCES**  
Judgment alone is not an authority trigger.

**COMPATIBILITY**  
Sage remains attachable on exceptional unresolved judgment.

**EVIDENCE**  
Draft SSOT capability/authority sections.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-011 — Sage is exceptional adjudication authority only

**CURRENT CONFLICT**  
Current Sage identity is “Engineering decision authority” with Diagnose, Architect and Execution Compile routes.

**FROZEN TARGET**  
Sage has one semantic purpose:

> Attach when a material unresolved decision cannot be safely closed under the selected capability's routine mandate.

Sage is domain-independent.

Sage does not own:

- architecture;
- debugging;
- research;
- design;
- marketing;
- SEO;
- ordinary strategy;
- contract compilation as a discipline.

**CANONICAL OWNER**  
`src/roster/sage.md` for identity/authority; `doctrine/sage.md` for adjudication method.

**CONSEQUENCES**  
“Engineering decision authority”, “Sage Architect”, “Sage Diagnose” and Sage-as-default-contract-compiler are retired.

**COMPATIBILITY**  
Authority identity `SAGE` may remain in frozen contracts/runtime vocabulary.

**EVIDENCE**  
`src/roster/sage.md`; `doctrine/sage.md`; `agents/sage.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-012 — Architect is a first-class engineering capability

**CURRENT CONFLICT**  
`skills/architect/SKILL.md` currently declares itself a public entrypoint to Sage Architect and disclaims owning the method.

**FROZEN TARGET**  
Architect owns software/system architecture craft, including:

- context and boundaries;
- architecture-significant requirements;
- quality attributes/scenarios;
- responsibility allocation;
- interfaces/contracts;
- invariants;
- state/data authority;
- consistency/lifecycle;
- runtime/deployment topology;
- architecture tactics;
- alternatives/trade-offs;
- ADRs where warranted;
- migration/evolution;
- architectural risk;
- simplest-sufficient architecture.

**CANONICAL OWNER**  
`skills/architect/SKILL.md` + `doctrine/architecture/**`

**CONSEQUENCES**  
Architect no longer routes through Sage for routine decisions.

**COMPATIBILITY**  
`/architect` remains.

**EVIDENCE**  
`skills/architect/SKILL.md`; `doctrine/bundles/sage-architect.md`; `doctrine/architecture/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-013 — Debugger is a first-class diagnosis capability

**CURRENT CONFLICT**  
`skills/debugger/SKILL.md` routes debugging to Sage Diagnose.

**FROZEN TARGET**  
Debugger owns:

- reproduction;
- bounded evidence collection;
- hypothesis formation;
- disconfirmation;
- isolation;
- root-cause determination;
- routine repair selection;
- repair verification.

Sage joins only when evidence exposes a material unresolved semantic/ownership/acceptance decision.

**CANONICAL OWNER**  
`skills/debugger/SKILL.md` + debugger-owned references.

**CONSEQUENCES**  
Useful `sage-diagnose` method is re-homed to Debugger; Sage Diagnose terminology retires.

**COMPATIBILITY**  
`/debugger` remains.

**EVIDENCE**  
`skills/debugger/SKILL.md`; `doctrine/bundles/sage-diagnose.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-014 — Executable-contract authorship is orchestration, not Sage authority

**CURRENT CONFLICT**  
Current Sage owns “Execution Compile”: turning settled meaning into EXACT/BOUNDED/OPEN execution contracts. Once Sage is exceptional-only, contract authorship would otherwise become ownerless or keep Sage as a mandatory stage.

**FROZEN TARGET**  
Legion + the producing capability materialize settled meaning into the executable work unit/contract.

Sage participates only when an item remains genuinely OPEN and requires exceptional adjudication.

Canonical flow:

```text
capability settles routine meaning
        ↓
Legion materializes work unit / executable contract
        ↓
OPEN semantic item?
  yes → Sage adjudicates that item
  no  → continue
        ↓
controlled execution if policy requires
        ↓
Alchemist
```

`EXACT / BOUNDED / OPEN` and `open_questions == []` may survive as useful execution semantics.

**CANONICAL OWNER**  
Legion orchestration/work-unit contract layer.

**CONSEQUENCES**  
Sage “Execution Compile” route is retired.

**COMPATIBILITY**  
Existing frozen contract schemas/mechanics may remain if their semantics fit this ownership.

**EVIDENCE**  
`src/roster/sage.md`; `doctrine/sage.md`; `src/packages/contracts/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-015 — Alchemist is controlled transformation authority

**CURRENT CONFLICT**  
Historical language can imply every mutation requires Alchemist and an executable contract.

**FROZEN TARGET**  
Alchemist owns bounded transformation of already-decided meaning **when policy requires a controlled execution authority boundary**.

It does not own ordinary permitted mutations by default.

**CANONICAL OWNER**  
`src/roster/alchemist.md` for identity/authority; `doctrine/alchemist.md` for method.

**CONSEQUENCES**  
Alchemist becomes policy-triggered rather than universally stage-triggered.

**COMPATIBILITY**  
`/alchemist` remains a compatibility entrypoint.

**EVIDENCE**  
`src/roster/alchemist.md`; `doctrine/alchemist.md`; `skills/alchemist/SKILL.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-016 — Ambient execution is the default permitted mutation path

**CURRENT CONFLICT**  
Role-chain doctrine competes with `AGENTS.md`'s existing ambient scope rule.

**FROZEN TARGET**  
Ordinary explicit, reversible, in-scope effects may execute directly under Legion/capability control when Arcane policy permits them.

Alchemist is used only where policy, locking, explicit contracting, or risk requires it.

**CANONICAL OWNER**  
Legion orchestration + Arcane effect policy.

**CONSEQUENCES**  
`execute` does not imply Alchemist.

**COMPATIBILITY**  
Contract chain remains for governed work.

**EVIDENCE**  
`AGENTS.md` ambient scope rule; Alchemist doctrine.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-017 — Arcane owns deterministic effect enforcement

**CURRENT CONFLICT**  
Older documentation calls Arcane “the control plane” while Legion also owns orchestration/control.

**FROZEN TARGET**  

```text
Legion = orchestration
Arcane = deterministic effect enforcement
```

Arcane owns:

- effect classification;
- deterministic gates;
- receipts;
- evidence freshness/staleness;
- deterministic state/control validation.

Arcane does not choose capability, architecture, strategy, or user intent.

**CANONICAL OWNER**  
`src/packages/arcane/**` for implementation; root SSOT for jurisdiction boundary.

**CONSEQUENCES**  
Do not use “control plane” ambiguously for both.

**COMPATIBILITY**  
Existing Arcane effects/gates/receipts remain.

**EVIDENCE**  
`docs/architecture.md`; `src/packages/arcane/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-018 — Oracle owns independent assurance

**CURRENT CONFLICT**  
Oracle doctrine currently overlaps broader Audit/QA method.

**FROZEN TARGET**  
Oracle owns independent assurance and Completion Validation.

Oracle:

- is read-only;
- does not implement;
- does not own architecture;
- does not own Audit methodology;
- does not certify its own fix.

Existing universal Oracle Completion Validation remains current policy during this migration.

**CANONICAL OWNER**  
`src/roster/oracle.md` + delegated `doctrine/oracle.md`

**CONSEQUENCES**  
Broader evaluation method is moved to the appropriate capability.

**COMPATIBILITY**  
Universal Completion Validation remains unchanged unless a separate policy change explicitly addresses it later.

**EVIDENCE**  
`src/roster/oracle.md`; `doctrine/oracle.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-019 — Covenant is challenge, not authority

**CURRENT CONFLICT**  
Some legacy language treats Covenant like a fourth authority/role while the roster excludes it.

**FROZEN TARGET**  
Covenant is:

- optional;
- bounded;
- advisory;
- read-only;
- policy/user-triggered;
- not the default reviewer;
- without disposition/effect authority.

**CANONICAL OWNER**  
`doctrine/covenant-seat.md`; lens files own delegated challenge method.

**CONSEQUENCES**  
Covenant does not join the authority roster.

**COMPATIBILITY**  
`/covenant` may remain an explicit/internal compatibility entrypoint.

**EVIDENCE**  
`doctrine/covenant-seat.md`; `src/roster/README.md`; current canon-map Covenant row.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# C. Evaluation, QA, and review ownership

## D-020 — Audit owns systematic evaluation methodology

**CURRENT CONFLICT**  
Audit method is split among `skills/audit/**`, global `docs/architecture.md`, and Oracle “broader audit” language.

**FROZEN TARGET**  
Audit owns:

- scope freeze;
- audit planning;
- provider/check selection;
- evidence collection;
- coverage accounting;
- candidate generation;
- methodological adjudication;
- finding classification;
- deduplication;
- typed degradation;
- reports/SARIF;
- rerun/reproducibility;
- evidence loci;
- completeness accounting.

**CANONICAL OWNER**  
`skills/audit/**` plus its declared provider/reference owners.

**CONSEQUENCES**  
Useful global audit method is migrated into Audit ownership before old global docs retire.

**COMPATIBILITY**  
`/audit` remains.

**EVIDENCE**  
`skills/audit/SKILL.md`; `docs/architecture.md`; `doctrine/oracle.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-021 — Audit internal verification is not Oracle

**CURRENT CONFLICT**  
Independence rules inside Audit can be misread as assurance authority.

**FROZEN TARGET**  
Audit may contain methodological independence such as:

> a generator cannot close its own finding.

That remains an Audit method invariant.

It does not turn Audit into Oracle.

**CANONICAL OWNER**  
Audit method.

**CONSEQUENCES**  
Methodological adjudication and independent completion assurance remain distinct.

**COMPATIBILITY**  
Existing evidence/finding independence can remain.

**EVIDENCE**  
`skills/audit/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-022 — `audit-fix` is a workflow capability

**CURRENT CONFLICT**  
`audit-fix` overlaps Audit rerun semantics and bounded remediation, and is currently projected as a domain capability.

**FROZEN TARGET**  
`audit-fix` is a **workflow capability** attached to a frozen Audit result.

It owns:

- bounded remediation of admitted findings;
- preservation of the frozen Audit plan;
- same-plan rerun;
- remediation lifecycle.

It does not own:

- Audit provider-selection methodology;
- Oracle assurance;
- Alchemist authority.

**CANONICAL OWNER**  
`skills/audit-fix/SKILL.md`

**CONSEQUENCES**  
It remains independently user-invocable without becoming an authority or domain-expertise parent/child hierarchy.

**COMPATIBILITY**  
`/audit-fix` remains public.

**EVIDENCE**  
`skills/audit-fix/SKILL.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-023 — Audit Visual, Designer, and QA are distinct

**CURRENT CONFLICT**  
Rendered-state evaluation, qualitative design critique and browser QA overlap in current bundles/doctrine.

**FROZEN TARGET**  

```text
audit-visual
→ rendered-state enumeration
→ screenshots/baselines/regression evidence
→ visual-state coverage
→ clipping/overlap/missing-state findings
→ deterministic visual evaluation

designer
→ qualitative design craft
→ hierarchy/composition/typography/interaction
→ design direction
→ remediation craft

qa
→ functional/behavioral QA
→ deterministic browser/runtime checks
→ mocks
→ contract tests
→ viewport capture as QA evidence
```

Shared capture machinery is an internal primitive, not a semantic owner.

**CANONICAL OWNER**  
`skills/audit-visual/**`; `skills/designer/**`; `skills/qa/**`

**CONSEQUENCES**  
Recovered Oracle assurance bundles do not remain duplicate owners of QA/visual method.

**COMPATIBILITY**  
All three user-facing capabilities may remain.

**EVIDENCE**  
`skills/{audit-visual,designer,qa}/**`; `doctrine/bundles/oracle-assurance.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-024 — Review ownership is concern-specific

**CURRENT CONFLICT**  
“Review” is spread across capability verification, Audit, Covenant, Oracle, Arcane and integration.

**FROZEN TARGET**  

```text
capability self-verification → method-local correctness
Audit                        → systematic evaluation methodology
Covenant                     → adversarial challenge
Oracle                       → independent assurance
Arcane                       → deterministic effect/control validity
Legion                       → integration and delivery ownership
```

There is no generic Review authority.

**CANONICAL OWNER**  
Each concern above.

**CONSEQUENCES**  
No new universal reviewer subsystem.

**COMPATIBILITY**  
Existing review mechanisms remain where correctly scoped.

**EVIDENCE**  
Roster/doctrine/capability files.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# D. Capability and entrypoint taxonomy

## D-025 — Minimal semantic taxonomy

**CURRENT CONFLICT**  
Current generated projection calls almost every public `SKILL.md` a `domain-capability`, even when it is a workflow, context provider, orchestration primitive, or role entrypoint.

**FROZEN TARGET**  
Use the smallest taxonomy that represents the actual semantics:

```text
kind: capability | entrypoint

when kind: capability
  capabilityClass: domain | workflow | context

discoverability: public | explicit | internal
```

Meaning:

```text
capability/domain
→ specialist expertise/method

capability/workflow
→ reusable user-facing procedure/stateful workflow

capability/context
→ reusable contextual input/provider

entrypoint
→ explicit compatibility or orchestration invocation surface,
  not peer semantic expertise
```

Do not add a larger ontology.

**CANONICAL OWNER**  
`SKILL.md` semantic metadata.

**CONSEQUENCES**  
Not every `SKILL.md` becomes peer domain expertise.

**COMPATIBILITY**  
The frozen host projection may continue using its current compatibility `kind` values if required by its consumer; canonical semantics are not inferred back from that lossy projection.

**EVIDENCE**  
`src/registry/host-projection.json`; `skills/*/SKILL.md`; projection generator.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-026 — Brand is a context capability

**CURRENT CONFLICT**  
`brand` and `brand-identity` are both projected as domain capabilities even though `brand` loads source-bound context.

**FROZEN TARGET**  

```text
brand
kind: capability
capabilityClass: context
discoverability: public

brand-identity
kind: capability
capabilityClass: domain
discoverability: public
```

Brand supplies source-bound context and never invents identity facts.

Brand Identity owns identity creation/evolution/design craft.

**CANONICAL OWNER**  
`skills/brand/SKILL.md`; `skills/brand-identity/SKILL.md`

**CONSEQUENCES**  
No generic utility bucket.

**COMPATIBILITY**  
`/brand` and `/brand-identity` remain.

**EVIDENCE**  
`skills/brand/**`; `skills/brand-identity/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-027 — Handoff is a workflow capability

**FROZEN TARGET**  

```text
handoff
kind: capability
capabilityClass: workflow
discoverability: public
```

It owns cross-session continuity:

- transcript/source bootstrap;
- continuation state;
- cold-start transfer;
- bounded continuity validation.

It does not delegate another executor; that is Dispatch.

**CANONICAL OWNER**  
`skills/handoff/SKILL.md`

**COMPATIBILITY**  
`/handoff` remains.

**EVIDENCE**  
`skills/handoff/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-028 — Tasklist is a workflow capability

**FROZEN TARGET**  

```text
tasklist
kind: capability
capabilityClass: workflow
discoverability: public
```

It owns same-agent executable task structuring/state.

Distinction:

```text
Tasklist → same agent
Dispatch → another executor
Handoff  → another session
```

**CANONICAL OWNER**  
`skills/tasklist/SKILL.md`

**COMPATIBILITY**  
`/tasklist` remains.

**EVIDENCE**  
`skills/tasklist/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-029 — Dispatch is an orchestration entrypoint, not a peer capability

**CURRENT CONFLICT**  
Dispatch is projected as a public domain capability even though it packages delegation mechanics.

**FROZEN TARGET**  

```text
dispatch
kind: entrypoint
discoverability: explicit
```

Dispatch is fundamentally a Legion orchestration primitive/workflow for creating validated zero-context delegation packets.

Natural-language orchestration may invoke the primitive directly without first classifying Dispatch as peer expertise.

**CANONICAL OWNER**  
Legion orchestration; `skills/dispatch/**` owns the packaged method.

**CONSEQUENCES**  
It leaves peer capability discovery.

**COMPATIBILITY**  
`/dispatch` remains deterministic.

**EVIDENCE**  
`skills/dispatch/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-030 — Commit is an explicit repository-effect workflow entrypoint

**CURRENT CONFLICT**  
Commit is projected as peer domain expertise.

**FROZEN TARGET**  

```text
commit
kind: entrypoint
discoverability: explicit
```

Commit is a guarded repository/effect workflow:

```text
freeze diff
→ review/verify
→ stage exact scope
→ commit
→ push
```

It is not domain expertise.

Natural-language “commit this” is ordinary Legion intent recognition, not capability discovery.

**CANONICAL OWNER**  
Legion repository-effect workflow; `skills/commit/**` owns packaged method.

**CONSEQUENCES**  
Commit leaves peer semantic capability discovery.

**COMPATIBILITY**  
`/commit` may remain deterministic.

**EVIDENCE**  
`skills/commit/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-031 — Coder is an explicit outsourced-analysis entrypoint

**CURRENT CONFLICT**  
Coder is publicly projected even though it is an explicit opt-in router to external API models with privacy/cost implications.

**FROZEN TARGET**  

```text
coder
kind: entrypoint
discoverability: explicit
```

It is invoked only by:

- `/coder`;
- explicit outsourced/API analysis request;
- explicit provider/model request.

It never auto-routes from generic code-analysis language.

**CANONICAL OWNER**  
`skills/coder/SKILL.md`

**CONSEQUENCES**  
No accidental paid/external model routing.

**COMPATIBILITY**  
`/coder` remains.

**EVIDENCE**  
`skills/coder/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-032 — Cortex remains a domain capability

**FROZEN TARGET**  

```text
cortex
kind: capability
capabilityClass: domain
discoverability: public
```

Cortex owns source-grounded repository mapping as a distinct semantic method/result.

Its `cortex-graph` backend is a host capability.

Cortex is not:

- the Legion capability router;
- a RAG layer;
- a general retrieval hierarchy.

**CANONICAL OWNER**  
`skills/cortex/SKILL.md`; host backend in `src/registry/capabilities.json`

**COMPATIBILITY**  
`/cortex` and `/blueprint` may remain.

**EVIDENCE**  
`skills/cortex/**`; host capability registry.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-033 — Role/challenge entrypoint semantics are data, not hard-coded identities

**CURRENT CONFLICT**  
The projection generator currently special-cases `alchemist` and `covenant` by name to classify them as internal role entrypoints.

**FROZEN TARGET**  
Semantic classification is declared in source metadata.

Conceptually:

```text
alchemist
kind: entrypoint
discoverability: explicit-or-internal
target: authority:alchemist

covenant
kind: entrypoint
discoverability: explicit-or-internal
target: challenge:covenant
```

No generator/kernel consumer special-cases those names.

**CANONICAL OWNER**  
Their source `SKILL.md` metadata.

**CONSEQUENCES**  
Future entrypoints are additive data, not code branches.

**COMPATIBILITY**  
Existing slash aliases remain.

**EVIDENCE**  
`scripts/generate-host-projection.mjs`; `skills/{alchemist,covenant}/SKILL.md`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# E. Skill metadata and semantic vocabulary

## D-034 — SKILL.md is the human-edited semantic owner

**CURRENT CONFLICT**  
Semantic metadata is split between prose bodies, manifests, generators and projections.

**FROZEN TARGET**  
For any packaged capability/entrypoint, `SKILL.md` owns the human-edited semantic contract.

Minimum semantic metadata:

```yaml
name:
description:
kind: capability | entrypoint
discoverability: public | explicit | internal

# when kind: capability
capabilityClass: domain | workflow | context

domain: engineering | research | commercial | editorial | design | null

operations:
  - route
  - analyze
  - diagnose
  - decide
  - produce
  - evaluate
  - execute

effects:
  - source-read
  - artifact-write
  - repository-write
  - process-exec
  - network-request

hostRequirements: []
```

Only fields actually required by the capability are populated.

Digests, inventories, parity and rights projections remain generated.

**CANONICAL OWNER**  
`skills/<id>/SKILL.md`

**CONSEQUENCES**  
Generated registries stop inventing semantics.

**COMPATIBILITY**  
Host projection schema need not be redesigned during this migration.

**EVIDENCE**  
`skills/*/SKILL.md`; manifests; projection generator.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-035 — MODE and DISCOVERY_PROFILE retire as global semantics

**CURRENT CONFLICT**  
Skill bodies use `MODE` and `DISCOVERY_PROFILE` values that conflate method, execution and safety.

**FROZEN TARGET**  
`MODE` and `DISCOVERY_PROFILE` are not global Legion architecture.

Their semantic jobs are replaced by:

```text
operations
effects
discoverability
hostRequirements
capability/entrypoint classification
```

Specialist-local labels may survive only when a real internal consumer requires them.

**CANONICAL OWNER**  
Root SSOT for global vocabulary; capability owner for specialist-local method.

**CONSEQUENCES**  
Effect safety is never inferred from a mode label.

**COMPATIBILITY**  
Legacy prose may mention retired values as provenance only.

**EVIDENCE**  
`skills/audit/SKILL.md`; `skills/dispatch/SKILL.md`; other skill headers.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-036 — Operations, effects and authority are independent axes

**FROZEN TARGET**  

```text
operations
→ what the work is doing

effects
→ what state interaction occurs

authority
→ exceptional responsibility/permission attached to this work
```

Never infer:

```text
diagnose → Sage
execute → Alchemist
effect X → capability Y
```

**CANONICAL OWNER**  
Root SSOT; Arcane for effect enforcement.

**CONSEQUENCES**  
Routing, effect policy and authority escalation can evolve independently.

**COMPATIBILITY**  
Existing Arcane effect vocabulary may map to canonical effect classes without a runtime rewrite.

**EVIDENCE**  
Draft SSOT; current role/mode doctrine.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-037 — Domains are metadata, not routing hierarchy

**CURRENT CONFLICT**  
`AGENTS.md` and `src/registry/routing/domains.json` encode five peer domains as the routing tree.

**FROZEN TARGET**  
Domain is optional metadata for:

- UI;
- grouping;
- evaluation;
- reporting.

It never decides routing.

**CANONICAL OWNER**  
Capability source metadata; domain projection derived.

**CONSEQUENCES**  
“Five peer domains” and “advisory domains” retire as routing constructs.

**COMPATIBILITY**  
Domain labels may remain.

**EVIDENCE**  
`AGENTS.md`; `src/registry/routing/domains.json`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# F. Routing, projections, and context economy

## D-038 — Natural-language routing is semantic over the flat catalog

**CURRENT CONFLICT**  
Current routing mixes domain-tree semantics and deterministic aliases.

**FROZEN TARGET**  
Natural-language routing:

1. interprets intent;
2. classifies against the compact complete semantic catalog;
3. selects zero, one, or many capabilities;
4. derives operations/effects/dependencies;
5. attaches authority only if required.

Slash aliases remain deterministic.

**CANONICAL OWNER**  
Legion orchestration over canonical capability metadata.

**CONSEQUENCES**  
Multi-capability requests compose directly.

**COMPATIBILITY**  
Explicit commands continue to work.

**EVIDENCE**  
`AGENTS.md`; domain registry; draft SSOT.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-039 — Generated registries are projections only

**CURRENT CONFLICT**  
Generated indexes/projections currently carry stale descriptions and sometimes identity-based classification.

**FROZEN TARGET**  
All generated registries are derived consumers.

Examples:

```text
src/registry/skills/index.json
src/registry/routing/domains.json
src/registry/host-projection.json
skills/manifests/*.json
```

They may transform canonical semantics into compatibility schemas but may not become the source of meaning.

**CANONICAL OWNER**  
Their respective source files.

**CONSEQUENCES**  
Fix source → regenerate projection.

Never hand-edit projection semantics.

**COMPATIBILITY**  
Existing host/runtime consumers remain supported.

**EVIDENCE**  
Projection generator and registries.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-040 — Host projection may be intentionally lossy during compatibility

**CURRENT CONFLICT**  
The host seam at `57d00b1f` currently consumes `public domain-capability` membership, while the canonical taxonomy now distinguishes domain/workflow/context capabilities and explicit entrypoints.

**FROZEN TARGET**  
The canonical semantic model lives in source metadata.

The existing host projection may map multiple public capability classes into its legacy compatibility shape **if required to preserve the frozen host/runtime consumer**.

That compatibility projection must not be read back as canonical taxonomy.

**CANONICAL OWNER**  
Canonical `SKILL.md` semantics; host projection as derived compatibility artifact.

**CONSEQUENCES**  
Phase A does not force a host-adapter redesign.

**COMPATIBILITY**  
`57d00b1f` host/runtime behavior remains stable.

**EVIDENCE**  
`src/lib/host/skill-projection.mjs`; `src/registry/host-projection.json`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-041 — No retrieval infrastructure for the current catalog

**FROZEN TARGET**  
At the present ~20–30 semantic entries, do not add:

- RAG;
- embeddings;
- vector search;
- graph routing;
- RDF/JSON-LD routing;
- hierarchical retrieval.

Use the flat compact catalog.

Add retrieval only after measured discovery failure.

**CANONICAL OWNER**  
Root SSOT.

**CONSEQUENCES**  
Cortex graph infrastructure remains unrelated to capability routing.

**COMPATIBILITY**  
None required.

**EVIDENCE**  
Draft SSOT and catalog scale.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-042 — Progressive loading/context economy

**FROZEN TARGET**  
Always-on Legion context contains only what is needed for:

- constitution;
- compact semantic catalog;
- global invariants;
- routing.

Then load progressively:

```text
catalog
→ selected SKILL.md
→ required specialist references/tools
```

The root SSOT is authoritative without being injected wholesale into every turn.

**CANONICAL OWNER**  
Legion orchestration/context policy.

**CONSEQUENCES**  
Semantic correctness does not require prompt bloat.

**COMPATIBILITY**  
Existing progressive-load patterns remain.

**EVIDENCE**  
Current skill/reference structure and draft SSOT.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# G. Execution substrate, governance, and compatibility

## D-043 — Bounded execution substrate is conditional, not universal ceremony

**CURRENT CONFLICT**  
Recovered worker/dispatch doctrine can read as if GoalRoute, Minimize, contracts and checkpoints wrap routine work.

**FROZEN TARGET**  
Typed terminals, numeric budgets, same-failure stop, checkpoints and resumability are execution substrate used where justified:

- locked/governed work;
- contracted work;
- dispatched workers;
- expensive/retry-prone work;
- resumable long-running work.

Ambient routine work does not require the full ceremony.

**CANONICAL OWNER**  
Legion work-unit execution substrate; Arcane for deterministic enforcement within its jurisdiction.

**CONSEQUENCES**  
No process for process's sake.

**COMPATIBILITY**  
Existing validators/GoalRoute/checkpoint machinery remains for scoped use.

**EVIDENCE**  
`doctrine/bundles/legion-worker-capsule.md`; dispatch/contracts machinery.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-044 — Complexity burden of proof

**FROZEN TARGET**  
Global order of preference:

```text
remove
→ reuse
→ inherit
→ adapt
→ add
```

Any new boundary/mechanism must pass:

- real driver;
- reuse test;
- one-fewer-moving-part test;
- retirement test.

**CANONICAL OWNER**  
Root SSOT.

**CONSEQUENCES**  
No replacement is complete while its superseded mechanism remains an active peer.

**COMPATIBILITY**  
Historical provenance may remain archived.

**EVIDENCE**  
Architecture doctrine and prior agreed Legion principles.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-045 — Capability federation / thin kernel

**FROZEN TARGET**  
Adding a capability should normally be additive:

```text
new capability package
+ canonical metadata
+ generated projections/evals
```

The orchestration kernel should not special-case capability identities unless a generic seam demonstrably fails.

**CANONICAL OWNER**  
Root SSOT.

**CONSEQUENCES**  
Identity-based switches are a smell and require justification.

**COMPATIBILITY**  
Existing unavoidable compatibility mappings may remain until generic metadata replaces them.

**EVIDENCE**  
Projection generator role-entrypoint special-case; agreed capability federation rule.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-046 — Model policy is tiered; concrete models are host configuration

**CURRENT CONFLICT**  
Roster uses abstract model tiers while doctrine/projections/worker profiles sometimes name concrete vendor models.

**FROZEN TARGET**  
Canonical architecture, role identity and generic capability doctrine use abstract model classes/tiers where model strength matters.

Concrete provider/model IDs belong to host/runtime configuration, except when a capability's explicit purpose is to invoke a user-selected named provider/model.

Examples:

```text
Sage      → frontier-judgment
Alchemist → balanced-executor / mechanical-cheap where safe
Oracle    → independent-assurance-capable tier
```

A capability such as `coder` may accept an explicit provider/model requested by the user, but does not canonically force one vendor.

**CANONICAL OWNER**  
Roster for role tiers; host config for concrete models.

**CONSEQUENCES**  
Vendor changes do not require semantic doctrine rewrites.

**COMPATIBILITY**  
Provider/model examples may remain clearly non-normative.

**EVIDENCE**  
`src/roster/README.md`; roster frontmatter; doctrine/worker profiles.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-047 — Compatibility preserves interface, not ontology

**FROZEN TARGET**  
A compatibility alias may preserve:

- slash command;
- external invocation path;
- legacy packet/schema reader;
- migration surface.

It may not preserve incorrect semantic ownership.

Examples:

```text
/alchemist → authority:alchemist
/covenant  → challenge:covenant
/dispatch  → orchestration:dispatch
/commit    → workflow:commit
```

**CANONICAL OWNER**  
The target concern.

**CONSEQUENCES**  
Compatibility shims are not capabilities merely because they have a SKILL package.

**COMPATIBILITY**  
Explicit shims may remain until consumers disappear.

**EVIDENCE**  
Role/dispatch/commit skill packages.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# H. Frozen boundaries, stale provenance, and retirement

## D-048 — Host/runtime freeze is behavioral, not semantic ownership

**CURRENT CONFLICT**  
“Freeze the host/runtime work” can be misread as freezing every projection label or preventing the semantic layer from being corrected.

**FROZEN TARGET**  
During the SSOT migration, preserve the behavior and safety guarantees delivered by `57d00b1f`:

- descriptor-driven host seam;
- canonical public-membership consumption;
- collision-safe/reversible install;
- truthful host fidelity;
- adapter detection behavior;
- legacy-writer quarantine;
- conformance/safety guarantees.

The host layer does not get to define the canonical capability ontology.

**CANONICAL OWNER**  
Host/runtime files for host integration behavior; semantic owners for meaning.

**CONSEQUENCES**  
Phase B may regenerate compatible projections but does not redesign adapters.

**COMPATIBILITY**  
Current host projection schema may remain.

**EVIDENCE**  
Commit `57d00b1f`; `src/lib/host/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-049 — Arcane/contracts freeze is scoped to current semantics, not permanent implementation freeze

**CURRENT CONFLICT**  
A broad “Arcane is frozen” statement would conflict with separately planned Arcane performance/security work.

**FROZEN TARGET**  
For the SSOT semantic migration only:

- preserve current authority identity strings required by contracts;
- preserve current effect-policy semantics unless a migration is strictly representational;
- do not redesign Arcane;
- do not fold the separate verified-prefix ledger/performance work into this migration.

Arcane may evolve in its own later workstream.

**CANONICAL OWNER**  
Root SSOT for boundary; `src/packages/arcane/**` and `src/packages/contracts/**` for current mechanics.

**CONSEQUENCES**  
Semantic migration and Arcane optimization remain separate.

**COMPATIBILITY**  
Current contracts remain usable.

**EVIDENCE**  
`src/packages/{arcane,contracts}/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-050 — Stale external provenance and superseded owners cannot constrain canon

**CURRENT CONFLICT**  
Contracts and doctrine contain references to old outer-workspace or superseded architecture documents, including historical `docs/plans/legion/*` authority references.

**FROZEN TARGET**  
Historical/external plan references are provenance only unless the current in-repo SSOT explicitly delegates authority to them.

Canonical meaning lives in the in-repo owner graph:

```text
root SSOT
AGENTS.md
SKILL.md / specialist refs
src/roster/*
doctrine delegated by those owners
src/packages/* runtime mechanics
generated projections
```

Phase B must:

1. migrate useful method;
2. repoint or remove stale authority references;
3. retire superseded active owners;
4. preserve provenance only where useful.

No implementation executor may revive an old plan because a stale reference still names it.

**CANONICAL OWNER**  
Current in-repo owners defined by this ledger and the final SSOT.

**CONSEQUENCES**  
Expected retirement/re-homing candidates include, subject to actual consumers:

```text
docs/architecture.md
docs/LEGION-CANONICAL-SSOT-v2.md after final adoption
old Sage Architect/Diagnose ownership bundles
oracle-assurance duplicate method
legion-worker-capsule material after re-homing
stale canon-map authority rows
stale outer-workspace plan references
```

**COMPATIBILITY**  
Archived provenance may remain outside active semantic loading paths.

**EVIDENCE**  
`docs/architecture.md`; `doctrine/bundles/*`; `doctrine/architecture/canon-map.md`; `src/packages/contracts/**`

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---


# I. Legacy semantic residue and migration acceptance

## D-051 — Bare G-rule numbers have no surviving normative authority

**CURRENT CONFLICT**  
Active doctrine and generated agent material still cite bare historical rule identifiers such as:

```text
G5
G7
G8
G9
G10
G12
G13
G14
G15
G16
G17
G22
G24
```

Their defining Architecture Book is being retired, while useful rule content is partially restated under newer owners.

**FROZEN TARGET**  
A bare `G<number>` identifier is provenance only.

Every surviving rule meaning is re-homed as ordinary owned method/invariant text under the canonical owner of its subject.

The migration must create an explicit mechanical mapping:

```text
legacy G-rule
→ surviving meaning
→ canonical owner
→ active source path
→ disposition of old reference
```

No executor may infer the meaning of an unresolved G-number from memory or surrounding prose.

**CANONICAL OWNER**  
The canonical owner of the rule's subject.

Examples include:

```text
dispatch/delegation rules → Legion orchestration / dispatch method
Covenant challenge rules  → covenant-seat
Oracle assurance rules    → Oracle method
Alchemist execution rules → Alchemist method
Sage adjudication rules   → Sage method
```

**CONSEQUENCES**  
Active doctrine may not depend on a bare G-number after migration.

If rule content survives, the owned text survives; the historical number need not.

**COMPATIBILITY**  
G-numbers may remain in archived provenance or migration notes.

**EVIDENCE**  
Current references appear across `doctrine/{sage,alchemist,oracle,covenant-seat}.md`, `agents/*.md`, and recovered bundles such as `doctrine/bundles/legion-worker-capsule.md`.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-052 — Legacy routing consumers cannot preserve the retired routing architecture

**CURRENT CONFLICT**  
The retired five-domain and regex-routing semantics exist not only in prose/projections but in live routing consumers, including current code/tests that hard-code domain identities, domain leaf rules, and natural-language regex mappings.

Known examples include:

```text
src/lib/routing/loader.mjs
src/lib/routing/validator.mjs
src/lib/skills/resolver.mjs
src/registry/routing/domains.json
tests/routing.test.mjs
skills/*/evals/evals.json
```

**FROZEN TARGET**  
No runtime loader, validator, resolver, test fixture, eval, generated registry, or compatibility helper may independently preserve the retired routing ontology.

After migration:

```text
semantic routing
→ compact canonical catalog
→ 0..N capability selection
→ work-graph composition
```

Domains remain grouping metadata only.

Deterministic explicit aliases remain aliases only.

Legacy regex positives may survive as **evaluation examples**, not as the routing algorithm.

**CANONICAL OWNER**  
Legion orchestration over the canonical SKILL metadata catalog.

**CONSEQUENCES**  
A documentation-only migration is invalid.

Every live consumer encoding:

- exactly five canonical routing domains;
- engineering-vs-advisory leaf rules;
- role-as-domain-leaf semantics;
- natural-language regex routing as primary classifier;

must either migrate, become a derived grouping consumer, or retire.

**COMPATIBILITY**  
Explicit slash/compatibility aliases remain deterministic.

**EVIDENCE**  
Live-repo review identified fixed domain sets/rules in routing loader/validator code and a `NATURAL_ROUTES` table in `src/lib/skills/resolver.mjs`, plus matching routing tests/evals.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-053 — Canonical effect semantics and Arcane enforcement are separate ownership layers

**CURRENT CONFLICT**  
Current material uses overlapping effect vocabularies:

```text
legacy EFFECT_PROFILES
SSOT-level effect names
Arcane runtime/enforcement classifications
host/internal primitive labels mixed into effect-like fields
```

Examples of legacy/non-canonical labels include concepts such as:

```text
source_read
output_write
repo_write
focused_check
runtime
audit_engine
child_packet
external_research
connector
graph_engine
```

Some describe effects; others describe engines, host capabilities, checks, or internal primitives.

**FROZEN TARGET**  
There is one canonical **semantic effect-class vocabulary** defined by the root architecture model.

Capabilities declare effects only from that semantic vocabulary.

Arcane owns:

- deterministic mapping from canonical effects to runtime observations/gates;
- effect classification mechanics;
- enforcement;
- receipts;
- degradation/coverage of enforcement.

Arcane's current implementation buckets do **not** become the semantic source of truth merely because they already exist.

Non-effect concepts such as providers, engines, connectors, child packets, or host requirements are classified in their proper metadata dimensions rather than forced into `effects`.

**CANONICAL OWNER**  
Root SSOT for semantic effect classes; Arcane for runtime mapping/enforcement; SKILL.md for per-capability declarations.

**CONSEQUENCES**  
Phase B must construct an explicit deterministic migration table:

```text
legacy EFFECT_PROFILE/value
→ canonical effect class OR non-effect dimension
→ Arcane runtime mapping if applicable
```

Any legacy value that cannot be classified mechanically is a `SEMANTIC_BLOCKER`.

**COMPATIBILITY**  
Existing Arcane runtime constants/buckets may remain behind the mapping layer.

**EVIDENCE**  
Live repo contains legacy `EFFECT_PROFILES` in skill/doctrine text and a distinct Arcane runtime classification vocabulary.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-054 — Routing/discovery evals are the semantic migration acceptance gate

**CURRENT CONFLICT**  
Per-skill discovery/routing evals and routing tests currently encode some retired semantics, including expectations such as Sage Architect / Sage Diagnose routing.

Without an explicit migration gate, stale tests could either block correct architecture or be deleted without replacement.

**FROZEN TARGET**  
The migration updates the existing evaluation corpus to the frozen Phase A semantics and then uses that corpus as a primary acceptance oracle for routing/discovery behavior.

Required evaluation concerns include:

```text
public capability discovery
explicit-only entrypoints
internal entrypoints
0-capability direct answers
single-capability routing
multi-capability composition
authority not inferred from capability
domain metadata not routing
slash/compatibility aliases
negative/minimal-pair routing
retired Sage Architect / Sage Diagnose behavior
retired regex-router behavior
```

Tests/evals are evidence of required behavior **after** they are reconciled to Phase A; stale fixtures are not architectural authority.

**CANONICAL OWNER**  
Capability owners for capability-specific evals; root SSOT/Legion orchestration for routing/composition acceptance semantics.

**CONSEQUENCES**  
Phase B must distinguish:

```text
KEEP valid eval
MODIFY stale semantic expectation
ADD missing acceptance case
RETIRE obsolete architecture fixture
```

Deleting a failing old test without an equivalent semantic acceptance check is not valid migration.

**COMPATIBILITY**  
Existing eval file formats may remain unless a schema change is mechanically necessary.

**EVIDENCE**  
Live-repo review found stale Architect/Debugger expectations and routing fixtures tied to the old ontology.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

## D-055 — AGENTS.md external-generator claim is a Phase B preflight, not an open semantic decision

**CURRENT CONFLICT**  
`doctrine/legion.md` claims an out-of-repo operator source generates `AGENTS.md`/`CLAUDE.md`, while no such generator/source is present in the Legion repository.

Phase A already freezes `AGENTS.md` as the shipped canonical constitution.

**FROZEN TARGET**  
The semantic decision does not reopen:

```text
AGENTS.md = canonical shipped constitution
```

Before Phase B mutates it, the executor must inspect the actual integration/workspace environment for any external process that rewrites or projects `AGENTS.md`.

If such a process exists:

- it is a projection mechanism, not a semantic owner;
- Phase B must update the real writable canonical source or disable/repoint the projection mechanism so the canonical `AGENTS.md` state persists;
- the external process may not override Phase A semantics.

If none exists, `AGENTS.md` is edited directly.

**CANONICAL OWNER**  
`AGENTS.md`

**CONSEQUENCES**  
This is an execution preflight, not an operator architecture decision.

The executor must not guess whether edits will be overwritten.

**COMPATIBILITY**  
External projection tooling may remain if it projects canonical content rather than owning it.

**EVIDENCE**  
`doctrine/legion.md` external-generator claim; no matching generator/source was found inside the reviewed Legion repository.

**CONFIDENCE**  
HIGH

**OPERATOR DECISION REQUIRED**  
NONE

---

# Minimal canonical semantic model

The migration must be able to express these distinctions without a larger ontology:

```text
LEGION
└── orchestrates WORK UNITS

WORK UNIT
├── capabilities
├── operations
├── effects
├── dependencies
└── optional authority attachment

CAPABILITY
├── domain
├── workflow
└── context

ENTRYPOINT
└── explicit/internal compatibility or orchestration invocation

AUTHORITY
├── Sage       exceptional adjudication
├── Alchemist  controlled transformation
└── Oracle     independent assurance

CHALLENGE
└── Covenant

DETERMINISTIC EFFECT ENFORCEMENT
└── Arcane
```

No parent/child role hierarchy is implied by this diagram.

---

# Canonical routing shape

```text
USER INTENT
    ↓
LEGION
    ↓
semantic classification over compact catalog
    ↓
0..N capabilities / internal entrypoints
    ↓
WORK GRAPH
    ├── operations
    ├── effects
    ├── dependencies
    └── authority only when required
            │
            ├── Sage       exceptional unresolved judgment
            ├── Alchemist  controlled transformation when policy requires
            └── Oracle     independent assurance
    ↓
Arcane gates declared effects
    ↓
execution / integration
    ↓
Oracle Completion Validation under current policy
    ↓
delivery

Covenant may be convened beside the graph as bounded advisory challenge.
```

---

# Migration blocker rule

Phase B and its executor may make **no new semantic decision**.

If implementation discovers a contradiction not resolved by this ledger:

```text
result: SEMANTIC_BLOCKER
decision_id: nearest D-XXX or NEW
paths: [...]
evidence: [...]
why_mechanical_execution_cannot_continue: ...
smallest_question_requiring_resolution: ...
```

Then stop that affected migration unit.

Do not infer, compromise, or silently preserve both meanings.

---

# Phase A semantic completeness test

## Result: PASS

If D-001 through D-050 are accepted, Phase B can be produced without making a new decision about:

- architecture;
- root ownership;
- specialist ownership;
- capability classification;
- authority semantics;
- executable-contract authorship;
- routing hierarchy;
- domain meaning;
- operation/effect separation;
- Audit/Oracle/QA/Designer boundaries;
- Sage/Architect/Debugger boundaries;
- Alchemist vs ambient execution;
- compatibility entrypoint meaning;
- projection authority;
- host/runtime semantic ownership;
- Arcane migration scope;
- model-policy ownership;
- retirement semantics;
- legacy G-rule disposition;
- live routing-consumer migration;
- canonical effect-vocabulary convergence;
- routing/discovery migration acceptance;
- AGENTS.md projection/generator preflight semantics.

**Operator semantic decisions remaining: NONE.**

**Phase B may now be mechanical.**

Phase B should contain only:

```text
Decision ID
File
Disposition: KEEP | MODIFY | MIGRATE | GENERATE | RETIRE
Exact source semantics
Exact target semantics
Exact forbidden semantics
Dependencies
Validation
Stop/escalation rule
```

The Phase B author may inspect the repository to enumerate exact files and consumers, but may not alter any Phase A semantic decision.
