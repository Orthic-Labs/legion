# Legion — Canonical System Architecture, Orchestration & Assurance Doctrine

**Status:** CANONICAL — single root architecture source of truth  
**Canonical as of:** 19 August 2026  
**Scope:** Legion-wide system architecture, orchestration, capability/authority boundaries, execution substrate, deterministic effect policy, adversarial challenge, independent completion assurance, routing/discovery architecture, progressive context loading, and canonical ownership.

This document supersedes the prior active architecture documents:

- `docs/architecture.md`
- `docs/capability-architecture.md` — already deleted in the working tree; tracked history at
  commit `b84ca9e6`
- `docs/provenance/research/2026-08-17-legion-final-architecture-synthesis.md`

Those are the real repository paths. There is no `legion-architecture-restructure-revised.md` or
`capability-architecture-final.md` in this repository; earlier drafts of this document named chat
artifacts rather than files, and that error is corrected here.

After adoption, those files are **non-authoritative provenance only**. They must not remain
competing normative sources.

Retirement is not deletion-first. `docs/architecture.md` carries substantial still-valid
Audit-specific operational doctrine, and `docs/capability-architecture.md` carries the `MODE`
survey. The order is:

```text
extract surviving method to its correct canonical owner
    ↓
retire the document as a competing global architecture source
```

Surviving Audit method moves to `skills/audit/**` and its owned references before
`docs/architecture.md` leaves the active loading path.

`doctrine/architecture/canon-map.md` is **also** a superseded ownership authority in the specific
rows listed in §31 Stage 1. It is not retired as a file — it is migrated.

---

## 0. Canonical rule

This file is the canonical owner of **Legion's system architecture and ownership boundaries**.

It does **not** become a monolithic owner of every specialist method.

The root SSOT defines:

- what kinds of things exist in Legion;
- which concern owns which responsibility;
- how Legion composes work;
- how capabilities, authority, effects, challenge, and assurance relate;
- which files are canonical for specialist semantics;
- global execution and stopping invariants;
- what generated projections may and may not own;
- which architecture decisions are globally binding.

Specialist canonical owners define the detailed method inside their delegated scope.

Conflict rule:

> **When a specialist file conflicts with this document about ownership, authority, orchestration, effect semantics, or another subject governed here, this document wins. Inside a delegated specialist method, that specialist's canonical owner wins unless it violates a global invariant defined here.**

A downstream file may operationalize these rules within its owned scope. It may not silently create a second owner for the same concept.

---

# 1. The whole system in one page

```text
USER INTENT
    ↓
LEGION
always-on orchestrator
    ↓
WORK GRAPH
    ├── capability / capabilities
    ├── operation
    ├── effects
    ├── dependencies
    └── authority state where required
            │
            ├── Sage
            │   exceptional adjudication
            │
            ├── Alchemist
            │   controlled bounded transformation
            │
            └── Oracle
                independent assurance
    ↓
TOOLS / ENGINES / HOST CAPABILITIES
    ↓
ARCANE
deterministic effect enforcement
    ↓
ORACLE COMPLETION VALIDATION
current global policy: required before successful delivery
    ↓
DELIVERY

COVENANT
optional bounded adversarial challenge beside the work graph
```

The system is governed by eight primary rules:

1. **Legion is the only always-on orchestrator.**
2. **Capabilities describe expertise and method; roles do not contain skills.**
3. **Capabilities own routine domain judgment. Sage handles exceptional material unresolved judgment.**
4. **Authority is attached to the work that requires it, not statically to a domain or skill.**
5. **Effects are explicit and deterministic effect policy belongs to Arcane.**
6. **Evaluation methodology is not the same as independent assurance.**
7. **Complexity carries the burden of proof. Add machinery only when a real driver pays for it.**
8. **Universal Oracle Completion Validation remains current Legion policy and is not changed by this refactor.**

---

# 2. The architectural correction

Legion grew from an engineering-focused system into a broader orchestration system containing engineering, research, design, writing, marketing, SEO, social, advertising, brand, and workflow capabilities.

The historical repository consequently fused several different concerns:

- engineering was organized around Sage, Alchemist, and Oracle;
- later domains were organized around skills;
- Architect became partly a Sage route instead of a standalone engineering capability;
- Audit mixed evaluation method with assurance-like semantics;
- natural-language routing existed separately from the domain registry;
- utilities, workflow primitives, context providers, and effect operations were grouped inconsistently;
- generated and hand-maintained registries could describe the same concept independently.

The correction is:

> **Orchestration, capability, authority, evaluation, effects, challenge, and deterministic control are separate concerns.**

This does not mean every concern requires a separate agent, service, prompt, process, or database.

The architecture separates **semantic ownership** while minimizing execution ceremony.

---

# 3. Legion — orchestration

**Canonical owners — one concept each, not a shared pair:**

```text
Legion operational constitution
identity, authority, scope, orchestration mandate
→ AGENTS.md

Legion routing reference
route tables, dispatch reference material
→ doctrine/legion.md
```

`AGENTS.md` is the constitution. `doctrine/legion.md` is a delegated routing reference and does
not co-own Legion identity or authority. Both are constrained by this SSOT.

Legion owns:

- interpretation of live user intent;
- route selection;
- decomposition into work units;
- capability selection and composition;
- dependency graph construction;
- delegation;
- context allocation;
- progressive loading;
- authority escalation;
- effect planning;
- application of global policy;
- integration;
- delivery.

Legion should answer directly when specialist method is unnecessary.

A user should never need to know that Sage, Alchemist, Oracle, Covenant, Arcane, Architect, Audit, or another internal component exists.

Example:

```text
User:
"Audit this repository."

Legion:
→ select Audit
→ add subject capability if required
→ build the smallest sufficient work graph
→ apply effect/authority policy
→ execute
→ obtain required Oracle Completion Validation
→ deliver
```

Routing is Legion working. It is not a separate product ontology the user must understand.

---

# 4. Work units and work graphs

The runtime planning abstraction is a **work unit**.

A work unit describes what must happen, not merely which skill name matched the prompt.

Conceptual form:

```yaml
id: competitor-evidence
capabilities:
  - research
operations:
  - analyze
effects:
  - source-read
depends_on: []
authority: auto
```

Another:

```yaml
id: launch-positioning
capabilities:
  - marketing
operations:
  - analyze
  - decide
effects: []
depends_on:
  - competitor-evidence
authority: auto
```

Another:

```yaml
id: launch-copy
capabilities:
  - writing
operations:
  - produce
effects:
  - artifact-write
depends_on:
  - launch-positioning
authority: auto
```

`authority: auto` means:

> the capability proceeds under its normal mandate unless global policy or discovered evidence requires escalation.

There is **no mandatory global**:

```text
capability routing
→ authority routing
→ execution
```

pipeline.

The work graph may discover a new authority need later.

Example:

```text
debugger
    ↓
evidence reveals two materially different valid semantics
    ↓
debugger + Sage
```

The invariant is:

> **Capability identity never statically determines authority. Authority is attached independently to the work that requires it and may change when evidence changes.**

---

# 5. Capabilities

**Canonical owner:** `skills/<id>/SKILL.md` for capability discovery semantics and method, with specialist references as delegated by that skill.

## 5.0 Two different things are called "capability"

The word is overloaded in this repository. Disambiguate it explicitly and permanently:

```text
DOMAIN CAPABILITY
expertise / method / packaged procedure
owned by skills/<id>/SKILL.md
examples: architect, audit, research, designer, seo

HOST CAPABILITY
externally supplied execution or tool facility the package does not contain
declared in src/registry/capabilities.json
examples: cortex-graph, web-search, omniroute, firecrawl
```

Unqualified "capability" in this document means **domain capability**. Host capabilities are
always named as such.

`src/registry/capabilities.json` may eventually be renamed `src/registry/host-capabilities.json`.
That rename is **not** part of this refactor; the terminology above disambiguates it without churn.
Do not perform the rename unless a measured clarity or tooling driver pays for it.

## 5.1 Domain capabilities

A capability answers:

> **What expertise, evaluation method, production method, or packaged procedure is required?**

Examples include:

- architect
- audit
- audit-visual
- audit-fix
- coder
- cortex
- debugger
- qa
- designer
- brand-identity
- research
- writing
- marketing
- seo
- ads
- social

A capability may own substantial specialized machinery.

A capability owns its **routine domain judgment**.

Examples:

- Designer may decide hierarchy, typography, spacing, composition, interaction, and visual direction.
- Architect may reason about software architecture alternatives, quality attributes, boundaries, state, interfaces, failure modes, topology, migration, and technical trade-offs.
- Research may choose appropriate study/evidence methods.
- SEO may prioritize information architecture and search opportunities.
- Marketing may select routine strategy within its domain.
- Audit may adjudicate findings as part of a valid audit method.

Routine expert judgment does **not** automatically require Sage.

---

# 6. Authority is orthogonal to capability

Roles are not parents of skills.

Skills do not belong to Sage, Alchemist, or Oracle.

Valid combinations include:

```text
architect
architect + Sage
architect + Oracle

designer
designer + Sage
designer + Oracle

research
research + Sage
research + Oracle

seo
seo + Sage
seo + Oracle

audit
audit + Oracle

audit + architect
audit-visual + designer
```

Authority is work-local.

One unit may require Sage while sibling units do not.

One request may contain:

```text
research
→ marketing + Sage
→ writing
→ Oracle
```

without turning research or writing into Sage-owned skills.

---

## 6.1 Role entrypoint skills are compatibility shims, not capabilities

Two skill bundles exist that are not domain capabilities. Both already declare themselves
entrypoints into an existing authority and disclaim owning a second system:

```text
skills/alchemist/SKILL.md
→ compatibility role entrypoint only
→ excluded from the semantic capability catalog
→ target replacement: /alchemist → authority:alchemist
→ delete the bundle when compatibility no longer requires it

skills/covenant/SKILL.md
→ compatibility challenge entrypoint only
→ excluded from the semantic capability catalog
→ target replacement: /covenant → challenge:covenant
→ delete the bundle when compatibility no longer requires it
```

There is no `skills/sage`, no `skills/oracle`, and no roster entry for Covenant. Do not create
any of them: that would recreate exactly the capability/authority coupling this document removes.

These two bundles must carry `discoverability: internal` so a public slash command does not make
an authority appear as a peer expertise capability in natural-language discovery.

---

# 7. Sage — exceptional adjudication authority

**Canonical owner:** `src/roster/sage.md`

Sage answers:

> **Does a material unresolved decision require authoritative closure beyond the selected capability's routine mandate?**

Sage is domain-independent.

Sage may be used for:

- material unresolved ambiguity;
- consequential choices the capability cannot safely settle by routine method;
- competing interpretations that materially change the outcome;
- cross-capability conflicts;
- disputed ownership or boundaries;
- acceptance-semantics decisions requiring explicit freeze;
- semantic blockers discovered during execution;
- explicit adjudication where the caller requires authoritative closure.

Sage does **not** own all judgment.

Canonical rule:

> **Capabilities own routine domain judgment. Sage owns escalation of material unresolved judgment.**

Examples:

```text
"Design a landing page."
→ designer

"Choose the layout hierarchy."
→ designer

"Choose the research methodology."
→ research normally
→ research + Sage only when material unresolved judgment exceeds routine mandate

"Compare software architectures."
→ architect

"Resolve a contested architecture decision affecting incompatible system invariants."
→ architect + Sage
```

Sage does not own architecture, diagnosis, research, design, marketing, SEO, or strategy as disciplines.

---

# 8. Architect — engineering architecture capability

**Canonical owners:**

- `skills/architect/SKILL.md`
- `doctrine/architecture/**`

`architect` remains named `architect`.

It is an **engineering capability**.

It owns software/system architecture craft, including:

- system context and technical boundaries;
- architecture-significant requirements;
- quality attributes and quality scenarios;
- responsibility allocation;
- interfaces and contracts;
- invariants;
- state/data authority;
- consistency and lifecycle;
- runtime and deployment topology;
- performance, reliability, scalability, security, operability, and architectural tactics;
- candidate software/system architectures;
- architecture-specific technical trade-offs;
- migration, modernization, compatibility, and evolution strategy;
- architecture views and ADRs where warranted;
- architecture-specific risk and assurance.

The boundary is:

```text
ARCHITECT
How should software/system architecture be reasoned about?

SAGE
Does a material unresolved decision require exceptional adjudication?
```

Do not move architecture-specific trade-off analysis into Sage merely because it requires judgment.

Do not route non-engineering uses of the verb "architect" through the engineering Architect capability.

Examples:

```text
"architect this backend"
→ architect

"architect the user experience"
→ designer

"architect the study"
→ research

"architect the SEO taxonomy"
→ seo
```

## 8.1 Architecture depth and rigor

The prior SSOT's D0/D1/D2 architecture method is **not global Legion routing**.

Architecture-specific obligations move under Architect.

Conceptually:

```text
local / no architecture decision
bounded architecture decision
whole-system architecture decision
```

The existing D0/D1/D2 labels may be retained inside Architect if they remain useful and have real consumers.

Any domain-neutral task-depth classification must be separately justified by a runtime consumer. Do not preserve a global depth enum merely because it existed historically.

## 8.2 Architecture method retained from competitor/research synthesis

The existing architecture method remains valid specialist doctrine:

- tailor rigor to consequence;
- reconstruct actual user intent;
- inspect real system state;
- identify architecture-significant drivers;
- model the whole system before selecting parts;
- compare materially distinct architectures rather than technology swaps;
- always give the evolutionary/minimum-change baseline a fair chance;
- include a simplest-sufficient candidate;
- evaluate hard constraints before preferences;
- explicitly account for failure/recovery, operations, migration, reversibility, and verifiability;
- apply a simplicity/YAGNI pass;
- stop architecting when remaining work is implementation rather than another architecture decision;
- reopen only on a material new delta.

These methods belong to **Architect**, not to Sage merely because the old system implemented Architect as a Sage route.

---

# 9. Audit — evaluation capability

**Canonical owner:** `skills/audit/**` plus its declared provider/reference owners.

Audit answers:

> **How should this subject be systematically examined, what evidence was collected, what coverage was achieved, and what findings follow?**

Audit may own:

- scope freezing;
- audit planning;
- provider/check selection;
- evidence collection;
- coverage accounting;
- candidate generation;
- methodological adjudication;
- finding classification;
- deduplication;
- typed degradation;
- report generation;
- SARIF/report projection;
- rerun information;
- evidence loci;
- completeness accounting.

Audit is not Oracle.

## 9.1 Internal verification is not independent assurance

A capability may contain verification required by its own method.

For example:

```text
scanner
→ candidate
→ independent audit-method adjudication
→ confirmed finding
```

may remain inside Audit.

A rule such as "a generator cannot close its own finding" can be an Audit methodology invariant.

Oracle answers a different question:

```text
audit result
+ raw user scope
+ actual evidence
→ did the delivered work actually satisfy the requested task?
```

Do not move every check, challenge, or adjudication rule into Oracle merely because it involves verification.

Canonical rule:

> **Evaluation methodology and independent completion assurance are separate concerns.**

---

# 10. Audit composes with subject expertise

Audit is not a universal subject-matter expert.

When a rigorous evaluation requires subject expertise, compose capabilities.

Examples:

```text
"Audit the architecture."
→ audit + architect

"Audit the SEO."
→ audit + seo

"Audit the marketing funnel."
→ audit + marketing

"Audit the research methodology."
→ audit + research

"Audit the visual design."
→ audit-visual + designer where qualitative design judgment is required
```

This creates independent dimensions:

```text
DOMAIN EXPERTISE        EVALUATION METHOD       AUTHORITY

architect         +     audit             +     Oracle
designer          +     audit-visual      +     Oracle
seo               +     audit             +     Oracle
marketing         +     audit             +     Oracle
research          +     audit             +     Oracle
```

Not every task needs all three.

---

# 11. Audit Visual — visual evaluation capability

**Canonical owner:** `skills/audit-visual/**`

Audit Visual remains a packaged capability because it owns specialized evaluation machinery.

Audit Visual owns:

- route/screen/state enumeration;
- viewport coverage;
- theme/locale/platform coverage;
- screenshot capture;
- baseline comparison;
- rendered-state coverage;
- visual regression detection;
- clipping/overflow/overlap detection;
- missing-state detection;
- capture evidence completeness;
- deterministic visual checks;
- structured findings;
- shared audit/report integration.

Designer owns qualitative visual/product design craft:

- hierarchy;
- typography;
- spacing;
- composition;
- balance;
- interaction quality;
- usability/design judgment;
- aesthetic coherence;
- design-system quality;
- remediation/design direction.

Oracle owns independent completion assurance.

Examples:

```text
"Find screenshot regressions."
→ audit-visual

"Critique this interface's visual design."
→ designer

"Perform a rigorous visual-design audit."
→ audit-visual + designer

"Independently validate that the requested visual audit is complete."
→ Oracle after the work, under current completion policy
```

Audit Visual must not absorb Designer merely because the subject is visual.

Designer must not absorb Audit Visual's coverage/capture/regression machinery merely because both work on UI.

---

# 12. Other ownership reviews

During migration, review at least:

- audit
- audit-visual
- audit-fix
- qa
- debugger
- cortex
- architect

For each meaningful rule/module ask:

> Is this orchestration, domain craft, evaluation methodology, exceptional adjudication, controlled transformation, independent assurance, effect policy, challenge, context provision, or workflow mechanics?

Do not split mechanically.

The goal is **one clear owner per concept**, not maximal fragmentation.

---

# 13. Alchemist — controlled bounded transformation authority

**Canonical owner:** `src/roster/alchemist.md`

Alchemist owns:

> **Make already-decided meaning exist where Legion policy requires controlled transformation authority.**

Alchemist:

- executes sealed/bounded work;
- applies exact or bounded transformations;
- integrates decided artifacts;
- runs declared implementation checks where the controlled flow assigns them;
- repairs mechanical failures;
- stops when continuing would require a new semantic decision;
- never self-certifies completion.

Do not infer:

```text
execute
→ Alchemist
```

mechanically.

Legion may permit ambient execution for ordinary authorized effects.

Conceptual rule:

```text
effect required
    ├── ambient effect permitted by policy
    │       → current executing capability / Legion
    │
    └── controlled / locked / contracted transformation
            → Alchemist
```

The existing ambient-versus-contract distinction survives this refactor.

---

# 14. Oracle — independent assurance authority

**Canonical owners — split by scope, not shared:**

```text
Oracle role identity and authority boundary
→ src/roster/oracle.md

Oracle Completion Validation method
→ doctrine/oracle.md
```

`src/roster/oracle.md` owns who Oracle is and what Oracle may do. `doctrine/oracle.md` owns how
Completion Validation is performed, as a method delegated by the roster entry. The same split
applies to Sage and Alchemist: `src/roster/*.md` owns identity and authority; `doctrine/*.md` owns
detailed operating method only where a method document is actually needed.

Oracle answers:

> **Does the completed result independently satisfy the raw user request and applicable completion criteria?**

Oracle does not own:

- domain methods;
- architecture decisions;
- design critique;
- audit methodology;
- implementation;
- ordinary capability self-checking.

Oracle owns structurally independent completion assurance.

## 14.1 Universal Oracle Completion Validation remains current policy

The current Legion rule requiring Oracle Completion Validation before every successful final delivery is **preserved unchanged in this architecture refactor**.

This is a policy decision separate from the capability/authority restructure.

The architecture must not encode Oracle as a property of capability identity, domain, or operation.

Instead:

```text
completed user-requested work
    ↓
current Legion completion policy
    ↓
Oracle Completion Validation
    ↓
PASS / BLOCK
    ↓
delivery
```

Whether universal Oracle is later replaced by risk-based, sampled, or another assurance policy must be evaluated separately.

Do not change that policy incidentally while migrating routing architecture.

## 14.2 Fresh-context, source-first assurance remains canonical

The competitor-derived assurance mechanics remain valid:

- Oracle is independent from the producer;
- raw user requests and corrections are authoritative;
- actual source/result is authoritative;
- producer prose is not proof;
- green test counts do not prove semantics;
- missing integration can invalidate completion;
- empty/no-op inspection cannot PASS;
- ordinary Completion Validation is not a ceremonial second test run;
- one repair and one recheck maximum absent a material new delta.

---

# 15. Covenant — adversarial challenge

**Canonical owner:** `doctrine/covenant-seat.md`

Covenant has no roster entry. The roster contains Sage, Alchemist, and Oracle only. Covenant seat
semantics — seat definition, independence requirements, packet scope, and stopping rules — are
owned by `doctrine/covenant-seat.md`.

Covenant answers:

> **What material defect, unsupported assumption, scope expansion, or avoidable complexity should prevent us from relying on this decision or blocker?**

Covenant is:

- optional unless policy requires it;
- bounded;
- advisory;
- structurally independent where independence is required;
- read-only;
- non-authorizing;
- non-certifying.

Covenant does not:

- replace Sage;
- grant execution authority;
- mutate product state;
- close Oracle findings;
- become the default reviewer for every task.

The strongest competitor-derived Covenant rules remain:

- challenge scope drift;
- challenge unnecessary new boundaries;
- challenge reuse failures;
- challenge one-more-layer complexity;
- challenge weak load-bearing assumptions;
- stop after one review + one targeted correction + one recheck absent material new evidence.

Architecture-specific Covenant review policy belongs under Architect's method, not as a universal semantic stage for every domain.

---

# 16. Arcane — deterministic effect enforcement

**Canonical owner:** `src/packages/arcane/**`

There is no top-level `packages/` directory in this repository. Arcane's policy, controls,
interfaces, and compatibility surfaces live under `src/packages/arcane/`.

Arcane is not a model role.

Arcane owns deterministic effect/policy enforcement.

Legion owns orchestration control.

Use this distinction:

```text
Legion = orchestration control
Arcane = deterministic effect enforcement
```

Effects must be declared explicitly.

Example:

```yaml
effects:
  - source-read
  - artifact-write
  - repository-write
  - process-exec
  - network-request
```

Arcane gates effects, not semantic capability labels.

Arcane should care that a unit requests `repository-write`, not whether the unit happens to be called `designer`, `architect`, or `audit-fix`.

Deterministic policy may express:

```text
allow
deny
require-approval
block
```

Policy may constrain judgment.

Policy must not pretend to answer semantic questions such as:

```text
"is this the right architecture?"
"which design is better?"
"what does the user mean?"
```

Mandatory authorization/security gates may never silently no-op.

---

# 17. Operations and effects

Do not use a single-valued `MODE` as the safety or authority model.

Capabilities may perform several operations.

Prefer a small multi-valued descriptive vocabulary such as:

```yaml
operations:
  - analyze
  - diagnose
  - decide
  - produce
```

Possible operations may include:

- route
- analyze
- diagnose
- decide
- produce
- evaluate
- execute

Keep only values with actual runtime consumers.

Effects are separate:

```yaml
effects:
  - source-read
  - artifact-write
  - process-exec
```

Canonical separation:

```text
operations
→ orchestration semantics

effects
→ Arcane deterministic policy/enforcement

authority
→ responsibility / escalation
```

Never mechanically infer authority from operation.

Never infer effect safety from a semantic mode label.

---

# 18. Cross-domain helpers and internal primitives

Do not force unrelated mechanisms into one semantic category called `utility`.

These items have different meanings:

```text
brand
→ cross-domain context capability / source-bound context provider

handoff
→ session-continuity workflow capability

tasklist
→ workflow/state capability

dispatch
→ internal orchestration/delegation primitive

commit
→ repository effect operation / internal primitive
```

Use explicit metadata such as:

```yaml
domain: null
discoverability: public
```

or:

```yaml
discoverability: internal
```

where useful.

A public slash command does not require a mechanism to appear as a peer expertise capability in natural-language discovery.

Recommended treatment:

- `brand` — cross-domain capability/context provider;
- `handoff` — cross-domain workflow capability if user-invocable;
- `tasklist` — cross-domain workflow capability if user-invocable;
- `dispatch` — internal orchestration primitive, with compatibility command if needed;
- `commit` — internal effect operation unless semantic discovery is demonstrably useful.

---

# 19. Canonical ownership map

## 19.1 Root system architecture

**This file**

Owns:

- global system model;
- concern boundaries;
- global invariants;
- orchestration semantics;
- capability/authority separation;
- evaluation/assurance separation;
- effect/control semantics;
- canonical ownership map;
- routing architecture;
- global migration/supersession rules.

## 19.2 Capability semantics

**`skills/<id>/SKILL.md`**

Owns:

- capability name;
- compact discovery description;
- domain;
- discoverability;
- declared operations;
- declared effects;
- host requirements;
- capability method;
- capability-specific boundaries;
- specialist reference loading rules.

## 19.3 Role identity and challenge seat

**`src/roster/{sage,alchemist,oracle}.md`**

Owns:

- role purpose;
- authority boundary;
- handoff/escalation semantics;
- evidence rules;
- role-specific model policy (capability tiers, never vendor model IDs).

The roster contains exactly three roles. Covenant is not a roster role.

**`doctrine/covenant-seat.md`**

Owns Covenant challenge-seat semantics.

**`doctrine/{sage,alchemist,oracle}.md` and `doctrine/bundles/**`**

Own detailed operating **method** only, as delegated by the corresponding roster entry. They do
not co-own role identity, authority boundary, or model policy. Where a role needs no separate
method document, none should exist.

`doctrine/architecture/canon-map.md` currently records the opposite for these rows and must be
migrated — see §31 Stage 1.

## 19.4 Specialist methods

Examples:

```text
skills/architect/SKILL.md
doctrine/architecture/**
→ software/system architecture method

skills/audit/**
→ audit/evaluation method

skills/audit-visual/**
→ rendered-state/visual-regression evaluation

skills/designer/**
→ design craft

skills/research/**
→ research craft

doctrine/oracle.md
→ independent Completion Validation method
```

## 19.5 Deterministic effect policy

**`src/packages/arcane/**`**

Owns:

- effect classification;
- allow/deny/approval rules;
- mandatory control gates;
- authorization logging.

## 19.6 Host capabilities and outward-reference classes

**`src/registry/capabilities.json`**

Owns:

- the four outward-reference classes — `PACKAGE_INTERNAL`, `HOST_CAPABILITY`, `PROJECT_OVERLAY`,
  `HISTORICAL_EVIDENCE`;
- host capability identifiers;
- availability probes where applicable;
- degradation behaviour per host capability;
- declared remedies.

Locked invariants that this file carries, per `docs/agent-rules.md`:

- every outward reference a packaged skill makes must be classified against one of the four
  classes; a reference fitting none of them is a leak;
- every host capability must declare its degradation behaviour;
- the package must never ship a fallback it does not contain.

This registry is a canonical semantic owner, not a generated projection. It does not own domain
capability semantics, which belong to `skills/<id>/SKILL.md`.

## 19.7 Host projection

**This file, §36**

Owns the projection boundary: host-neutrality of canon, adapter-as-renderer rule, installation-path
exclusivity, declared fidelity axes and values, gate earnability, and enforcement-mechanism
selection.

**`src/lib/cli/commands/bind/**` and the harness plugin packages**

Own rendering only. They are generated/derived surfaces and never a semantic authority.

**`legion doctor`**

Owns installation, discovery, and enforcement-health diagnosis (§36.9).

## 19.8 Machine/package state

Generated manifests/projections may own:

- version;
- package file inventories;
- digests;
- integrity metadata;
- rights receipts;
- generated indexes;
- generated target manifests;
- compatibility projections.

These are machine-derived state, not competing semantic definitions.

---

# 20. SKILL.md contract

`SKILL.md` is the semantic source of truth for capability discovery and method.

It is **not** the source of truth for every machine-derived package property.

Keep compact capability metadata in frontmatter.

Example:

```yaml
---
name: architect
description: >
  Software and system architecture capability for architecture decisions,
  ADRs, quality attributes, interfaces, invariants, migrations, and
  architecture-significant planning.
domain: engineering
discoverability: public
operations:
  - analyze
  - decide
  - produce
effects:
  - source-read
---
```

Do not add static fields such as:

```yaml
role: sage
role: oracle
```

to ordinary capabilities.

That would recreate the coupling being removed.

Generated/package metadata such as digests and file inventories should remain generated.

---

# 21. Generated projections

Hand-maintained registries must not compete with canonical semantics.

Generate from canonical owners.

Conceptually:

```text
skills/*/SKILL.md
    ↓
compact capability catalog
    ↓
optional domain/index projections
    ↓
host/harness projections
```

Roles:

```text
src/roster/*
    ↓
generated agent/harness role projections
```

Concretely, the generated discovery projections in this repository are:

```text
src/registry/skills/index.json
src/registry/routing/domains.json
```

Generated artifacts must have deterministic drift verification.

Do not generate a projection unless an actual consumer needs it.

A domain map may remain if a runtime, UI, validator, or external consumer requires it.

If the capability catalog already contains domain membership, `domains.json` must not become a second semantic routing authority.

---

# 22. Natural-language routing

Explicit commands and compatibility aliases remain deterministic.

Natural-language routing should not use a hand-authored regex table as the primary semantic router.

At the current scale, Legion should expose the complete compact capability catalog directly.

Natural-language routing must support:

- zero capabilities;
- one capability;
- multiple capabilities.

Examples:

```text
"what is CAP theorem?"
→ direct Legion answer

"audit this repository"
→ audit

"research competitors and create positioning"
→ research → marketing

"audit the architecture"
→ audit + architect

"perform a rigorous visual-design audit"
→ audit-visual + designer
```

Natural-language routing should produce work semantics rather than merely one label where composition is required.

---

# 23. Progressive disclosure

The canonical system uses shallow progressive loading.

## Layer 1 — compact discovery catalog

Always available to Legion.

Contains enough information to choose and compose capabilities.

## Layer 2 — selected SKILL.md

Loaded after selection.

Contains the actual method and boundaries.

## Layer 3 — directly required references/tools

Loaded only when required by the current work unit.

Do not create unnecessary:

```text
domain
→ family
→ subfamily
→ capability
→ sub-capability
→ reference router
```

hierarchies.

The SSOT is authoritative.

It is **not** a giant mandatory prompt.

---

# 24. No retrieval infrastructure at current scale

Do not introduce RAG, embeddings, vector databases, graph databases, RDF/JSON-LD routing, or hierarchical semantic retrieval for capability discovery at the current scale.

The current capability catalog is small enough to expose directly.

Introduce retrieval only when measured evidence shows:

- the compact catalog materially harms context cost;
- semantic routing accuracy degrades with scale;
- catalog size grows substantially;
- latency becomes unacceptable;
- specialist reference selection grows beyond shallow loading;
- held-out evals demonstrate measurable improvement from retrieval.

No fixed "50 skills" or "100 skills" threshold is canonical.

Use measured context cost and routing quality.

Cortex remains responsible for repository/system structure where applicable; it does not become the capability router merely because capability relationships form a conceptual graph.

---

# 25. Bounded execution substrate

The strongest competitor-derived execution mechanics remain canonical.

Legion should have one configurable bounded execution-loop substrate rather than many ceremonial loops.

Conceptually:

```text
open(unit)
while not terminal:
    act()
    gate()
    apply()
    verify()
    decide()
close(unit)
```

This is an **execution substrate**, not a universal semantic lifecycle.

A work unit may use only the portions it needs.

## 25.1 Typed terminal outcomes

Recoverable conditions should be represented as typed results rather than success prose.

Examples include:

```text
CANDIDATE
BLOCKED_DECISION
BUDGET_STOP
FAILED_CONTRACT
NEEDS_AMENDMENT
SAFETY_BLOCK
REPAIR_EXHAUSTED
```

Exact enums may evolve in their canonical runtime owner.

`CANDIDATE` does not mean final success.

Current Legion policy requires Oracle PASS before successful delivery.

## 25.2 Numeric bounds

Dispatched/autonomous units should inherit explicit bounds where relevant:

```text
step_limit
cost_limit
wall_time_limit_seconds
max_consecutive_same_class_failure
```

Same failure fingerprint without material change stops rather than retries indefinitely.

Bounds are policy/config, not narrated after the fact.

## 25.3 Execution dependencies

Parallelism follows actual dependencies.

Derive dependencies from consumed outputs / shared state.

Do not serialize independent work merely because a taxonomy or stage list placed one item before another.

Serialize shared writes and integration where necessary.

---

# 26. Anti-ceremony and simplicity

The competitor-analysis anti-ceremony doctrine remains globally valid.

For every new mechanism, artifact, role, service, process, gate, reviewer, store, schema, or workflow stage ask:

> **Does this materially improve the decision, implementation, control of effects, resumability, or proof of completion?**

If not, omit it.

Complexity carries the burden of proof.

Default preference:

```text
remove
> reuse
> inherit
> adapt
> add
```

A new boundary must identify a real driver.

Challenge:

1. **New-boundary test** — what fails without this process/service/store/queue/agent/protocol?
2. **Reuse test** — does an existing owner already solve it?
3. **One-fewer-moving-part test** — can the requested outcome be satisfied with less machinery?
4. **Retirement test** — what older mechanism does this replace?

Do not remove mechanisms required by:

- correctness;
- safety;
- security;
- durable public contracts;
- irreversible data protection;
- explicit user requirements.

The objective is **minimum sufficient architecture**, not minimum code.

---

# 27. Durable state and artifacts

Do not manufacture process artifacts because the system has templates for them.

Persist state when it buys real control, such as:

- resumability;
- stale-evidence prevention;
- significant multi-step execution;
- destructive/privileged effects;
- external auditability;
- exact-state verification.

The prior competitor-derived artifact discipline remains:

- trajectory/journal where the execution substrate requires it;
- checkpoint only when resumability warrants it;
- Arcane authorization log when classified effects occur.

A producer-generated receipt does not prove correctness or honesty.

Authorization logs prove authorization/effect history, not semantic correctness.

Independent source-first assurance supplies completion proof.

---

# 28. Capability federation

The competitor-derived thin-kernel / federated-capability architecture remains canonical.

A shipped capability may own, as applicable:

```text
SKILL.md / instructions
scripts/tools
references
domain lenses/checks
eval corpus
manifest/catalog declaration
```

Adding a capability should be additive.

Load-bearing rule:

> **The kernel/runtime must not know specific capability identities unless a truly generic extension seam cannot express the requirement.**

If adding a new domain capability requires a new global execution architecture path, inspect the design.

Shipping must be manifest/catalog driven where the repository requires packaging discipline.

Filesystem existence alone should not silently create active capability semantics.

Promotion states such as:

```text
in-progress
promoted
deprecated
```

may be retained where useful.

---

# 29. Routing and orchestration evaluations

Routing is not complete because the schema looks clean.

Maintain held-out evals covering:

## 29.1 Capability selection

- direct/single capability;
- synonyms;
- paraphrases;
- multi-capability composition;
- zero-capability/direct answer;
- irrelevant keyword traps;
- cross-domain wording;
- over-selection;
- under-selection.

Measure:

- precision;
- recall;
- exact-set accuracy;
- F1 where useful;
- confusion matrix.

## 29.2 Minimal pairs

Examples:

```text
"design the backend architecture"
→ architect

"design the landing page"
→ designer

"audit the repository"
→ audit

"audit the visual design"
→ audit-visual + designer where qualitative design judgment is requested

"architect the study"
→ research

"architect the backend"
→ architect
```

## 29.3 Sage escalation

Test:

- correct escalation;
- missed escalation;
- unnecessary escalation;
- routine domain judgment staying within the capability;
- dynamic escalation after evidence;
- cross-capability conflict;
- explicit adjudication requests.

## 29.4 Alchemist routing

Test:

- ambient execution remains ambient where policy permits;
- controlled/locked/contracted execution invokes Alchemist;
- new semantic questions return to Sage;
- bounded executor does not invent meaning.

## 29.5 Oracle

For this refactor:

- universal Completion Validation remains enforced;
- Oracle remains independent;
- ordinary tests are not rerun as ceremony;
- live integration is inspected where relevant;
- no empty/no-op PASS;
- one targeted repair + one recheck maximum absent material new delta.

Do not use architecture migration to change Oracle policy.

## 29.6 Work graph

Test:

- correct dependencies;
- correct parallelism;
- no false dependencies;
- correct capability composition;
- authority only on the work that requires it;
- authority escalation after new evidence;
- no global Sage contamination.

## 29.7 Stability and cost

Run repeated trials across supported model/harness configurations.

Track:

- routing consistency;
- capability-set stability;
- authority stability;
- end-to-end task success;
- routing context tokens;
- loaded skill/reference tokens;
- model calls;
- latency.

If confidence labels exist, evaluate calibration or remove them.

---

# 30. Conformance invariants

## I-1 — one root architecture owner

Exactly one active root SSOT governs Legion system architecture and ownership boundaries.

## I-2 — one owner per concept

No second live file independently redefines the same semantic responsibility.

## I-3 — Legion is the always-on orchestrator

The user does not need to invoke internal roles.

## I-4 — capability and authority are orthogonal

No ordinary capability statically belongs to Sage, Alchemist, or Oracle.

## I-5 — routine judgment belongs to capabilities

Sage is exceptional adjudication, not the default domain brain.

## I-6 — authority is work-local

One work unit can escalate without escalating the entire request.

## I-7 — authority can change with evidence

Initial routing does not permanently determine authority.

## I-8 — effects are explicit

Arcane gates effects, not semantic labels.

## I-9 — evaluation is not assurance

Audit methodology and Oracle Completion Validation remain distinct.

## I-10 — internal verification may remain inside capabilities

Not every check becomes Oracle work.

## I-11 — Architect owns architecture craft

Software/system architecture methodology does not live under Sage merely because historical Legion was engineering-first.

## I-12 — Audit does not own every audited subject

Compose Audit with subject expertise when needed.

## I-13 — SKILL.md owns capability semantics

Generated package/integrity state remains generated.

## I-14 — generated projections are projections

Indexes and domain maps do not become competing semantic authorities.

## I-14b — role identity and role method are separately owned

`src/roster/*.md` owns identity and authority. `doctrine/*.md` and `doctrine/bundles/**` own
method only. No file co-owns both, and no capability bundle owns an authority.

## I-14c — outward references are classified

Every outward reference a packaged skill makes is classified against
`src/registry/capabilities.json`. Host capabilities declare degradation behaviour. No shipped
fallback the package does not contain.

## I-14d — "capability" is disambiguated

Domain capability (`skills/<id>/SKILL.md`) and host capability
(`src/registry/capabilities.json`) are distinct concepts and are never conflated in doctrine,
schema, or routing.

## I-15 — routing complexity is empirical

No RAG/vector/graph/hierarchy without measured need.

## I-16 — Oracle policy is independent

Universal Completion Validation remains current policy but is not encoded as a skill property.

## I-17 — composition follows actual dependencies

Taxonomy does not serialize independent work.

## I-18 — complexity must earn its existence

New mechanisms require a real driver and should retire replaced machinery.

## I-19 — canon is host-neutral

No canonical file carries harness-conditional semantics; no host artifact introduces a capability,
role, or effect rule that does not exist canonically. Adapters render, they do not compose.

## I-20 — one installation path per harness

At most one Legion installation path is active for a harness at a time. `legion bind` is a
compatibility projection, never a second installer for a harness with a native package.

## I-21 — declared fidelity is truthful

Every supported harness declares `strong`/`degraded`/`unsupported` for skill discovery, authority
agents, MCP, and Arcane enforcement. A harness lacking a mechanism declares it `unsupported`
rather than claiming the doctrine's intent.

## I-22 — gates must be earnable

A mandatory gate never requires state the governed workflow had no opportunity to create.
Enforcement denies at the point of the effect, not at termination for state that could never have
existed. Ambient work is not judged by governed-work contract evidence.

## I-23 — blocking surface is minimal and effect-scoped

Arcane registers for events carrying effects it can classify and materially govern. Fail-open
transports are never the sole mechanism for a mandatory gate.

---

# 31. Migration plan

## Stage 0 — adopt one canonical root

Adopt this file as the root Legion architecture SSOT.

Extract surviving method to its correct owner, then remove from active doctrine/loading:

- `docs/architecture.md` — extract still-valid Audit operational doctrine into `skills/audit/**`
  and its owned references **first**, then retire it as a competing global architecture document;
- `docs/capability-architecture.md` — superseded outright, and already removed from the working
  tree. It describes the roles as a universal
  cross-domain decide/execute/certify axis and treats `MODE` as determining which role becomes
  involved. Both claims are reversed by §6 and §17 of this document;
- `docs/provenance/research/2026-08-17-legion-final-architecture-synthesis.md` — retained as non-normative
  research provenance only.

**Done when:** no loader, prompt, skill, contributor guide, or agent can treat a superseded architecture document as current authority, and no Audit method was lost in the retirement.

## Stage 1 — canonicalize ownership and migrate the canon map

Freeze:

```text
Legion constitution              → AGENTS.md
Legion routing reference         → doctrine/legion.md
Root system architecture         → this file
Role identity/authority          → src/roster/{sage,alchemist,oracle}.md
Role method                      → doctrine/{sage,alchemist,oracle}.md, doctrine/bundles/**
Challenge seat                   → doctrine/covenant-seat.md
Domain capabilities              → skills/<id>/SKILL.md
Architecture method              → doctrine/architecture/**
Audit method                     → skills/audit/** + owned references/providers
Oracle assurance method          → doctrine/oracle.md
Arcane effect control            → src/packages/arcane/**
Host capabilities / ref classes  → src/registry/capabilities.json
Generated discovery projections  → src/registry/skills/index.json,
                                   src/registry/routing/domains.json
```

`doctrine/architecture/canon-map.md` currently contradicts this and must be migrated in the same
stage, not left as a second live ownership authority:

- the `sage-role`, `alchemist-role`, and `oracle-role` rows list `doctrine/*.md` **plus**
  `doctrine/bundles/*` as role source owners. Narrow every one of those rows to role **method**,
  and add `src/roster/*.md` as the identity/authority owner. The bundles
  (`sage-architect.md`, `sage-diagnose.md`, `oracle-assurance.md`, `legion-worker-capsule.md`)
  each need an explicit disposition — method under a named role, or retirement — not silent
  inheritance;
- the `sage-role` row states Sage owns "architecture decisions". That is the Stage 2 migration
  target: architecture craft moves to Architect and only exceptional adjudication stays with Sage;
- reconcile the `legion-identity` row with `src/roster/README.md`, which declares the roster the
  sole source for role identity. Today those two documents disagree.

**Done when:** every major concept has exactly one canonical owner, `canon-map.md` agrees with
this table, and no `doctrine/bundles/*` file is an unowned orphan.

Two I-22 defects found while implementing §36 are fixed and recorded here, since both were
mandatory gates that no workflow could satisfy:

- the VCS history-rewrite gate refused every `git push --force` for an approval no wired store
  could produce; it now escalates to the host's operator prompt when the target ref is isolated,
  and still hard-denies an ambiguous target;
- the Stop completion gate refused ambient sessions for contract receipts they had no opportunity
  to create; contract certification now applies only to governed work (§36.7).

Implementation sequencing for §36 lives in `docs/host-integration-plan.md`, which is a plan, not
a canonical owner.

## Stage 2 — separate Architect from Sage

- keep `architect` as engineering capability;
- move/retain software architecture craft under `skills/architect` + `doctrine/architecture/**`;
- move generic exceptional adjudication semantics to Sage;
- ensure routine Architect work can occur without Sage;
- ensure Sage can compose with any domain.

**Done when:** "architect" is not synonymous with Sage and non-engineering "architecting" does not route through engineering architecture.

## Stage 3 — clean Audit family

Review:

- audit;
- audit-visual;
- audit-fix;
- qa;
- debugger;
- cortex.

Separate:

- domain craft;
- evaluation method;
- implementation/effects;
- independent assurance;
- orchestration.

Preserve capability-internal verification where methodologically required.

**Done when:** Audit is rigorous without pretending to be Oracle or every subject expert.

## Stage 4 — canonicalize SKILL.md metadata

Add compact discovery/operation/effect metadata.

Do not duplicate role identity or machine-derived package state.

**Done when:** capability discovery semantics have one human-edited owner.

## Stage 5 — generated catalog/projections

Generate the compact capability catalog and only the projections real consumers need.

Add deterministic drift checks.

**Done when:** generated indexes cannot silently diverge from canonical sources.

## Stage 6 — replace hard-coded natural-language regex routing

Keep slash/compatibility aliases deterministic.

Natural language routes semantically over the full compact catalog.

Support 0..N capabilities.

**Done when:** semantic routing, not regex fixtures, determines normal natural-language capability selection.

## Stage 7 — work-unit orchestration

Represent composed work using:

- capabilities;
- operations;
- effects;
- dependencies;
- authority state/policy.

**Done when:** multi-capability requests can be represented without forcing one global capability label or one global authority phase.

## Stage 8 — dynamic authority

Allow:

- Sage escalation after new evidence;
- ambient execution where policy permits;
- Alchemist controlled execution where policy requires;
- universal Oracle Completion Validation unchanged.

**Done when:** authority follows work semantics rather than skill identity.

## Stage 9 — progressive loading

Ensure:

```text
compact catalog
→ selected SKILL.md
→ directly required references/tools
```

**Done when:** Legion does not preload all specialist doctrine.

## Stage 10 — eval gate

Run routing, composition, authority, effect, context-cost, and end-to-end evaluations.

Do not remove compatibility paths until required thresholds are met.

---

# 32. Explicit non-goals

This architecture does **not** attempt to:

- change universal Oracle Completion Validation policy;
- build a general ontology engine;
- build RAG/vector/graph capability routing;
- add a control-plane service or daemon without a real driver;
- create a universal semantic lifecycle every domain must traverse;
- make Sage the general architect/strategist of every domain;
- turn Oracle into the owner of every verification step;
- turn Audit into the expert for every subject;
- make every internal primitive a natural-language capability;
- create a new role for every specialist method;
- preserve old machinery indefinitely after its replacement lands;
- collapse every specialist doctrine into this root file.

---

# 33. Competitor-analysis conclusions retained

The prior 18-repository comparison remains valid as architectural evidence.

Its durable conclusions are retained:

## 33.1 Constitutional/document monolith

**Finding:** strong readable intent, weak enforcement, amendment growth.

**Decision:** reject as Legion's governing implementation shape.

This root SSOT defines global ownership and invariants but delegates specialist methods to canonical owners.

## 33.2 Distributed control plane/event bus

**Finding:** strong observability/state machinery, but unjustified process/transport/operations cost for Legion's current shape.

**Decision:** reject unless a future architecture-significant driver requires it.

## 33.3 Bounded SWE harness / nested-loop mechanics

**Finding:** useful for:

- typed failures;
- numeric bounds;
- checkpoints;
- cycle stopping;
- explicit terminal states.

**Decision:** retain as execution substrate beneath work units.

## 33.4 Skill federation with thin kernel

**Finding:** strong additive capability model with catalog/promotion/eval ownership.

**Decision:** retain and strengthen through canonical SKILL.md semantics and generated projections.

## 33.5 Policy as data

**Finding:** useful for deterministic gates; dangerous when used to fake semantic judgment.

**Decision:** retain under Arcane only for genuinely deterministic effect/control policy.

## 33.6 Independent verification

Strongest cross-system convergence:

- producer-side receipts do not prove correctness;
- fresh contexts reduce producer-bias leakage;
- source-first semantic inspection is stronger than success narrative;
- no-op/empty verification must fail;
- loops require mechanical stop conditions;
- cheap deterministic checks should precede expensive semantic checks.

**Decision:** retain.

The competitor research is therefore **not discarded**.

What is superseded is the old ontology that forced those mechanics into a universal:

```text
Sage
→ Covenant
→ Alchemist
→ Oracle
```

semantic pipeline across all domains.

---

# 34. Target examples

## 34.1 Repository architecture audit

```text
User:
"Audit the architecture of this repository."

Legion
    ↓
work: architecture evaluation
    capabilities: audit + architect
    effects: source-read
    authority: auto
    ↓
work: report
    capability: audit
    ↓
Oracle Completion Validation
    ↓
delivery
```

Sage appears only if a material unresolved decision requires adjudication.

## 34.2 Architecture design

```text
User:
"Design the architecture for this feature."

Legion
    ↓
architect
    ↓
architecture result
    ↓
Oracle Completion Validation
    ↓
delivery
```

If a consequential unresolved conflict appears:

```text
architect
    ↓
architect + Sage
    ↓
settled decision
```

## 34.3 Visual regression audit

```text
User:
"Find visual regressions against these baselines."

Legion
    ↓
audit-visual
    ↓
findings
    ↓
Oracle Completion Validation
    ↓
delivery
```

Designer is unnecessary unless qualitative design judgment is part of the request.

## 34.4 Visual design audit

```text
User:
"Audit the visual quality of this application."

Legion
    ↓
audit-visual + designer
    ↓
capture/coverage evidence + design analysis
    ↓
Oracle Completion Validation
    ↓
delivery
```

## 34.5 Competitor research and launch work

```text
research competitors
    ↓
marketing positioning
    ↓
writing launch copy
    ↓
Oracle Completion Validation
```

Sage attaches only when material unresolved positioning judgment requires exceptional adjudication.

---

# 35. Final operational doctrine

> **Legion interprets intent and decomposes it into the smallest sufficient work graph.**  
> **Capabilities own domain expertise, method, and routine judgment.**  
> **Architect owns software/system architecture craft.**  
> **Audit owns systematic evaluation methodology and composes with subject expertise where needed.**  
> **Sage supplies exceptional adjudication when routine capability judgment is insufficient.**  
> **Alchemist supplies controlled bounded transformation where policy requires it.**  
> **Effects are explicit and Arcane gates them deterministically.**  
> **Covenant challenges material decisions without owning them.**  
> **Oracle independently validates completion under Legion's current universal Completion Validation policy.**  
> **Routing uses a compact semantic capability catalog and shallow progressive disclosure.**  
> **Execution is bounded mechanically, not by narrative promises.**  
> **Complexity carries the burden of proof.**  
> **Generated projections never become competing semantic owners.**  
> **Add retrieval, hierarchy, services, roles, gates, artifacts, or new machinery only when measured need justifies them.**  
> **When new architecture replaces old machinery, retire the old machinery rather than stacking both indefinitely.**

---

# 36. Host projection, discovery, and enforcement

Legion's canonical semantics are host-neutral. Harnesses are not.

This section governs how canonical capabilities, roles, and effect enforcement reach a specific
harness (Claude Code, Codex, Gemini CLI, an AGENTS-only editor, or an unknown future host). It
owns the projection boundary. It does not redefine any canonical owner named in §19.

## 36.1 Canon is host-neutral

```text
CANONICAL (host-neutral)
skills/<id>/SKILL.md          domain capabilities
src/roster/*.md               role identity and authority
doctrine/**                   method
src/registry/capabilities.json host capabilities and reference classes
src/packages/arcane/**        effect policy

    ↓ projection (generated, one direction only)

HOST-SPECIFIC
.claude/**, .codex/**, .gemini/**, AGENTS.md, plugin packages
```

No canonical file may contain harness-conditional semantics. No host artifact may introduce a
capability, role, authority, or effect rule that does not exist canonically.

## 36.2 Host adapters are renderers

A host adapter is a pure projection: it translates the canonical projection into one harness's
native format. It does not decide what Legion contains.

> **An adapter that hand-authors capability or role content is a second semantic owner and violates
> I-2. Adapters render; they do not compose.**

The single canonical projection — capability catalog, roster, host-capability requirements, and
declared effects — is generated once and consumed by every adapter. Adding a harness is a new
renderer, not a new copy of Legion's contents.

## 36.3 Prefer native host mechanisms

Where a harness has a native mechanism for a concept, project into it rather than emulating it:

- native skill/plugin packaging over injected prompt text;
- native agent/subagent definitions over role prose in a context file;
- native MCP registration over bespoke tool shims;
- native hook registration over wrapper processes.

Emulation is a fallback for harnesses that lack the mechanism, and it must be declared as reduced
fidelity under §36.5.

## 36.4 One installation path owns a harness

At most one Legion installation path may be active for a given harness at a time.

Today `legion bind` writes `.claude/agents/**` while the plugin package ships `agents/**` for the
same three roles. That is two competing installers for one harness, and it is the direct cause of
version/identity confusion during development.

Canonical rule:

```text
Claude Code       → the plugin package is the installation path
Codex             → the Codex plugin package is the installation path
Gemini CLI        → the Gemini extension/skill surface is the installation path
AGENTS-only/other → legion bind projection
```

`legion bind` is a **compatibility and lower-fidelity projection mechanism**. It is not a second
installer for a harness that has a native package. Once native projection is equivalent for a
harness, the superseded bind path for that harness is retired, not kept in parallel (§26
retirement test).

Development against a live tree uses the harness's own live-source mechanism (for Claude Code,
`--plugin-dir` against the repository root), never a stale installed copy. A packaged install is
for release; it is identified by version, and a layout or content change without a version change
is an unshippable state.

## 36.5 Declared fidelity per harness

Every supported harness declares, in the generated projection, its fidelity for four independent
axes:

```text
skill discovery
authority agents
MCP tools
Arcane effect enforcement
```

Each axis takes one of Arcane's existing enforcement-health values:

```text
strong        native mechanism, full canonical semantics
degraded      projected with stated loss
unsupported   the harness has no mechanism for this axis
```

These declarations must be **true**. A harness with no hook mechanism declares Arcane enforcement
`unsupported`; it does not declare `strong` because the doctrine says Arcane gates every effect.

> **A false fidelity declaration is worse than an absent mechanism: it converts a known gap into an
> unknown one.**

This is the §16 rule (mandatory gates may never silently no-op) applied to projection. A gate that
cannot exist on a harness must be *stated* as absent, and the operator must be able to see it
(§36.9).

## 36.6 Gates must be earnable

A mandatory gate may not require state that the workflow it governs had no opportunity to create.

```text
gate requires evidence E
    ↓
the governed workflow must have a path that produces E
    ↓
otherwise the gate is not enforcement, it is a dead end
```

Where a gate needs binding state, that state is established **at the point the governed effect is
first attempted**, not discovered to be missing at termination. Denying early with a named remedy
is enforcement. Refusing at the end for state that could never have existed is a defect.

## 36.7 Ambient work and governed work are different

```text
AMBIENT
ordinary authorized work under standing policy
no contract, no run binding
completion asserts nothing beyond itself

GOVERNED
an explicitly opened run/contract
completion claims a level and must earn it
```

Contract-completion enforcement applies only to governed work. An ambient session must not be
refused for lacking receipts belonging to a contract it never opened. This does not weaken §14.1:
Oracle Completion Validation remains Legion policy for delivery, and is a separate concern from
Arcane's contract certification.

## 36.8 Arcane gates effects, not orchestration

Restating §16 in projection terms, because this is where it is most often violated:

```text
Arcane's jurisdiction        declared effect classes
Not Arcane's jurisdiction    which capability ran, how the turn was shaped,
                             whether prose looked complete, general orchestration
```

Hook registration follows jurisdiction. Intercepting every tool invocation because interception is
available is not enforcement — it is a tax that buys nothing at the events Arcane cannot classify.
Register for the events carrying effects Arcane can classify and materially govern, and no others.

Enforcement mechanism selection:

```text
mandatory fail-closed gate      → blocking host-specific path only
observation / context / telemetry → non-blocking transport
```

Transports that fail open when unavailable (HTTP endpoints, MCP-tool hooks) are legitimate for
observation and context, and are **never** the sole mechanism for a mandatory gate. Keep the
blocking, host-specific surface as small as the set of effects that genuinely require deterministic
enforcement.

## 36.9 Installation and enforcement must be diagnosable

An operator must be able to determine, without reading source:

- which Legion source is active, and whether it is live or a packaged copy;
- enabled/disabled state;
- version and cache identity, and whether they match the source;
- which capabilities were discovered;
- which authority agents were discovered;
- MCP connectivity;
- hook registrations, including duplicates across installation paths;
- Arcane key and runtime health;
- projection drift against canonical sources;
- the declared enforcement tier per §36.5, and whether it is currently met.

`legion doctor` is the canonical owner of this diagnosis. It is extended for host projection, not
duplicated by a second tool.

## 36.10 Ordering constraint

Native projection replaces bind per harness; it does not run beside it indefinitely. A superseded
path is retired once its native equivalent is demonstrated, per §26's retirement test and §32's
non-goal on preserving old machinery.
