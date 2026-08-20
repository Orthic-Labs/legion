# Legion Phase B — Final Mechanical Migration Manifest v1.0

**Status:** FINAL PHASE B — execution specification  
**Repository:** `Orthic-Labs/legion`  
**Frozen repository baseline:** `57d00b1f5d337e72d5cf58274a8c6a258e1ee6f3`  
**Frozen semantic input:** `legion-ssot-phase-a-final-v1.1.md` (`D-001` … `D-055`)  
**Execution target:** one coherent Legion implementation and one permanent root architecture SSOT  
**Executor role:** mechanical implementation only; no new semantic design

---

## 0. Authority, scope, and lifecycle

Phase A answers:

> What must Legion mean?

This Phase B answers:

> Exactly how is the repository migrated to that meaning?

Phase B **does not reopen Phase A**. The executor may make local syntax and implementation choices only where they are behaviorally equivalent and do not alter ownership, routing, authority, effects, discoverability, compatibility, or policy.

### 0.1 Permanent end state

The permanent normative shape after successful migration is:

```text
docs/LEGION-CANONICAL-SSOT.md
  → permanent system architecture + ownership boundaries

AGENTS.md
  → live operational constitution, constrained by the root SSOT

skills/<id>/SKILL.md
  → canonical packaged capability/entrypoint semantics and top-level method

src/roster/{sage,alchemist,oracle}.md
  → canonical role identity / authority / model tier

delegated doctrine and skill references
  → specialist method only

src/packages/**
  → runtime implementation of the semantics above

generated registries / manifests / agent files
  → projections only
```

### 0.2 Migration provenance

After successful implementation:

```text
legion-ssot-phase-a-final-v1.1.md
LEGION-PHASE-B-FINAL-MECHANICAL-MIGRATION-v1.0.md
```

become **migration provenance**. They are not co-equal permanent architecture authorities.

`docs/LEGION-CANONICAL-SSOT-v2.md` is also provenance after the migration. It must leave every active normative loading/ownership path.

Therefore the lifecycle is:

```text
SSOT-v2 + live repository
        ↓
Phase A v1.1
        ↓
Phase B v1.0
        ↓
mechanical implementation
        ↓
independent validation / Completion Validation
        ↓
docs/LEGION-CANONICAL-SSOT.md       ← permanent architecture SSOT
AGENTS.md                            ← live constitution
delegated owners                     ← specialist canon
Phase A / Phase B / SSOT-v2          ← provenance only
```

### 0.3 Absolute executor rules

The executor MUST NOT:

- redesign Legion;
- change a Phase A decision;
- preserve old semantics because a current consumer implements them;
- add RAG, embeddings, vector search, graph routing, or another routing hierarchy;
- add a mandatory capability → Sage → Alchemist chain;
- make Sage the default contract compiler or sealer;
- infer authority from an operation or effect;
- turn Covenant into an authority;
- turn generated projections into semantic owners;
- reopen the host adapter/install architecture completed at `57d00b1f`;
- redesign Arcane or fold separate Arcane performance/security work into this migration;
- delete useful method before it has a reachable canonical destination;
- make generated output pass by hand-editing it;
- silently resolve a repository contradiction that conflicts with this manifest.

Unexpected semantic contradiction:

```text
SEMANTIC_BLOCKER
decision_id: D-XXX / M-XXX
paths: [...]
evidence: [...]
why_execution_cannot_continue: ...
smallest_question_requiring_resolution: ...
```

Stop the affected migration unit only. Continue independent units.

---

# 1. Baseline and preflight

## M-001 — Verify immutable baseline and external writers

**PHASE_A_DECISIONS:** D-048, D-049, D-055  
**DISPOSITION:** KEEP / VERIFY

### Required baseline

```bash
git rev-parse HEAD
# expected:
57d00b1f5d337e72d5cf58274a8c6a258e1ee6f3

git status --porcelain
git log --oneline -1
```

If the repository is not at the baseline:

1. record the exact delta;
2. determine whether it touches this migration's semantic surfaces;
3. do not silently plan/execute against a different semantic baseline.

### Capture baseline test state

Run and retain exact output:

```bash
pnpm legion:check
pnpm test

node --test --test-concurrency=1 \
  tests/routing.test.mjs \
  tests/architect-debugger-entrypoint-parity.test.mjs \
  tests/dispatch-qa-entrypoint-parity.test.mjs \
  tests/host-adapter-conformance.test.mjs \
  tests/host-adapter-safety.test.mjs
```

Pre-existing failures are baseline failures, not migration passes and not migration regressions.

### External `AGENTS.md` writer preflight

Before editing `AGENTS.md` or `CLAUDE.md`, inspect the actual workspace/integration environment for an external writer, overlay, bind process, parent-workspace generator, or hook that rewrites either file.

If one exists:

- it is a projection mechanism, not a semantic owner;
- update/repoint the writable source or writer so canonical `AGENTS.md` persists;
- do not let an external projection restore old semantics.

If none exists:

- edit `AGENTS.md` directly.

**STOP_RULE:** external writer exists but its writable source/ownership cannot be identified.

---

# 2. Canonical final ownership

## 2.1 Ownership matrix

| Semantic concern | Permanent canonical owner | Derived / consumer only |
|---|---|---|
| System architecture and ownership boundaries | `docs/LEGION-CANONICAL-SSOT.md` | all architecture summaries/maps |
| Live Legion constitution | `AGENTS.md` | `CLAUDE.md`, harness context projections |
| Legion routing/orchestration reference | `doctrine/legion.md` | generated summaries |
| Sage identity / authority / tier | `src/roster/sage.md` | `agents/sage.md`, doctrine method |
| Alchemist identity / authority / tier | `src/roster/alchemist.md` | `agents/alchemist.md`, doctrine method |
| Oracle identity / authority / tier | `src/roster/oracle.md` | `agents/oracle.md`, doctrine method |
| Covenant challenge standing | `doctrine/covenant-seat.md` | `agents/covenant-seat.md`, entrypoint |
| Architecture craft | `skills/architect/SKILL.md` + `doctrine/architecture/**` | old Sage Architect bundle |
| Diagnosis craft | `skills/debugger/SKILL.md` + debugger references | old Sage Diagnose bundle |
| Audit method | `skills/audit/**` | Oracle may consume evidence |
| Audit Fix workflow | `skills/audit-fix/**` | no authority owner implied |
| Rendered-state visual evaluation | `skills/audit-visual/**` | Oracle may consume evidence |
| Functional/browser/runtime QA | `skills/qa/**` | Oracle may consume evidence |
| Qualitative design craft | `skills/designer/**` | Audit Visual may provide evidence |
| Capability/entrypoint semantics | `skills/<id>/SKILL.md` | catalogs/manifests/projections |
| Host capability availability | `src/registry/capabilities.json` | SKILL `hostRequirements` |
| Explicit aliases | `src/config/capability-aliases.json` | resolver/projections |
| Semantic effect vocabulary | root SSOT | SKILL declarations |
| Runtime effect mapping/enforcement | Arcane | receipts/projections |
| Executable work-unit materialization | Legion + producing capability | contract runtime |
| Independent Completion Validation | Oracle | Audit/QA evidence may be inputs |

No row has two independent semantic owners.

---

# 3. Permanent root SSOT and constitution

## M-002 — Create `docs/LEGION-CANONICAL-SSOT.md`

**PHASE_A_DECISIONS:** D-001, D-006, D-044, D-050  
**DISPOSITION:** MIGRATE / CREATE  
**DEPENDENCIES:** M-001

### Source material

Use:

```text
docs/LEGION-CANONICAL-SSOT-v2.md
legion-ssot-phase-a-final-v1.1.md
live canonical specialist owners
```

### Precedence

```text
Phase A D-001..D-055
    >
compatible system-level text in SSOT-v2
    >
legacy architecture/provenance documents
```

### Exact final root structure

Create:

```text
docs/LEGION-CANONICAL-SSOT.md
```

with these sections:

1. Status, scope, precedence
2. Legion system model
3. Canonical ownership model
4. Work units and work graphs
5. Capabilities and entrypoints
6. Authority model
7. Operations and effects
8. Arcane enforcement boundary
9. Routing and discoverability
10. Context loading
11. Evaluation, challenge, assurance, and review ownership
12. Ambient vs governed execution
13. Host/runtime and projection boundary
14. Model policy
15. Complexity / simplicity / retirement rules
16. Compatibility surfaces
17. Revisit triggers and architecture-change policy
18. Delegated canonical owners

### Root content rule

The root describes **architecture, ownership, and invariants**.

It does not duplicate detailed specialist procedure.

For example:

```text
root:
  "Audit owns systematic evaluation methodology"
  → pointer to skills/audit/**

NOT:
  another full copy of the Audit provider method
```

### Do not copy SSOT-v2 verbatim

Where v2 contains specialist method that Phase A delegates, replace that method with:

```text
owner
boundary
invariant
canonical path
```

The specialist text survives at its specialist owner under later migration actions.

### Validation

- root exists;
- every Phase A architectural decision is represented or explicitly delegated;
- no specialist method has two active owners;
- no file claims `SSOT-v2` outranks the root;
- no live architecture file claims parallel root authority.

**FORBIDDEN:** verbatim rename/copy of v2 that preserves duplicate specialist ownership.

---

## M-003 — Make `AGENTS.md` the live constitution

**PHASE_A_DECISIONS:** D-002, D-003, D-007, D-031, D-037, D-055  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-001, M-002

### Preserve

- Legion identity as orchestrating lead;
- ambient scope rule;
- worker-output distrust;
- integration ownership;
- current Completion Validation policy;
- global/package-level operational invariants;
- delivery behavior.

### Remove / rewrite

- five-peer-domain routing hierarchy;
- engineering vs advisory routing distinction;
- role-as-domain-leaf routing;
- external operator-source supremacy;
- ambiguous Arcane “control plane” wording.

### Final wording model

```text
Legion orchestrates.
Capabilities provide method/expertise.
Authority attaches only when required.
Arcane enforces declared effects deterministically.
Oracle performs independent Completion Validation under current policy.
Domains are optional grouping metadata only.
```

---

## M-004 — Narrow `doctrine/legion.md`

**PHASE_A_DECISIONS:** D-003, D-007  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-002, M-003

Final purpose:

```text
delegated Legion routing/orchestration reference
```

May describe:

- routing reference;
- capability composition;
- work-graph reference;
- authority attachment;
- dispatch/handoff relationships.

Must not claim:

- external unpublished constitution ownership;
- role identity ownership;
- five-domain hierarchy;
- architecture root authority.

---

# 4. Roles, architecture, diagnosis, and assurance

## M-005 — Split role identity from role method

**PHASE_A_DECISIONS:** D-005, D-011, D-015, D-018, D-019, D-046  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-002

### Canonical identity

Update:

```text
src/roster/sage.md
src/roster/alchemist.md
src/roster/oracle.md
src/roster/README.md
```

Roster owns only:

- identity;
- authority boundary;
- trigger boundary;
- abstract model tier.

### Delegated method

Update:

```text
doctrine/sage.md
doctrine/alchemist.md
doctrine/oracle.md
doctrine/covenant-seat.md
```

Doctrine owns detailed method only.

### Final role identities

```text
Sage
  exceptional adjudication
  domain-independent
  only when material unresolved meaning cannot safely close under routine capability mandate

Alchemist
  controlled bounded transformation
  only where policy/locking/contract/risk requires a controlled authority boundary

Oracle
  independent assurance
  read-only
  owns Completion Validation under current policy

Covenant
  advisory/read-only challenge
  not authority
  not release gate
  optional/policy/user-triggered
```

### Model tiers

Canonical files use abstract tiers, not vendor IDs.

Minimum semantic target:

```text
Sage      → frontier-judgment
Oracle    → frontier-judgment / independent-assurance-capable tier
Alchemist → balanced-executor; mechanical-cheap only where policy says safe
```

Concrete provider/model IDs remain host configuration.

---

## M-006 — Re-home Sage Architect into Architect

**PHASE_A_DECISIONS:** D-006, D-010, D-012  
**DISPOSITION:** REHOME_THEN_RETIRE  
**DEPENDENCIES:** M-002, M-005

### Sources

```text
skills/architect/SKILL.md
doctrine/bundles/sage-architect.md
doctrine/architecture/**
agents/sage.md
doctrine/sage.md
```

### Exact destination

Do not invent a second new architecture router file.

Use:

```text
skills/architect/SKILL.md
  → discovery + top-level architect method

doctrine/architecture/README.md
  → architecture method index / ownership statement

doctrine/architecture/**
  → detailed architecture workflow/method/reviews/templates/controls
```

Re-home only useful architecture-specific material from `sage-architect.md` into the existing `doctrine/architecture/**` structure.

### Architect owns

- context/boundaries;
- ASRs;
- quality scenarios;
- responsibilities/interfaces;
- invariants;
- state/data ownership;
- consistency/lifecycle;
- runtime/deployment topology;
- tactics;
- alternatives/trade-offs;
- ADRs when warranted;
- migration/evolution;
- architecture risk;
- simplest-sufficient architecture.

### Remove

- `Sage Architect`;
- Architect-as-wrapper language;
- mandatory Sage handoff;
- generic domain-independent decision method from Architect if duplicated.

Sage remains attachable only for material unresolved judgment.

---

## M-007 — Re-home Sage Diagnose into Debugger

**PHASE_A_DECISIONS:** D-006, D-010, D-013  
**DISPOSITION:** REHOME_THEN_RETIRE  
**DEPENDENCIES:** M-002, M-005

### Sources / destination

```text
doctrine/bundles/sage-diagnose.md
    ↓
skills/debugger/SKILL.md
skills/debugger/references/manual.md
```

If `skills/debugger/references/manual.md` already exists, merge into it. Do not create a parallel diagnosis method file.

### Debugger owns

- reproduction;
- bounded evidence;
- hypotheses;
- disconfirmation;
- isolation;
- root cause;
- routine repair choice;
- repair verification.

Remove mandatory Sage routing.

---

## M-008 — Separate Audit / Audit Visual / Designer / QA / Oracle / Covenant

**PHASE_A_DECISIONS:** D-018, D-019, D-020, D-021, D-023, D-024  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-005

### Re-home `doctrine/bundles/oracle-assurance.md`

Split useful material by concern:

```text
systematic audit method
  → skills/audit/**

functional/browser/runtime QA
  → skills/qa/references/manual.md

rendered-state enumeration/capture/regression
  → skills/audit-visual/references/manual.md

independent assurance / Completion Validation
  → doctrine/oracle.md
```

Do not leave duplicate copies under Oracle.

### Final boundaries

```text
Audit
  systematic evaluation methodology

Audit Visual
  rendered-state enumeration, baseline/regression evidence,
  visual-state coverage, clipping/overlap/missing-state findings

Designer
  qualitative craft, hierarchy, composition, typography,
  interaction, design direction, remediation craft

QA
  functional/behavioral QA, deterministic browser/runtime checks,
  mocks, contract tests, viewport capture as QA evidence

Oracle
  independent assurance + Completion Validation
  may consume Audit/QA/AuditVisual evidence
  does not own their methods

Covenant
  bounded adversarial challenge
  advisory only
```

---

## M-009 — Keep Audit Fix as frozen-plan workflow

**PHASE_A_DECISIONS:** D-022, D-024  
**DISPOSITION:** MODIFY / KEEP  
**DEPENDENCIES:** M-008

`skills/audit-fix/**` remains independently invocable.

Final invariants:

- consumes a frozen Audit result;
- cannot choose a new provider plan;
- applies only admitted/bounded remediations;
- preserves plan/denominator;
- reruns the same frozen plan;
- is not Oracle;
- is not Alchemist merely because it writes;
- actual effects remain Arcane-gated.

---

# 5. Executable contracts and the Sage-seal correction

## M-010 — Move executable-contract authorship to Legion + producing capability

**PHASE_A_DECISIONS:** D-008, D-009, D-014, D-016, D-043, D-049  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-002, M-005

Preserve:

```text
EXACT / BOUNDED / OPEN
openQuestions
versioned amendment semantics
contract identity/digest
evidence requirements
dispatch digest
existing wire fields unless explicitly changed below
```

Final flow:

```text
capability settles routine meaning
        ↓
Legion materializes executable work unit / contract
        ↓
OPEN material semantic item?
  yes → Sage adjudicates that item
  no  → no Sage
        ↓
controlled execution if required
        ↓
Alchemist may execute under policy
```

Ambient routine work remains outside mandatory contract ceremony.

---

## M-011 — Remove the hidden Sage-only executable-contract seal

**PHASE_A_DECISIONS:** D-009, D-011, D-014, D-049  
**DISPOSITION:** MODIFY — narrow semantic compatibility change  
**DEPENDENCIES:** M-005, M-010

### Verified current implementation

Current:

```text
src/packages/arcane/lib/contract-seal-store.mjs
```

requires:

```text
authorityAssertion.authority === 'sage'
```

and persists:

```text
sealedBy.authority = 'sage'
```

for every sealed executable contract.

This silently recreates a mandatory Sage stage and therefore must change.

### Exact target

A settled executable contract may be sealed/materialized under:

```text
authority: legion
```

A contract whose settled meaning includes an actual Sage adjudication may be sealed/attributed under:

```text
authority: sage
```

Only these two identities are valid contract-semantic sealers for this migration:

```text
legion
sage
```

Alchemist, Oracle, Covenant, Arcane, and arbitrary capability IDs do not become semantic contract seal authorities.

### `contract-seal-store.mjs`

Change validation from:

```text
authorityAssertion.authority === 'sage'
```

to:

```text
authorityAssertion.authority ∈ {'legion', 'sage'}
```

Preserve:

```text
assertedBy: non-empty string
verificationMethod: 'capability-signature'
perMessage: true
```

Persist:

```text
sealedBy.authority = authorityAssertion.authority
```

Do not hard-code `sage` into the record or conflict comparison.

Idempotency/conflict comparison must compare the stored sealer identity with the current expected identity rather than requiring Sage.

### Arcane runtime schema

Locate the schema used by:

```text
schema.validate('arcane-contract-seal-v1', record)
```

Change only the `sealedBy.authority` constraint necessary to admit:

```text
legion | sage
```

Do not change unrelated schema fields or Arcane gate policy.

### Amendment schema

Current:

```text
src/packages/contracts/schemas/amendment-v1.schema.json
```

contains Sage-only language / `sealedBy` Sage constraint.

Final distinction:

```text
ordinary settled work-unit/contract materialization
  → Legion may seal

semantic amendment whose changed meaning was adjudicated by Sage
  → Sage remains valid sealer

amendment that is purely mechanical representation of already-settled meaning
  → Legion may seal
```

Therefore a generic amendment schema must admit:

```text
sealedBy: legion | sage
```

If inspection proves there is a separate schema explicitly and exclusively for a Sage adjudication record, leave that Sage-specific schema Sage-only; do not force a generic amendment through it.

### Backward compatibility

Existing stored/fixture Sage seals remain valid.

No migration rewrites historical Sage seals.

### Required tests

Add/modify tests proving:

1. executable settled contract + Legion assertion → seals;
2. executable adjudicated contract + Sage assertion → seals;
3. `OPEN` / non-empty `openQuestions` → rejected exactly as before;
4. Alchemist assertion → rejected;
5. Oracle assertion → rejected;
6. Covenant assertion → rejected;
7. missing/invalid capability signature fields → rejected;
8. legacy Sage seal fixture → still verifies;
9. same Legion-sealed immutable version → idempotent;
10. same contract/version with conflicting sealer/digest → version mismatch;
11. Arcane pre-effect gate behavior otherwise unchanged.

**FORBIDDEN:** broad Arcane redesign.

---

# 6. Canonical packaged skill taxonomy

## M-012 — Add canonical semantic metadata to every `SKILL.md`

**PHASE_A_DECISIONS:** D-025 … D-035, D-045  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-006, M-007, M-008, M-009

Canonical human-edited metadata:

```yaml
name:
description:
kind: capability | entrypoint
discoverability: public | explicit | internal

# only for kind: capability
capabilityClass: domain | workflow | context

# optional grouping only
domain: engineering | research | commercial | editorial | design | null

operations: [...]
effects: [...]
hostRequirements: []
```

### Semantics

`operations` and `effects` are a capability's **possible supported repertoire**, not a claim that every invocation performs every listed operation/effect.

Each work unit still declares the actual operations/effects for that invocation, and Arcane gates actual effects.

### Final classification table

| Skill | kind | capabilityClass | discoverability | domain |
|---|---|---|---|---|
| ads | capability | domain | public | commercial |
| alchemist | entrypoint | — | explicit | null |
| architect | capability | domain | public | engineering |
| audit | capability | domain | public | engineering |
| audit-fix | capability | workflow | public | engineering |
| audit-visual | capability | domain | public | engineering |
| brand | capability | context | public | null |
| brand-identity | capability | domain | public | design |
| coder | entrypoint | — | explicit | null |
| commit | entrypoint | — | explicit | null |
| cortex | capability | domain | public | engineering |
| covenant | entrypoint | — | explicit | null |
| debugger | capability | domain | public | engineering |
| designer | capability | domain | public | design |
| dispatch | entrypoint | — | explicit | null |
| handoff | capability | workflow | public | null |
| marketing | capability | domain | public | commercial |
| qa | capability | domain | public | engineering |
| research | capability | domain | public | research |
| seo | capability | domain | public | commercial |
| social | capability | domain | public | commercial |
| tasklist | capability | workflow | public | null |
| writing | capability | domain | public | editorial |

Cross-domain workflows/context use `domain: null`.

Do not invent a domain solely to fill metadata.

### Entrypoint target meaning

Entrypoint targets remain semantically explicit in body/config:

```text
/alchemist → authority:alchemist
/covenant  → challenge:covenant
/dispatch  → orchestration:dispatch
/commit    → workflow:commit
/coder     → outsourced-analysis:coder
```

Do not add a generic `authority` field that would make Covenant an authority.

If a compact target field is required by an existing deterministic consumer, permit:

```yaml
target: authority:alchemist
target: challenge:covenant
target: orchestration:dispatch
target: workflow:commit
target: outsourced-analysis:coder
```

only for `kind: entrypoint`.

Do not add it to ordinary capabilities.

---

## 6.1 Operations and effects target table

This table is the migration target. Do not broaden a skill beyond its current method merely because the vocabulary permits more verbs/effects.

| Skill | operations | possible effects |
|---|---|---|
| ads | analyze, decide, produce | source-read, network-request |
| alchemist | execute | source-read, repository-write, process-exec |
| architect | analyze, decide, produce | source-read, artifact-write |
| audit | analyze, evaluate, produce | source-read, process-exec, artifact-write |
| audit-fix | analyze, evaluate, execute, produce | source-read, repository-write, process-exec |
| audit-visual | analyze, evaluate, produce | source-read, artifact-write, process-exec |
| brand | analyze, produce | source-read |
| brand-identity | analyze, decide, produce, evaluate | source-read, artifact-write |
| coder | analyze | source-read, network-request |
| commit | analyze, evaluate, execute | source-read, repository-write, process-exec, network-request |
| cortex | analyze, produce | source-read, process-exec |
| covenant | analyze, evaluate, produce | source-read |
| debugger | analyze, diagnose, decide, produce | source-read, process-exec |
| designer | analyze, decide, produce, evaluate | source-read, artifact-write |
| dispatch | route, produce | source-read, artifact-write, process-exec |
| handoff | analyze, produce | source-read, artifact-write, process-exec |
| marketing | analyze, decide, produce | source-read, network-request |
| qa | analyze, evaluate, execute, produce | source-read, artifact-write, process-exec |
| research | route, analyze, produce | source-read, artifact-write, network-request |
| seo | analyze, diagnose, produce | source-read, artifact-write, process-exec, network-request |
| social | analyze, decide, produce | source-read, artifact-write, network-request |
| tasklist | analyze, produce, execute | source-read, artifact-write, process-exec |
| writing | analyze, produce, evaluate | source-read, artifact-write |

Notes:

- `network-request` on Commit covers authorized push/network git effects; it does not authorize push by itself.
- Coder remains explicit before any external/provider call.
- A listed effect means “supported possible effect”; actual work-unit effects are narrower.
- Host facilities such as `cortex-graph`, QA engines, providers, connectors, or web search belong in `hostRequirements`/method, not `effects`.

---

# 7. Legacy metadata migration

## M-013 — Retire `MODE`

**PHASE_A_DECISIONS:** D-035, D-036  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-012

Remove `MODE` as global semantic metadata.

Mechanical legacy mapping:

```text
DIAGNOSE
  → one or more of analyze / diagnose / evaluate

EXECUTE / IMPLEMENT
  → execute where actually supported

OUTPUT_ONLY
  → produce

ROUTE
  → route
```

The exact final operations are the table in §6.1, not a one-to-one inference from the old value.

---

## M-014 — Retire `DISCOVERY_PROFILE`

**PHASE_A_DECISIONS:** D-035  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-012

Remove global `DISCOVERY_PROFILE`.

Final discoverability comes only from:

```text
public | explicit | internal
```

and final routing does not use D1/D2/D3 profile identity.

If no runtime consumer exists, delete the field from active semantic blocks.

---

## M-015 — Migrate `EFFECT_PROFILES`

**PHASE_A_DECISIONS:** D-035, D-036, D-053  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-012

Canonical effects:

```text
source-read
artifact-write
repository-write
process-exec
network-request
```

### Exact legacy mapping classes

```text
source_read
  → source-read

output_write
  → artifact-write

repo_write
  → repository-write

external_research / network / equivalent outbound-call labels
  → network-request

runtime / browser/runtime execution where it means process interaction
  → process-exec
```

### Non-effects

These are not effect classes:

```text
focused_check
audit_engine
child_packet
diff_broker
connector
graph_engine
provider ids
engine ids
packet types
check ids
sensitivity labels
host facilities
```

For each such value:

1. remove it from global `effects`;
2. if it names a host facility that the skill requires, map to existing `hostRequirements`;
3. if it names an operation, represent the operation using the frozen operation vocabulary;
4. otherwise preserve its behavioral meaning in the owning skill/method prose;
5. do not create a new global metadata dimension merely to preserve a dead legacy label.

This closes the prior B-002 ambiguity without enlarging the taxonomy.

### Arcane

Arcane maps canonical effects into its existing runtime observation/enforcement buckets.

Do not rename or collapse Arcane's internal runtime effect enums merely to match the five semantic names.

---

## M-016 — Preserve real bounded-execution limits; retire dead header ceremony

**PHASE_A_DECISIONS:** D-043, D-044  
**DISPOSITION:** MIGRATE / KEEP-AS-LOCAL-METHOD  
**DEPENDENCIES:** M-012

Do **not** blindly delete these fields:

```text
PRIMARY_DELIVERABLE
SPECIALIST_REFS_MAX
CHILD_AGENTS_MAX
EXTERNAL_REQUESTS_MAX
MAY_ADD_TASKS
MAY_CALL_SKILLS
TERMINAL
RESOURCE_BUDGET
```

For every occurrence:

```text
consumer exists in runtime/validator/test?
  yes → preserve behavior at existing bounded-execution/workflow owner;
        move from loose global header only if the existing consumer can
        read the owned location without behavior change

no consumer?
  → it is not global architecture;
    preserve useful stopping/budget/safety meaning as specialist method prose,
    otherwise retire the dead label
```

Do not create a new universal lifecycle/config schema solely to retain these labels.

`TERMINAL`, retry budgets, checkpoint/resume rules, and worker limits may remain in Dispatch/Alchemist/Audit/etc. when their actual method uses them.

---

# 8. Catalog and grouping projections

## M-017 — Add one deterministic skill-catalog generator

**PHASE_A_DECISIONS:** D-027, D-028, D-034, D-037, D-039, D-045  
**DISPOSITION:** CREATE GENERATOR + GENERATE  
**DEPENDENCIES:** M-012, M-013, M-014, M-015

The baseline has committed:

```text
src/registry/skills/index.json
src/registry/routing/domains.json
```

without a clear canonical generator.

Do not make them human-edited semantic owners.

Create exactly one small deterministic generator:

```text
scripts/generate-skill-catalog.mjs
```

### Inputs

Sorted:

```text
skills/*/SKILL.md
src/config/capability-aliases.json
```

Aliases remain independently canonical in the aliases config; the generator may project them but does not own them.

### Output A — `src/registry/skills/index.json`

Generate a compact sorted catalog containing every one of the 23 packaged sources.

Each row:

```json
{
  "id": "...",
  "name": "...",
  "description": "...",
  "kind": "capability|entrypoint",
  "capabilityClass": "domain|workflow|context|null",
  "discoverability": "public|explicit|internal",
  "domain": "engineering|research|commercial|editorial|design|null",
  "operations": [],
  "effects": [],
  "hostRequirements": [],
  "source": "skills/<id>/SKILL.md"
}
```

If existing consumers also need manifest paths, preserve that compatibility field:

```json
"manifest": "skills/manifests/<id>.json"
```

No row becomes an owner.

### Output B — `src/registry/routing/domains.json`

Retain this file only because live grouping/lens consumers exist.

Generate it as **grouping-only metadata**:

- groups only `kind: capability`;
- includes only capabilities with non-null domain;
- entrypoints do not appear;
- roles do not appear;
- no `targetType`;
- no engineering/advisory distinction;
- no fixed exactly-five invariant;
- absence of a domain is valid;
- domain value must be from the five optional labels if present.

### CLI

Support:

```bash
node scripts/generate-skill-catalog.mjs
node scripts/generate-skill-catalog.mjs --check
```

Add `--check` to `pnpm legion:check`.

This generator is justified because two committed projections have live consumers and otherwise lack a deterministic source path.

No second generator is added.

---

# 9. Production routing seam

## M-018 — Remove regex natural-language routing and make Legion's model the semantic classifier

**PHASE_A_DECISIONS:** D-007, D-008, D-029, D-030, D-031, D-038, D-041, D-052, D-054  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-017

### Current

```text
src/lib/skills/resolver.mjs
```

contains `NATURAL_ROUTES`, a regex classifier, and `resolveSkillPrompt()`.

### Final production architecture

Natural-language semantic classification is **not another JavaScript classifier service**.

It is performed by the already-always-on Legion orchestration model from the compact canonical catalog in context.

Canonical path:

```text
user natural language
        ↓
Legion model sees compact public catalog
        ↓
Legion selects 0..N public capability IDs
        ↓
deterministic runtime validates selected IDs / availability / discoverability
        ↓
Legion composes work units / work graph
```

Explicit path:

```text
slash command / deterministic alias
        ↓
resolveSkillInvocation()
        ↓
explicit entrypoint or capability target
```

### `src/lib/skills/resolver.mjs`

Preserve:

```text
COMMAND parsing
resolveSkillInvocation()
alias-cycle detection
canonical ID lookup
manifest/catalog availability validation
```

Remove:

```text
NATURAL_ROUTES
regex-as-natural-language-classifier
external-capability return caused only by old regex routes
```

### `resolveSkillPrompt()`

Search all repository consumers.

If there is **no non-test production consumer**, retire `resolveSkillPrompt()` entirely and update tests/imports.

If a production consumer exists, replace it with a deterministic function that accepts an already-produced selection, not raw natural language. Use:

```js
validateCapabilitySelection(selection, options)
```

Contract:

```text
input:
  selection.ids: 0..N canonical ids
  selection.source: semantic | explicit
  optional work-unit metadata

semantic source:
  every selected item must be kind=capability
  discoverability must be public

explicit source:
  explicit capabilities and entrypoints may resolve according to alias/config

output:
  resolved catalog records + manifest paths
  typed invalid/not-found/unavailable result
```

The deterministic validator does **not** interpret prose.

### Do not implement

- stop-word scorer;
- BM25;
- embeddings;
- vector lookup;
- graph router;
- local classifier model;
- regex replacement table.

The model is already present. Do not build a second semantic classifier.

### Legacy `NATURAL_ROUTES`

Move every valid old positive prompt into routing/discovery eval fixtures.

The regex patterns themselves are retired.

---

## M-019 — Convert `src/lib/routing/**` from ontology router to grouping integrity

**PHASE_A_DECISIONS:** D-031, D-037, D-052  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-017, M-018

Paths:

```text
src/lib/routing/loader.mjs
src/lib/routing/validator.mjs
src/lib/routing/resolver.mjs
src/lib/routing/index.mjs
tests/routing.test.mjs
```

Remove:

```text
DOMAIN_IDS fixed routing authority
ADVISORY_DOMAIN_IDS
exactly-five-root requirement
engineering-only agent leaves
advisory-only content leaves
mixed-leaf-type as routing rule
role-as-domain-leaf semantics
```

Keep only generic grouping/integrity validation needed by live consumers:

- valid JSON/schema;
- unique domain IDs;
- children resolve to catalog capabilities;
- no duplicate child membership if the existing UI/grouping consumer assumes uniqueness;
- no entrypoints/roles in the grouping projection.

Do not use the domain grouping as input to semantic routing.

---

## M-020 — Migrate lens/grouping consumers

**PHASE_A_DECISIONS:** D-037, D-052  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-017, M-019

Paths found at baseline include:

```text
src/lib/lenses/routing.mjs
src/lenses/commercial.json
src/lenses/research.json
src/lenses/editorial.json
src/lenses/design.json
src/registry/lenses/commercial-routing.json
src/schemas/lenses/commercial-routing.v1.schema.json
```

Retain grouping/presence/UI behavior.

Remove routing authority assumptions such as:

- targetType content vs agent-dispatch;
- exactly-four/five typed routing-root semantics;
- domain graph as classifier.

---

# 10. Host/runtime compatibility projection

## M-021 — Make host projection metadata-driven without changing the host seam

**PHASE_A_DECISIONS:** D-033, D-039, D-040, D-045, D-048  
**DISPOSITION:** MODIFY GENERATOR + GENERATE  
**DEPENDENCIES:** M-012

### Preserve frozen host behavior

Do not redesign:

```text
src/lib/host/**
src/lib/cli/commands/bind/**
host adapter fidelity
install ownership
collision safety
reversible install/uninstall
legacy-writer quarantine
adapter detection
```

### Generator

Update:

```text
scripts/generate-host-projection.mjs
```

Remove identity special-case:

```js
['alchemist', 'covenant'].includes(id)
```

Read canonical SKILL metadata instead.

### Deliberately lossy compatibility projection

Do **not** force the host projection schema to become the canonical semantic schema.

For the frozen host consumer:

```text
source kind=capability + discoverability=public
    → project as current public projectable capability row
      using the existing compatibility kind expected by host code

source kind=entrypoint
    → do not project as public host skill membership
```

Public workflow/context capabilities remain projectable because they are still public capabilities.

The host projection may therefore continue to use a legacy compatibility `kind` such as `domain-capability` if the frozen host consumer requires it.

That value is not read back as semantic truth.

### Validation

```bash
node scripts/generate-host-projection.mjs --check
node --test --test-concurrency=1 tests/host-adapter-conformance.test.mjs
node --test --test-concurrency=1 tests/host-adapter-safety.test.mjs
node scripts/verify-plugin-parity.mjs --check
```

Host test behavior must remain baseline-equivalent.

---

# 11. Role projections and runtime route residue

## M-022 — Remove stale role-method route mapping

**PHASE_A_DECISIONS:** D-005, D-011, D-012, D-013, D-018  
**DISPOSITION:** MODIFY / GENERATE  
**DEPENDENCIES:** M-005, M-006, M-007, M-008

Inspect and migrate:

```text
src/lib/roster/index.mjs
agents/sage.md
agents/alchemist.md
agents/oracle.md
agents/covenant-seat.md
```

Remove mappings equivalent to:

```text
sage → sage-architect
sage → sage-diagnose
oracle → oracle-assurance as owner of QA/Audit method
```

Generated agent files become thin projections:

- identity summary from roster where applicable;
- method pointer to doctrine;
- no duplicate role canon.

Covenant remains challenge projection, not roster role.

---

# 12. Explicit entrypoints and compatibility aliases

## M-023 — Preserve interface; change ontology

**PHASE_A_DECISIONS:** D-029, D-030, D-031, D-033, D-047  
**DISPOSITION:** MODIFY / KEEP  
**DEPENDENCIES:** M-012, M-018

Canonical explicit entrypoints:

```text
alchemist
covenant
dispatch
commit
coder
```

Natural-language semantic catalog excludes them from automatic capability selection.

Legion may understand a user's **explicit intent** to commit, dispatch, invoke Coder, etc.; explicit intent resolves to the explicit workflow/entrypoint rather than turning it into peer domain expertise.

Preserve current valid aliases from:

```text
src/config/capability-aliases.json
```

including valid compatibility aliases such as:

```text
/justdoit
/jfdi
/council
/blueprint
/glass
/motion
/hormozi
```

according to the existing canonical alias file.

Do not preserve an obsolete ontology just to preserve an alias.

---

# 13. Bounded execution and worker method

## M-024 — Re-home worker-capsule method without universalizing it

**PHASE_A_DECISIONS:** D-006, D-008, D-014, D-016, D-029, D-043, D-044  
**DISPOSITION:** REHOME_THEN_RETIRE  
**DEPENDENCIES:** M-003, M-010, M-016

Source:

```text
doctrine/bundles/legion-worker-capsule.md
```

Destination:

```text
doctrine/legion.md
  → orchestration boundary only

skills/dispatch/SKILL.md
skills/dispatch/references/manual.md
  → zero-context delegation/packet method

existing dispatch-validator / contracts runtime
  → deterministic mechanics
```

Preserve where currently valid:

- zero-context/lossless relay;
- dependency/DAG/maximal-ready behavior;
- typed terminals;
- budgets;
- same-failure stop;
- checkpoints/resume;
- receipts;
- distrust of worker completion claims.

Apply these only to work that justifies them:

- dispatched;
- governed;
- locked;
- contracted;
- expensive/retry-prone;
- resumable/long-running.

Do not wrap ambient routine work in the full worker lifecycle.

---

# 14. G-rule migration

## M-025 — Re-home bare Legion G-rules

**PHASE_A_DECISIONS:** D-051  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-005, M-006, M-007, M-008, M-010, M-024

A bare `G<number>` has no normative authority after migration.

Use the following mapping for active Legion G-rule references:

| Legacy rule | Surviving meaning | Final owner |
|---|---|---|
| G5 | do not materialize useless ceremony; reuse/economy | root simplicity invariant + owning method |
| G7 | implementer self-check does not substitute for independent Oracle | Oracle/Alchemist boundary |
| G8 | author/fixer cannot independently close its own finding where independence is required | relevant Audit/Oracle method |
| G9 | executable contract has no unresolved open questions | contracts executable semantics |
| G10 | sealed semantic change uses explicit versioned amendment | contracts layer |
| G11 | evidence invalidation follows dependencies | Arcane invalidation |
| G12 | Covenant has no authority | covenant-seat |
| G13 | Covenant is not a release gate | covenant-seat |
| G14 | no recursive assurance / Oracle does not routinely convene Covenant | Oracle + covenant-seat |
| G15 | out-of-scope finding is recorded, not opportunistically fixed | Alchemist / bounded execution method |
| G16 | worker output is untrusted until local verification | dispatch/Alchemist worker method |
| G17 | output depth follows intent / bounded need | owning capability / orchestration |
| G22 | lossless dispatch context | Dispatch |
| G24 | dispatch packet/worker relay invariants | Dispatch |

Repository namespaces that independently use labels such as Ads `G01–G24` or audit lane identifiers are **not** Legion architecture G-rules. Do not rename them merely because the token matches.

Replace active Legion bare references with owned descriptive text.

Historical/provenance/test labels may retain `Gnn` only when:

- the actual rule meaning is written beside it;
- no runtime semantic lookup depends on the bare number;
- it is clearly provenance, not normative ownership.

---

# 15. Stale external references and contract prose

## M-026 — Remove stale owners without breaking compatibility readers

**PHASE_A_DECISIONS:** D-003, D-004, D-050, D-051  
**DISPOSITION:** MIGRATE  
**DEPENDENCIES:** M-002, M-010, M-025

Sweep at minimum:

```text
docs/plans/legion
Architecture Book
ARCHITECTURE.md §
sage-architect
sage-diagnose
oracle-assurance
legion-worker-capsule
canon-map authority claims
```

Paths include:

```text
src/packages/contracts/schemas/*.json
src/packages/contracts/FREEZE.md
src/packages/contracts/ids.md
src/packages/arcane/compatibility/**
doctrine/**
agents/**
docs/**
scripts/run-architecture-evals.mjs
```

Rules:

- active normative references point to current in-repo owners;
- compatibility fixtures/readers may retain historical paths as explicitly marked provenance;
- stale outer-workspace source never outranks current canon;
- schema descriptions may change without changing wire structure unless M-011 explicitly requires the narrow seal authority widening.

Rewrite universal:

```text
"No product-state mutation begins without a bounded executable contract"
```

into the Phase A boundary:

```text
controlled/contracted execution requires the appropriate executable contract;
ordinary permitted ambient work does not acquire contract ceremony solely because it mutates.
```

Do not weaken actual Arcane gates for work that currently requires governed execution.

---

# 16. Evaluation and tests

## M-027 — Migrate routing/discovery eval corpus

**PHASE_A_DECISIONS:** D-038, D-052, D-054  
**DISPOSITION:** MODIFY / ADD  
**DEPENDENCIES:** M-018, M-019, M-023

Existing routing/eval fixtures are evidence after their expected semantics are reconciled to Phase A.

Required cases:

### Public discovery

- direct answer with no capability;
- one public capability;
- multiple public capabilities;
- capability composition without domain tree;
- public workflow capability discovery where appropriate;
- public context capability (`brand`) discovery.

### Explicit-only entrypoints

Natural-language auto-discovery must not silently select:

```text
alchemist
covenant
dispatch
commit
coder
```

unless the request contains explicit intent to invoke that action/entrypoint according to the explicit routing contract.

Slash aliases remain deterministic.

### Authority independence

- routine Architect → no Sage;
- material unresolved Architect issue → Sage attached;
- routine Debugger → no Sage;
- unresolved acceptance/ownership issue → Sage attached;
- `repository-write` does not imply Alchemist;
- `execute` does not imply Alchemist;
- `source-read` does not imply Oracle/Sage;
- Covenant never gains authority.

### Assurance boundaries

- Audit owns method;
- Audit Fix reruns frozen plan;
- QA owns functional/browser checks;
- Audit Visual owns rendered-state evidence;
- Designer owns qualitative craft;
- Oracle owns independent final assurance.

### Minimal pairs

Include at least:

```text
Designer vs Audit Visual
Audit vs Oracle
Tasklist vs Dispatch vs Handoff
Brand vs Brand Identity
Coder vs ordinary code analysis
Architect vs non-engineering “architect a design/research/SEO structure”
```

### Legacy regex examples

Every positive example formerly in `NATURAL_ROUTES` is retained as an eval input, with expected behavior updated to the frozen architecture.

Regex source patterns themselves are not kept.

---

## M-028 — Update structural/routing tests

**PHASE_A_DECISIONS:** D-037, D-052, D-054  
**DISPOSITION:** MODIFY  
**DEPENDENCIES:** M-017, M-018, M-019, M-020, M-027

At minimum inspect/update:

```text
tests/routing.test.mjs
tests/architect-debugger-entrypoint-parity.test.mjs
tests/dispatch-qa-entrypoint-parity.test.mjs
tests/skills/**
tests/distribution/**
tests/stage*-architecture-*.test.mjs
skills/*/evals/evals.json
src/evals/architecture/**
```

Do not delete an old failing test merely because its expected semantics are obsolete.

Convert the underlying scenario into a new acceptance case wherever the behavior still matters.

---

# 17. Generated artifacts

## M-029 — Regenerate package/manifests/projections from canonical sources

**PHASE_A_DECISIONS:** D-028, D-033, D-039, D-040, D-048  
**DISPOSITION:** GENERATE  
**DEPENDENCIES:** M-012, M-017, M-021, M-022, M-027, M-028

Use existing generators where they exist:

```text
skills/manifests/*.json
  ← existing local skill-manifest refresh/generation path

src/registry/host-projection.json
  ← scripts/generate-host-projection.mjs

src/registry/skills/index.json
src/registry/routing/domains.json
  ← scripts/generate-skill-catalog.mjs  [new, M-017]

manifest.json
  ← scripts/generate-manifest.mjs

qualification/generated-catalogs.json
  ← scripts/generate-catalogs.mjs

generated schemas
  ← scripts/generate-schemas.mjs

agent/plugin projections
  ← existing roster/plugin projection path
```

Do not hand-edit generated output.

If any alleged generated file has no writer after M-017 and the existing repository does not establish one:

```text
SEMANTIC_BLOCKER
```

Do not create another generator by guess.

---

# 18. Canon-map disposition

## M-030 — Retire `doctrine/architecture/canon-map.md` unless a non-test runtime consumer proves necessity

**PHASE_A_DECISIONS:** D-004, D-028, D-039, D-050  
**DISPOSITION:** RETIRE by default  
**DEPENDENCIES:** M-002, M-022, M-028

Do not create a permanent canon-map generator merely for ceremony.

Before retirement, search exact consumers.

### If consumers are only:

- conformance tests;
- documentation;
- migration tooling;

migrate those consumers to canonical owners / generated catalog / root ownership table and retire:

```text
doctrine/architecture/canon-map.md
```

### If a non-test runtime consumer exists

Do not infer.

Stop M-030 and record:

```text
SEMANTIC_BLOCKER M-030
consumer:
required fields:
why root/catalog/roster cannot replace it mechanically:
```

Only then consider retaining a derived canon-map.

The default final architecture does not need two ownership maps.

---

# 19. Retirement and provenance

## M-031 — Re-home, validate, then retire superseded active owners

**PHASE_A_DECISIONS:** D-001, D-004, D-006, D-044, D-050  
**DISPOSITION:** RETIRE / ARCHIVE  
**DEPENDENCIES:** M-006, M-007, M-008, M-024, M-025, M-026, M-029, M-030

Final dispositions:

| Source | Disposition |
|---|---|
| `docs/LEGION-CANONICAL-SSOT-v2.md` | archive as provenance after root adoption |
| `docs/architecture.md` | re-home useful method, archive as provenance |
| `doctrine/bundles/sage-architect.md` | rehome to Architect, retire active file |
| `doctrine/bundles/sage-diagnose.md` | rehome to Debugger, retire active file |
| `doctrine/bundles/oracle-assurance.md` | split to QA/Audit Visual/Oracle, retire duplicate bundle |
| `doctrine/bundles/legion-worker-capsule.md` | rehome Dispatch/orchestration method, retire global bundle |
| `doctrine/architecture/canon-map.md` | retire unless M-030 proves runtime need |
| old external plan/Architecture Book references | provenance only; no active authority |
| old five-domain routing ontology | retire; grouping metadata only |
| `NATURAL_ROUTES` | retire; examples become evals |

Recommended provenance paths:

```text
docs/provenance/LEGION-CANONICAL-SSOT-v2.md
docs/provenance/architecture.md
docs/provenance/migrations/LEGION-SEMANTIC-DECISIONS-v1.1.md
docs/provenance/migrations/LEGION-PHASE-B-v1.0.md
```

Do not duplicate migration files into provenance until implementation is complete and their hashes are frozen.

---

# 20. Exact dependency-ordered execution sequence

This sequence is acyclic.

## Wave 0 — baseline

```text
M-001
```

## Wave 1 — establish permanent architecture owners

```text
M-002
M-003
M-004
M-005
```

`M-003` and `M-004` follow root creation. Role cleanup can proceed once root ownership is fixed.

## Wave 2 — re-home specialist method

Parallel where files do not overlap:

```text
M-006  Architect
M-007  Debugger
M-008  Audit/QA/AuditVisual/Designer/Oracle/Covenant
M-009  Audit Fix
```

## Wave 3 — work-unit / authority correction

```text
M-010
M-011
```

Run focused contract/Arcane tests immediately after M-011.

## Wave 4 — canonical skill semantics

```text
M-012
M-013
M-014
M-015
M-016
```

The 23 individual SKILL edits may run in parallel after the canonical table is frozen.

## Wave 5 — deterministic projections

```text
M-017
```

Do not edit generated registries first.

## Wave 6 — routing/runtime consumers

```text
M-018
M-019
M-020
M-021
M-022
M-023
M-024
```

M-018/M-019/M-020 are the routing cutover.
M-021 preserves host behavior.
M-022 removes stale role-route projection.
M-023 preserves aliases.
M-024 re-homes worker method.

## Wave 7 — provenance vocabulary

```text
M-025
M-026
```

## Wave 8 — acceptance corpus and generated output

```text
M-027
M-028
M-029
M-030
```

## Wave 9 — retirement

```text
M-031
```

Only retire after reachability and test evidence prove the new owners are live.

## Wave 10 — full validation

Run §21 in full.

No retirement is “complete” until this wave passes.

---

# 21. Final validation suite

## 21.1 Canonical source checks

Assert:

- exactly one permanent root SSOT;
- AGENTS is live constitution;
- roster owns Sage/Alchemist/Oracle identity;
- Covenant absent from authority roster;
- every SKILL has valid canonical semantic metadata;
- no ordinary capability has a static authority owner;
- no entrypoint is accidentally public semantic expertise;
- no generated projection claims canonical authority.

---

## 21.2 Catalog generation

```bash
node scripts/generate-skill-catalog.mjs --check
```

Assert:

- all 23 source IDs present exactly once;
- no support directory becomes a capability;
- `domains.json` is grouping-only;
- entrypoints absent from domain groups;
- null-domain capabilities valid.

---

## 21.3 Routing

```bash
node --test --test-concurrency=1 tests/routing.test.mjs
```

Plus migrated capability/discovery evals.

Assert:

- no `NATURAL_ROUTES`;
- no fixed five-domain routing;
- semantic classification is model-side over compact catalog;
- deterministic runtime validates selection only;
- explicit slash/aliases still work;
- 0/1/N composition cases pass.

---

## 21.4 Sage / Architect / Debugger

```bash
node --test --test-concurrency=1 \
  tests/architect-debugger-entrypoint-parity.test.mjs
```

Plus architecture/debugger evals.

Assert routine Architect/Debugger does not require Sage.

---

## 21.5 Contract seal / Arcane

Run:

```bash
node --test src/packages/contracts/smoke.test.mjs
node --test src/packages/arcane/tests/*.test.mjs
```

and new/focused contract-seal tests.

Assert:

- Legion can seal settled executable contract;
- Sage can seal adjudicated executable contract;
- no other authority can;
- legacy Sage seal remains valid;
- OPEN remains non-executable;
- Arcane effect enforcement unchanged otherwise.

---

## 21.6 Host freeze

```bash
node scripts/generate-host-projection.mjs --check

node --test --test-concurrency=1 \
  tests/host-adapter-conformance.test.mjs \
  tests/host-adapter-safety.test.mjs

node scripts/verify-plugin-parity.mjs --check
```

No new host fidelity claim.
No new adapter owner.
No changed install semantics.

---

## 21.7 Generated manifests / schemas / dependency closure

Use repository-supported commands, including:

```bash
node scripts/generate-manifest.mjs --check
node scripts/generate-schemas.mjs --check
node scripts/check-dependency-closure.mjs
```

and the existing skill-manifest regeneration/check path.

Generated output must be reproducible from canonical source.

---

## 21.8 Legacy semantic absence scan

Search active normative/runtime sources for:

```text
Sage Architect
Sage Diagnose
Engineering decision authority
Execution Compile
five peer domains
advisory domains
NATURAL_ROUTES
DOMAIN_IDS
ADVISORY_DOMAIN_IDS
domain-capability          # except deliberately lossy host compatibility projection
role-entrypoint            # except deliberately lossy host compatibility projection if required
MODE:
DISCOVERY_PROFILE:
EFFECT_PROFILES:
docs/plans/legion
Architecture Book
```

Every remaining hit must be one of:

- explicit provenance;
- compatibility fixture;
- intentionally lossy host projection vocabulary;
- unrelated domain-specific identifier;
- local specialist method label with a proven consumer.

No active ownership/routing semantics may remain.

---

## 21.9 G-rule scan

Search:

```regex
\bG[0-9]+\b
```

Classify every remaining occurrence.

Allowed:

- unrelated Ads/audit namespaces;
- explicit provenance;
- test/historical label with owned meaning adjacent.

Disallowed:

- bare Legion architectural authority reference.

---

## 21.10 Full repository gates

```bash
pnpm legion:check
pnpm test
```

Compare against Wave 0.

Report:

```text
baseline failures
new failures
fixed baseline failures
skips
```

Do not claim “full PASS” if unrelated baseline failures remain.

---

## 21.11 Independent Completion Validation

After implementation and local validation:

- run Oracle-style independent validation from the original migration request;
- validator must inspect current repository state, not implementation narration;
- verify owner uniqueness;
- verify generated drift;
- verify no stale semantic consumer;
- verify host freeze;
- verify contract-seal correction;
- verify routing semantic seam;
- verify all retirements are safe.

Completion claim states separately:

```text
produced
verified
completion-validated
committed
pushed
deployed
```

Do not conflate them.

---

# 22. Phase A coverage matrix

Every Phase A decision is mechanically covered.

| Phase A | Phase B actions |
|---|---|
| D-001 | M-002, M-031 |
| D-002 | M-003 |
| D-003 | M-004, M-026 |
| D-004 | M-030, M-031 |
| D-005 | M-005, M-022 |
| D-006 | M-006, M-007, M-008, M-024, M-031 |
| D-007 | M-003, M-018 |
| D-008 | M-010, M-018, M-024 |
| D-009 | M-005, M-010, M-011, M-027 |
| D-010 | M-006, M-007, M-008 |
| D-011 | M-005, M-011, M-027 |
| D-012 | M-006 |
| D-013 | M-007 |
| D-014 | M-010, M-011 |
| D-015 | M-005, M-023 |
| D-016 | M-003, M-010, M-024 |
| D-017 | M-015, M-021 |
| D-018 | M-005, M-008 |
| D-019 | M-005, M-008, M-023 |
| D-020 | M-008 |
| D-021 | M-008 |
| D-022 | M-009 |
| D-023 | M-008 |
| D-024 | M-008, M-009 |
| D-025 | M-012 |
| D-026 | M-012 |
| D-027 | M-012 |
| D-028 | M-012, M-017, M-029 |
| D-029 | M-012, M-018, M-023, M-024 |
| D-030 | M-012, M-018, M-023 |
| D-031 | M-012, M-018, M-023 |
| D-032 | M-012 |
| D-033 | M-012, M-021, M-023 |
| D-034 | M-012, M-017 |
| D-035 | M-013, M-014, M-015 |
| D-036 | M-010, M-012, M-015 |
| D-037 | M-012, M-017, M-019, M-020 |
| D-038 | M-018, M-027 |
| D-039 | M-017, M-021, M-022, M-029 |
| D-040 | M-021 |
| D-041 | M-018 |
| D-042 | M-003, M-018 |
| D-043 | M-010, M-016, M-024 |
| D-044 | M-002, M-016, M-024, M-031 |
| D-045 | M-017, M-021 |
| D-046 | M-005 |
| D-047 | M-023 |
| D-048 | M-001, M-021, M-029 |
| D-049 | M-010, M-011, M-015, M-026 |
| D-050 | M-002, M-026, M-031 |
| D-051 | M-025, M-026 |
| D-052 | M-018, M-019, M-020, M-027 |
| D-053 | M-015 |
| D-054 | M-027, M-028 |
| D-055 | M-001, M-003 |

Coverage:

```text
55 / 55
```

No Phase A semantic decision is left for the executor.

---

# 23. Mechanical readiness

## Status

```text
PHASE A DECISIONS COVERED: 55 / 55

KNOWN PREVIOUS PHASE-B AMBIGUITIES CLOSED:
  ✓ Sage-only executable-contract seal
  ✓ production semantic-routing seam
  ✓ generator for skills/index + grouping domains
  ✓ non-effect EFFECT_PROFILE disposition
  ✓ per-capability domain membership
  ✓ Architect method destination
  ✓ canon-map default disposition
  ✓ host projection canonical-vs-compatibility distinction
  ✓ bounded-execution header preservation rule

MECHANICAL EXECUTION READY: YES
```

“YES” means the executor is not expected to choose what Legion should mean.

It does not mean unexpected repository drift can never produce a blocker.

---

# 24. Executor completion contract

The implementation is complete only when all of the following are true:

1. `docs/LEGION-CANONICAL-SSOT.md` exists and is the sole active root architecture SSOT.
2. `AGENTS.md` is the live operational constitution.
3. role identity is canonical only in roster files.
4. Architect and Debugger own their methods directly.
5. Sage is exceptional-only.
6. ordinary settled executable contracts do not require Sage to seal.
7. Alchemist is policy-triggered, not inferred from `execute`.
8. Audit / QA / Audit Visual / Designer / Oracle / Covenant ownership is non-duplicative.
9. all 23 packaged SKILL sources carry canonical semantic metadata.
10. MODE / DISCOVERY_PROFILE / legacy EFFECT_PROFILES no longer act as global semantics.
11. skill/index and domain/grouping registries are deterministic projections.
12. regex natural-language routing is gone.
13. natural-language capability selection is model-side over the compact catalog.
14. deterministic runtime only validates/loads selected capabilities and resolves explicit aliases.
15. domains do not route.
16. host/runtime integration behavior from `57d00b1f` remains intact.
17. Arcane behavior remains intact except the narrow contract-seal authority compatibility correction.
18. useful method is re-homed before stale owners retire.
19. v2 and old architecture docs leave active normative paths.
20. all required focused tests, drift checks, `pnpm legion:check`, and full-test comparison are evidenced.
21. independent Completion Validation passes.
22. no unresolved semantic blocker remains.

---

# 25. Forbidden completion claims

Do not claim:

```text
"done"
"all tests pass"
"fully migrated"
"canonical"
"verified"
```

from implementation narration alone.

Evidence must distinguish:

```text
PRODUCED
VERIFIED
COMPLETION-VALIDATED
COMMITTED
PUSHED
DEPLOYED
```

Only claim stages actually completed.

---

# 26. Final migration rule

Phase B is an execution manifest, not an invitation to optimize Legion.

If implementation reveals a better architecture:

```text
do not adopt it here
record it separately
finish the frozen migration first
```

The only permitted changes are those required to make the repository faithfully implement Phase A v1.1 and this manifest.

That is the stop condition for architecture churn.
