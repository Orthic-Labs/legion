# Legion — Canonical System Architecture SSOT

**Status:** CANONICAL — permanent root system-architecture source of truth  
**Repository:** `Orthic-Labs/legion`  
**Adopted:** 19 August 2026  
**Supersedes as active architecture authority:** `docs/LEGION-CANONICAL-SSOT-v2.md`, `docs/architecture.md`, `doctrine/architecture/canon-map.md` (architecture-authority claims)

This file is the **one permanent root system-architecture SSOT** for Legion. It owns system
architecture, ownership boundaries, global invariants, orchestration semantics,
capability/authority/effect relationships, canonical-owner delegation, and globally binding
architectural decisions.

It delegates specialist method rather than duplicating it. Where a concern has a specialist
owner, this file states the owner, boundary, invariant, and canonical path — not a second copy of
the method.

## 1. Status, scope, precedence

**Scope.** Legion-wide system architecture, orchestration, capability/authority boundaries,
execution substrate, deterministic effect enforcement, adversarial challenge, independent
completion assurance, routing/discovery architecture, progressive context loading, and canonical
ownership.

**Precedence.**

```text
this root SSOT
    >
AGENTS.md (live operational constitution, constrained by this SSOT)
    >
docs/canon/*.md (atomic capability inventory/state, constrained by this SSOT)
    >
src/roster/* (role identity/authority) and doctrine/* (delegated method)
    >
skills/<id>/SKILL.md (packaged capability/entrypoint semantics)
    >
generated projections (never semantic owners)
```

When a specialist file conflicts with this document about ownership, authority, orchestration,
effect semantics, or another subject governed here, this document wins. Inside a delegated
specialist method, that specialist's canonical owner wins unless it violates a global invariant
defined here.

**Provenance.** `docs/provenance/migrations/LEGION-SEMANTIC-DECISIONS-v1.1.md`,
`docs/provenance/migrations/LEGION-PHASE-B-v1.0.md`, and
`docs/provenance/LEGION-CANONICAL-SSOT-v2.md` are migration provenance, not co-equal architecture
authorities. They must not remain active normative loading paths.

## 2. Legion system model

```text
USER INTENT
    ↓
LEGION — always-on orchestrator
    ↓
WORK GRAPH — work units: capabilities, operations, effects, dependencies,
             authority only where required
    ↓
CAPABILITIES (domain / workflow / context) and ENTRYPOINTS
    ↓
TOOLS / ENGINES / HOST CAPABILITIES
    ↓
ARCANE — cognitive control plane
    ↓
GUARD — deterministic effect enforcement
    ↓
ORACLE COMPLETION VALIDATION — current global policy: required before successful delivery
    ↓
DELIVERY

COVENANT — optional bounded adversarial challenge beside the work graph
```

Primary rules:

1. **Legion is the only always-on orchestrator.** All other components — Sage, Alchemist,
   Oracle, Covenant, Audit, Architect, Debugger, Arcane, capabilities — are selected/attached
   concerns, not peer orchestrators.
2. **Capabilities describe expertise and method; roles do not contain skills.**
3. **Capabilities own routine domain judgment. Sage handles exceptional material unresolved
   judgment only.**
4. **Authority is attached to the work that requires it, not statically to a domain, capability,
   operation, or effect.**
5. **Effects are explicit, and deterministic effect enforcement belongs to the Guard.**
6. **Evaluation methodology is not independent assurance.**
7. **Complexity carries the burden of proof.**
8. **Universal Oracle Completion Validation remains current Legion policy.**

## 3. Canonical ownership model

| Semantic concern | Permanent canonical owner | Derived / consumer only |
|---|---|---|
| System architecture and ownership boundaries | `docs/LEGION-CANONICAL-SSOT.md` | all architecture summaries/maps |
| Live Legion constitution | `AGENTS.md` | `CLAUDE.md`, harness context projections |
| Atomic capability inventory and lifecycle state | `docs/canon/{legion,sage,alchemist,oracle,arcane,guard,covenant,skills}.md` | `docs/canon/README.md`, generated `docs/pending/README.md` |
| Legion routing/orchestration reference | `doctrine/legion.md` | generated summaries |
| Sage identity / authority / tier | `src/roster/sage.md` | `agents/sage.md`, doctrine method |
| Alchemist identity / authority / tier | `src/roster/alchemist.md` | `agents/alchemist.md`, doctrine method |
| Oracle identity / authority / tier | `src/roster/oracle.md` | `agents/oracle.md`, doctrine method |
| Sage / Alchemist / Oracle role architecture | `docs/architecture/{sage,alchemist,oracle}.md` | role-specific architecture summaries |
| Covenant challenge standing | `doctrine/covenant-seat.md` | `agents/covenant-seat.md`, entrypoint |
| Architecture craft | `skills/architect/SKILL.md` + `skills/architect/doctrine/architecture/**` | old Sage Architect bundle |
| Diagnosis craft | `skills/debugger/SKILL.md` + debugger references | old Sage Diagnose bundle |
| Audit method | `skills/audit/**` | Oracle may consume evidence |
| Audit Fix workflow | `skills/audit-fix/**` | no authority owner implied |
| Rendered-state visual evaluation | `skills/audit-visual/**` | Oracle may consume evidence |
| Functional/browser/runtime QA | `skills/qa/**` | Oracle may consume evidence |
| Qualitative design craft | `skills/designer/**` | Audit Visual may provide evidence |
| Capability/entrypoint semantics | `skills/<id>/SKILL.md` | catalogs/manifests/projections |
| Host capability availability | `src/registry/capabilities.json` | SKILL `hostRequirements` |
| Public distribution and client integration | `docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md` | release policy, bootstrap, host adapters |
| Explicit aliases | `src/config/capability-aliases.json` | resolver/projections |
| Semantic effect vocabulary | this root SSOT | SKILL declarations |
| Cognitive control plane and response policy | `doctrine/arcane.md` | host delivery surfaces |
| Runtime effect mapping/enforcement | `doctrine/guard.md` (seed: `engine/bins/legion-hook/**`) | receipts/projections |
| Executable work-unit materialization | Legion + producing capability | contract runtime |
| Independent Completion Validation | Oracle (`src/roster/oracle.md` + `doctrine/oracle.md`) | Audit/QA evidence may be inputs |

No row has two independent semantic owners.

The two meanings of "capability" are permanently disambiguated:

```text
DOMAIN CAPABILITY
expertise / method / packaged procedure, owned by skills/<id>/SKILL.md
examples: architect, audit, research, designer, seo

HOST CAPABILITY
externally supplied execution or tool facility the package does not contain,
declared in src/registry/capabilities.json
examples: blueprint-graph, web-search, omniroute
```

Unqualified "capability" in this document means **domain capability**. Host capabilities are
always named as such.

## 4. Work units and work graphs

Legion decomposes non-trivial work into a work graph of work units. A work unit expresses:

```text
capabilities
operations
effects
dependencies
authority state only where required
bounds/checkpoints only where required
```

Work is modeled by what must happen, not by which role name matched first.

```yaml
id: competitor-evidence
capabilities: [research]
operations: [analyze]
effects: [source-read]
depends_on: []
authority: auto
```

`authority: auto` means the capability proceeds under its normal mandate unless global policy or
discovered evidence requires escalation. There is **no mandatory global**
`capability → authority → execution` pipeline. The work graph may discover a new authority need
later (for example, Debugger evidence reveals two materially different valid semantics →
Debugger + Sage).

**Invariant:** capability identity never statically determines authority. Authority is attached
independently to the work that requires it and may change when evidence changes.

Simple requests may execute directly without durable work-unit artifacts.

## 5. Capabilities and entrypoints

Canonical owner of capability/entrypoint semantics: `skills/<id>/SKILL.md`.

Minimal semantic taxonomy:

```text
kind: capability | entrypoint

when kind: capability
  capabilityClass: domain | workflow | context

discoverability: public | explicit | internal
```

Meaning:

```text
capability/domain    → specialist expertise/method
capability/workflow  → reusable user-facing procedure/stateful workflow
capability/context   → reusable contextual input/provider
entrypoint           → explicit compatibility or orchestration invocation surface,
                       not peer semantic expertise
```

Do not add a larger ontology. Domains (`engineering | research | commercial | editorial |
design | null`) are optional grouping metadata only — never a routing hierarchy.

Capabilities own routine domain judgment: Architect decides routine architecture trade-offs;
Debugger evaluates routine root-cause hypotheses; Designer decides routine design hierarchy and
craft; Research selects routine evidence methods; Marketing makes routine marketing strategy
decisions; Audit adjudicates findings inside its method. Judgment alone is not an authority
trigger.

Entrypoint targets are semantically explicit:

```text
/alchemist → authority:alchemist
/covenant  → challenge:covenant
/commit    → workflow:commit
/coder     → outsourced-analysis:coder
```

Only `kind: entrypoint` may carry a `target` field. No ordinary capability has a static
authority owner.

## 6. Authority model

Authority attaches to work, not to a domain tree or skill parent. The three authority identities
and their detailed mandate, boundary, inputs, outputs, and interactions are delegated to
`docs/architecture/{sage,alchemist,oracle}.md`; this SSOT retains their cross-role relationships:

| Authority | Cross-role responsibility |
|---|---|
| Sage | exceptional adjudication of material unresolved meaning; never a routine domain owner or product-state executor |
| Alchemist | controlled bounded transformation of settled meaning; never an independent semantic decision-maker |
| Oracle | independent, read-only Completion Validation; never an implementer or self-certifier |

Sage does not own architecture, debugging, research, design, marketing, SEO, ordinary strategy,
or contract compilation as a discipline. "Engineering decision authority", "Sage Architect",
"Sage Diagnose", and "Execution Compile" as Sage routes are retired.

Executable-contract authorship is orchestration, not Sage authority: the producing capability
settles routine meaning, Legion materializes the executable work unit/contract, and Sage
participates only when an item remains genuinely OPEN and requires exceptional adjudication.
Alchemist applies settled bounded work; Oracle independently validates the delivered result.

Covenant is not an authority. It is optional, bounded, advisory, read-only, policy/user-triggered,
not the default reviewer, and without disposition/effect authority. It does not join the
authority roster.

## 7. Operations and effects

Operations, effects, and authority are independent axes:

```text
operations → what the work is doing
effects    → what state interaction occurs
authority  → exceptional responsibility/permission attached to this work
```

Canonical operation vocabulary (only values with actual runtime consumers are kept):

```text
route | analyze | diagnose | decide | produce | evaluate | execute
```

Canonical semantic effect-class vocabulary:

```text
source-read
artifact-write
repository-write
process-exec
network-request
```

Never infer:

```text
diagnose → Sage
execute → Alchemist
effect X → capability Y
```

Never infer effect safety from a mode label. Effects are declared explicitly and the Guard gates
them deterministically.

## 8. Cognitive control and deterministic effect-enforcement boundary

```text
Legion  = orchestration control
Arcane  = cognitive control plane
Guard   = deterministic effect enforcement
```

Arcane owns cognitive processing shape and response policy, including Brief/Minimize,
ending-shape discipline, and Bounded Falsification; its detailed method is delegated to
`doctrine/arcane.md`. The Guard owns effect classification, policy matching, deterministic
fail-closed gates, enforcement health, and effect-decision receipts; its detailed method is
delegated to `doctrine/guard.md`.

Cross-boundary invariants:

- Arcane does not authorize effects or keep effect-enforcement receipts.
- The Guard may deliver Arcane-owned cognitive policy through a host lifecycle surface such as
  the Stop event, but it never becomes the owner or enforcer of that cognitive policy.
- The Guard gates typed effects, not semantic capability labels. Enforcement failures fail
  closed; mandatory authorization/security gates may never silently no-op; blocking surfaces are
  minimal and effect-scoped; gates must be earnable.

## 9. Routing and discoverability

Natural-language routing is semantic over the flat compact catalog:

1. Legion interprets intent;
2. classifies against the compact complete semantic catalog;
3. selects zero, one, or many capabilities;
4. derives operations/effects/dependencies;
5. attaches authority only if required.

Slash aliases and deterministic explicit commands remain deterministic. Natural-language semantic
classification is performed by the always-on Legion orchestration model from the compact catalog
in context — not by a regex table, stop-word scorer, BM25, embeddings, vector lookup, graph
router, local classifier model, or a second JavaScript classifier service. The deterministic
runtime only validates/loads selected capability IDs and resolves explicit aliases.

At the current ~20–30 semantic entries, no retrieval infrastructure (RAG, embeddings, vector
search, graph routing, RDF/JSON-LD, hierarchical retrieval) is added. Add retrieval only after
measured discovery failure. Blueprint graph infrastructure remains unrelated to capability routing.

Explicit-only entrypoints (`alchemist`, `covenant`, `commit`, `coder`) are excluded
from automatic natural-language capability selection; explicit user intent resolves them.

Dispatch is a public workflow capability: natural-language delegation intent selects it
semantically, while `/dispatch` remains a deterministic explicit invocation of the same capability.

Domains never decide routing. Generated registries (`src/registry/skills/index.json`,
`src/registry/routing/domains.json`, `src/registry/host-projection.json`, `skills/manifests/*.json`)
are projections only: fix source, regenerate projection; never hand-edit projection semantics.

## 10. Context loading

Always-on Legion context contains only what is needed for: constitution, compact semantic catalog,
global invariants, routing. Then load progressively:

```text
catalog
→ selected SKILL.md
→ required specialist references/tools
```

The root SSOT is authoritative without being injected wholesale into every turn. Semantic
correctness does not require prompt bloat.

## 11. Evaluation, challenge, assurance, and review ownership

Review ownership is concern-specific. There is no generic Review authority.

```text
capability self-verification → method-local correctness
Audit                        → systematic evaluation methodology
Covenant                     → adversarial challenge
Oracle                       → independent assurance
Arcane                       → cognitive processing shape and response policy
Guard                        → deterministic effect enforcement
Legion                       → integration and delivery ownership
```

Ownership boundaries:

- **Audit** (`skills/audit/**`) owns scope freeze, audit planning, provider/check selection,
  evidence collection, coverage accounting, candidate generation, methodological adjudication,
  finding classification, deduplication, typed degradation, reports/SARIF, rerun/reproducibility,
  evidence loci, and completeness accounting. Methodological independence ("a generator cannot
  close its own finding") is an Audit method invariant, not Oracle authority.
- **Audit Fix** (`skills/audit-fix/**`) is a workflow capability attached to a frozen Audit
  result: bounded remediation of admitted findings, preservation of the frozen Audit plan,
  same-plan rerun, remediation lifecycle. It is not Oracle; it is not Alchemist merely because it
  writes; actual effects remain Guard-gated.
- **Audit Visual** (`skills/audit-visual/**`) owns rendered-state enumeration, screenshots/
  baselines/regression evidence, visual-state coverage, clipping/overlap/missing-state findings,
  deterministic visual evaluation.
- **Designer** (`skills/designer/**`) owns qualitative design craft: hierarchy/composition/
  typography/interaction, design direction, remediation craft.
- **QA** (`skills/qa/**`) owns functional/behavioral QA, deterministic browser/runtime checks,
  mocks, contract tests, viewport capture as QA evidence.
- **Oracle** (`doctrine/oracle.md` delegated from `src/roster/oracle.md`) owns independent
  assurance and Completion Validation; it may consume Audit/QA/Audit Visual evidence but does not
  own their methods.
- **Covenant** (`doctrine/covenant-seat.md`) owns bounded adversarial challenge, advisory only.
- **Arcane** (`doctrine/arcane.md`) owns the cognitive processing shape and response policy.
- **Guard** (`doctrine/guard.md`; seed `engine/bins/legion-hook/**`) owns deterministic effect
  enforcement and its receipts.

Shared capture machinery (screenshots/browser engines) is an internal primitive, not a semantic
owner.

## 12. Ambient vs governed execution

Ordinary explicit, reversible, in-scope effects may execute directly under Legion/capability
control when Guard policy permits them (ambient execution). Alchemist is used only where policy,
locking, explicit contracting, or risk requires it. `execute` does not imply Alchemist.

Controlled/contracted execution requires the appropriate executable contract; ordinary permitted
ambient work does not acquire contract ceremony solely because it mutates. Typed terminals,
numeric budgets, same-failure stop, checkpoints, and resumability are execution substrate used
where justified: locked/governed work, contracted work, dispatched workers, expensive/retry-prone
work, resumable long-running work. Ambient routine work does not require the full ceremony.

## 13. Host/runtime and projection boundary

Canonical semantics are host-neutral; harnesses are not. Host adapters are renderers, not second
semantic owners: they translate the canonical projection into a harness's native format and never
hand-author capability or role content.

```text
CANONICAL (host-neutral)
skills/<id>/SKILL.md, src/roster/*.md, doctrine/**,
src/registry/capabilities.json, `doctrine/arcane.md`, `doctrine/guard.md`,
`engine/bins/legion-hook/**`

    ↓ projection (generated, one direction only)

HOST-SPECIFIC
.claude/**, .codex/**, .gemini/**, AGENTS.md, plugin packages
```

Canonical semantic ownership defined by this SSOT remains authoritative. Target product topology
and native runtime lifecycle are described by `migration/native-rust/PRODUCT-ARCHITECTURE-V2.md`.
Public distribution, activation transactions, Agent Plugins packaging, and exact client boundaries
are owned by `docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md`. Thin target adapters preserve
collision-safe/reversible installation, truthful fidelity, legacy-writer quarantine, and
conformance/safety guarantees without preserving descriptor-driven semantic hosting. Legacy
`.claude`, `.codex`, `.gemini`, and equivalent projections are migration/compatibility surfaces
only and have no target-runtime semantic authority.

Host projection may be deliberately lossy for compatibility: source `kind=capability` +
`discoverability=public` projects as a public projectable capability row (using the legacy
compatibility `kind` the host consumer requires); source `kind=entrypoint` does not project as
public host skill membership. That compatibility projection is not read back as canonical
taxonomy.

### 13.1 Installed product versus development execution

Legion has two explicit execution origins:

```text
installed   → production harness/PATH/hooks/MCP/client activation bind only to
              %LOCALAPPDATA%\Orthic Labs\Legion\current\bin\legion.exe
development → explicit repository commands with isolated development state
              roots, ports, process identity, and client overrides
```

Production bindings to repository, `dist`, `target`, or `node_modules` executables are
prohibited. Default development commands must not mutate global harness configuration, PATH,
startup registration, the stable `current` target, or installed state; tests use temporary roots.
Bootstrap is the sole authority that stages immutable versions, journals integrations, switches
the stable `current` target, and activates clients. Setup/status must report
`origin=installed|development`, executable, install root, and generation. Production status fails
closed whenever any binding escapes the stable `current` executable. Private workspace content is
excluded from installed releases, client projections, and production bindings.

### 13.2 Public CI & protected release boundary

Public `Orthic-Labs/legion` GitHub Actions owns compile, test, candidate/package qualification, package smoke, SBOM,
provenance, candidate production, Windows Azure OIDC signing, & macOS Developer ID
signing/notarization from protected environment secrets. Package smoke stages each supplied candidate
into an isolated product-root `current` tree before exercising installed-boundary runtime resolution on
its target OS. CI cannot publish release payloads.

Protected local release hosts consume exact candidate & evidence digests. They own post-sign
installed-artifact qualification, release sealing, manifest-catalog signing, & upload to immutable
GitHub Releases & approved bootstrap publication; they do not rebuild candidates. Private `bogusyogi`
repos run same RightKit pipeline locally with zero
GitHub Actions; public & private differ only by runner, authentication, & spend boundary. Release trust
binds `release-manifest.json` to `release-manifest.cat`, a Windows Authenticode catalog. An unsigned CI
candidate is not a published release.

## 14. Model policy

Model policy is tiered; concrete models are host configuration. Canonical architecture, role
identity, and generic capability doctrine use abstract model classes/tiers where model strength
matters; the role-specific policy is delegated to `docs/architecture/{sage,alchemist,oracle}.md`.

Concrete provider/model IDs belong to host/runtime configuration, except when a capability's
explicit purpose is to invoke a user-selected named provider/model (for example `coder`, which
remains explicit before any external/provider call and does not canonically force one vendor).

## 15. Complexity / simplicity / retirement rules

Global order of preference:

```text
remove
→ reuse
→ inherit
→ adapt
→ add
```

Any new boundary/mechanism must pass: real driver; reuse test; one-fewer-moving-part test;
retirement test. No replacement is complete while its superseded mechanism remains an active
peer. Useful method is re-homed before its old owner is retired; retirement is never
delete-first. Historical documents may remain archived as provenance.

Capability federation: adding a capability should normally be additive
(`new capability package + canonical metadata + generated projections/evals`). The orchestration
kernel does not special-case capability identities unless a generic seam demonstrably fails;
identity-based switches are a smell and require justification.

## 16. Compatibility surfaces

Compatibility preserves interface, not ontology. A compatibility alias may preserve a slash
command, external invocation path, legacy packet/schema reader, or migration surface — it may not
preserve incorrect semantic ownership. Compatibility shims are not capabilities merely because
they have a SKILL package. Explicit shims may remain until consumers disappear.

Deterministic slash aliases may invoke internal concerns without changing ownership.

## 17. Revisit triggers and architecture-change policy

Architecture changes to this SSOT require a real driver and must pass the complexity tests in
§15. No change may silently create a second owner for a concept owned here. A bare
`G<number>` has no surviving normative authority; surviving rule meanings are owned prose under
their subject's canonical owner. Historical/external plan references are provenance only unless
this SSOT explicitly delegates authority to them.

This migration is an execution manifest, not an invitation to optimize Legion. If implementation
reveals a better architecture, it is recorded separately and the frozen migration is finished
first.

## 18. Delegated canonical owners

```text
Legion operational constitution    → AGENTS.md
Atomic capability inventory/state → docs/canon/{legion,sage,alchemist,oracle,arcane,guard,covenant,skills}.md
Legion routing reference           → doctrine/legion.md
Role identity/authority/tier       → src/roster/{sage,alchemist,oracle}.md
Role architecture                  → docs/architecture/{sage,alchemist,oracle}.md
Role method                        → doctrine/{sage,alchemist,oracle}.md
Covenant challenge seat            → doctrine/covenant-seat.md
Architecture craft                 → skills/architect/SKILL.md + skills/architect/doctrine/architecture/**
Diagnosis craft                    → skills/debugger/SKILL.md + skills/debugger/references/manual.md
Audit method                       → skills/audit/**
Audit Fix workflow                 → skills/audit-fix/**
Rendered-state visual evaluation   → skills/audit-visual/**
Functional/browser/runtime QA      → skills/qa/**
Design craft                       → skills/designer/**
Capability/entrypoint semantics    → skills/<id>/SKILL.md
Host capabilities / ref classes    → src/registry/capabilities.json
Explicit aliases                   → src/config/capability-aliases.json
Cognitive control plane             → doctrine/arcane.md
Deterministic effect enforcement   → doctrine/guard.md + engine/bins/legion-hook/**
Executable work-unit materialization → Legion orchestration + producing capability
Independent Completion Validation  → Oracle (roster + doctrine/oracle.md)
```
