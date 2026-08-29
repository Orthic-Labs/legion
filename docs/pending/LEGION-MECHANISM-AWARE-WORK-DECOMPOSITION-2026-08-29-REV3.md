# Legion --- Mechanism-Aware Work Decomposition

**Date:** 2026-08-29\
**Status:** architecture proposal based on the current repository state\
**Scope:** `tasklist`, `dispatch`, Legion plan contracts, portable
executor requirements, host binding, and the lowering boundary from
Arcane cognitive routing

------------------------------------------------------------------------

## 1. Executive decision

Legion already has strong machinery for answering:

``` text
what work exists?
what depends on what?
what may run in parallel?
who owns each changed file?
what evidence proves completion?
```

The next useful dimension is:

> **What execution semantics does each materialized task node require?**

Arcane may already have classified the request or subproblem cognitively
--- context need, cognition depth, semantic requirement, capability
candidates, authority conditions, and verification posture. Legion does
not redo that cognitive routing. It lowers the relevant constraints into
portable work semantics.

Today a mechanical lane can still be expressed as a **cheap LLM
worker**. That is better than sending everything to an expensive model,
but it is one level too late.

The stronger rule is:

> **If the work is mechanically specified and an exact host capability
> can satisfy it, the portable plan should allow --- and preferably
> require --- zero-model execution.**

Legion should therefore add a portable **execution requirement** to
task/dispatch/plan nodes.

This is the work-compilation counterpart to Arcane's cognitive route.
The shared bridge is `semanticRequirement`; the detailed execution
contract remains Legion-owned.

Legion should not decide:

``` text
use CodeRight's LSP
run Python script foo.py
use GPT-5.6
use provider X
```

Instead it should express:

``` text
semantic interpretation forbidden / conditional / required
required capabilities
required effects
authority ceiling
completion checks
permitted escalation
```

The host resolves those requirements to actual machinery.

------------------------------------------------------------------------

## 1.1 Relationship to Arcane

Arcane and Legion operate at different compilation layers.

``` text
USER INTENT
    ↓
ARCANE
cognitive compilation
    - what context is needed?
    - direct vs deliberate cognition?
    - is grounding needed?
    - semanticRequirement?
    - likely capabilities?
    - exceptional authority conditions?
    - verification/cost posture?
    ↓
LEGION
work compilation
    - what work exists?
    - what depends on what?
    - who owns each mutation?
    - what capability must each node provide?
    - what effects are permitted?
    - what completion contract proves the node?
    ↓
HOST
physical binding
    - deterministic builtin
    - script/process
    - LSP/structured operation
    - Membrane
    - resident small model
    - larger model
    - human
```

The shared interface is deliberately small.

Arcane may emit:

``` text
context requirements
cognition depth
semanticRequirement
capability candidates
authority conditions
compute posture
verification posture
```

Legion may lower those into:

``` text
work nodes
dependencies
ExecutionRequirementV1
effects
completion contracts
escalation ceilings
```

Legion must not become a second cognitive router, and Arcane must not
own task DAGs, file allowlists, integration ownership, or
executor-binding receipts.

### No mandatory plan

Mechanism awareness applies **when Legion materializes work nodes**.

It does not imply that every user request must become a tasklist,
dispatch packet, or Rust `Plan`.

``` text
simple request → DIRECT remains valid

materialized executable node → execution requirement required
```

This preserves the anti-ceremony property of the Arcane architecture.

The historical reason for this rule is explicit: Arcane previously
became unproductive when optional governance and routing machinery
turned into mandatory work. Legion must not recreate that failure by
forcing every request through a compiled plan.

------------------------------------------------------------------------

## 2. Legion's role: portable work compiler

A work compiler should separate:

``` text
task semantics
dependency graph
execution requirements
host binding
```

Legion owns the first three. The host owns the fourth.

``` text
objective
   |
   v
Legion decomposition
   |
   v
typed work DAG
   |
   +--> node contract
   +--> dependency edges
   +--> file/effect ownership
   +--> executor requirement
   +--> completion contract
   |
   v
host binding
   |
   +--> deterministic built-in
   +--> script / process
   +--> LSP / structured operation
   +--> Membrane operation
   +--> LLM
   +--> human
```

This preserves Legion's portability across CodeRight and other
harnesses.

------------------------------------------------------------------------

## 3. Research basis

### PAL

Program-Aided Language Models separate semantic reasoning from exact
computation.

https://arxiv.org/abs/2211.10435

Legion implication:

> A plan node should describe the required computation without assuming
> the LLM itself performs it.

### LLM+P

LLM+P translates a natural-language task into a formal planning
representation and delegates actual planning to a classical planner.

https://arxiv.org/abs/2304.11477

Legion implication:

> Formal task structure and dependency reasoning can be first-class
> artifacts rather than repeated free-form model reasoning.

### LLMCompiler

LLMCompiler represents work as a task graph and schedules ready
functions in parallel.

https://arxiv.org/abs/2312.04511

Legion already moves in this direction through dependency waves,
disjoint file ownership and integration-owner semantics. The missing
extension is to make each node **mechanism-aware**.

### Compound AI systems

https://bair.berkeley.edu/blog/2024/02/18/compound-ai-systems/

Legion implication:

> Decomposition should expose enough structure for a host to route each
> component independently.

### Workflow versus agent

https://www.anthropic.com/engineering/building-effective-agents

Legion implication:

> A task node that is predictable and fully specified should not be
> forced through an autonomous model loop.

### LATM

Large Language Models as Tool Makers shows the economic advantage of
converting capable-model work into reusable tools.

https://arxiv.org/abs/2305.17126

Legion implication:

> Repeated semantic procedures can eventually become explicit capability
> requirements backed by reusable host machinery.

------------------------------------------------------------------------

## 4. Fresh Legion repository observations

### 4.1 `tasklist` already has strong execution structure

Current:

``` text
skills/tasklist/SKILL.md
```

It requires:

-   frozen current/target state;
-   exact numbered actions;
-   exact paths or `PATHS: none`;
-   dependencies;
-   parallel lanes versus serial execution;
-   completion checks;
-   expected results;
-   evidence paths;
-   bounded recovery;
-   one-touch path ownership;
-   fresh adversarial review.

It also explicitly routes:

``` text
same-agent work -> tasklist
delegation -> dispatch
continuity -> handoff
unresolved target design -> architect
```

What it does not yet make first-class is:

``` text
this step should be executed by a deterministic mechanism
```

versus:

``` text
this step requires semantic judgment
```

### 4.2 `dispatch` already distinguishes "agent or executor"

Current:

``` text
skills/dispatch/SKILL.md
```

Its description says it creates a zero-context work packet for another
**agent or executor**.

It already owns:

-   dependency waves;
-   maximum safe parallelism;
-   exact file allowlists;
-   integration ownership;
-   worker constraints;
-   validation;
-   adversarial Oracle review.

Legion does not need to redefine Dispatch around agents. It can extend
the existing executor concept.

### 4.3 Current mechanical-remediation packet exposes the gap

The 2026-08-29 mechanical-remediation packet selected:

``` text
modelTier: CHEAP
workerProfile: mechanical-cheap
```

because the work was settled, bounded and had no open decisions.

That is good **model routing**.

But several such operations are candidates for something stronger:

``` text
semantic_required: false
```

If a lane is exact enough to say:

``` text
add this declared capability
run this known generator
compare these exact fields
remove these known references
validate this schema
```

then an LLM should not be the default executor merely because it is
cheap.

### 4.4 Rust `Plan` is a DAG but not mechanism-aware

Current:

``` text
engine/crates/legion-contracts/src/plan.rs
```

`PlanNodeKind` is:

``` text
Provider
Gate
Report
External
```

The plan validates:

-   unique node IDs;
-   provider identity;
-   dependency references;
-   acyclicity;
-   deterministic topological order;
-   canonical digest.

Do not solve mechanism awareness by adding many node kinds such as:

``` text
Python
Shell
LLM
LSP
Search
```

That would mix **what a node means** with **how a host executes it**.

A separate execution-requirement contract is cleaner.

------------------------------------------------------------------------

## 5. Proposed portable contract

Recommended concept:

``` text
ExecutionRequirementV1
```

Possible shape:

``` yaml
schemaVersion: 1

semanticRequirement: forbidden | conditional | required

capabilities:
  - structured-text-edit
  - json-schema-validation
  - symbol-reference-resolution

effects:
  - source-read
  - artifact-write

authorityCeiling:
  - workspace

completion:
  - kind: exact-check
    id: no-unresolved-references

escalation:
  permittedOn:
    - unsupported
    - ambiguous
  forbiddenOn:
    - denied
```

This answers:

``` text
what must an executor be able to do?
```

not:

``` text
which executor should be used?
```

------------------------------------------------------------------------

## 6. Semantic requirement should be tri-state

`semanticRequirement` is the principal shared field between Arcane
cognitive compilation and Legion work compilation.

Arcane may classify it at request/subproblem level. Legion carries or
refines it at the executable-node level when decomposition is
materialized. A boolean `needs_llm` is too weak.

Use:

``` text
FORBIDDEN
CONDITIONAL
REQUIRED
```

### FORBIDDEN

Use when semantic inference is unnecessary or would weaken determinism.

Examples:

``` text
regenerate a known manifest
run a known formatter
validate JSON against a schema
perform exact text replacement with protected anchors
enumerate files matching a declared path predicate
```

A host that cannot satisfy the required deterministic capability should
return a typed unsupported result rather than silently substituting an
LLM.

### CONDITIONAL

Use when deterministic execution is preferred but bounded semantic
escalation is allowed.

Example:

``` text
resolve a symbol reference
```

A language server may satisfy it exactly. If it does not support the
language or returns ambiguity, semantic assistance may be allowed.

### REQUIRED

Use when the task itself asks for interpretation or judgment.

Examples:

``` text
evaluate architectural tradeoffs
rewrite a passage while preserving intent
decide whether evidence supports a conclusion
produce a research synthesis
```

Even here, execution and verification may still use deterministic
mechanisms around the semantic core.

------------------------------------------------------------------------

## 7. Dispatch changes

Today a lane may contain:

``` json
{
  "executor": "cheap worker (OmniRoute mechanical-cheap or sonnet subagent)"
}
```

The portable authority should instead be closer to:

``` json
{
  "executorRequirement": {
    "semanticRequirement": "forbidden",
    "capabilities": [
      "structured-json-edit",
      "manifest-refresh"
    ],
    "effects": [
      "source-read",
      "artifact-write"
    ]
  }
}
```

A resident tiny model is not the default meaning of `mechanical`.
`semanticRequirement: forbidden` means the host should use a zero-model
mechanism or report typed `unsupported`; it must not silently substitute
a small LLM.

A non-authoritative hint could optionally remain:

``` json
{
  "preferredExecutorHint": "mechanical"
}
```

For a semantic lane:

``` json
{
  "executorRequirement": {
    "semanticRequirement": "required",
    "capabilities": [
      "code-reasoning"
    ],
    "effects": [
      "source-read",
      "artifact-write"
    ]
  }
}
```

Do not require a particular model/provider unless the user or task
contract explicitly does.

------------------------------------------------------------------------

## 8. Tasklist changes

Each numbered action should gain:

``` text
EXECUTOR:
  semantic = forbidden | conditional | required
  capabilities = [...]
```

Example:

``` text
3. Refresh the local skill manifest.
   PATHS: skills/manifests/alchemist.json
   DEPENDS: 2
   LANE: A
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - manifest-refresh
   DONE:
     refresh-local-skill-manifests --check passes
```

Semantic example:

``` text
6. Determine whether the changed authority surface still matches the role doctrine.
   PATHS: none
   DEPENDS: 4,5
   LANE: B
   EXECUTOR:
     semantic: required
     capabilities:
       - architecture-reasoning
       - source-read
   DONE:
     structured finding with evidence and explicit uncertainty
```

This lets a host execute a tasklist efficiently without changing its
meaning.

------------------------------------------------------------------------

## 9. Keep executor requirements host-neutral

Avoid portable contract fields like:

``` text
use gpt-5.6
run CodeRight's lsp_tool
use D:\Tools\foo.exe
call membrane_context over port 7001
```

unless an explicit user requirement makes that exact implementation part
of the task.

Prefer:

``` text
reasoning-tier: capable
capability: symbol-reference-resolution
capability: context-evidence-read
capability: process-exec
```

Host-specific binding belongs in an execution receipt.

------------------------------------------------------------------------

## 10. Host binding receipt

At runtime:

``` text
ExecutionRequirementV1
        |
        v
host resolver
        |
        v
ExecutorBindingReceiptV1
```

Example:

``` yaml
nodeId: lane-schema-citation-hygiene
requirementDigest: sha256:...
binding:
  class: builtin
  capability: structured-text-edit
  implementationVersion: ...
semanticModelUsed: false
escalation: none
verification:
  status: passed
```

Model-backed example:

``` yaml
binding:
  class: semantic-model
semanticModelUsed: true
modelReceiptRef: ...
```

This preserves portability and auditability.

------------------------------------------------------------------------

## 11. Validator implications

Legion validators should remain structural, not become hidden semantic
planners.

Useful deterministic checks:

### Requirement completeness

Every executable lane/node declares an execution requirement.

### Semantic contradiction

Reject obvious contradictions such as:

``` text
semanticRequirement = forbidden
capability = open-ended-architecture-judgment
```

or:

``` text
semanticRequirement = required
worker policy forbids every semantic executor
```

### Escalation monotonicity

Never allow:

``` text
Denied -> semantic fallback
```

An LLM cannot be used to route around authority.

### Mechanical-lane proof

For `semanticRequirement = forbidden`, require at least one
independently checkable completion condition when practical.

### Binding is not authority

A selected executor may not widen:

``` text
file allowlist
effect boundary
budget
authority ceiling
```

------------------------------------------------------------------------

## 12. Mechanical remediation becomes a first-class work class

Recommended definition:

``` text
mechanical =
  target state settled
  no user-reserved decision
  no architecture/product judgment
  exact mutation boundary
  exact verification available
```

Default:

``` text
semanticRequirement = forbidden
```

Exception:

``` text
semanticRequirement = conditional
```

only when the transformation itself contains ambiguity that
deterministic machinery cannot resolve.

"Mechanical" should stop meaning merely:

``` text
cheap model
```

and start meaning:

``` text
prefer zero-model executor; cheap model is bounded fallback only where permitted
```

------------------------------------------------------------------------

## 13. Integration-owner semantics stay unchanged

Keep:

``` text
workers edit only their allowlists
workers do not merge
integration owner owns checkpoints
integration owner owns final evidence
repair returns to lane owner
```

A deterministic executor is still a bounded worker/executor.

Example:

``` text
lane owns:
  package.json
  scripts/ci/right-git-ci.sh

executor:
  structured edit engine

allowed patch:
  exact declared files only

integration owner:
  runs final checks
```

No autonomous agent is required merely to perform the patch.

------------------------------------------------------------------------

## 14. Relation to CodeRight

Recommended boundary:

``` text
Legion
  defines:
    node
    dependencies
    capabilities
    semantic requirement
    effects
    verification
    escalation ceiling

CodeRight
  resolves:
    exact executable mechanism
    live availability
    tool implementation
    model/provider when semantic
    process lifecycle
    filesystem/network effects
    approval
```

The CodeRight model router should run only after host resolution says:

``` text
semantic model required
```

for a Legion node.

------------------------------------------------------------------------

## 15. Relation to Membrane

Arcane is the attention controller: it may decide that a request needs
repository topology, current project truth, prior decisions, or external
grounding.

Legion's role is to preserve those needs portably when they become
work-node requirements.

Legion should express context/source needs as portable capabilities.

Example:

``` yaml
semanticRequirement: conditional
capabilities:
  - repository-truth-read
  - decision-history-read
```

A first-party CodeRight host may bind those to Membrane.

Another host may bind them differently.

Where Legion intentionally treats Membrane/Blueprint as an
authority-bearing source, keep that ownership explicit; do not
reconstruct repository truth inside Legion just to avoid the capability
call.

The preferred flow is:

``` text
Arcane decides context need
    ↓
Legion declares portable context capability
    ↓
host binds capability to Membrane when available
    ↓
Membrane returns bounded semantic context
```

This preserves portability without making Legion independently decide
attention allocation.

------------------------------------------------------------------------

## 16. Rust Plan evolution

Two reasonable options:

### Option A --- embed requirement in `PlanNode`

Future version:

``` rust
struct PlanNodeV2 {
    id: NodeId,
    kind: PlanNodeKind,
    provider: Option<ProviderId>,
    depends_on: Vec<NodeId>,
    execution_requirement: ExecutionRequirementV1,
    configuration: BTreeMap<String, Value>,
}
```

Advantages:

-   requirement inseparable from node identity;
-   canonical digest includes it;
-   clear executor contract.

Costs:

-   schema migration;
-   all producers update.

### Option B --- separate requirement map

``` text
Plan
ExecutionRequirements
```

keyed by `NodeId`.

Advantages:

-   lower migration pressure;
-   evolves separately.

Costs:

-   more joining;
-   easier to construct an incomplete pair.

Long term, Option A is cleaner if execution requirement becomes
canonical Legion semantics. Short term, Option B can stage migration.

------------------------------------------------------------------------

## Fact-Derived Work State and Supervision

Mechanism-aware execution needs a clean distinction between **what
happened** and **what Legion currently concludes from it**.

Legion should prefer durable execution facts over persisted derived
status.

Example facts:

``` text
executor_bound
executor_started
activity_observed
approval_pending
effect_completed
executor_exited
completion_check_passed
completion_check_failed
external_check_changed
output_committed
dependency_invalidated
observation_unavailable
```

Derived node state may then be computed from those facts:

``` text
ready
running
waiting
blocked
failed
completed
stale
uncertain
```

> **Persist facts; derive status.**

This prevents stale status fields from becoming a second source of truth
and lets state derivation evolve without rewriting execution history.

### Observation is not action

External observation should not directly mutate work semantics.

``` text
observer
  ↓
typed fact
  ↓
work-state reducer
  ↓
scheduler decision
  ↓
action
```

Observers may report executor liveness, CI/check results, review
feedback, mergeability/conflicts, filesystem/artifact changes, host
capability availability, or Membrane/context-source changes. Observers
report facts; Legion decides their work-graph consequence.

### Loss of observability is not executor death

A failed probe or unavailable observer must not silently become
`executor_failed`.

Keep at least these outcomes distinct:

``` text
unsupported
ambiguous
unreachable
denied
terminated
verification_failed
```

A scheduler may retry or rebind on `unreachable`, semantically escalate
on `ambiguous` only where permitted, and select another mechanism on
`unsupported`.

`denied` is different: authority denial must never be converted into
mechanism or semantic fallback.

### Causal invalidation

External feedback should resolve to the work that produced or depends on
the affected state.

``` text
A: change API
B: regenerate client
C: prepare delivery

external check:
generated client stale
        ↓
fact resolves to B
        ↓
B becomes invalid
C becomes stale
A remains valid
        ↓
rerun B + downstream verification only
```

Legion should preserve enough provenance to answer:

``` text
which node produced this state?
which completion claim depended on it?
which downstream nodes are now stale?
```

This is a work-graph concern, not an agent-session concern.

### Executor identity is not work identity

A Legion node should survive loss or replacement of its concrete
executor when its contract permits rebinding.

``` text
work node
  ↓
executor binding A
  ↓
executor becomes unreachable
  ↓
typed observation
  ↓
host rebinds executor B if permitted
  ↓
same work-node identity and completion contract
```

Sessions, processes, model conversations, and tool runtimes are bindings
to work. They are not the canonical identity of the work itself.

### Event transport is an implementation detail

A persistent implementation may use an event log, CDC stream, polling,
callbacks, or another transport. Legion should depend only on typed
observations, durable facts where persistence is required, deterministic
state reduction, and causal provenance.

It should not require a daemon, SQLite, SSE, a particular event bus, or
any external orchestration runtime.

------------------------------------------------------------------------

## 17. Evaluation

Recommended metrics:

``` text
nodes by semantic requirement
nodes bound deterministically
nodes bound to models
conditional escalations
false mechanical classifications
unsupported deterministic bindings
cost per completed plan
wall-clock plan completion
end-to-end success
verification failures
```

Important metric:

``` text
semantic_execution_avoided
```

Count it as positive only when the node passes its completion contract.

------------------------------------------------------------------------

## 18. From repeated skills to compiled capabilities

Today:

``` text
skill describes a procedure
LLM follows the procedure
```

Future:

``` text
skill describes a procedure
        |
stable mechanical segment identified
        |
host capability exists or is created
        |
skill declares capability requirement
        |
model no longer executes that segment
```

High-frequency skills can become increasingly declarative:

``` text
semantic checkpoints
+
capability invocations
+
verification
```

rather than long prompts telling a model how to imitate a workflow
engine.

------------------------------------------------------------------------

## 19. Proposed implementation sequence

### LEG-MR-0 --- doctrine only

State:

> use the least nondeterministic authorized executor capable of
> satisfying each node contract.

Clarify that "mechanical" does not imply "cheap model."

### LEG-MR-1 --- Dispatch and Tasklist schemas

Introduce:

``` text
semanticRequirement
capabilities
effects
permitted escalation
completion contract
```

Update validators.

Concrete first targets: `skills/dispatch/assets/direct-packet.json`
(replace the free-text `"executor"` string with `executorRequirement`),
`src/lib/dispatch-validator/validate-dispatch.py` (add the
completeness, contradiction, and escalation-monotonicity checks from
§11), and `skills/tasklist/SKILL.md` (the EXECUTOR block from §8).

Post-execution evidence for this priority: the 2026-08-29
mechanical-remediation packet ran its four lanes through a cheap LLM
worker; three of the four (a JSON capability append, an exact schema
string replacement, CI wiring) were zero-model candidates, and the LLM
introduced exactly the defect classes a structured mechanism cannot: a
platform-specific interpreter name (`python3` on Windows) and stray
scratch files outside the allowlist. Both were caught by the
integration owner, but under this proposal neither could have occurred.

### LEG-MR-2 --- skills

Require explicit executor requirements for every action/lane.

Mechanical examples should use:

``` text
semanticRequirement: forbidden
```

### LEG-MR-3 --- host-binding receipt

Define portable receipt shape for how a host satisfied the requirement.

### LEG-MR-4 --- Rust Plan

After schema behavior is proven in Dispatch/Tasklist, move the concept
into canonical engine contracts.

### LEG-MR-5 --- evaluations

Fixtures should cover:

-   deterministic execution clearly sufficient;
-   semantic interpretation clearly required;
-   deterministic-first requiring escalation;
-   authority denial that must never escalate.

------------------------------------------------------------------------

## 20. Acceptance tests

1.  A fully mechanical dispatch can be valid with **no model executor**.
2.  A host may bind the same Legion requirement differently without
    changing plan semantics.
3.  `semanticRequirement: forbidden` cannot silently fall back to an
    LLM.
4.  `conditional` may escalate only on listed typed outcomes.
5.  `denied` never permits semantic fallback.
6.  File/effect/authority ceilings survive host binding unchanged.
7.  One plan may contain deterministic and semantic nodes.
8.  Canonical digest changes when execution requirements change.
9.  Validators catch missing/contradictory execution requirements.
10. Integration-owner semantics remain unchanged.

------------------------------------------------------------------------

## 21. Recommended invariant

> **Legion specifies the work and the capability required to perform it;
> the host chooses the concrete executor.**

And:

> **A settled mechanical task is not a small-model task by definition.
> It is a zero-model task unless semantic interpretation is genuinely
> required.**

And the cross-layer boundary:

> **Arcane compiles cognitive requirements; Legion compiles work
> requirements; the host binds work to concrete machinery.**

------------------------------------------------------------------------

## 22. Repository evidence reviewed

Fresh paths:

``` text
skills/dispatch/SKILL.md
skills/tasklist/SKILL.md
engine/crates/legion-contracts/src/plan.rs
```

Recent evidence:

``` text
2026-08-29
bac6317  chore(dispatch): mechanical-remediation packet A — validated + adversarial PASS
24d5205  fix: authority discoverability, hook denials, oracle contract wiring + audit reports
```

The mechanical-remediation packet explicitly selected a cheap mechanical
worker because the work was bounded and contained no open decisions.
That is the immediate design opportunity addressed here.

------------------------------------------------------------------------

## 23. Research references

-   PAL --- https://arxiv.org/abs/2211.10435
-   LLM+P --- https://arxiv.org/abs/2304.11477
-   LLMCompiler --- https://arxiv.org/abs/2312.04511
-   LATM --- https://arxiv.org/abs/2305.17126
-   MRKL --- https://arxiv.org/abs/2205.00445
-   Toolformer --- https://arxiv.org/abs/2302.04761
-   Berkeley Compound AI Systems ---
    https://bair.berkeley.edu/blog/2024/02/18/compound-ai-systems/
-   Anthropic, Building effective agents ---
    https://www.anthropic.com/engineering/building-effective-agents

------------------------------------------------------------------------

## 24. Adopted decisions (2026-08-29)

- The Arcane/Legion/host three-stage boundary and the shared
  `semanticRequirement` tri-state are adopted as the target
  architecture; the guard/cognitive split and Arcane-side decisions are
  recorded in `ARCANE-COGNITIVE-CONTROL-PLANE-2026-08-29-REV3.md` §16
  and §29.
- Implementation follows the LEG-MR-0..5 sequence in §19, starting with
  doctrine (LEG-MR-0) and the Dispatch/Tasklist schemas (LEG-MR-1,
  concrete targets above). Rust `Plan` migration (LEG-MR-4) waits until
  the schema behavior is proven; Option B (separate requirement map)
  stages it.
- Architecture documentation separates per role and per skill as part
  of this work; this document seeds the Legion work-compilation half.
- Consolidated tracking: `PENDING-WORK-2026-08-29.md` in this folder.
