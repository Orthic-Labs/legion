# Arcane Cognitive Control Plane Architecture

## Status

Concept proposal for review.

## Executive Summary

Arcane should not be reduced to either:

-   a conventional skill/model router, or
-   the current large deterministic enforcement subsystem.

Its stronger role is as a **bounded cognitive control plane** positioned
between user intent and the systems that provide context, capabilities,
authority, compute, and effect control.

Arcane answers one question:

> **How should this request be processed?**

It does not solve the user's problem itself. It compiles each request
into the **minimum sufficient cognitive execution topology**.

The surrounding systems remain cleanly separated:

-   **Membrane** --- what is known?
-   **Legion** --- what can do this, and what exceptional authority is
    required?
-   **Arcane** --- how should this request be processed?
-   **Model / agent** --- perform the actual reasoning and work.

The key architectural principle is **progressive cognition, not
progressive bureaucracy**.

Arcane should normally do almost nothing. It adds machinery only when
the task justifies it.

------------------------------------------------------------------------

# 1. Historical Context: What Arcane Was, What It Became, and Why It Failed

Arcane did **not** begin as a general governance, authority, contract,
or execution system.

Its original role was a thin cognitive harness around the working model:

1.  invoke deliberate/sequential thinking when a problem benefited from
    it;
2.  ground current or documentation-dependent claims through
    Context7/Groundwork-style retrieval;
3.  apply Brief / Minimize so answers stayed dense and useful;
4.  check the answer before replying;
5.  avoid asking permission for work the user had already requested;
6.  avoid stopping with obvious in-scope work still left to do.

The important property was that Arcane improved the model's work while
adding very little work of its own.

Its operating idea was roughly:

``` text
think when useful
→ ground when necessary
→ do the work
→ check before replying
→ answer cleanly
```

## 1.1 How Arcane drifted

Arcane later absorbed or accumulated machinery for:

-   effect classification and policy;
-   execution contracts;
-   authority bindings;
-   receipts and evidence seals;
-   lifecycle state;
-   completion governance;
-   architecture routing;
-   execution ownership;
-   locked-domain handling;
-   replay/freshness checks;
-   multiple stop/completion gates;
-   process artifacts intended to prove that the right process had
    occurred.

Many of these mechanisms were individually motivated by real failures.

The problem was cumulative.

Arcane crossed the boundary from:

> helping the agent perform the user's task

to:

> making the agent satisfy Arcane's own process before it could finish
> the user's task.

That distinction is the central historical lesson behind this redesign.

## 1.2 What stopped working in practice

The expanded Arcane became unproductive because it created too much
ceremony around normal work.

Observed failure modes included:

-   agents spending large portions of a session reasoning about
    orchestration rather than the user's problem;
-   recursive or repeated validation;
-   process artifacts whose main purpose was satisfying another process
    requirement;
-   authority and contract machinery being invoked when ordinary work
    could have proceeded directly;
-   stop gates and completion checks repeatedly pushing agents back into
    work that did not improve the requested outcome;
-   agents getting trapped for long periods in governance, evidence,
    routing, or architecture loops;
-   optional machinery becoming de facto mandatory because the agent
    interpreted its existence as a requirement;
-   the system optimizing for "provably governed" rather than "correctly
    completed."

The practical result was the opposite of the original Arcane intent:
instead of making the model sharper and more efficient, Arcane could
keep capable agents occupied with the wrong work for hours.

This redesign treats that as an architectural failure, not as a
prompting problem.

## 1.3 What this redesign is doing

The current direction is a deliberate **rollback and recomposition**.

It restores the useful original Arcane behaviors, then extends them only
where the extension remains thin and task-serving.

The redesigned Arcane becomes a **bounded cognitive control plane**.

It may decide:

-   whether deliberate cognition is useful;
-   whether grounding/context retrieval is required;
-   how much context should be retrieved;
-   whether work is semantic, conditionally semantic, or should use no
    model at all;
-   which Legion capability candidates are relevant;
-   whether exceptional authority conditions appear to exist;
-   what compute posture is proportionate;
-   what verification posture is proportionate;
-   how the final response should be shaped.

It does **not** own detailed work decomposition, task DAGs, file
ownership, contract machinery, executor binding, or durable supervision.

Those responsibilities remain with Legion, the host, Membrane, or a
deterministic guard according to their own boundaries.

The governing rule is:

> **Arcane may improve the work. Arcane must never become the work.**

## 1.4 What is restored, moved, isolated, or removed

  -----------------------------------------------------------------------
  Historical element                  Current decision
  ----------------------------------- -----------------------------------
  Sequential / deliberate thinking    **Restore** as bounded, conditional
                                      cognition

  Context7 / Groundwork-style         **Restore** as targeted, pull-based
  grounding                           grounding/context access

  Brief / Minimize                    **Restore** as Arcane postflight
                                      response discipline

  Check-before-reply                  **Restore** as bounded postflight
                                      validation

  No-stop-short / no                  **Restore selectively**, with hard
  permission-seeking endings          bounds and genuine-blocker
                                      carve-outs

  Skill/capability routing            **Use as lightweight cognitive
                                      routing**, with Legion owning
                                      canonical capabilities

  Sage / Alchemist / Oracle           **Arcane may detect conditions;
  attachment                          Legion owns authority attachment
                                      and execution**

  Detailed task graphs / dispatch     **Keep in Legion**, not Arcane
  packets                             

  Execution requirements              **Shared boundary concept**,
                                      materialized and owned by Legion
                                      when work nodes exist

  Durable work-state supervision      **Keep in Legion/host**, not Arcane

  Membrane retrieval                  **Arcane decides attention need;
                                      Membrane provides context**

  Deterministic effect/security       **Isolate as a hard deterministic
  enforcement                         guard boundary**; do not let it
                                      expand into cognitive ceremony

  Architecture/domain judgment        **Keep with capabilities**; Arcane
                                      may route, not decide the domain
                                      question

  Recursive governance and            **Remove**
  self-validation                     

  Mandatory process artifacts whose   **Remove**
  purpose is proving process          

  Universal heavyweight               **Remove**
  routing/validation for trivial      
  requests                            
  -----------------------------------------------------------------------

## 1.5 Anti-regression interpretation

The redesign must not be evaluated by asking:

> "How much of old Arcane did we preserve?"

It should be evaluated by asking:

> "Does this intervention make the user's task more likely to succeed,
> with less wasted cognition and less unnecessary machinery?"

If an Arcane mechanism cannot justify itself on that basis, it should
not be part of Arcane.

------------------------------------------------------------------------

# 2. Core Definition

> **Arcane is a bounded cognitive interposition layer that compiles each
> request into the minimum sufficient combination of context, cognition,
> capability, authority, compute, effects, verification, and response
> policy.**

Arcane is not another autonomous agent.

Arcane does not own domain expertise.

Arcane does not become a giant rules engine for natural language.

Arcane does not require durable artifacts merely to prove that Arcane
ran.

Arcane coordinates the processing shape of a request.

------------------------------------------------------------------------

# 3. System Responsibilities

## Membrane

**Question:** What is known?

Membrane is the context and memory substrate.

Primary components may include:

-   **Ledger** --- current operational/project truth.
-   **Cortex** --- accumulated semantic memory.
-   **Blueprint** --- repository topology, structure, dependencies,
    relationships.
-   Other contextual stores or retrieval mechanisms.

Membrane should return **bounded semantic context**, not
indiscriminately dump source material into the main model.

------------------------------------------------------------------------

## Legion

**Question:** What can do this?

Legion owns:

-   capabilities,
-   skills,
-   specialist methods,
-   orchestration,
-   authority attachment,
-   Sage,
-   Alchemist,
-   Oracle.

Capabilities own routine judgment.

Authorities attach only when exceptional responsibility is required.

------------------------------------------------------------------------

## Arcane

**Question:** How should this request be processed?

Arcane decides the processing topology:

-   context needs,
-   cognition depth,
-   grounding requirement,
-   capability selection,
-   authority attachment conditions,
-   model tier,
-   execution cost,
-   effect constraints,
-   verification depth,
-   response shaping.

Arcane should prefer the cheapest and least ceremonial valid route.

A central compute invariant is:

> **A settled mechanical task is not a small-model task by definition.
> It is a zero-model task unless semantic interpretation is genuinely
> required.**

Arcane therefore routes not only between model tiers, but between
**model and no-model execution**.

------------------------------------------------------------------------

## Working Model / Agent

**Question:** Solve the problem.

The working model receives a task environment assembled by Arcane.

It should not need to reconstruct the entire system topology itself.

------------------------------------------------------------------------

# 4. High-Level Architecture

``` text
                         ┌──────────────┐
                         │    USER      │
                         └──────┬───────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │        ARCANE         │
                    │   Cognitive Kernel    │
                    │                       │
                    │  How should this task │
                    │  be processed?        │
                    └───────┬───────────────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
     MEMBRANE            LEGION             COMPUTE
   context/data         capabilities         models
      plane            + authorities          plane
          │                 │                  │
 Ledger/Cortex/      Skills / Sage /       local/cheap/
 Blueprint/etc.      Alchemist/Oracle      frontier model
          └─────────────────┼──────────────────┘
                            │
                            ▼
                        EXECUTION
                            │
                            ▼
                    ┌──────────────────┐
                    │ Arcane postflight│
                    │ check + Brief    │
                    └────────┬─────────┘
                             ▼
                           ANSWER
```

------------------------------------------------------------------------

# 5. Route Across Multiple Axes

Most routers optimize one dimension: model selection, agent selection,
or tool selection.

Arcane should coordinate several orthogonal dimensions.

  -----------------------------------------------------------------------
  Axis                    Arcane determines       System providing
                                                  capability
  ----------------------- ----------------------- -----------------------
  Attention               What context is         Membrane
                          necessary?              

  Cognition               Direct answer,          Arcane primitives
                          deliberate thinking,    
                          grounding,              
                          decomposition           

  Expertise               Which capability/skill  Legion
                          is useful?              

  Authority               Whether Sage,           Legion
                          Alchemist, or Oracle    
                          must attach             

  Compute                 Whether a model is      Compute/router + host
                          needed at all; if so,   resolver
                          which tier              

  Mechanism               Deterministic,          Legion execution
                          conditional-semantic,   requirement + host
                          or semantic execution   

  Effects                 What effects require    deterministic guard
                          constraints or approval 

  Verification            What independent        Oracle / checks
                          validation is           
                          proportionate           

  Expression              How concise/complete    Brief/Caveman-style
                          the final response      policy
                          should be               
  -----------------------------------------------------------------------

This makes Arcane a **cognitive control plane**, not merely a
dispatcher.

------------------------------------------------------------------------

# 6. Route Attention Before Intelligence

Conventional agent routing often looks like:

``` text
prompt
  ↓
choose model/agent
  ↓
give it large context
  ↓
work
```

Arcane should invert that:

``` text
prompt
  ↓
what must this task KNOW?
  ↓
retrieve minimum sufficient context
  ↓
what type/depth of cognition is needed?
  ↓
what capability/authority is needed?
  ↓
what compute tier is sufficient?
  ↓
execute
```

This is important because context selection happens **before** expensive
cognition.

A frontier model should not have to inspect an entire repository merely
to discover which 2% matters.

------------------------------------------------------------------------

# 7. Semantic Requirement: Model vs No-Model

Arcane should make one early classification that is more fundamental
than model selection:

``` text
semanticRequirement:
  FORBIDDEN
  CONDITIONAL
  REQUIRED
```

## FORBIDDEN

Use when semantic inference is unnecessary or would reduce determinism.

Examples:

-   regenerate a known manifest;
-   run a formatter;
-   validate a schema;
-   exact text replacement with protected anchors;
-   enumerate files matching a declared predicate;
-   perform a known structured transformation.

The correct route is **zero-model execution**. A cheap model is not a
substitute for an exact mechanism.

## CONDITIONAL

Use when deterministic execution is preferred but bounded semantic
escalation is legitimate.

Example:

``` text
resolve a symbol reference
```

An LSP or structured index may resolve it exactly. If the mechanism
reports a typed `unsupported` or `ambiguous` outcome, Arcane may permit
semantic escalation.

A denial must never be converted into semantic fallback.

## REQUIRED

Use when interpretation or judgment is the substance of the work.

Examples:

-   architecture trade-offs;
-   diagnosis under ambiguous evidence;
-   intent-preserving rewriting;
-   research synthesis;
-   deciding whether evidence supports a conclusion.

Even here, deterministic mechanisms should surround the semantic core
wherever possible.

This tri-state is a shared Arcane → Legion concept. Arcane uses it while
compiling the cognitive route; Legion carries it into executable work
nodes where a work graph is materialized.

------------------------------------------------------------------------

# 8. Cognitive Route Envelope

Arcane may internally compile an ephemeral route object.

Example:

``` json
{
  "intent": ["diagnose", "mutate"],
  "context": {
    "budget": "small",
    "ledger": ["recent relevant decisions"],
    "blueprint": ["parser module", "callers", "recent dependency changes"],
    "cortex": ["prior parser-related reasoning"]
  },
  "cognition": {
    "depth": "deliberate",
    "external_grounding": false
  },
  "capabilities": ["debugger"],
  "authority": {
    "sage": false,
    "alchemist": false,
    "oracle": "post-change-validation"
  },
  "compute": {
    "reasoning": "strong",
    "mechanical_execution": "cheap"
  },
  "effects": {
    "repository_write": "allowed",
    "destructive": false
  },
  "response": {
    "brief": true,
    "no_unresolved_work_ending": true
  }
}
```

This is a runtime structure, not a required Markdown artifact.

It should normally disappear when the task finishes.

No receipt should be required merely to prove that a route envelope
existed.

------------------------------------------------------------------------

# 9. Deterministic Kernel + Semantic Micro-Router

Not all routing can or should be deterministic.

Some conditions are structural:

``` text
/seo                   → SEO capability
@sage                  → Sage
locked domain          → controlled execution boundary
destructive operation  → deterministic effect gate
external/current claim → grounding requirement
explicit contract      → governed path
```

Other routing requires semantic interpretation:

``` text
"My app feels sluggish when switching accounts."
```

That may imply:

-   debugging,
-   architecture,
-   performance profiling,
-   database investigation,
-   UX,
-   multiple capabilities.

Trying to encode all of this in deterministic rules will produce brittle
complexity.

A better design:

``` text
               ARCANE
                  │
        ┌─────────┴─────────┐
        │                   │
 deterministic kernel   semantic micro-router
        │                   │
        └─────────┬─────────┘
                  ▼
           Route Envelope
```

Use deterministic rules where truth is structural.

Use a small model where natural-language interpretation is necessary.

If the micro-router is uncertain, it should expose uncertainty to the
stronger working model rather than starting an escalation ritual.

------------------------------------------------------------------------

# 10. Resident Small Model

Arcane is a strong candidate for a resident small model because the
small model does not need to solve the user's task.

Its job can be constrained to narrow functions such as:

-   intent classification,
-   capability ranking,
-   context-request construction,
-   identifying likely relevant Membrane stores,
-   estimating cognition depth,
-   deciding whether external grounding appears necessary,
-   identifying obvious ambiguity,
-   choosing a cheap vs strong compute tier,
-   compressing retrieved context into routing metadata,
-   detecting whether more context is needed.

This model can remain loaded locally and operate as a low-latency
control model.

The main model then receives a cleaner environment.

See Sections 18 and 21 for design constraints.

------------------------------------------------------------------------

# 11. Arcane → Legion Lowering Interface

Arcane and Legion should not duplicate decomposition.

Arcane emits **cognitive constraints and route state**:

``` text
intent
context requirements
cognition depth
semanticRequirement
capability candidates
authority conditions
compute posture
effect posture
verification posture
response policy
```

Legion lowers that into portable work semantics only when decomposition
is actually useful:

``` text
work nodes
dependencies
ownership
ExecutionRequirementV1
effects
completion contracts
escalation boundaries
```

The host then binds each executable node to concrete machinery:

``` text
deterministic builtin
script / process
LSP / structured operation
Membrane operation
resident tiny model
larger semantic model
human
```

The boundary is:

> **Arcane decides what kind of processing the request deserves. Legion
> specifies what work exists and what each work unit requires. The host
> chooses the concrete executor.**

Arcane should not generate file allowlists, integration-owner mechanics,
task DAGs, or binding receipts. Those remain Legion/host concerns.

Likewise, Legion should not independently redo Arcane's cognitive
routing merely because it materializes a work graph.

## No mandatory compilation

This interface must not make every request a plan.

``` text
If Legion materializes an executable work node,
that node should carry an execution requirement.

But simple work does not have to materialize work nodes.
```

`DIRECT` remains a valid and desirable Arcane route.

------------------------------------------------------------------------

# 12. Membrane Integration

Membrane is what turns Arcane from a normal agent router into something
more significant.

Arcane should be able to issue semantic context requests such as:

``` json
{
  "task": "diagnose parser regression",
  "budget": "small",
  "sources": {
    "ledger": ["recent relevant decisions"],
    "blueprint": ["parser", "callers", "changed dependencies"],
    "cortex": ["prior parser-related reasoning"]
  },
  "exclude": [
    "unrelated repository history",
    "full source files unless required"
  ]
}
```

Membrane returns a compact context capsule.

The main model therefore does not need to "read the repository" in the
traditional agent sense.

It requests semantic context through Arcane/Membrane.

This creates a context-routing layer below model execution.

------------------------------------------------------------------------

# 13. Authority Attachment

Sage, Alchemist, and Oracle should become conditional attachments to
route state rather than vague suggestions.

## Sage

Attach when there is a genuine exceptional decision condition such as:

``` text
material semantic conflict
OR
ownership conflict
OR
multiple valid interpretations with materially different outcomes
OR
routine capability cannot safely settle the decision
```

Routine architecture, debugging, research, or design judgment does not
imply Sage.

------------------------------------------------------------------------

## Alchemist

Attach when:

``` text
bounded work already exists
AND
controlled execution is required
```

Examples:

-   locked domain,
-   explicit contract,
-   frozen Sage handoff,
-   policy-controlled transformation.

Ordinary ambient implementation does not imply Alchemist.

Cheap mechanical execution should be available independently of
Alchemist.

------------------------------------------------------------------------

## Oracle

Attach proportionately.

Potential triggers:

``` text
artifact produced
OR
state mutated
OR
high-consequence claim
OR
explicit validation request
OR
high-risk task
OR
controlled/contracted work
```

A trivial factual answer should not require a full Oracle ceremony.

------------------------------------------------------------------------

# 14. Caveman / Brief

Caveman-like behavior fits Arcane naturally as response-processing
policy.

Arcane postflight may handle:

-   information density,
-   removal of useless narration,
-   preservation of technical precision,
-   elimination of unnecessary hedging,
-   avoiding redundant explanation,
-   preventing "I can do that if you want" when the user already
    requested it.

This is a continuation of the original Brief/Minimize role.

Important invariant:

> Response compaction must occur **after** canonical evidence is
> captured.

Presentation shaping must never alter the underlying evidence used for
verification.

------------------------------------------------------------------------

# 15. Ponytail / Implementation Economy

Ponytail-like doctrine is adjacent to Arcane but should not become a
universal hard gate.

For implementation or architecture tasks, Arcane may enable a
minimal-solution lens:

``` text
1. Do we need to build anything?
2. Can existing code solve it?
3. Can stdlib/native platform solve it?
4. Can an already-installed dependency solve it?
5. What is the minimum new implementation required?
```

This should be a reasoning aid, not a compliance ceremony.

The model should never have to produce proof that it passed every
Ponytail step.

------------------------------------------------------------------------

# 16. Effect Enforcement

Deterministic effect/security enforcement may remain a sibling subsystem
underneath Arcane or a sharply isolated Arcane kernel.

The architectural requirement is more important than the name:

-   effect policy must remain deterministic,
-   it must not own natural-language routing,
-   it must not expand into cognitive ceremony,
-   security controls must be independently testable,
-   missing policy must never be mislabeled as strong enforcement.

If naming causes conceptual conflation, separate the effect guard
explicitly from the cognitive Arcane layer.

Adopted split (owner decision, 2026-08-29):

``` text
Arcane
= cognitive control plane (kept separate; its own doctrine and docs)

Guard (working name; final name open)
= deterministic effect and safety enforcement
```

The current `legion-hook` binary is the Guard's seed implementation. Two
consequences follow immediately:

1. The Guard keeps receipts; the cognitive plane keeps none. The
   no-receipt rule in Section 8 applies to route envelopes only, never
   to effect enforcement.
2. The Guard's live defects are day-zero work for this architecture, not
   a separate track: the shipped binary loads no policy
   (`LEGION_NATIVE_APPLICATION_CONFIG` is set nowhere outside tests) yet
   labels enforcement `"strong"`; `mcp__*` tools and subagent dispatch
   are unmatched; and the deployed exe predates the committed
   subdirectory-resolution fix (this lockout was reproduced live on
   2026-08-29). A redesign built on a fail-open, mislabeled gate
   inherits its dishonesty.

Only the Guard's final name remains open.

------------------------------------------------------------------------

# 17. Anti-Ceremony Invariants

The most important invariant:

> **Arcane may improve cognition, grounding, routing, context, cost, or
> answer quality. It may never create work whose primary purpose is
> satisfying Arcane.**

Corollaries:

1.  Arcane cannot require durable planning artifacts unless the user's
    task genuinely requires them.
2.  Arcane cannot require a receipt in order to satisfy another Arcane
    receipt.
3.  Arcane cannot recursively validate itself.
4.  Arcane cannot dispatch agents merely to prove that a process
    occurred.
5.  Optional cognitive machinery being unavailable should normally
    degrade, not halt useful work.
6.  Retry/check loops must have very small hard bounds.
7.  If Arcane consumes more attention than the user's task, Arcane is
    malfunctioning.
8.  Deliberate thinking is invoked because the problem benefits from it,
    not to make reasoning ceremony visible.
9.  Grounding is targeted and pull-based, not "research before every
    answer."
10. Brief shapes the final answer; it does not become a work-management
    system.
11. Semantic routing uncertainty should escalate to the stronger working
    model, not to a workflow ritual.
12. The default route should be nearly empty.
13. The default route must resolve deterministically in single-digit
    milliseconds with zero model calls. The semantic micro-router runs
    only when the deterministic kernel abstains — never as a standing
    tax on every prompt. This invariant is measured, not asserted: if
    routing latency on trivial requests is observable, the control plane
    has recreated the ceremony failure it exists to remove.

------------------------------------------------------------------------

# 18. Resident 0.5B--1B Control Model

A very small resident model may be useful, but only if its role is
deliberately narrow.

It should **not** be treated as a weaker general agent, and it should
**not** become the default executor for mechanical work.

The execution preference is:

``` text
exact deterministic mechanism
    ↓ if unavailable/ambiguous and policy permits
resident semantic model
    ↓ if confidence/capability is insufficient
stronger model
```

The resident model is therefore a learned control/semantic mechanism,
not the definition of "cheap execution."

Its best role is as an inexpensive learned function inside Arcane.

Potential tasks:

-   classify intent into a constrained vocabulary,
-   rank 3--10 candidate skills,
-   classify context requirements,
-   construct retrieval queries,
-   score whether retrieved context is sufficient,
-   classify "needs fresh/external grounding",
-   predict task complexity,
-   select direct vs deliberate cognition,
-   select cheap vs strong model tier,
-   identify likely ambiguity,
-   run lightweight answer-shape checks.

A small model can be fine-tuned specifically on Arcane's routing schema.

Its outputs should be constrained to typed structures rather than
unconstrained prose.

For example:

``` json
{
  "intent": ["diagnose"],
  "capability_candidates": [
    ["debugger", 0.82],
    ["architect", 0.31]
  ],
  "context": {
    "blueprint": true,
    "ledger": true,
    "cortex": false,
    "external": false
  },
  "depth": "deliberate",
  "confidence": 0.78
}
```

Deterministic validation then checks the output.

Low confidence or invalid output falls through to the main model.

The small model therefore never becomes a single point of failure.

------------------------------------------------------------------------

# 19. Small-Model Escalation Pattern

``` text
request
   ↓
deterministic Arcane rules
   ↓
resident micro-model
   │
   ├── high confidence + valid typed route
   │       ↓
   │    use route
   │
   └── low confidence / disagreement / invalid route
           ↓
       stronger model decides
```

This creates a learned fast path.

The small model can remain resident and amortize load latency across
many requests.

The value is not its raw intelligence.

The value is:

> **small model performs repetitive learned control decisions so
> frontier intelligence is reserved for the problem itself.**

------------------------------------------------------------------------

# 20. Possible Multi-Model Extension

The same resident model could operate between Membrane and the large
model.

Instead of:

``` text
large model → read many files → decide relevance
```

use:

``` text
large model / Arcane requests a concept
          ↓
Membrane retrieves candidate context
          ↓
resident small model
  ranks / filters / compresses
          ↓
large model receives minimum sufficient context
```

This creates two complementary functions for the small model:

1.  **pre-execution routing**
2.  **context mediation**

These may eventually use separate adapters or fine-tunes even if they
share a base model.

------------------------------------------------------------------------

# 21. Trust Boundary for Small Models

The small model must not be allowed to make irreversible decisions
merely because it is cheap and resident.

Suitable decisions:

-   ranking,
-   retrieval,
-   context filtering,
-   capability suggestion,
-   model-tier suggestion,
-   cognition-depth suggestion.

Unsuitable autonomous decisions:

-   destructive authorization,
-   publication approval,
-   credential release,
-   high-impact policy changes,
-   final safety adjudication.

Those remain deterministic or escalate to stronger authority.

------------------------------------------------------------------------

# 22. Default Route

The anti-ceremony architecture is enforced by making the default route
trivial:

``` text
context: none
thinking: direct
capability: none
authority: none
model: current
effects: none
verification: proportional
response: brief
```

Arcane only adds fields when the task requires them.

This produces **progressive cognition**.

------------------------------------------------------------------------

# 23. Example: Small Coding Fix

User:

> Fix the typo in the parser error.

Possible route:

``` text
context:
  Blueprint → exact file only

cognition:
  direct

capability:
  implementation

authority:
  none

compute:
  cheap/current

effects:
  repository-write

verification:
  focused test or direct inspection

postflight:
  brief
```

No Sage. No Alchemist. No persistent contract. No full-repo context. No
audit.

------------------------------------------------------------------------

# 24. Example: Ambiguous Architecture Change

User:

> Move the cache ownership out of the API layer.

Possible route:

``` text
context:
  Blueprint → ownership/call graph
  Ledger → current architecture decisions
  Cortex → prior cache discussions

cognition:
  deliberate

capability:
  architect

authority:
  Sage only if two materially different valid ownership interpretations remain

compute:
  strong reasoning
  cheap implementation after architecture settles

effects:
  repository-write

verification:
  architectural invariants + focused tests
  Oracle if substantial implementation is delivered

postflight:
  brief
```

------------------------------------------------------------------------

# 25. Example: Current External Fact

User:

> Does the latest SDK support this API?

Possible route:

``` text
context:
  local project metadata

cognition:
  direct + grounding

external grounding:
  required

capability:
  research/documentation

authority:
  none

compute:
  cheap/medium

verification:
  source citation

postflight:
  brief
```

------------------------------------------------------------------------

# 26. Three-Stage Compilation Model

The combined architecture can be understood as a compiler stack:

``` text
human intent
    ↓
ARCANE — cognitive compilation
    attention
    context
    cognition depth
    semantic requirement
    capability/authority conditions
    verification/cost posture
    ↓
LEGION — work compilation
    task nodes
    dependencies
    ownership
    execution requirements
    effects
    completion contracts
    escalation boundaries
    ↓
HOST — physical binding
    builtin
    script
    LSP
    Membrane
    tiny model
    frontier model
    human
```

This is analogous to:

``` text
source program
→ intermediate representation
→ lowered IR
→ target machine
```

but for agentic work:

``` text
human intent
→ cognitive route
→ portable work graph
→ concrete execution topology
```

Different hosts may lower the same Legion work semantics differently
without changing the meaning of the task.

------------------------------------------------------------------------

# 27. Strategic Thesis

Most agent systems route one dimension:

-   tools,
-   agents,
-   models,
-   or workflows.

The proposed Arcane architecture routes the **entire cognitive execution
topology**:

-   attention,
-   context,
-   cognition,
-   capability,
-   authority,
-   compute,
-   effects,
-   verification,
-   expression.

Membrane provides the context substrate.

Legion provides capabilities and authorities.

Arcane composes them per request.

The main model spends frontier intelligence on the problem rather than
on discovering how to operate the surrounding system.

That is the architectural opportunity.

------------------------------------------------------------------------

# 28. Concise System Definition

``` text
Membrane
"What is known?"
Context and memory substrate.

Legion
"What can do this?"
Capabilities, orchestration, and exceptional authorities.

Arcane
"How should this request be processed?"
Cognitive control plane.

Model / Agent
"Do the actual work."
```

And the Arcane design principle remains:

> **Think when useful → ground when necessary → retrieve only what
> matters → use the minimum sufficient intelligence and machinery →
> verify proportionately → answer cleanly.**

------------------------------------------------------------------------

# 29. Adopted Decisions and Pending Work (2026-08-29)

Reviewed against the 2026-08-29 subsystem audits
(`docs/audits/2026-08-29/`) and workspace git archaeology. The audits
corroborate Section 1 independently: groundwork (sequential thinking +
Context7) was built at workspace commit `dc8ab150`, renamed at
`df1e09bf`, and later deleted unregistered; the Brief/Minimize
SessionStart injection (2,295 chars, `MINIMIZE:ON`) and the
ending-shape Stop discipline (`stop-shape.mjs` anti-caveat +
no-permission-endings detectors) were orphaned by the native cutover
(`cae05d40`).

## Adopted decisions

1. Arcane stays a **separate subsystem** with its own doctrine and
   documentation (`doctrine/arcane.md` is currently missing — writing it
   is part of this work, covering the cognitive plane only).
2. The deterministic effect guard **splits out** of Arcane (Section 16);
   `legion-hook` is its seed. Guard keeps receipts; cognitive plane
   keeps none.
3. Architecture documentation is **separated per role and per skill**
   over time: one architecture document per authority (Sage, Alchemist,
   Oracle), one for the Guard, one for the Arcane cognitive plane, and
   per-skill docs following the existing manifest structure — replacing
   the current single-SSOT-plus-scattered-prose shape.
4. v0 of the cognitive plane is **static and deterministic** — no
   resident model. Resident 0.5–1B work (Sections 18–21) is a later
   phase; nothing gates on it.

## Pending work (ordered)

**P0 — Guard honesty (prerequisite for everything):**
- Ship a **canonical default Guard policy**, always present in the
  normal installed state: ordinary reversible effects ambient-allowed
  *as an explicit policy decision*; reserved/high-risk effects
  (credential access, publish, delete, push) deny/approval. A missing
  or corrupt baseline is a real Guard failure → fail closed. Ambient
  permission is a policy decision, not the absence of policy.
  (`engine/bins/legion-hook/src/main.rs:128-141`, `protocol.rs:179-189`;
  resolution recorded in `PENDING-WORK-2026-08-29.md` P0.1.)
- Redeploy the built binary: the committed subdirectory-resolution and
  MultiEdit fixes are not in the installed exe (lockout reproduced live
  2026-08-29).
- Reconcile the two policy artifacts (shipped empty stub vs unloaded
  `src/packages/arcane/policy/arcane-policy-v1.json`).

**P1 — Cognitive plane v0 (all deterministic):**
- SessionStart `additionalContext` injection: Brief/Minimize policy +
  one-paragraph routing summary (restores the lost 2,295-char payload;
  also fixes the bare-install orphan problem).
- Restore groundwork: `git checkout df1e09bf -- mcps/groundwork
  docs/GROUNDWORK.md` in the workspace repo, re-register in host
  configs, reference from the injection. Pull-based; zero loop risk.
- Port the ending-shape Stop discipline from
  `src/packages/arcane/lib/stop-shape.mjs` (anti-caveat family,
  no-permission-endings, ending-only judgment, real-failure exemption)
  into the Guard's Stop branch with never-hang bounds: deterministic
  regex only, bounded re-entry (2–3), forced clean exit.

**P2 — Guard coverage:**
- Match `mcp__*` and subagent dispatch in hooks.json AND add
  `parse_effect_class` arms together (widening the matcher alone
  fail-closes everything).
- `SubagentStop` event support (binary + hooks.json) so authority
  dispatch outcomes are receipted.

**P3 — Micro-router and resident model (deferred):**
- Deterministic kernel first; routing evals with a rank-1 ratchet
  (addyosmani/LambdaTest pattern) before any learned component; the
  invariant in Section 17.13 is the acceptance test.

Companion work-compilation pending items live in
`LEGION-MECHANISM-AWARE-WORK-DECOMPOSITION-2026-08-29-REV3.md` §19 and
the consolidated tracker `PENDING-WORK-2026-08-29.md`.
