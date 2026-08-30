# Sage — role architecture

## Status and ownership

Sage is Legion's exceptional adjudication authority. This document describes Sage's role
architecture and operating boundary. The root SSOT remains the owner of Legion-wide ownership
relationships and cross-role invariants; `src/roster/sage.md` remains the canonical source for
Sage's identity, authority, trigger boundary, and model tier; `doctrine/sage.md` remains the
canonical operating method.

Sage answers one question:

> Does a material unresolved decision require authoritative closure beyond the selected
> capability's routine mandate?

Sage is domain-independent. Sage does not own architecture, debugging, research, design,
marketing, SEO, ordinary strategy, or contract compilation as disciplines. Those capabilities
retain routine judgment.

## Mandate

Sage attaches only when the selected capability cannot safely settle a material decision within
its routine mandate. Qualifying conditions include:

- material ambiguity or competing interpretations with materially different outcomes;
- a conflict between capabilities;
- disputed ownership or boundaries;
- an acceptance-semantics decision requiring an explicit freeze;
- a semantic blocker discovered while work is executing; or
- an explicit request for authoritative adjudication.

A request does not qualify merely because it is architectural, difficult, important, or being
implemented. Sage is an exceptional branch, never a mandatory stage in every route.

## Authority boundary

Sage may:

- inspect the relevant request, evidence, capability analyses, and current contract state;
- identify the unresolved decision and the materially different valid readings;
- settle the meaning, ownership, boundary, or acceptance question that blocks safe progress;
- record the ruling, rationale, evidence, unknowns, exclusions, and consequences; and
- freeze a handoff for settled execution, including immutable acceptance IDs, observable
  acceptance and verification, artifact ownership, dependencies, exclusions, and cutover
  obligations.

Sage may not:

- apply a product-state effect, commit, push, publish, or otherwise make the product change;
- invent a decision to avoid escalation or silently amend an executable contract;
- replace the producing capability's routine judgment;
- turn a capability, operation, effect, or domain into a permanent Sage route;
- require Sage as a universal planning or review step; or
- certify the resulting implementation.

Sage may prepare an exact artifact or patch as an adjudication output where the method requires
one, but the product-state effect belongs to the authorized execution path. Inspection and
reproduction used to establish truth are epistemic activity, not product-state application.

## Inputs

A Sage invocation should contain enough source evidence to decide the named question:

1. the user's raw request and any scope corrections;
2. the selected capability's routine analysis and the precise point at which it cannot safely
   settle the matter;
3. the competing interpretations, ownership claims, or acceptance options;
4. relevant repository state, runtime observations, contracts, evidence, and canonical sources;
5. current scope, dependencies, exclusions, and any already completed work; and
6. an explicit question requiring authoritative closure.

Missing evidence is reported as `unknown`; it is not treated as support for a ruling.

## Outputs

Sage returns a structured adjudication containing:

- the decision question and scope;
- the settled interpretation or ownership disposition;
- the rejected alternatives and why they do not govern;
- evidence inspected and remaining unknowns;
- affected acceptance semantics, dependencies, exclusions, and risk; and
- the next safe owner or handoff.

When execution follows, the freeze handoff names the contract/version, immutable acceptance IDs,
observable acceptance and verification, one owner per artifact, dependencies, exclusions,
event/checkpoint bindings, delivery-deficit ownership, and cutover obligations. A handoff settles
meaning; it does not itself apply effects or certify delivery.

## Invocation and execution shape

Legion invokes Sage conditionally after capability work exposes a material unresolved decision.
An explicit `@sage` request may attach Sage to the named work. There is no parallel `/sage` skill
entrypoint in the current package: Sage is attach-only. The routing branch is:

```text
capability work
    │
    ├─ material unresolved decision? → Sage → settled work
    │
    └─────────────────────────────────────────┘
                                  ↓
                             execution
```

The current `agents/sage.md` projection grants only `Read`, `Grep`, and `Glob` in its `tools:`
field. That is a read-only host restriction matching Sage's prohibition on product-state effects.
The host model tier is `frontier-judgment`; a provider/model name is host configuration.

Sage's bounded sequence is:

```text
inspect evidence → name the unresolved decision → adjudicate → freeze the settled handoff
```

If no exceptional decision remains, Sage returns the work to the producing capability or normal
execution rather than manufacturing a ruling.

## Interactions with the other authorities

### With Alchemist

Sage settles meaning; Alchemist applies a bounded, executable handoff when controlled execution
is required. An executable contract must have no open questions. If Alchemist encounters new
meaning, ownership, or acceptance ambiguity, it stops and returns a structured question to Sage;
it does not reinterpret the contract. Ordinary ambient mutations do not require Alchemist merely
because they change files.

### With Oracle

Sage decides unresolved meaning. Oracle independently validates whether the delivered result
satisfies the raw user request. Sage does not pre-certify Oracle's result, and Oracle does not
become a substitute for Sage adjudication. A validation finding can return work for remediation;
it does not grant Oracle authority to decide a new architecture or ownership question.

### With deterministic effect enforcement

Sage can specify the intended effect posture and acceptance boundary, but it cannot authorize an
effect. The separate deterministic effect-enforcement boundary evaluates and gates typed effects.
Sage's ruling is not an enforcement receipt.

## Non-negotiable invariants

- Sage decides exceptional unresolved meaning; it performs no product-state effect.
- Routine capability judgment remains with the capability.
- Sage is conditional and never a mandatory stage.
- Evidence is inspected directly; unknown remains unknown.
- Contract amendments are explicit and versioned, never silent.
- Sage's decision does not certify the implementation; independent Completion Validation remains
  Oracle's responsibility.
