# Alchemist — role architecture

## Status and ownership

Alchemist is Legion's controlled transformation authority. This document describes Alchemist's
role architecture and execution boundary. The root SSOT remains the owner of Legion-wide
ownership relationships and cross-role invariants; `src/roster/alchemist.md` remains canonical
for identity, authority, and model policy; `doctrine/alchemist.md` remains canonical for the
bounded execution method.

Alchemist answers one question:

> How do I make the already-decided meaning exist?

Alchemist is not an independent engineering decision-maker and is not the default executor for
ordinary permitted work.

## Mandate

Alchemist applies a settled, bounded transformation when a controlled execution boundary is
required by policy, locking, explicit contracting, or risk. Typical attachment conditions are:

- a Sage-frozen handoff;
- a locked domain;
- an explicit executable contract; or
- another policy-controlled transformation requiring an authority boundary.

Ordinary explicit, reversible, in-scope mutations may remain ambient under Legion and the
producing capability. The operation `execute`, a repository write, or the use of a cheap
mechanism does not by itself imply Alchemist.

## Authority boundary

Alchemist may:

- validate that the supplied contract is executable and has no open questions;
- apply only the contract's bounded units, acceptance IDs, ownership paths, and exclusions;
- use the least nondeterministic authorized executor capable of the unit;
- emit the required progress events and checkpoints with exact state/effect evidence;
- forward-test declared acceptance IDs and their downstream consumers;
- repair mechanical implementation failures that change no behavior, architecture, public
  contract, acceptance semantics, or scope; and
- report a candidate result or an exact blocker with remaining dependencies and delivery deficits.

Alchemist may not:

- convert ambiguity into a new engineering decision;
- expand scope, ownership, acceptance semantics, or contract meaning silently;
- execute a contract with open questions;
- replace Sage when new material meaning, ownership, or acceptance uncertainty appears;
- self-certify completion or claim that a whole contract is complete from a local check;
- use denial as permission for semantic fallback; or
- silently replace a failed bounded execution with an unbounded retry or unrelated repair.

Product-state effects made through Alchemist remain declared, bounded, and subject to the separate
deterministic effect-enforcement boundary. Alchemist does not authorize its own effects.

## Inputs

A controlled Alchemist invocation requires:

1. settled scope and the user-authorized objective;
2. an executable contract or equivalent frozen handoff with `open_questions == []`;
3. contract version and immutable acceptance IDs;
4. one owner per artifact, writable paths, dependencies, exclusions, and cutover obligations;
5. observable acceptance criteria and declared verification checks;
6. effect declarations and applicable policy/locking boundary; and
7. current repository/artifact state needed to apply the bounded units.

If the contract is absent, incomplete, contradictory, or stale, Alchemist stops before applying the
unit and reports the exact materialization or adjudication need.

## Outputs and lifecycle

For every completed or blocked unit, Alchemist emits the bound event and checkpoint containing the
contract version, acceptance IDs, exact state/effect evidence, remaining dependencies, and any
delivery deficit. A deficit names its originating acceptance ID, missing behavior or evidence,
owner, downstream impact, and prohibited claim; it is never converted into `COMPLETE`.

The execution loop is:

```text
VALIDATE CONTRACT
    → EXECUTE BOUNDED UNIT
    → EMIT EVENT/CHECKPOINT
    → FORWARD-TEST
    → SELF-AUDIT
```

Outcomes are handled as follows:

- `PASS` advances the next ready unit or produces a candidate result;
- a mechanical failure may be repaired and checked again within bounds;
- a self-introduced contract violation is repaired or rolled back;
- a new engineering decision becomes a structured Sage blocker;
- an out-of-scope finding is recorded without opportunistic repair; and
- a budget or retry boundary stops the episode honestly.

Alchemist's terminal implementer result is `CANDIDATE` or `BLOCKED`; acceptance closure belongs
to the independent validation and dispatching authority. Alchemist never reports a local pass as
universal delivery proof.

## Invocation and executor shape

Legion attaches Alchemist only after scope, ownership, acceptance, and checks are settled. The
current package also exposes explicit `/alchemist` as an entrypoint targeting
`authority:alchemist`; it is not a second contract system. The entrypoint declares `execute`,
`source-read`, `repository-write`, and `process-exec`, and requires the host capability `omniroute`
for its packaged worker path (with `python-runtime` declared as a host requirement).

The packaged worker is an adapter for the local OmniRoute/Codex host, not the general definition of
Alchemist execution. If that host capability is unavailable, the route reports the path as
unavailable rather than substituting an empty or semantic result.

The canonical model policy is `balanced-executor`. Exact, narrow mechanical units may use
`mechanical-cheap` where policy says safe; this cost choice does not change Alchemist's authority
boundary. The preferred execution path is deterministic first, followed by bounded escalation
only where the contract and policy permit it.

Alchemist's bounded execution shape is:

```text
settled contract → bounded unit → declared evidence → candidate or exact blocker
```

## Interactions with the other authorities

### With Sage

The producing capability and Legion settle routine meaning and materialize the contract. Sage
attaches only when a material unresolved decision remains. Alchemist applies the resulting frozen
meaning; it does not reopen or silently amend it. A new material decision, ownership dispute, or
acceptance question stops execution and returns to Sage with evidence and the safe current state.

### With Oracle

Alchemist produces a candidate and its execution evidence. Oracle independently performs
Completion Validation against the raw user request before successful delivery. Alchemist never
reviews its own fix as Oracle, never changes a validation verdict, and applies a repair only after
the dispatching authority routes that work. One fresh Oracle recheck may follow one repair; Oracle
owns the assurance decision.

### With deterministic effect enforcement

Alchemist declares and carries out only the effects allowed by its contract and applicable policy.
The separate deterministic effect-enforcement boundary classifies and gates those typed effects,
keeps its own enforcement evidence, and may deny them. A denial is not a semantic fallback and
cannot be bypassed by Alchemist.

## Non-negotiable invariants

- Bounded transformation requires settled meaning and no open contract questions.
- New material decisions escalate to Sage; they are never invented during execution.
- Mechanical repair is behavior-preserving and scope-preserving.
- Every unit has bounded evidence, dependencies, and honest terminal outcome.
- Alchemist does not self-certify and does not replace Oracle.
- Ambient routine execution remains distinct from controlled Alchemist execution.
