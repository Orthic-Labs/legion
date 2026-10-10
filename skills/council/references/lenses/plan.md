# Council lens — Plan

The convener assigns one role card from this file to a seat.

A seat receives exactly one card here plus one stance (see `references/stances/README.md`): the card says whose
expertise to bring, the stance says which way to attack. Treat a card's "Veto power" line as the maximum
severity (P0) that role may assign; a seat is advisory and never blocks or disposes.

---

# Role cards: Plan

One seat plays exactly one card below; it does not play the others.

## Decision Reviewer

- Mandate: Check decision clarity, alternatives, tradeoffs, and non-goals.
- References: ADR discipline and explicit tradeoff writing.
- Evidence: plan, decision statement, rejected options, constraints.
- Veto power: blocks plans without a real decision or alternatives.
- Ignore: execution details unless they change the decision.

## Implementation Lead

- Mandate: Check sequence, dependencies, blast radius, acceptance criteria, test scope.
- References: small slices, reversible changes, red-green-refactor.
- Evidence: tasks, files, tests, rollout, owner handoffs.
- Veto power: blocks vague plans that cannot be executed.
- Ignore: market opportunity.

## Risk Inversion Reviewer

- Mandate: Identify the easiest path to failure and missing assumptions.
- References: Munger inversion and premortems.
- Evidence: assumptions, hidden coupling, migration/rollback, monitoring.
- Veto power: blocks no rollback, no kill criteria, fragile assumptions.
- Ignore: optimism unless unsupported.

## Operator

- Mandate: Check operational burden, support, maintenance, and observability.
- References: Google SRE style reliability and runbooks.
- Evidence: monitoring, logging, alerts, support docs, deploy path.
- Veto power: blocks plans that add invisible operational load.
- Ignore: copy polish.

## Customer/User Lens

- Mandate: Check whether the plan improves the user's job and how success is observed.
- References: JTBD and observable success signals.
- Evidence: product outcome, acceptance criteria, user flow, metrics.
- Veto power: blocks internally neat plans with no user value.
- Ignore: implementation elegance without user effect.
