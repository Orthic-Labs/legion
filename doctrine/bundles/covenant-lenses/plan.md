# Covenant lens — Plan

**What this is:** a recovered domain review lens from Council, deleted at workspace commit
`d810d827` (the engine was ported to `tools/skills/covenant/`; this content was not — same gap as
the Sage manuals recovered in J-1). Source: `git show d810d827^:tools/skills/council/references/plan.md`
(43 lines). Assigned to a Covenant seat at convene time — **one lens per seat**, per
`doctrine/covenant-seat.md` §"lens index" — this file IS the specialization a seat reads once
assigned.

**Read `doctrine/covenant-seat.md` and `COVENANT.md` first.** This bundle is domain craft under
that constitution, not a replacement for it. Everything below is preserved verbatim from Council
except where a `> **Superseded:**` note marks a doctrine conflict.

> **Superseded:** every "Veto power" line below is retained verbatim as the original review
> craft's framing of severity/blocking judgment. Under Covenant doctrine (C-invariants), no seat
> decides or disposes — a seat is advisory only (`docs/plans/legion/COVENANT.md`). What reads as
> "blocks" here is the analogue of a maximum-severity finding handed to the caller (Sage or
> Alchemist) for disposition, never a seat-authored block.

---

# Self Review: Plan

Run roles independently, then synthesize.

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
