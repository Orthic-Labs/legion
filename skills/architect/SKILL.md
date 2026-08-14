---
name: architect
description: Route engineering design, ADR, interface, invariant, or implementation-plan requests to Sage Architect. Do not use for current-state mapping, diagnosis, or execution.
---

# Architect

`/architect` is a public, intent-only entrypoint for Sage's Architect route. It owns no decision
method, runtime, state, or executor.

## Trigger

Use for a proposed engineering change needing a design decision: architecture, ADR, refactor,
approach comparison, interface or invariant definition, migration design, or implementation plan.
Natural-language equivalents include "design this feature", "plan this refactor", and "how should
we build this?".

Do not use for current repository mapping (`/cortex`), failure diagnosis (`/debugger` → Sage
Diagnose), independent state assurance (`/audit` → Oracle), or applying a settled decision
(`/alchemist`).

## Route

1. Read [`agents/sage.md`](../../agents/sage.md).
2. Apply [`sage-architect.md`](../../doctrine/bundles/sage-architect.md) and [`sage.md`](../../doctrine/sage.md).
3. Match output depth to intent: answer, architecture decision, or executable contract.
4. Hand any product-source effect to Alchemist; Sage may run only epistemic checks.

Required Architect output, when depth warrants it: `R-*` requirements, `D-*` decisions, `I-*`
invariants, `NG-*` non-goals, and `AC-*` acceptance criteria. An executable contract is valid only
when its open questions are empty.

## Artifact boundary

This entrypoint deliberately reuses Sage doctrine and shared architecture templates/schemas. It
must not create a parallel planner, authority, receipt format, or architecture store.

Evaluation manifest: `evals/evals.json`.
