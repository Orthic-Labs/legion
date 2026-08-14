---
name: debugger
description: Route known engineering failures, crashes, regressions, wrong data, intermittent tests, or unexplained slowness to Sage Diagnose. Do not use for preflight or completion-only verification.
---

# Debugger

`/debugger` is a public, intent-only entrypoint for Sage's Diagnose route. It owns no alternate
debug engine, authority, runtime, or executor.

## Trigger

Use for a known failure needing reproduction, isolation, hypothesis testing, root-cause evidence,
or a minimal verified repair. Natural-language triggers include "this test is failing", "debug
this crash", and "why is production returning 403?".

Do not use for preflight validation of an unrun command, repository mapping (`/cortex`),
completion-only verification (`/audit`/Oracle), or design of a future state (`/architect` → Sage
Architect).

## Route

1. Read [`agents/sage.md`](../../agents/sage.md).
2. Apply [`sage-diagnose.md`](../../doctrine/bundles/sage-diagnose.md) and [`sage.md`](../../doctrine/sage.md).
3. Establish a reproduction or bounded oracle, isolate evidence, form disconfirmable hypotheses,
   and identify root cause before proposing a permanent repair.
4. Return frozen evidence and a Sage handoff; product-source effects route to Alchemist.

For an active incident, reversible containment may precede diagnosis only when labelled
containment, never as a claimed fix.

## Artifact boundary

This entrypoint deliberately reuses Sage doctrine and shared engines. It must not create a
parallel debugger workflow, receipt format, or execution owner.

Evaluation manifest: `evals/evals.json`.
