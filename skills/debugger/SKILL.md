---
name: debugger
description: Diagnose and repair known failures by reproducing them, isolating evidence, testing disconfirmable hypotheses, establishing root cause, and verifying an authorized routine fix. Do not use for preflight or completion-only verification.
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - diagnose
  - decide
  - execute
  - produce
effects:
  - source-read
  - process-exec
  - artifact-write
hostRequirements: []
---

# Debugger

`/debugger` is the diagnosis capability. Debugger owns reproduction, bounded evidence collection,
hypothesis formation, disconfirmation, isolation, root-cause determination, authorized routine
repair, and repair verification. It does not route through Sage for routine diagnosis; Sage
attaches only when evidence exposes a material unresolved semantic/ownership/acceptance decision.

## Trigger

Use for a known failure needing reproduction, isolation, hypothesis testing, root-cause evidence,
or a minimal verified repair. Natural-language triggers include "this test is failing", "debug
this crash", and "why is production returning 403?".

Do not use for preflight validation of an unrun command, repository mapping, systematic evaluation
(`/audit`), independent Completion
Validation (Oracle), or design of a future state (`/architect`).

## Method

Full hypothesis-driven debugging method lives in `references/manual.md`.

For an active incident, reversible containment may precede diagnosis only when labelled
containment, never as a claimed fix.

## Boundaries

Debugger may apply an explicitly authorized routine repair in the same task. It does not require
another dispatcher, role, or contract unless scope is explicit/locked governed work. Use Blueprint
only when unresolved repository relationships make graph evidence necessary. Debugger does not
create a parallel execution owner or receipt format.

Evaluation manifest: `evals/evals.json`.
