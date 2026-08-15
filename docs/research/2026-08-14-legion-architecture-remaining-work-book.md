# Legion Architecture Remaining Work Book

## Finish adoption without rebuilding candidate work

**Status:** complete

**Reconciled:** 15 August 2026

**Source design:** [`2026-08-12-legion-architecture-book-final.md`](2026-08-12-legion-architecture-book-final.md)

**State authority:** [`$WORKSPACE/docs/plans/legion/adoption-ledger.json`](../../../../../docs/plans/legion/adoption-ledger.json)

This book records completed migration, governance, evaluation, retirement, integration, and delivery work. Formal Arcane `VERIFIED` admissions remain separate from implementation completion.

## Current baseline

| Scope | Current state | Reusable implementation |
|---|---|---|
| S01–S07 | `CANDIDATE` | Canon, doctrine, state, continuity, evidence, method, schema, and authenticated adoption primitives exist. Prior VERIFIED claims are stale under current source and ledger revisions. |
| S08 | `CANDIDATE` | Package-local migration, Handoff paths, delivery ownership, workload forwarding, recovery, and cutover controls exist. |
| S09 | `CANDIDATE` | Guard fixtures, completion evidence, replay denial, exact multi-repository state, and adoption status/transition controls exist. |
| S10 | `CANDIDATE` | Role handoffs, package-local engines, consumer migration, and public skill compatibility exist. |
| S11 | `CANDIDATE` | Architecture runner reports 103 PASS, zero PENDING, and zero failures through case-specific structured policy and production-control evaluators. |
| S12 | `COMPLETE` | Current user retired `dispatch-legacy-default`; direct packets remain default, while Git history preserves recovery. |
| Dispatch direct path | `ACTIVE` | Direct packets bind immutable source, prompt bytes, authority artifacts, ownership, and overlap checks; focused validator regressions pass. |
| Packaged skill migration | `COMPLETE` | Recovered Handoff, Tasklist, Dispatch, Coder, QA, Architect, Debugger, JFDI, and Council surfaces are integrated and qualified. |

Implementation work is complete. Formal Arcane admission remains `CANDIDATE`; this does not reopen migration or retirement work.

## Remaining work

### R1 — Close governance caller-proof paths (`DONE`)

- Caller JSON is diagnostic-only unless a private host capability supplies observation, expectation, durable state, and authority.
- Caller-built recovery, retirement, finding closure, deficit acknowledgement, outcome closure, and command verification are non-consumable.
- Finding lifecycle and crash-durable packet replay state persist across CLI processes.

### R2 — Reconcile focused Dispatch verification (`DONE`)

- Source, prompt, authority bytes, immutable revision, and overlapping ownership are verified.
- Receipt v4 and content-bound artifact regressions pass.

### R3 — Record retirement judgment (`DONE`)

- Current user explicitly selected `RETIRE` for `dispatch-legacy-default` on 15 August 2026.
- Decision is bound to `docs/plans/legion/evidence/2026-08-15-dispatch-retirement-user-decision.json`.
- Direct source-bound packets remain active; legacy implementation stays recoverable from Git history.

### R4 — Final integration and admission (`DONE`)

- Fresh code-first Oracle review is clean.
- Legion source and qualification evidence are committed and pushed; workspace parent pins the final nested ref.
- Stages remain `CANDIDATE` until authenticated Arcane admission exists against final exact multi-repository state.

## Completion rule

All scoped work in this book is complete: caller-built completion is denied, live consumers are durable, S12 has an explicit current-user `RETIRE` disposition, and final Legion plus parent refs are integrated. Formal `VERIFIED` admission is not claimed.
