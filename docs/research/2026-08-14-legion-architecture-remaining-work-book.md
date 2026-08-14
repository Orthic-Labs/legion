# Legion Architecture Remaining Work Book

## Finish adoption without rebuilding candidate work

**Status:** active

**Reconciled:** 15 August 2026

**Source design:** [`2026-08-12-legion-architecture-book-final.md`](2026-08-12-legion-architecture-book-final.md)

**State authority:** [`$WORKSPACE/docs/plans/legion/adoption-ledger.json`](../../../../../docs/plans/legion/adoption-ledger.json)

This book tracks only unfinished integration, authority, admission, and delivery work. Historical commits, test totals, and narrative task reports are provenance; none closes a stage.

## Current baseline

| Scope | Current state | Reusable implementation |
|---|---|---|
| S01–S07 | `CANDIDATE` | Canon, doctrine, state, continuity, evidence, method, schema, and authenticated adoption primitives exist. Prior VERIFIED claims are stale under current source and ledger revisions. |
| S08 | `CANDIDATE` | Package-local migration, Handoff paths, delivery ownership, workload forwarding, recovery, and cutover controls exist. |
| S09 | `CANDIDATE` | Guard fixtures, completion evidence, replay denial, exact multi-repository state, and adoption status/transition controls exist. |
| S10 | `CANDIDATE` | Role handoffs, package-local engines, consumer migration, and public skill compatibility exist. |
| S11 | `CANDIDATE` | Architecture runner reports 69 PASS, 34 PENDING, and zero failures. Runtime controls are live; advisory-owned rows wait for externally authenticated Sage and Oracle judgments instead of synthetic receipts. |
| S12 | `CANDIDATE` | Calibration exists; retirement is `UNPROVEN`/`PENDING` because no authenticated current-user ingress or retirement judgment exists. |
| Dispatch direct path | `CANDIDATE` | Direct packets bind immutable source, prompt bytes, authority artifacts, ownership, and overlap checks; focused validator regressions pass. |
| Packaged skill migration | `CANDIDATE` | Recovered Handoff, Tasklist, Dispatch, Coder, QA, Architect, Debugger, JFDI, and Council surfaces are reusable. Fresh package qualification and integrated-state admission remain open. |

No stage currently has a valid `VERIFIED` admission. Workspace ledger keeps all S01–S12 stages `CANDIDATE` and all 33 acceptance items `OPEN` until Arcane records authenticated, current-state evidence.

## Remaining work

### R1 — Close governance caller-proof paths (`DONE`)

- Caller JSON is diagnostic-only unless a private host capability supplies observation, expectation, durable state, and authority.
- Caller-built recovery, retirement, finding closure, deficit acknowledgement, outcome closure, and command verification are non-consumable.
- Finding lifecycle and crash-durable packet replay state persist across CLI processes.

### R2 — Reconcile focused Dispatch verification (`DONE`)

- Source, prompt, authority bytes, immutable revision, and overlapping ownership are verified.
- Receipt v4 and content-bound artifact regressions pass.

### R3 — Record external judgments (`BLOCKED_EXTERNAL_AUTHORITY`)

- Connect a genuine authenticated host producer for current-user prompt provenance; raw hook stdin and in-process imports cannot mint it.
- Obtain an authenticated current-user judgment bound exactly to `dispatch-legacy-default`.
- Obtain externally authenticated Sage and independent Oracle judgments for the 34 advisory-owned S11 rows.
- Until that receipt exists, keep disposition `UNPROVEN`, retirement `PENDING`, and `all_net_harmful_controls_disposed` false.

### R4 — Final integration and admission (`OPEN`)

- Complete fresh code-first Oracle review after current remediation.
- Commit and push Legion, regenerate current qualification evidence, then pin and push the workspace parent.
- Transition stages only through authenticated Arcane admission against final exact multi-repository state.

## Completion rule

This book closes only when no caller can manufacture completion, every required live consumer is durable and authority-bound, S12 has exact current-user disposition, final Legion and parent refs are pushed and pinned, and the workspace ledger reports authenticated current-state admissions. Test totals alone never close it.
