# Legion Architecture Remaining Work Book

## Finish adoption without rebuilding completed work

**Status:** active execution book
**Date:** 14 August 2026
**Source design:** [`2026-08-12-legion-architecture-book-final.md`](2026-08-12-legion-architecture-book-final.md)
**State authority:** [`$WORKSPACE/docs/plans/legion/adoption-ledger.json`](../../../../../docs/plans/legion/adoption-ledger.json)

This book contains only unfinished implementation or acceptance work. Existing merged artifacts are inputs, not tasks to recreate.

## Closed baseline

| Scope | State | Evidence boundary |
|---|---|---|
| S01–S04 and S06 | `VERIFIED` | Adoption ledger contains exact integrated-state evidence and independent PASS history. |
| S05 | `VERIFIED` | Fresh independent exact-state checks passed 28/28 focused authorization/evidence cases at `b05bafae`. |
| S07 | `VERIFIED` | Fresh independent exact-state checks passed 4/4 template/lens cases at `b05bafae`. |
| S10 role-doctrine implementation | `CANDIDATE` | Merged from `a71bfa4`; current handoff conformance tests pass 5/5. |
| S11 corpus and runner | `IN_PROGRESS` | Merged from `90beed4` and `a4c36d4`; 41/103 static cases pass, 62 await runtime execution. |
| Canonical naming and eval-gate repair | complete remediation | Integrated through Legion `b9dfab6`; parent pin `31d338cc9`; both match `origin/main`. |
| R1 packaged skill migration | `VERIFIED` | Integrated through Legion `f450326`; 25 public entrypoints resolve through digest-bound manifests, all 110 retired evals execute, 87 retired artifacts retain byte parity, advisory domains resolve, and clean assembled-package proof passes on Mac and Windows. |

Do not re-author, re-dispatch, or replace these artifacts unless a remaining acceptance check finds a concrete defect.

## Validated skill-migration gap — closed 14 August 2026

Commit `c1c7e818` retired nine engineering skill entrypoints together before parity. A no-rename diff confirms 15,202 deleted source lines across those nine directories, correcting the previously reported 16,201. Their removed eval manifests contain exactly 110 cases:

| Retired entrypoint | Removed eval cases | Recovered local surface | Local state |
|---|---:|---|---|
| `handoff` | 10 | Entrypoint, validator, validator suite, template, compiler/bootstrap workflow, manual, examples, semantic routing, and shared Orthic transcript tests | `DONE` |
| `tasklist` | 8 | Callable entrypoint, validation semantics, template, durable workflow, examples, and semantic routing | `DONE` |
| `dispatch` | 36 | Callable workflow, validator, manual/agent routing, artifact set, receipts, and semantic routing | `DONE` |
| `coder` | 6 | Callable opt-in entrypoint, API-worker adapter, provider runbook, hooks, and eval parity | `DONE` |
| `qa` | 10 | Callable entrypoint, browser reference/manual, QA-engine adapters, and resolved runners | `DONE` |
| `architect` | 14 | Callable Sage Architect entrypoint and trigger parity | `DONE` |
| `debugger` | 9 | Callable Sage Diagnose entrypoint and trigger parity | `DONE` |
| `jfdi` | 3 | Natural-language compatibility plus retired alias resolution to `/alchemist` | `DONE` |
| `council` | 14 | Covenant entrypoint, compatibility resolution, and legacy packet parity | `DONE` |

Historical baseline before R1 began, retained as provenance rather than pending work:

- Legion's registry exposed only eight advisory packs.
- Commercial, research, editorial, and design routing nodes were `unavailable`; engineering exposed only Sage, Alchemist, and Oracle dispatch.
- Discovery coverage was presence-only and did not execute semantic resolution.
- Alias registry lacked Handoff, Tasklist, Dispatch, Coder, QA, Architect, Debugger, JFDI, and Council compatibility routes.
- Package allowlist omitted root `SKILL.md`, `audit-fix/`, and `audit-visual/`.
- Advisory manifests already enforced unresolved rights, null receipts, and `publish: false`; that non-publication boundary remains intentional.
- Compatibility entrypoints remained top-level after the earlier engineering-only migration; verified package-local consumers now permit their deletion.
- `docs/SKILL-ARCHITECTURE.md` used a retired assurance-role name; integration corrected it to Oracle.

Public skill entrypoints may route into Sage, Alchemist, Oracle, Covenant, Cortex, or existing engines without moving authority or infrastructure into skill-shaped owners. Private brand and venture overlays remain excluded from Legion packages.

## Remaining work

### R1 — Close packaged-install parity (`DONE`)

Completed:

- 25 public entrypoints, package-local engines, full Handoff/Dispatch/Tasklist callable behavior, Brand/Content routing, and JFDI/Council compatibility.
- All 110 retired evals execute through the resolver; 87 retired artifacts retain byte-for-byte parity under canonical entrypoints.
- Canonical and legacy resolution, digest binding, nested `--skill` filtering, package discovery, and assembled-package execution pass on Mac and Windows.
- Codex, Claude Code, Gemini, and agents-md binding artifacts are present in the clean assembled package.
- Obsolete top-level compatibility entrypoints and shared-engine roots are removed after consumer migration.
- Rights-restricted packs remain non-publishable with null receipts.

### R2 — Implement S08 live execution closure

- Run one representative governed workload through existing S05 and S07 producers.
- Prove one integration owner, ownership disposition, migration/cutover closure, exact integrated-state identity, and observed user-visible acceptance.
- Record fresh evidence and independently verify S08.

### R3 — Implement S09 Arcane guards

- Wire authenticated runtime execution for all declared negative and sanctioned-path cases.
- Enforce epochs, cancellation, replay, budgets, evidence freshness, gate validity, ownership, deficit acknowledgement, adoption proof, acceptance closure, and machinery isolation.
- Prove denials do not block valid delivery paths, then independently verify S09.

### R4 — Close S10

- After S08, rerun existing role-handoff conformance against exact integrated state.
- Confirm completed R1 packaged-install parity and absence of duplicate canon or authority drift.
- Move S10 from `CANDIDATE` to `VERIFIED`.

### R5 — Finish S11 runtime evaluation

- Execute 62 currently pending runtime cases through S09's authenticated executor.
- Repair concrete failures and rerun the smallest affected families.
- Require 103/103 reproducible results and independent S11 verification.

### R6 — Complete S12 calibration and retirement

- Replay real Legion history, a minimal ambient baseline, and the S08 governed workload.
- Measure outcome, coordination, tool, token, delivery-time, quiescence, and duplicate-effect deltas.
- Present each net-harmful control for current-user `RETIRE | ACCEPT` judgment and record every disposition.

### R7 — Finalize delivery

- Run one exact-state independent audit across all twelve stages.
- Require every stage `VERIFIED`, no open blocker, 103/103 evals, observed workload acceptance, and all S12 judgments.
- Commit and push Legion, pin and push parent, then pull and validate Windows without overwriting local changes.

## Execution order

```text
R1 ─> R2 ─┬─> R3 ─> R5 ─> R6 ─> R7
          └─> R4 ────────────────┘
```

R1 is closed. R2 is the live integration gate. After R2, R3 and R4 may overlap until shared wiring or integration. R7 waits for both paths. One owner serializes ledger writes, nested commits, parent pins, and pushes.

## Completion rule

This book closes only when S01–S12 are `VERIFIED` against current integrated state, all public entrypoints pass semantic and packaged-install parity across declared harnesses and hosts, all 110 retired skill eval cases and 103 architecture eval cases pass, the representative workload reaches its acceptance surface, advisory publication rights are explicitly resolved or kept non-publishable, and every required S12 judgment is recorded.
