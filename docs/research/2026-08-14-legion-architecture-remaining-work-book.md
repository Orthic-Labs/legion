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
| Canonical naming and eval-gate repair | complete remediation | Legion `b05bafae`; parent pin `adb742cdd`; both match `origin/main`. |
| R1 local skill migration | implementation complete | 17 public entrypoints resolve through digest-bound manifests; all 110 retired evals retained; advisory domains resolve; package smoke passes locally. |

Do not re-author, re-dispatch, or replace these artifacts unless a remaining acceptance check finds a concrete defect.

## Validated skill-migration gap — 14 August 2026

Commit `c1c7e818` retired nine engineering skill entrypoints together before parity. A no-rename diff confirms 15,202 deleted source lines across those nine directories, correcting the previously reported 16,201. Their removed eval manifests contain exactly 110 cases:

| Retired entrypoint | Removed eval cases | Current surviving capability | Missing closure |
|---|---:|---|---|
| `handoff` | 10 | `tools/lib/orthic_transcripts/`; current parser passes 23/23 tests | Entrypoint, 493-line validator, 394-line validator suite, template, compiler/bootstrap workflow, manual, examples, semantic routing |
| `tasklist` | 8 | 45-line compatibility adapter and passing compatibility test | Original 571-line validation semantics, template, durable workflow, examples, semantic routing |
| `dispatch` | 36 | 2,918-line validator, route fixtures, and passing cost-routing test | Callable workflow, manual/agent routing, full artifact set, semantic routing |
| `coder` | 6 | API worker parses | Callable opt-in entrypoint, provider runbook, hook/receipt parity |
| `qa` | 10 | QA engine modules parse | Callable entrypoint, browser reference/manual, resolved runner binding |
| `architect` | 14 | Sage Architect doctrine | Callable intent entrypoint and trigger parity |
| `debugger` | 9 | Sage Diagnose doctrine | Callable intent entrypoint and trigger parity |
| `jfdi` | 3 | retired alias → `/alchemist` | Natural-language and compatibility trigger boundary |
| `council` | 14 | Covenant capability | retired alias → `/covenant` compatibility boundary and legacy packet parity |

Baseline checks before R1 began confirmed:

- Legion's skill registry exposes only eight advisory packs: `ads`, `brand-identity`, `designer`, `marketing`, `research`, `seo`, `social`, and `writing`.
- Commercial, research, editorial, and design routing nodes remain `unavailable`; engineering exposes only Sage, Alchemist, and Oracle dispatch.
- Discovery coverage for all eight packs is presence-only: current test passes 1/1 but does not execute semantic resolution.
- Alias registry lacks Handoff, Tasklist, Dispatch, Coder, QA, Architect, Debugger, JFDI, and Council compatibility routes.
- Package allowlist includes `skills/` but omits root `SKILL.md`, `audit-fix/`, and `audit-visual/`, so local Audit entrypoints are not packaged.
- All eight advisory manifests have `licenseState: unresolved`, null rights receipts, and `publish: false`; they are locally discoverable but not publishable.
- `commit`, `brand`, `content`, `alchemist`, `cortex`, `covenant`, and `compshop` remain top-level workspace skills. Commit deletion was explicitly deferred; brand/content were excluded by the earlier engineering-only migration scope, then left behind when Legion expanded to five domains.
- `docs/SKILL-ARCHITECTURE.md` still used a retired assurance-role name; integration corrects it to Oracle.

Public skill entrypoints may route into Sage, Alchemist, Oracle, Covenant, Cortex, or existing engines without moving authority or infrastructure into skill-shaped owners. Private brand and venture overlays remain excluded from Legion packages.

## Remaining work

### R1 — Close packaged-install parity

Local implementation is complete: parity manifests, Handoff, 17 public entrypoints, Brand/Content routing, JFDI/Council compatibility, all 110 retired evals, canonical/legacy resolver tests, digest binding, non-publishable rights state, and package smoke pass.

- Prove clean packaged-install discovery and behavior in Codex, Claude Code, Gemini, and agents-md on Mac and Windows.
- Repair only reproduced harness or host failures.
- Keep unresolved-rights packs non-publishable unless explicit rights receipts land.
- Delete remaining top-level compatibility entrypoints only after both-host acceptance passes.

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
- Prove R1 callable-entrypoint parity and absence of duplicate canon or authority drift.
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
R0 ─┐
    ├─> R2 ─> R3 ─┬─> R5 ─> R6 ─> R7
R1 ─┘             └─> R4 ─┘
```

R0 and R1 may run concurrently. R2 is the only live integration gate. After R2, R3 and R4 may overlap until shared wiring or integration. One owner serializes ledger writes, nested commits, parent pins, and pushes.

## Completion rule

This book closes only when S01–S12 are `VERIFIED` against current integrated state, all public entrypoints pass semantic and packaged-install parity across declared harnesses and hosts, all 110 retired skill eval cases and 103 architecture eval cases pass, the representative workload reaches its acceptance surface, advisory publication rights are explicitly resolved or kept non-publishable, and every required S12 judgment is recorded.
