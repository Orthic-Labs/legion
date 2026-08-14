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
| S08 live execution closure | `VERIFIED` | Representative assembled-package workload passed 3/3 at `d95e4846`; independent receipt `sha256:7aa837db95b974854fbe11e1dcc9384811dc006b205d421f15e88df4e5ccb386`. |
| S09 Arcane guards | `VERIFIED` | 43/43 focused checks and 9/9 runtime fixtures pass; EC-609 v2 sealed, opened, and closed with strong authenticated evidence. |
| S10 role-doctrine implementation | `VERIFIED` | Handoff conformance, R1 parity, canonical naming, and authority-boundary checks pass on current integrated state. |
| S11 corpus and runner | `IN_PROGRESS` | Merged from `90beed4` and `a4c36d4`; 41/103 static cases pass, 62 await runtime execution. |
| Dispatch production usability | `NOT_STARTED` | Default still copies a 421-line legacy template whose GoalRoute, timing, Minimize, author-gate, and validator ceremony rejected a valid seven-owner packet with 115 unrelated defects. |
| Canonical naming and eval-gate repair | complete remediation | Integrated through Legion `b9dfab6`; parent pin `31d338cc9`; both match `origin/main`. |
| R1 packaged skill migration | `VERIFIED` | Closure recorded at Legion `2b1523b`; 25 public entrypoints resolve through digest-bound manifests, all 110 retired evals execute, 87 retired artifacts retain byte parity, advisory domains resolve, and clean assembled-package proof passes on Mac and Windows. |

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

### R2 — Implement S08 live execution closure (`DONE`)

Completed: assembled-package Handoff workload reached fresh S05/S07-backed acceptance; one integration owner/shared writer, ownership disposition, hard cut, exact state, and independent Oracle verification are recorded.

### R3 — Implement S09 Arcane guards (`DONE`)

Implemented: canonical fixtures cover epochs/cancellation, replay, terminal budgets, freshness/reachability, gate validity/machinery isolation, writer ownership, untrusted rehydration, authenticated host ingress, sanctioned ambient delivery, exact-state acceptance, and delivery deficits. Stage 9 evidence inventories but does not falsely complete 62 Stage 11 cases.

Completed: host-observed Sage binding sealed EC-609 v2, opened `run_01KZZR82AN6RPQ5S2MQB4YN4CP`, bound deterministic Oracle evidence, and closed with strong enforcement and complete delivery disposition.

### R4 — Close S10 (`DONE`)

Completed: exact-state handoff conformance, packaged-install parity, canonical naming, and duplicate-canon/authority-drift checks pass independently.

### R4A — Simplify Dispatch production path

- Make existing typed authority/worker JSON packet the default for bounded delegation; keep 421-line Markdown only as explicit legacy compatibility.
- Require GoalRoute, critical-path timing, Minimize authority, and 15-point author gate only when locked, contracted, or explicitly requested.
- Add quoted seven-owner, 175-unique-path, zero-collision DeepSeek packet as regression proof; validator must accept it without legacy schema ceremony.

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

R1 through R4 are closed. R4A and R5 are next, followed by R6 and final R7 certification. One owner serializes ledger writes, nested commits, parent pins, and pushes.

## Completion rule

This book closes only when S01–S12 are `VERIFIED` against current integrated state, all public entrypoints pass semantic and packaged-install parity across declared harnesses and hosts, all 110 retired skill eval cases and 103 architecture eval cases pass, the representative workload reaches its acceptance surface, advisory publication rights are explicitly resolved or kept non-publishable, and every required S12 judgment is recorded.
