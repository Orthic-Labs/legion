# COLD-START HANDOFF: Handoff package restoration

## 0. Handoff Control

- **Handoff ID:** handoff-package-example-20260814
- **Created:** 2026-08-14T12:00:00+05:30
- **Source task / chat:** Codex task /root/handoff_skill
- **Target:** Fresh Codex task with workspace access
- **Author:** Handoff package maintainer
- **Receiver role:** EXECUTION
- **Proceed mode:** IMMEDIATE
- **Readiness:** READY
- **Handoff reason:** Transfer restored skill verification into a zero-context task.
- **Source evidence mode:** LIVE_CONTEXT
- **Transcript evidence path:** NOT_APPLICABLE: package example derives from checked workspace state.
- **Source prefix receipt:** NOT_APPLICABLE: LIVE_CONTEXT has no transcript prefix.
- **Packet path:** /workspace/legion/skills/handoff/examples/validated-forward-test.md
- **Receipt path:** /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json

## 1. Intent & Mission

- **Original user intent verbatim:** Restore Handoff artifacts while preserving unrelated workspace changes.
- **Underlying goal:** Ship a callable, validated cold-start Handoff skill package.
- **Current objective:** Verify package template, parser, validator, & focused tests.
- **Definition of success:** Template self-check, receipt verification, & focused tests exit successfully.
- **Out of scope:** Registry, aliases, parent pins, commits, pushes, & unrelated package edits.
- **First responsibility:** Verify this packet receipt before inspecting live state.
- **Must not do first:** Do not reset, stage, commit, or overwrite shared checkout work.

## 2. Current State

- **Phase:** Verification handoff example
- **Completed:** Package skill docs, template, library scripts, & focused tests are available.
- **In progress:** Fresh receiver verifies receipt then runs focused tests.
- **Blocked:** NONE_CHECKED: all prerequisite artifacts are present.
- **Not started:** No repository mutation beyond verification is required.
- **Last action:** Run template validator self-check.
- **Last observed result:** Template validator exited zero with PASS evidence.
- **Active goal / plan:** Restore package parity then report exact paths & hashes.
- **Current hypothesis:** Library wrappers preserve legacy validation semantics.

## 3. Environment & Active Work

- **Work type:** CODE
- **Workspace / repo:** /workspace
- **Branch / version:** Current shared workspace branch; inspect live before change.
- **Baseline revision:** c1c7e818 legacy-retirement boundary.
- **Dirty state:** Shared checkout may contain concurrent Handoff library & test edits.
- **OS / shell:** macOS zsh with python3.
- **Tools / dependencies:** Python standard library plus tools.lib.orthic_transcripts.
- **Services / processes:** NONE_CHECKED: do not stop any shared process.
- **Agents / tasks / threads:** Concurrent Handoff library & test owners may be active.
- **Scheduled work:** NONE_CHECKED: no scheduler inspection needed.
- **Credentials / access:** No credentials required; do not inspect stores.

## 4. Decisions, Invariants & User Corrections

| ID | Decision / invariant / correction | Source / why | Status | Reopen only when |
|---|---|---|---|---|
| DECISION-01 | Skill remains documentation & routing layer over shared library scripts. | Package ownership boundary prevents duplicate parser/validator. | LOCKED | Library public interface changes. |

## 5. Artifacts & Evidence

| Artifact | Path / URL | Role | State | Version / hash | Validation + last checked |
|---|---|---|---|---|---|
| Handoff template | /workspace/legion/skills/handoff/assets/handoff-template.md | Canonical packet structure | COMPLETE | SHA recorded by validator | Run template self-check before release. |

## 6. Failures, Dead Ends & Attempts

| ID | Attempt / command | Exact symptom / result | Cause / diagnosis | Evidence | DO_NOT_RETRY_UNLESS | Replacement / next diagnostic |
|---|---|---|---|---|---|---|
| FAILURE-01 | Legacy script path invocation | Path no longer exists after package migration. | Runtime moved into package-local library. | /workspace/legion/lib/handoff | Never invoke retired path. | Use package-local wrapper. |

## 7. Learnings, Gotchas & Landmines

| Signal | Hidden trap / learning | Required safe behavior | Source |
|---|---|---|---|
| Shared checkout | Other Handoff owners write concurrently. | Edit only owned skill directory. | Task ownership boundary. |

## 8. Open Loops & Context Gaps

| Gap / open loop | Severity | Impact | Recovery action | Safe subset | Owner |
|---|---|---|---|---|---|
| No known context gap | NONE | No impact on focused verification. | Recheck repository state before edits. | Full verification scope. | Receiver |

## 9. Safety, Authority & Boundaries

- **May do:** Run focused Handoff verification commands.
- **Do not change:** Registry, aliases, library ownership, tests owned by other agents.
- **Do not run:** Reset, cleanup, commit, push, or broad formatters.
- **Irreversible / production actions:** None authorized for this packet.
- **Spend / external effects:** No network, publication, or paid effect.
- **Secrets handling:** No secret values; do not inspect credential stores.
- **Reserved decisions:** Package architecture changes remain reserved to integration owner.

## 10. Exact Resume Sequence

### Resume Step 1 — Verify packet receipt

- **Owner:** Fresh receiver
- **Working directory / system:** /workspace
- **Exact action:**

```text
python3 /workspace/legion/lib/handoff/validate-handoff.py /workspace/legion/skills/handoff/examples/validated-forward-test.md --verify-receipt /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json
```

- **Expected result:** Receipt verifier reports RECEIPT_PASS.
- **Evidence path:** /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json
- **Timeout / retry:** 30 seconds; retry once after reading failure.
- **If failure:** Stop use of packet & regenerate receipt only after packet validation.
- **Depends on:** None checked.

### Resume Step 2 — Check template

- **Owner:** Fresh receiver
- **Working directory / system:** /workspace
- **Exact action:**

```text
python3 /workspace/legion/lib/handoff/validate-handoff.py /workspace/legion/skills/handoff/assets/handoff-template.md --template-self-check
```

- **Expected result:** Template self-check reports PASS.
- **Evidence path:** /workspace/legion/skills/handoff/assets/handoff-template.md
- **Timeout / retry:** 30 seconds; retry once after named repair.
- **If failure:** Repair only template defect, then repeat receipt verification.
- **Depends on:** Resume Step 1 receipt verification.

### Resume Step 3 — Run focused suite

- **Owner:** Fresh receiver
- **Working directory / system:** /workspace
- **Exact action:**

```text
Run python3 -m unittest discover -s /workspace/legion/tests -p '*handoff*.py'
```

- **Expected result:** Focused Handoff tests exit zero.
- **Evidence path:** /workspace/legion/tests
- **Timeout / retry:** 60 seconds; retry once after inspecting named test failure.
- **If failure:** Preserve output & route only owned defect to correct owner.
- **Depends on:** Resume Step 2 template verification.

## 11. State Verification & Invalidation

- **Verification command:**

```text
Check package changes: git -C /workspace status --short -- legion/skills/handoff
```

- **Expected state:** Only package-owned Handoff artifact paths appear.
- **Invalidated by:** Any packet edit, library interface change, or newly completed Handoff test.
- **Refresh action:** Re-run focused validation from /workspace.
- **Validator command:**

```text
python3 /workspace/legion/lib/handoff/validate-handoff.py /workspace/legion/skills/handoff/examples/validated-forward-test.md --write-receipt /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json
```

- **Receiver receipt check:**

```text
python3 /workspace/legion/lib/handoff/validate-handoff.py /workspace/legion/skills/handoff/examples/validated-forward-test.md --verify-receipt /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json
```

## 12. First Output & Readback Contract

```text
READBACK
MISSION: Verify restored Handoff package artifacts.
CURRENT_STATE: Library, skill docs, template, & tests require focused proof.
LOCKED_DECISIONS: D1.
SAFETY_BOUNDARIES: Preserve concurrent owners and do not alter shared integration state.
NEXT_ACTION: Run Resume Step 1 exactly.
CRITICAL_GAPS: none.
ASSUMPTIONS: Shared state can drift; recheck before edits.
FIRST_VERIFICATION: Verify packet receipt.
PACKET_RECEIPT: <verified sha256>
```

- **First deliverable after readback:** Exact readback plus receipt result.
- **Gap report format:** `GAP: <severity> | <missing> | <impact> | <recovery> | <safe subset> | <owner>`

## 13. Ready-to-Paste First Message

```text
You are receiving a cold-start handoff with zero prior memory.
Treat only this packet plus its verified artifacts as context.
Verify packet receipt, return READBACK exactly as specified, correct any mismatch from packet, then follow Proceed mode.
Do not infer missing context, reopen LOCKED decisions, expose secrets, overwrite unrelated work, or execute reserved actions.
BEGIN HANDOFF PACKET AT: /workspace/legion/skills/handoff/examples/validated-forward-test.md
RECEIPT AT: /workspace/legion/skills/handoff/examples/validated-forward-test.receipt.json
```

## 14. Context Gap Report

- **Gap summary:** 0 FATAL, 0 HIGH, 0 MEDIUM, 0 LOW, 1 NONE.
- **Safe-to-proceed scope:** Full focused Handoff verification.
- **Fatal recovery owner:** NOT_APPLICABLE: no fatal gap exists.
- **Exact recovery sequence:** Verify receipt, check template, then run focused suite.

## 15. Handoff Author Gate

- [x] Original user intent is exact enough for this example.
- [x] Active goal and source evidence mode are explicit.
- [x] Live state is rechecked before action.
- [x] Work state is separated by phase.
- [x] Package path is explicit.
- [x] Concurrent owners are named.
- [x] Decision includes reopen condition.
- [x] Artifact includes validation location.
- [x] Failure includes retry guard.
- [x] Shared-checkout gotcha is recorded.
- [x] No secret values appear.
- [x] Gap includes recovery and owner.
- [x] Readiness matches gap severity.
- [x] Resume Step 1 is executable.
- [x] State verification is exact.
- [x] Readback detects mismatch.
- [x] Fresh receiver has no unseen-context dependency.
- [x] Validator receipt is required before use.
