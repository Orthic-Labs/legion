# COLD-START HANDOFF: Dispatch, Handoff & Council-Packet Skill Release

## 0. Handoff Control

- **Handoff ID:** dispatch-handoff-council-release-20260728
- **Created:** 2026-07-28T14:25:37+05:30
- **Source task / chat:** Codex Desktop task /root; current skill-building release
- **Target:** New Codex Desktop task with workspace access to D:/Claude
- **Author:** /root/handoff_forward_author
- **Receiver role:** EXECUTION
- **Proceed mode:** IMMEDIATE
- **Readiness:** READY_WITH_GAPS
- **Handoff reason:** Preserve exact release context before current task reaches context limit.
- **Source evidence mode:** LIVE_CONTEXT
- **Transcript evidence path:** NOT_APPLICABLE: packet was authored from current live context before transcript-ingest mode existed.
- **Source prefix receipt:** NOT_APPLICABLE: packet was authored from current live context before transcript-ingest mode existed.
- **Packet path:** D:/Claude/tools/skills/handoff/examples/validated-forward-test.md
- **Receipt path:** D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json

## 1. Intent & Mission

- **Original user intent verbatim:** Create a robust dispatch-authoring skill in D:\Claude that forces context-complete, end-to-end executable agent tasks with explicit evidence, recovery paths, escalation rules, handoffs, and enforceable validation gates. dispatch should also follow /script skill when scripts are involved. the orchestrating agent should create the scripts where it can. also a /handoff skill that ensures all context, gotchas, learnings, goal, intent is properly transferred for a cold chat that has 0 prior context that will avoid wasting time and failures. if i asked for /council packet, i would like a md or in line if i specify that explains the full problem + my intent in a simple brief way such that i can get outside help, like i did with minimax and qwen here, does that make sense? so that doesn't mean i want to run the skill, i just want a easy to paste explanation so other 3rd party agents can propose fixes. can you do this too? to be very clear, they are completely independent skills, handoff is to start a new chat when context/ tokens get bloated and dispatch is to send tasks to a smaller model while the orchestrator validates, observes etc. they can share bits of course but they shouldn't be interdependent always. commit and push to main
- **Underlying goal:** Ship independent /dispatch & /handoff skills plus packet-only /council packet mode, each with durable artifacts, validators, tests, registration, Council/Jury review, scoped commit, & push to main.
- **Current objective:** Finish fresh-agent proof, run final Council/Jury review, apply findings, validate all scoped artifacts, commit scoped changes, & push main.
- **Definition of success:** Dispatch & handoff validate from durable Markdown plus matching sidecar receipts; fresh readers can execute/read back without task-history inference; /council packet writes durable Markdown by default or returns exact inline packet only when explicitly requested; release commit reaches origin/main.
- **Out of scope:** Do not alter unrelated dirty work, run product builds, deploy, change policies outside scoped skill files, or use a packet-only request to launch reviewers.
- **First responsibility:** Reconstruct current state with Step 1, verify this packet receipt, then resume remaining release gates.
- **Must not do first:** Do not switch/reset/rebase branches, stage all dirty files, run destructive commands, or declare release complete before fresh-agent proof plus Council/Jury disposition.

## 2. Current State

- **Phase:** Final forward-test, Council/Jury, validation, commit, push.
- **Completed:** tools/skills/dispatch/ & tools/skills/handoff/ contain SKILL, agent metadata, template, evals, validator, adversarial tests; both are registered in .claude/rules/skills.md & docs/SKILL-ARCHITECTURE.md; dispatch forward packet plus receipt validates with SHA-256 42a0c84903c95c89fd370dead48c90f18c568a5ca9c8aecbd475ab6cfca475be; /council packet mode, template, validator, & evals are present under tools/skills/council/.
- **In progress:** This permanent handoff packet plus receipt; root agent is integrating final review & release work.
- **Blocked:** NONE_CHECKED — no true blocker exists; external Council provider authentication failed earlier, then permitted native fallback supplied advisory findings.
- **Not started:** Fresh cold-reader proof for this handoff; final joint Council, disposition, fresh Jury, scoped commit, & push to main.
- **Last action:** Get-ScheduledTask inventory plus Get-FileHash at 2026-07-28T14:25:37+05:30.
- **Last observed result:** Scheduled claudecodex-proxy & crypt-replication were Running, crypt-daily Disabled, crypt-serve Ready; dispatch forward packet SHA-256 was 42A0C84903C95C89FD370DEAD48C90F18C568A5CA9C8AECBD475AB6CFCA475BE.
- **Active goal / plan:** User-owned objective requires robust independent skills, /script integration for dispatch, packet-only Council export, commit, & push; remaining plan is forward proof, joint review, scoped validation, release.
- **Current hypothesis:** Durable file-plus-receipt enforcement removes temporary-validation & inline-only bypasses; a cold reader must now prove packet completeness.

## 3. Environment & Active Work

- **Work type:** MIXED
- **Workspace / repo:** D:/Claude
- **Branch / version:** absorption/phase1-6 at inspection; user explicitly requested final commit & push to main.
- **Baseline revision:** 2e162e538bfd577504cb98148615e9c7f4aac58b — docs: start Windows P3 round one prepare at 2026-07-28T14:07:54+05:30.
- **Dirty state:** git status --short showed unrelated modified .agent/flows.json, .agent/stale.json, .blueprint/manifest.json, docs/architecture.md, docs/product.md, tools/skills/council/*, tasks/lessons.md, submodule states membrane & citadel, untracked bakeoff/memory files; scoped modified .claude/rules/skills.md, docs/SKILL-ARCHITECTURE.md; scoped untracked tools/skills/dispatch/, tools/skills/handoff/.
- **OS / shell:** Windows PowerShell on D:/Claude; Python launcher py -3.11.
- **Tools / dependencies:** Stdlib Python validators only; skill discovery validator through D:/Claude/tools/skills/.system/skill-creator/scripts/quick_validate.py; run relevant test files with py -3.11.
- **Services / processes:** Many Node processes are live with unknown unrelated ownership; do not stop them. Process inventory at 2026-07-28T14:25:37+05:30 also showed py.exe PID 8608 & Python 3.11 PID 29672.
- **Agents / tasks / threads:** /root integration agent was running; council_operator completed with REVISE findings; dispatch_forward_author completed durable dispatch proof; this handoff author is producing durable packet. Re-run live agent inventory before review/commit.
- **Scheduled work:** claudecodex-proxy Running; crypt-replication Running; crypt-daily Disabled; crypt-serve Ready. Do not alter scheduled tasks.
- **Credentials / access:** External Council provider credentials were unavailable during earlier room attempt; do not print or add secrets. Native review fallback is authorized when provider route fails.

## 4. Decisions, Invariants & User Corrections

| ID | Decision / invariant / correction | Source / why | Status | Reopen only when |
|---|---|---|---|---|
| DECISION-01 | /dispatch & /handoff are independent skills with distinct runtime purposes. | User objective explicitly separates smaller-agent delegation from context rollover. | LOCKED | User explicitly changes purpose boundary. |
| DECISION-02 | Every dispatch is a durable named Markdown artifact plus sidecar receipt before send/spawn. | User corrected temporary validation-file failure; dispatch SKILL Step 0A, Step 8, Hard rules. | LOCKED | User explicitly permits ephemeral dispatch. |
| DECISION-03 | Every handoff is a durable named Markdown artifact plus sidecar receipt; inline is transport only. | User asked whether systematic documentation is better for audit; handoff SKILL Step 0 & Step 9. | LOCKED | User explicitly chooses inline-only non-audited handoff. |
| DECISION-04 | Dispatch invoking a script/runner must follow /script; orchestrator creates script where feasible. | Active user goal. | LOCKED | User changes script-authoring responsibility. |
| DECISION-05 | /council packet authors outside-review context only; it never runs Council/Jury/reviewers. | Active user goal; council SKILL packet-only mode. | LOCKED | User explicitly requests actual Council review. |
| DECISION-06 | Preserve unrelated dirty work; stage only scoped files; primary checkout only. | D:/Claude/AGENTS.md & current dirty state. | LOCKED | User explicitly requests broad cleanup or isolation. |
| DECISION-07 | External provider failure routes to isolated native Council/Jury fallback. | Earlier provider auth/proxy failure; Council SKILL fallback rule. | ACTIVE_ASSUMPTION | User mandates particular external reviewer route. |

## 5. Artifacts & Evidence

| Artifact | Path / URL | Role | State | Version / hash | Validation + last checked |
|---|---|---|---|---|---|
| Dispatch skill | D:/Claude/tools/skills/dispatch/SKILL.md | Durable zero-context delegation rules | DRAFT_READY | live uncommitted source | Earlier scoped static validation passed; re-run after final edits. |
| Dispatch validator tests | D:/Claude/tools/skills/dispatch/scripts/test_validate_dispatch.py | Rejects structural, semantic, status, script, receipt bypasses | COMPLETE | stdlib Python | Earlier output: PASS with concrete packet & adversarial rejections. |
| Dispatch forward packet | D:/Claude/tools/skills/dispatch/examples/validated-forward-test.md | Fresh-agent authored packet proof | COMPLETE | sha256 42a0c84903c95c89fd370dead48c90f18c568a5ca9c8aecbd475ab6cfca475be | Dispatch validator & receipt verifier passed. |
| Dispatch forward receipt | D:/Claude/tools/skills/dispatch/examples/validated-forward-test.receipt.json | Exact-bytes evidence for dispatch proof | COMPLETE | sidecar JSON | Receipt verifier passed against dispatch forward packet. |
| Handoff skill | D:/Claude/tools/skills/handoff/SKILL.md | Cold-start context-transplant rules | DRAFT_READY | live uncommitted source | Earlier static validation & adversarial test passed; re-run after this proof. |
| Handoff validator tests | D:/Claude/tools/skills/handoff/scripts/test_validate_handoff.py | Rejects readiness, secret, resume, table, temporary-storage, receipt bypasses | COMPLETE | stdlib Python | Earlier output: PASS with durable cold-start packet & adversarial rejections. |
| This handoff packet | D:/Claude/tools/skills/handoff/examples/validated-forward-test.md | Fresh-reader handoff proof | IN_PROGRESS | receipt written by Step 1 validation | Validate & bind receipt before transfer. |
| Council packet mode | D:/Claude/tools/skills/council/SKILL.md | Third-party problem brief without review execution | DRAFT_READY | live uncommitted source | Packet-only rules, external template, validator, & eval entries exist; include in final validation. |
| Skill registrations | D:/Claude/.claude/rules/skills.md; D:/Claude/docs/SKILL-ARCHITECTURE.md | Discovery & architecture registration | DRAFT_READY | scoped modified files | Re-run skill discovery validation. |

## 6. Failures, Dead Ends & Attempts

| ID | Attempt / command | Exact symptom / result | Cause / diagnosis | Evidence | DO_NOT_RETRY_UNLESS | Replacement / next diagnostic |
|---|---|---|---|---|---|---|
| FAILURE-01 | dual-review jury-plan --stage advisory --room | Council room fell to provider-failure path; Claude CLI unauthenticated & MiniMax proxy unavailable. | External review credentials/routes unavailable in current environment. | D:/Claude/tools/review/.council-runs/dispatch-skill-20260728/ | Provider credential/route is deliberately restored & named by user. | Use isolated native Council fallback, preserve findings/disposition, then run fresh native Jury. |
| FAILURE-02 | Initial dispatch authoring used temporary validation artifact. | User reported agent failure because dispatch was not always written to durable file. | Completion gate allowed validation artifact rather than canonical audit artifact. | Current user correction & dispatch SKILL Step 0A/8/Hard rules. | User explicitly changes durable-artifact rule. | Enforce durable .md plus sidecar receipt in skill, template, validator, test, & forward proof. |
| FAILURE-03 | Handoff was initially considered for inline-only transfer. | User asked whether systematic documentation is better for audit. | Inline-only transfer loses audit/resume source & byte binding. | Current user correction & handoff SKILL Step 0/9/Hard rules. | User explicitly requests non-audited inline-only use. | Retain canonical packet plus receipt; paste only exact validated bytes when filesystem inaccessible. |

## 7. Learnings, Gotchas & Landmines

| Signal | Hidden trap / learning | Required safe behavior | Source |
|---|---|---|---|
| Readable plan | Clear prose can hide decisions an executor cannot reconstruct. | Require exact commands, paths, evidence, failure branches, owner, bounds, & TRUE_BLOCKER proof. | User failure analysis; dispatch skill design. |
| Validator fixture | Placeholder substitution can falsely prove parser structure without operational semantics. | Keep adversarial tests & fresh-agent execution evidence; review every table row. | Earlier native Council operator finding. |
| Dirty checkout | git status contains multiple unrelated concurrent changes & submodule state. | Never reset, revert, stage-all, switch, or commit unrelated paths. | Live inventory & D:/Claude/AGENTS.md. |
| Primary checkout | Final user request is commit/push to main, but live checkout was absorption/phase1-6. | Inspect branch/ref state immediately; move only with explicit user authorization already supplied; preserve dirtiness. | Live inventory & user goal. |
| Council packet request | Packet authoring is not permission to run external reviewers. | Return durable MD by default, inline only when requested, never fabricate findings/verdict. | Active user goal & council SKILL. |

## 8. Open Loops & Context Gaps

| Gap / open loop | Severity | Impact | Recovery action | Safe subset | Owner |
|---|---|---|---|---|---|
| Live branch/HEAD/dirty state can change while agents finish. | MEDIUM | Release commands may target stale state. | Run Resume Step 1 before edits, review, staging, or branch movement. | Packet receipt verification & readback remain safe. | Cold receiver |
| External Council provider authentication is unavailable. | LOW | Named external lane cannot run in current environment. | Use native isolated fallback required by Council skill; record lane & output. | Full review using native fallback. | Root integrator |
| Fresh cold-reader proof for this packet remains incomplete at packet authoring time. | MEDIUM | Handoff skill lacks end-to-end receiver evidence until reader responds. | Give this file plus receipt to a zero-context agent; require exact READBACK & Step 1 result. | Validation, review, & source inspection remain safe. | Root integrator |

## 9. Safety, Authority & Boundaries

- **May do:** Inspect scoped source, run local validators/tests, author durable review artifacts, use native review fallback, apply in-scope fixes, stage scoped changes, commit, & push to main after all gates.
- **Do not change:** Unrelated dirty paths, active Node processes, scheduled tasks, membrane, citadel, product code, external services, secret stores, or user-authored work outside skill release scope.
- **Do not run:** git reset --hard, git checkout --, broad cleanup, destructive deletion, deployment, paid compute, or external reviewer calls without explicit request.
- **Irreversible / production actions:** Commit & git push origin main are explicitly requested only after final scope validation; no deploy/publication follows from this request.
- **Spend / external effects:** No paid compute, message sending, or external API is required; native local review fallback has no external provider dependency.
- **Secrets handling:** Reference only credential presence/route state; never print tokens, keys, config secret values, or receipt secrets.
- **Reserved decisions:** User did not reserve skill design decisions; user explicitly reserved audit durability by requiring permanent dispatch file.

## 10. Exact Resume Sequence

### Resume Step 1 — Refresh state & verify this packet

- **Owner:** Cold receiver
- **Working directory / system:** D:/Claude
- **Exact action:**

```text
Set-Location D:/Claude; git branch --show-current; git rev-parse HEAD; git status --short; py -3.11 D:/Claude/tools/skills/handoff/scripts/validate-handoff.py D:/Claude/tools/skills/handoff/examples/validated-forward-test.md --verify-receipt D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
```

- **Expected result:** Current branch, SHA, dirty inventory print; receipt check exits 0 with RECEIPT_PASS and reports this handoff SHA-256.
- **Evidence path:** D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
- **Timeout / retry:** 30 seconds; retry once after reading exact failure output.
- **If failure:** If receipt mismatch, do not trust packet state; inspect diff, rebuild receipt only after revalidating corrected packet. If branch/dirty state differs, record delta in final review packet before staging.
- **Depends on:** D:/Claude/tools/skills/handoff/examples/validated-forward-test.md

### Resume Step 2 — Run scoped validator & test suite

- **Owner:** Cold receiver
- **Working directory / system:** D:/Claude
- **Exact action:**

```text
Run scoped validators: Set-Location D:/Claude; py -3.11 D:/Claude/tools/skills/dispatch/scripts/test_validate_dispatch.py; py -3.11 D:/Claude/tools/skills/handoff/scripts/test_validate_handoff.py; py -3.11 D:/Claude/tools/skills/.system/skill-creator/scripts/quick_validate.py D:/Claude/tools/skills/dispatch; py -3.11 D:/Claude/tools/skills/.system/skill-creator/scripts/quick_validate.py D:/Claude/tools/skills/handoff; py -3.11 D:/Claude/tools/skills/.system/skill-creator/scripts/quick_validate.py D:/Claude/tools/skills/council
```

- **Expected result:** Every command exits 0; both test files print PASS; each quick validator prints Skill is valid.
- **Evidence path:** D:/Claude/tools/skills/dispatch/scripts/test_validate_dispatch.py; D:/Claude/tools/skills/handoff/scripts/test_validate_handoff.py
- **Timeout / retry:** 120 seconds; retry once only after repairing named scoped defect.
- **If failure:** Read failing script/test path, make smallest scoped correction, rerun only failed command then full Step 2. If command invokes or changes a runner script, invoke /script first & preserve its receipt requirements.
- **Depends on:** Resume Step 1 receipt verification.

### Resume Step 3 — Finish fresh proof, review, release

- **Owner:** Root integrator
- **Working directory / system:** D:/Claude
- **Exact action:**

```text
Use a zero-context reader to return Section 12 READBACK from this packet, run final joint Council with the three scoped skills, apply every accepted finding, run a fresh Jury on revised packet, then stage only .claude/rules/skills.md docs/SKILL-ARCHITECTURE.md tasks/lessons.md tools/skills/dispatch tools/skills/handoff tools/skills/council and commit/push main.
```

- **Expected result:** Cold reader completes readback without task-history questions; Council disposition is complete; Jury verdict is SHIP; scoped commit exists on main & git push origin main succeeds.
- **Evidence path:** D:/Claude/tools/review/.council-runs/dispatch-handoff-final/; D:/Claude/tools/skills/dispatch/examples/validated-forward-test.receipt.json; D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
- **Timeout / retry:** 3 review attempts maximum; each review retry only after accepted fixes & revised packet.
- **If failure:** For provider failure use native isolated fallback. For REVISE, apply each in-scope finding & rerun Jury. For push rejection, fetch remote state, preserve dirty scope, integrate without reset, rerun scoped validation, then push.
- **Depends on:** Resume Step 2 full pass & fresh handoff readback.

## 11. State Verification & Invalidation

- **Verification command:**

```text
Run state verification: Set-Location D:/Claude; git status --short; git branch --show-current; git rev-parse HEAD; py -3.11 D:/Claude/tools/skills/dispatch/scripts/test_validate_dispatch.py; py -3.11 D:/Claude/tools/skills/handoff/scripts/test_validate_handoff.py
```

- **Expected state:** Branch/HEAD/dirty set captured anew; both test suites exit 0 & print PASS; no unrelated path is changed by validation.
- **Invalidated by:** Any source edit, receipt rewrite, agent completion, branch/HEAD movement, new dirty file, Council finding, reviewer output, staging, commit, or push.
- **Refresh action:** Rerun Resume Step 1, update this packet only if using it as current canonical handoff, then revalidate its receipt.
- **Validator command:**

```powershell
py -3.11 D:/Claude/tools/skills/handoff/scripts/validate-handoff.py D:/Claude/tools/skills/handoff/examples/validated-forward-test.md --write-receipt D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
```

- **Receiver receipt check:**

```powershell
py -3.11 D:/Claude/tools/skills/handoff/scripts/validate-handoff.py D:/Claude/tools/skills/handoff/examples/validated-forward-test.md --verify-receipt D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
```

## 12. First Output & Readback Contract

Receiver returns before work:

```text
READBACK
MISSION: Ship independent durable /dispatch, /handoff, and packet-only /council packet capabilities with scoped validation, review, commit, and push.
CURRENT_STATE: Skills exist uncommitted; dispatch forward proof is complete; this handoff needs receipt verification and cold-reader proof; final review and release remain.
LOCKED_DECISIONS: D1, D2, D3, D4, D5, D6.
SAFETY_BOUNDARIES: Preserve unrelated dirtiness; no reset, stage-all, process/task changes, deploy, secret exposure, or reviewer launch from packet-only work.
NEXT_ACTION: Run Resume Step 1 exactly.
CRITICAL_GAPS: none; state drift is MEDIUM and must be refreshed.
ASSUMPTIONS: Branch/HEAD may have moved since timestamp; use live command output.
FIRST_VERIFICATION: Verify this packet receipt and capture current git state.
PACKET_RECEIPT: <verified sha256>
```

- **First deliverable after readback:** Exact READBACK plus Step 1 command output summary; proceed immediately to Step 2 unless receipt mismatch or a true boundary conflict occurs.
- **Gap report format:** GAP: <severity> | <missing> | <impact> | <recovery> | <safe subset> | <owner>

## 13. Ready-to-Paste First Message

```text
You are receiving a cold-start handoff with zero prior memory.
Treat only this packet plus its verified artifacts as context.
Verify packet receipt, return READBACK exactly as specified, correct any mismatch from packet, then follow Proceed mode.
Do not infer missing context, reopen LOCKED decisions, expose secrets, overwrite unrelated work, or execute reserved actions.
BEGIN HANDOFF PACKET AT: D:/Claude/tools/skills/handoff/examples/validated-forward-test.md
RECEIPT AT: D:/Claude/tools/skills/handoff/examples/validated-forward-test.receipt.json
```

## 14. Context Gap Report

- **Gap summary:** 2 MEDIUM gaps, 1 LOW gap, 0 HIGH gaps, 0 FATAL gaps.
- **Safe-to-proceed scope:** Full scoped skill release after Resume Step 1 refresh.
- **Fatal recovery owner:** NOT_APPLICABLE — no FATAL gap after live inventory.
- **Exact recovery sequence:** Verify receipt; refresh live git/agent state; use native fallback if external review route remains unavailable; record all revisions before final Jury & release.

## 15. Handoff Author Gate

- [x] Original user intent + active goal are exact, not paraphrased away.
- [x] Source evidence mode is explicit; transcript ingest binds compiled ledger path + prefix receipt.
- [x] Live state was re-read from workspace/tools this turn.
- [x] Completed/in-progress/blocked/not-started states are separated.
- [x] Branch/version/dirty state or non-code equivalent is exact.
- [x] Active agents/processes/scheduled work were inventoried.
- [x] Decisions include rationale + reopen conditions.
- [x] Artifacts include locations + validation freshness.
- [x] Failures include raw evidence + DO_NOT_RETRY_UNLESS.
- [x] User corrections, learnings, gotchas, naming locks, & do-not-touch zones are captured.
- [x] No secret values appear.
- [x] Every gap has severity, impact, recovery, safe subset, & owner.
- [x] Readiness matches gap severities.
- [x] Resume Step 1 is immediately executable.
- [x] State verification + invalidation rules are exact.
- [x] Readback detects mission/state/boundary/next-action mismatch.
- [x] Cold-chat simulation passed with no unseen-context dependency.
- [x] validate-handoff.py PASS receipt matches exact packet bytes.
