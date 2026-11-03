# COLD-START HANDOFF: Legion lead — fix-plan implementation, cut, sweep lane and approved compile loop

## 0. Handoff Control

- **Handoff ID:** 26440622-legion-lead
- **Created:** 2026-11-02T22:10:00+05:30
- **Source task / chat:** Claude Code session 26440622-40ce-4ba3-a479-a06612fb46a7, the Legion lead chat in /Volumes/D/claude/legion
- **Target:** Claude Code session fb87e7b8-9edb-4cd9-8f97-94de0470de68 (profile claude-b), new Legion lead
- **Author:** Legion (target chat, TRANSCRIPT_INGEST)
- **Receiver role:** Continuation as Legion lead for the Legion repository
- **Proceed mode:** IMMEDIATE
- **Readiness:** READY_WITH_GAPS
- **Handoff reason:** Adrian, 2026-11-02T16:32Z: "we're at 84% of 5 hour limit and reset is 2 hours away. i need to move your work to another chat"
- **Source evidence mode:** TRANSCRIPT_INGEST
- **Transcript evidence path:** /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-40ce-4ba3-a479-a06612fb46a7.context.json (receipt 26440622-40ce-4ba3-a479-a06612fb46a7.context.receipt.json beside it, RECEIPT_PASS this turn)
- **Source prefix receipt:** PLATFORM: claude; SESSION_ID: 26440622-40ce-4ba3-a479-a06612fb46a7; CUTOFF_BYTES:28828672; SHA256:9d07ee624cd8a77d91b5e0dcb8d1a40c1f632898c19e2afa81a7470effb5d36a; PARSER_VERSION: legion.transcript-event.v1
- **Packet path:** /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.md
- **Receipt path:** /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.receipt.json

## 1. Intent & Mission

- **Original user intent verbatim:** Adrian, 2026-11-02T08:23Z: "I want you start a reviewer chat to review all chat transcriptions on my dell and mac in the past 2 weeks. i want you to find each and every failure. how are agents constantly fucking up. i want a full log of every fuck up and how it can be avoided. i then want you to look at tstack, pstack. Look if there are things in there that would've helped fix this." Then at 11:07Z: "List out every failure in 2 weeks, give me exact fixes for each bucket of failures." At 15:02Z: "Approve the loop". At 15:32Z: "Yes, cut it down" (to "are we adding junk ai slop into our code?"). At 16:28Z: "I don't think the hook should automatically close the process. It should prompt the chat that started it. Is that possible?" followed by "ok".
- **Underlying goal:** Agents stop repeating the logged failures because Legion enforces Adrian's rules deterministically (hook checks, approval gate, recorded words, daily failure scan, stuck-call sweep), shipped as a released Legion.
- **Current objective:** Finish the stopped sweep lane (notify-only), register it, then Class A, one Oracle review of 0f5e9cee..HEAD, then the approved local compile-and-test loop until green.
- **Definition of success:** Legion main compiles and tests green locally through the gate with all fix-plan checks; then CI and release requests sent to Adrian in his format and approved; issues closed only on proven fixes.
- **Out of scope:** CI runs, pushes to Legion main (they trigger CI), releases, installs, schedule creation, killing any process, new chats, closing issues on unverified code.
- **First responsibility:** Verify live repo state (Resume Step 1), then finish the sweep lane.
- **Must not do first:** Must not compile, push, release, or kill anything before the sweep is finished, Class A passes and Oracle clears.

## 2. Current State

- **Phase:** Implementation done for waves 1 and 2 and cut to size; sweep lane partial; nothing compiled.
- **Completed:** Local unpushed commits on main above origin/main 0f5e9cee: 5732509f, ab2bedc1, 98b81bee, 8d3ed185 (hook checks), dc3bb993 (CI, switches, Class A config), d3286c70 (approval gate, recorded words, rustfmt on edit, debugger after red), ff3f070c (Oracle findings), 04a5cd5f (daily scan), 86dd76a4 (hook checks cut to 2,174 lines from 11,682), 71d3527f (legion daily cut to 1,556 lines plus 448 test lines). Range diff 0f5e9cee..HEAD: 64 files, +7123/-379. Workspace rules fix on both machines (commit 76f9b89e88, then 13d509b45 on Mac and Dell; manage.py check 0 errors both). 12 Legion issues closed as done/duplicate/stale; 29 open.
- **In progress:** Sweep lane, stopped mid-work: only `engine/bins/legion-hook/src/governor.rs` is dirty (+43/-1: new-chat block ARC_NO_NEW_CHAT, `starts_chat`, test). `engine/bins/legion/src/commands/sweep.rs` does not exist yet.
- **Blocked:** None. Adrian's approval for the loop exists (Section 4 D3).
- **Not started:** sweep.rs; registering sweep in cli.rs and commands/mod.rs; `legion-dev check-retirements` (deleted daily/*.rs files may need rows in docs/provenance/retirements.md); Class A on HEAD; Oracle review; compile loop; skill manifest refresh inside the loop; CI and release requests. Also unassigned backlog listed in /Volumes/D/scratch/legion-impl/INTEGRATION.md "Still to assign".
- **Last action:** Source chat ran the handoff bootstrap at 16:32Z after telling Adrian two lanes were running.
- **Last observed result:** This turn: `git status --short` shows ` M engine/bins/legion-hook/src/governor.rs` and `?? tasks/`; HEAD 71d3527f80c98f534384b2b9da35399830083c65.
- **Active goal / plan:** sweep finish -> register -> check-retirements -> Class A -> Oracle -> compile loop -> requests.
- **Current hypothesis:** The cut code will show a few type errors on first compile (the cutting writer predicted this); the loop fixes them.

## 3. Environment & Active Work

- **Work type:** CODE
- **Workspace / repo:** /Volumes/D/claude/legion
- **Branch / version:** main
- **Baseline revision:** 71d3527f80c98f534384b2b9da35399830083c65 (origin/main 0f5e9cee)
- **Dirty state:** `git status --short` -> ` M engine/bins/legion-hook/src/governor.rs`, `?? tasks/`
- **OS / shell:** macOS Darwin 27.0.0, zsh
- **Tools / dependencies:** `legion` CLI; `rightkit-host-gate` (gate); `rustfmt --edition 2021`; `legion-dev`; Pulse (`pulse chat said`, `pulse chat read`); `win "<cmd>"` for the Dell.
- **Services / processes:** Source chat process PID 63804 (main profile) still alive with child `legion serve --stdio` 64099; it is idle at its handoff. A `rustright cargo deny` (PID 97720) was seen briefly at 22:04 IST, owner not confirmed. No build of Legion running from this chat.
- **Agents / tasks / threads:** Source chat's sweep lane subagent (legion:alchemist-specialist) was stopped by Adrian; daily-cut lane finished (71d3527f). Linked sessions from the source chat: failure-review local_e5bb1d70-6b77-495d-abde-6c2a28035ce7 (done), EGM review local_f57947ca-2af8-47fb-aae0-4824a91e67ad (done). This chat cannot message the source chat's subagents.
- **Scheduled work:** None created; Adrian has set no wake interval.
- **Credentials / access:** gh CLI auth present (used for issues); no values recorded.

## 4. Decisions, Invariants & User Corrections

| ID | Decision / invariant / correction | Source / why | Status | Reopen only when |
|---|---|---|---|---|
| Decision D1 | Compile, build, test, CI, push that triggers CI, publish, install only with Adrian's express approval in the chat doing it. "Compile don't free." | Adrian 11:29Z; workspace rules | LOCKED | Adrian changes the rule in his own words |
| Decision D2 | Preflight means Class A only, never compile. Approval requests carry full Class A output on the exact commit, exact commands, and a plain "will pass" verdict with evidence; only send when confident (Adrian earlier asked >=95%). | Adrian 11:29Z, 11:32Z; workspace rules R3/T3226 | LOCKED | Adrian changes format |
| Decision D3 | Approved: one local compile-and-test loop for Legion on this Mac through the gate, repeated until green. No CI, no push, no release. Starts after Oracle clears and Class A is green. | Adrian 15:02Z "Approve the loop"; recorded in INTEGRATION.md | LOCKED | Scope would exceed local compile/test |
| Decision D4 | Cut code to fix-plan scope with shared plumbing; no duplicated readers. | Adrian 15:32Z "Yes, cut it down" | LOCKED | Adrian asks for more |
| Decision D5 | Sweep never kills or signals. It maps each long call to its owning chat and messages it over Pulse (at most one reminder per item per 2h, every 30 min); chats blocked inside their own hung call are reported to Adrian; broker leftovers and Dell items report only. Agents blocked from starting interactive `claude`/`codex` chats. | Adrian 16:28Z + "ok" 16:31Z | LOCKED | Adrian changes sweep behaviour |
| Decision D6 | No new chat without Adrian's express approval. | Workspace rules | LOCKED | Adrian approves a specific new chat |
| Decision D7 | Relayed words: read the sender's transcript and judge; never ask Adrian to repeat. | Adrian 11:36Z; rules T2559 | LOCKED | Adrian accepts closing without proof |
| Decision D8 | Memory: delete completely / auto memory off. | Adrian 12:08Z, 12:52Z | LOCKED | Adrian re-enables memory |
| Decision D9 | Medium effort on the lead for Opus 5.5. | Adrian 11:32Z | LOCKED | Adrian changes the effort setting |
| Decision D10 | Turn classifier: ScaleDown (50M free tokens) now, local later; test Laya and LFM 3; no Ollama; log-only for a day or two. | Adrian 11:43Z–12:52Z | ACTIVE_ASSUMPTION | Adrian picks a model |
| Decision D11 | New checks ship in shadow/log mode first (approvals, evidence). | Source chat design, Adrian did not object | ACTIVE_ASSUMPTION | After a day of logs |
| Decision D12 | No issue closed until its fix is proven. | Source chat 14:59Z, workspace evidence rules | LOCKED | Adrian accepts closing without proof |

## 5. Artifacts & Evidence

| Artifact | Path / URL | Role | State | Version / hash | Validation + last checked |
|---|---|---|---|---|---|
| Lead integration list | /Volumes/D/scratch/legion-impl/INTEGRATION.md | Wiring order, lane reports, approval record, handoff state | Current, lead-maintained | mtime 2026-11-02 22:03 IST | Read 2026-11-02 22:06 IST by this chat |
| Lane rules | /Volumes/D/scratch/legion-impl/LANE-RULES.md | Rules every writer lane follows | Current, lead-maintained | mtime 2026-11-02 19:37 IST | Read 2026-11-02 22:06 IST by this chat |
| Fix plan | /Volumes/D/scratch/failure-review/fix-plan.md | Design source for every check | Input, authoritative design | Not hashed; read on demand | Existence checked 2026-11-02 22:07 IST |
| Failure log | /Volumes/D/scratch/failure-review/every-failure.md, failure-log.md, summary.md, skills-analysis.md, tstack-pstack-mapping.md | 2-week failure review | Complete review output | 372 failures logged | Existence checked 2026-11-02 22:07 IST |
| EGM output | /Volumes/D/scratch/failure-review/egm/proposal-final.md, egm-findings.md | Reviewed proposal | Complete review output | Not hashed; read on demand | Existence checked 2026-11-02 22:07 IST |
| Class A logs | /Volumes/D/scratch/legion-impl/classa/ | Prior Class A runs (run3 108/108 at dc3bb993) | Stale for HEAD 71d3527f | run3 108/108 at dc3bb993 | Not rerun on HEAD as of 22:07 IST |
| Audit oversize issue | legion#139 | Audit fails on 35 MB CI log | Open, unfixed | Issue number 139 | Listed open via gh 2026-11-02 22:10 IST |
| Context JSON | /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-40ce-4ba3-a479-a06612fb46a7.context.json | Transcript evidence | Complete, receipt-bound | sha256 9d07ee624cd8a77d91b5e0dcb8d1a40c1f632898c19e2afa81a7470effb5d36a | RECEIPT_PASS 2026-11-02 22:03 IST |

## 6. Failures, Dead Ends & Attempts

| ID | Attempt / command | Exact symptom / result | Cause / diagnosis | Evidence | DO_NOT_RETRY_UNLESS | Replacement / next diagnostic |
|---|---|---|---|---|---|---|
| Failure F1 | Six parallel writer lanes, no size cap | ~18,000 code + 6,900 test lines, duplicated plumbing | No size limit or shared modules in briefs | Source chat 15:31Z | Briefs carry hard line caps and one writer per area | One writer per area with caps (done) |
| Failure F2 | `/legion:audit` on Legion | Refuses whole run: one CI log is 35 MB > 32 MB per-file limit | Audit reads every file before folder filter | legion#139 | legion#139 fixed and released | Skip audit on Legion until then |
| Failure F3 | Oracle review of uncut code | Stopped mid-run | Code was about to be cut | Source chat 15:31Z | The code under review changes again | One Oracle review on 0f5e9cee..HEAD after sweep |
| Failure F4 | Hook skill-first check as first written | Would lock agents out for up to an hour; hook never received Skill/Agent calls | Registration missed those tools | Fixed in d3286c70, ff3f070c | A compile or test shows the lockout again | Verify in compile/test |
| Failure F5 | Installed hook refused a command mentioning "cargo" | False positive in subagent no-build hook | Substring match | Source chat 16:11Z | The substring match is replaced | Fix that hook (open item) |

## 7. Learnings, Gotchas & Landmines

| Signal | Hidden trap / learning | Required safe behavior | Source |
|---|---|---|---|
| governor.rs dirty | Partial work from a stopped lane; may be incomplete | Review the diff, finish it, rustfmt, then commit locally | INTEGRATION.md "Sweep lane stopped" |
| Subagents | Subagents never run cargo/tests/builds/commits | Lead runs the gate; lanes only rustfmt and read | LANE-RULES.md |
| main.rs, protocol.rs | Lead-owned | Only the lead edits them | LANE-RULES.md |
| Gate builds committed snapshot | Uncommitted files are not in the build | Commit locally before gate | Source chat 15:03Z |
| Pushing Legion main | Triggers CI and Pages republish (#129) | No push without approval | Rules, #129 |
| Summary box commit ids | Once printed a wrong id (3b1e9a29 vs d3286c70) | Quote ids from git, not memory | Source chat 15:01Z |
| Deleted daily/*.rs files | check-retirements may fail | Run `legion-dev check-retirements` and add rows | INTEGRATION.md |
| New env reads | LEGION_HOOK_OFF, LEGION_STATE_DIR, LEGION_EVIDENCE_MODE, LEGION_MODEL_TIERS, LEGION_APPROVALS_MODE, LEGION_MAX_AGENTS must be in switches.json | Release scan fails otherwise | INTEGRATION.md CI lane |
| Codex hook events | Adrian must re-trust them after install | Put in install approval request | INTEGRATION.md |
| Two profiles | This chat runs on profile claude-b; source on main profile | Don't assume shared agent ids | ps this turn |

## 8. Open Loops & Context Gaps

| Gap / open loop | Severity | Impact | Recovery action | Safe subset | Owner |
|---|---|---|---|---|---|
| Sweep lane's exact brief text and any partial notes are only in the source transcript | MEDIUM | Sweep design detail beyond D5 may differ | Read the Agent tool_call text at 2026-11-02T16:28:16Z and the SendMessage at 16:29:03Z in the context JSON with jq | All work; design from D5 and fix-plan.md | Receiver |
| Pending decisions from 14:59Z: #129 Pages, #122 one-command install, #135 Adapt pilot, forks rule | MEDIUM | Not answered in transcript tail | Search context JSON userRequests 15:00–16:32Z; if unanswered, ask Adrian with the question tool later | All loop work | Receiver |
| Pulse plugin installer proposal (Pulse Claude B chat) vs rightkit#1442 | LOW | Coordination only | Leave to Pulse chat; mention when relevant | All Legion loop work; Pulse plugin delivery excluded | Receiver |
| Rules tool lock file differs per machine | LOW | Shows as modified on Dell | Fix in rules tool later | All Legion loop work; rules-tool lock file excluded | Receiver |
| Unassigned backlog (#117, #41, #118, Audit backlog, #133, #109, #111, #37, #43, Codex notes) | LOW | Future work | Schedule after loop is green | Resume Steps 1-3 only; backlog issues untouched | Receiver |
| Source chat confirmation 2026-11-02 (Pulse abddabab): no work in flight after cutoff; last Class A was run6 20:40 IST on 04a5cd5f, not rerun on 71d3527f; cargo deny PID 97720 not the source's | LOW | Confirms no orphaned writer | None needed; Class A reruns in Resume Step 3 | Full scope of Resume Steps 1-3 | Receiver |
| Further open items for Adrian: dev-server scope for web (#133 covers desktop/Tauri only); tell Pulse to build plugin bundling on rightkit#1442; switch evidence and approvals from shadow to enforce after a day of logs | LOW | Decisions pending, not blocking the loop | Raise with Adrian via question tool after loop | All Legion loop work | Receiver |
| Further pending: #127 switches.json (12 compiled out, 34 classified) or release scan fails; #133 qa manual.md and visual-qa-capture.md dev-server text; #109 doctrine/sage.md prior-art step; #139 blocks /legion:audit on Legion; Dell rules lock file fix in manage.py; install request must cover Codex hook re-trust and the Claude B profiles (~/ClaudeProfiles/claude-b-home, claude-b/claude-config); #111 handoff gaps still open | LOW | Release and install readiness | Handle before CI and release requests | Resume Steps 1-3 only | Receiver |
| Verify the cut kept Oracle fixes from ff3f070c: hooks.json routes Skill, Agent and scheduler tools; named-skill clears from transcript; Codex exempt from event skills; LEGION_STATE_ROOT; failed Agent frees cap slot | MEDIUM | Lockout or cap leak could return silently | Check in the Oracle review of 0f5e9cee..HEAD (Resume Step 3) | All work before the compile loop | Receiver |

## 9. Safety, Authority & Boundaries

- **May do:** Edit and commit locally on main; rustfmt; read-only commands; launch legion:alchemist/oracle lanes per rules; run Class A (preflight); run the approved local compile-and-test loop for Legion on this Mac through the gate once Oracle clears and Class A is green.
- **Do not change:** Other repos' files except via their owners; E drive; parent gitlinks.
- **Do not run:** CI, push to Legion main, release, install, publish, schedule creation, process kills, new chats, no-cache builds, worktrees/branches.
- **Irreversible / production actions:** Bring to Adrian with full Class A output and will-pass verdict.
- **Spend / external effects:** GitHub issue writes are allowed for filing/updating Legion issues (search existing first). No Pulse messages from the sweep until released.
- **Secrets handling:** Never print or inspect credentials.
- **Reserved decisions:** CI qualification push, release, install, #129, #122, #135, forks rule.

## 10. Exact Resume Sequence

### Resume Step 1 — Verify live state

- **Owner:** Receiver (Legion lead)
- **Working directory / system:** /Volumes/D/claude/legion
- **Exact action:**

```text
Run and verify: git -C /Volumes/D/claude/legion rev-parse HEAD; git -C /Volumes/D/claude/legion status --short; git -C /Volumes/D/claude/legion diff --stat
```
- **Expected result:** HEAD 71d3527f80c98f534384b2b9da35399830083c65; only governor.rs modified plus untracked tasks/
- **Evidence path:** /Volumes/D/claude/legion/.git (git output in this chat)
- **Timeout / retry:** 10 s, once
- **If failure:** If HEAD moved or new files changed, re-read git log and INTEGRATION.md before editing; another writer may be active.
- **Depends on:** No dependency; first step

### Resume Step 2 — Finish the sweep lane

- **Owner:** Receiver, or one legion:alchemist-specialist with a capped brief
- **Working directory / system:** /Volumes/D/claude/legion
- **Exact action:**

```text
Read the 16:28:16Z sweep brief and 16:29:03Z scope change from the context JSON; write engine/bins/legion/src/commands/sweep.rs (notify-only per D5, fail open, kill switch, tests beside it, hard size cap); register it in cli.rs and commands/mod.rs; review and keep the governor.rs new-chat block; rustfmt --edition 2021 on touched files; commit locally.
```
- **Expected result:** One local commit; no compile run
- **Evidence path:** /Volumes/D/claude/legion/engine/bins/legion/src/commands/sweep.rs and git log
- **Timeout / retry:** 1 writer, at most 1 revision, about 60 minutes
- **If failure:** Load legion:debugger; fix; do not compile
- **Depends on:** Resume Step 1 passing

### Resume Step 3 — Retirements, Class A, Oracle, then the loop

- **Owner:** Receiver
- **Working directory / system:** /Volumes/D/claude/legion
- **Exact action:**

```text
legion-dev check-retirements   (add rows to docs/provenance/retirements.md if needed; commit)
rightkit-host-gate check --repo /Volumes/D/claude/legion --commit HEAD
legion:oracle review of 0f5e9cee..HEAD against fix-plan.md and Adrian's words
rightkit-host-gate --route ; rightkit-host-gate --to compile ; rightkit-host-gate --to test   (approved loop, repeat until green)
```
- **Expected result:** Class A all pass; Oracle no blocking findings; compile and tests green
- **Evidence path:** /Volumes/D/scratch/legion-impl/classa/ and gate output
- **Timeout / retry:** 1 background wait per gate run, 0 polling; repeat until green with debugger after each red
- **If failure:** legion:debugger, root-cause fix, rerun Class A
- **Depends on:** Resume Step 2 committed

## 11. State Verification & Invalidation

- **Verification command:**

```text
Run and verify: git -C /Volumes/D/claude/legion rev-parse HEAD; git -C /Volumes/D/claude/legion status --short
```
- **Expected state:** 71d3527f80c98f534384b2b9da35399830083c65; ` M engine/bins/legion-hook/src/governor.rs`; `?? tasks/`
- **Invalidated by:** Any new commit, a change to governor.rs not made by this chat, or new Adrian instructions.
- **Refresh action:** Re-read git log, INTEGRATION.md, and Adrian's latest message.
- **Validator command:**

```text
legion script handoff/validate-handoff /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.md --write-receipt /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.receipt.json
```

- **Receiver receipt check:**

```text
legion script handoff/validate-handoff /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.md --verify-receipt /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.receipt.json
```

## 12. First Output & Readback Contract

```text
READBACK
MISSION: <exact>
CURRENT_STATE: <exact>
LOCKED_DECISIONS: <list>
SAFETY_BOUNDARIES: <list>
NEXT_ACTION: <exact>
CRITICAL_GAPS: <none | list>
ASSUMPTIONS: <none | list>
FIRST_VERIFICATION: <exact>
PACKET_RECEIPT: <verified sha256>
```

- **First deliverable after readback:** Finished sweep lane committed locally.
- **Gap report format:** `GAP: <severity> | <missing> | <impact> | <recovery> | <safe subset> | <owner>`

## 13. Ready-to-Paste First Message

```text
You are receiving a cold-start handoff with zero prior memory.
Treat only this packet plus its verified artifacts as context.
Verify packet receipt, return READBACK exactly as specified, correct any mismatch from packet, then follow Proceed mode.
Do not infer missing context, reopen LOCKED decisions, expose secrets, overwrite unrelated work, or execute reserved actions.
BEGIN HANDOFF PACKET AT: /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.md
RECEIPT AT: /Volumes/D/claude/legion/tasks/handoffs/2026-11-02/26440622-legion-lead.receipt.json
```

## 14. Context Gap Report

- **Gap summary:** 0 FATAL, 0 HIGH, 3 MEDIUM, 6 LOW
- **Safe-to-proceed scope:** Full scope of Resume Steps 1–3
- **Fatal recovery owner:** NOT_APPLICABLE: no fatal gap
- **Exact recovery sequence:** NOT_APPLICABLE: no fatal gap; MEDIUM gaps recover via jq reads of the context JSON

## 15. Handoff Author Gate

- [x] Original user intent + active goal are exact, not paraphrased away.
- [x] Source evidence mode is explicit; Legion context path + prefix receipt are bound.
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
- [x] `legion script handoff/validate-handoff` PASS receipt matches exact packet bytes.
