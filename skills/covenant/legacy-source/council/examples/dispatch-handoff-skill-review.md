# EXTERNAL REVIEW PACKET — Dispatch, Handoff & Council Packet Gates

## 0. Packet Control

- **Created:** 2026-07-28T14:26:23.2774016+05:30
- **Mode:** PACKET_ONLY — DO_NOT_RUN_COUNCIL
- **Audience:** MiniMax, Qwen, or another zero-context third-party reviewer
- **Packet path:** D:/workspace/tools/skills/council/examples/dispatch-handoff-skill-review.md
- **Requested response:** Diagnose bypasses & propose enforceable skill improvements

## 1. Problem in Plain Language

An orchestrator cleaned up an agent plan but treated it as readable prose, not executable system contract. A smaller agent could still guess, stop early, mark ordinary failures blocked, or validate temporary bytes with no permanent audit artifact. Separate dispatch & handoff skills now need hard gates which make those failures difficult to bypass. A third packet-only Council mode must prepare context for outside reviewers without running any review workflow.

## 2. User Intent

### Exact request

> Create a robust dispatch-authoring skill in D:\workspace that forces context-complete, end-to-end executable agent tasks with explicit evidence, recovery paths, escalation rules, handoffs, and enforceable validation gates. Also create an independent handoff skill for a cold chat with zero prior context. If I ask for /council packet, give me Markdown, or inline when specified, which explains full problem and intent for outside help without running the skill. Commit and push to main.

### Desired outcome

Three explicit, independent behaviors:

1. `/dispatch` writes permanent executable task packet + receipt before smaller executor starts; orchestrator observes, validates, & integrates.
2. `/handoff` writes permanent cold-start context transplant + receipt so new chat can resume without old history.
3. `/council packet` writes simple outside-review brief by default, or returns it inline only when explicitly requested, without invoking reviewers.

### Definition of success

Fresh executors can act end to end; expected failures have bounded recovery; TRUE_BLOCKER requires proof; packet paths bind to validated files; temporary/cache/review-run storage fails validation; handoff readback reconstructs correct mission/state/next action; packet-only Council mode cannot silently turn into panel execution.

## 3. What Went Wrong

| Failure | Exact symptom/evidence | Consequence |
|---|---|---|
| Readable replaced executable | “I used wrong completion criterion: plan reads clearly instead of fresh agent can execute every failure path without judgment.” | Missing commands, evidence, ownership, fallback, & blocker threshold survived review. |
| Context remained in author’s head | “I relied on context in my head instead of forcing every dependency into document.” | Zero-context executor had to infer intent/state. |
| Temporary-only dispatch artifact | “I used a temporary validation file.” | No canonical audit, replay, or integration source remained. |
| Dispatch/handoff conflation | Prior drafts treated delegation return & cold-chat transfer as similar packet concerns. | Orchestrator task assignment could become bloated, while cold chat still missed live state. |
| Council invocation ambiguity | `/council` previously stated every invocation runs full workflow. | Asking only for outside-review context could accidentally trigger reviewer execution. |

## 4. Current System & State

`D:/workspace/tools/skills/dispatch/` owns zero-context executable task authoring, standard-library validator, adversarial tests, template, evals, & permanent forward example. `D:/workspace/tools/skills/handoff/` independently owns cold-start state transfer, validator, tests, template, evals, & forward proof. `D:/workspace/tools/skills/council/` keeps full review workflow while adding isolated packet-only route, external-review template, validator, tests, evals, & this example.

Dispatch/handoff validators require absolute declared artifact paths matching files passed to validators, adjacent sidecar receipts, receipt hash/path verification, Markdown format, & rejection of Temp, `.cache`, `.council-runs`, scratch, or similar disposable storage.

## 5. Constraints & Invariants

- Dispatch & handoff remain independent skills with no runtime dependency.
- Dispatch uses `/script` for script-bearing work; orchestrator creates scripts when it has context/authority.
- Blocked is last-resort `TRUE_BLOCKER`, never ordinary terminal state.
- Preserve unrelated dirty work; no reset, worktree, or inferred branch isolation.
- `/council packet` never runs self-review, Council, Jury, subagents, CLIs, APIs, or review tools.
- Default Council packet output is durable Markdown; inline output requires explicit `inline`.
- Do not include secrets or assume outside agent can access local paths.

## 6. Existing Attempts & Inputs

| Attempt/input | Result | Keep, reject, or reconsider |
|---|---|---|
| Claude plan cleanup | Improved scope/sequence but removed load-bearing failure contract. | Reject readability as completion gate. |
| MiniMax dispatch/handoff drafts | Added failure lattice, readiness, readback, gap classification, exact state & recovery ideas. | Keep valuable structures; enforce mechanically. |
| Qwen handoff draft | Strong cold-start laws, decision/artifact/failure maps, safety boundaries, resume sequence. | Keep as handoff-specific structure. |
| Native Council advisory on dispatch | Found status, script-gate, row-validation, receipt, & forward-proof bypasses. | Accepted & implemented before final Jury. |
| Current validator suites | Dispatch, handoff, & Council packet adversarial tests pass locally. | Retain as regression gates. |

## 7. Evidence Bundle

```text
Observed failure chain:
- Plan was reviewed like document, not executable specification.
- Fresh-agent simulation was skipped.
- Completion meant “reads clearly,” not “every failure path executes without judgment.”
- Simplification removed failure-handling contract.
- Context stayed in author memory.
- Agent later reported: “I used a temporary validation file.”

Required invariant:
Every dispatch and handoff is authored as permanent named Markdown before validation.
Each retains adjacent receipt; inline copy is transport only.
Council packet is different: Markdown by default, inline only when explicitly requested, and never executes review.
```

## 8. Known Unknowns

- Whether third-party reviewers find remaining semantic bypasses in failure rows, cold-chat state reconstruction, or packet-only routing after current tests.
- Whether canonical packet storage should later add a centralized append-only index beyond tracked dated directories.

## 9. Questions for Reviewer

1. What is root cause?
2. What exact design or wording changes close it?
3. Which bypasses or failure paths remain?
4. What should be enforced mechanically rather than requested in prose?
5. Which recommendations are must-fix vs optional value additions?

## 10. Response Contract

Return:

1. concise diagnosis;
2. must-fix findings with evidence;
3. concrete proposed changes;
4. failure-path / bypass analysis;
5. optional value additions;
6. final verdict: `READY_TO_IMPLEMENT` or `REVISE_PACKET`.

Do not assume access to old chat, local filesystem, or unstated context.
