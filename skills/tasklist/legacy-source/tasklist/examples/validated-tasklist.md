# TASKLIST tasklist-validator-example

## 0. Control

- **Tasklist ID:** tasklist-validator-example
- **Created:** 2026-07-28T21:00:00+05:30
- **Purpose:** GOAL_RECORD
- **Owner:** current Codex agent
- **Canonical path:** D:/Claude/tools/skills/tasklist/examples/validated-tasklist.md
- **Status:** PLANNED
- **Tasklist revision:** TASKLIST_REVISION:1
- **Goal ID:** NOT_CREATED
- **Scope boundary:** IN:validate route, task structure, and receipts; OUT:delegation, handoff, production mutation, and paid calls
- **Authority:** latest user request for simple /tasklist skill

## 1. Goal Contract

- **State A:** STATE_A:No durable route-verified tasklist exists for current validation goal.
- **State B:** STATE_B:Permanent tasklist example passes route, structure, and receipt verification.
- **Success proof:** PROOF_COMMAND:py -3.11 D:/Claude/tools/skills/tasklist/scripts/test_validate_tasklist.py; EXPECTED:Exit 0 and output begins PASS: tasklist validator.; EVIDENCE:D:/Claude/.audit/tasklist-example/test-output.txt
- **Non-goals:** dispatch to another agent, cold-chat handoff, architecture design, production mutation, or personal todo management
- **Hard constraints:** AUTHORITY=current user request; SAFETY=local owned artifacts only; SCOPE=tasklist contract; QUALITY=adversarial tests and receipt replay; COST=zero paid calls

## 2. GoalRoute Binding

- **Goal route artifact:** D:/Claude/tools/skills/tasklist/examples/validated-tasklist.route.json
- **Goal route receipt:** D:/Claude/tools/skills/tasklist/examples/validated-tasklist.route.receipt.json
- **Goal route schema:** goal-route.v2
- **Selected route:** SELECTED_ROUTE:R_RELIABLE
- **Expected time to verified B:** EXPECTED_TIME_TO_VERIFIED_B_MS:624000
- **Route revision:** ROUTE_REVISION:1
- **Critical path:** CRITICAL_PATH:R_RELIABLE/S1>R_RELIABLE/S2>R_RELIABLE/S3
- **Parallel lanes:** PARALLEL_LANES_JSON:[]
- **Deleted work:** DELETED_WORK_JSON:[{"item":"Unvalidated one-step shortcut","reason":"Expected rework makes it slower to verified B."}]
- **Deferred work:** DEFERRED_WORK_JSON:[]

## 3. Execution Tasks

### Task 1 — Validate route authority

- **Task status:** TODO
- **Route step:** ROUTE_STEP:R_RELIABLE/S1
- **Action:** ACTION:Validate GoalRoute artifact and exact-byte receipt.
- **Depends on:** START
- **Advances target:** ADVANCES_STATE_B:Route authority and expected-success winner are proven.
- **Done check:** CHECK:py -3.11 D:/Claude/tools/lib/goalroute/scripts/validate-route.py D:/Claude/tools/skills/tasklist/examples/validated-tasklist.route.json --verify-receipt D:/Claude/tools/skills/tasklist/examples/validated-tasklist.route.receipt.json
- **Expected result:** EXPECTED:exit 0 and RECEIPT_PASS output
- **Evidence path:** D:/Claude/.audit/tasklist-example/route-check.txt
- **On failure:** TRY:regenerate receipt from unchanged valid route; FALLBACK:preserve route errors and continue template-only checks; RECOMPILE_IF:route bytes, target, constraints, or winner changed

### Task 2 — Validate task DAG

- **Task status:** TODO
- **Route step:** ROUTE_STEP:R_RELIABLE/S2
- **Action:** ACTION:Validate tasklist structure against selected route DAG.
- **Depends on:** AFTER:R_RELIABLE/S1
- **Advances target:** ADVANCES_STATE_B:Every selected route step has one executable evidence-bearing task.
- **Done check:** CHECK:py -3.11 D:/Claude/tools/skills/tasklist/scripts/validate-tasklist.py D:/Claude/tools/skills/tasklist/examples/validated-tasklist.md --write-receipt D:/Claude/tools/skills/tasklist/examples/validated-tasklist.receipt.json
- **Expected result:** EXPECTED:exit 0 and PASS output
- **Evidence path:** D:/Claude/.audit/tasklist-example/structure-check.txt
- **On failure:** TRY:repair exact reported structural defect; FALLBACK:run py_compile and template self-check independently; RECOMPILE_IF:selected route step set or dependency DAG changed

### Task 3 — Verify tasklist receipt

- **Task status:** TODO
- **Route step:** ROUTE_STEP:R_RELIABLE/S3
- **Action:** ACTION:Verify exact tasklist receipt and record final acceptance.
- **Depends on:** AFTER:R_RELIABLE/S2
- **Advances target:** ADVANCES_STATE_B:Permanent tasklist and receipt reach verified target state.
- **Done check:** CHECK:py -3.11 D:/Claude/tools/skills/tasklist/scripts/validate-tasklist.py D:/Claude/tools/skills/tasklist/examples/validated-tasklist.md --verify-receipt D:/Claude/tools/skills/tasklist/examples/validated-tasklist.receipt.json
- **Expected result:** EXPECTED:exit 0 and RECEIPT_PASS output
- **Evidence path:** D:/Claude/.audit/tasklist-example/receipt-check.txt
- **On failure:** TRY:compare tasklist SHA-256 against receipt and regenerate after valid change; FALLBACK:preserve both files plus raw mismatch; RECOMPILE_IF:tasklist goal, route binding, or task DAG changed

## 4. Recovery & TRUE_BLOCKER

- **Retry contract:** deterministic validation defects get zero blind retries; transient file-read errors get one retry after path check
- **Alternative route policy:** RECOMPILE_GOAL_ROUTE_IF:current selected route cannot reach verified B or lower-expected valid route becomes available
- **TRUE_BLOCKER allowed only if:** RECOVERY_EXHAUSTED; INDEPENDENT_WORK_COMPLETE; NO_FEASIBLE_ROUTE; ONE_MISSING_EXTERNAL_INPUT
- **Blocked artifact path:** NOT_APPLICABLE_UNLESS_TRUE_BLOCKER
- **Blocked artifact fields:** SYMPTOM; ATTEMPTS; MISSING_INPUT; UNBLOCK_CHANGE; RESUME_ACTION; OWNER

## 5. Progress & Change Control

- **Boundary update rule:** BEFORE=IN_PROGRESS; PASS=DONE_WITH_EVIDENCE; RECOVERABLE_FAILURE=IN_PROGRESS_WITH_ATTEMPT
- **Receipt update rule:** REWRITE_RECEIPT_AFTER_EVERY_DURABLE_TASKLIST_CHANGE
- **Semantic correction:** STOP -> PRESERVE_EVIDENCE -> RECOMPILE_ROUTE_FROM_ROOT -> REBUILD_TASKS -> NEW_RECEIPTS
- **Resume rule:** VERIFY_TASKLIST_RECEIPT -> VERIFY_ROUTE_RECEIPT -> CONFIRM_FIRST_NON_DONE_TASK -> CONTINUE

## 6. Completion Contract

- **Final verification:** py -3.11 D:/Claude/tools/skills/tasklist/scripts/test_validate_tasklist.py
- **Final expected result:** exit 0 and PASS: tasklist validator output
- **Final evidence path:** D:/Claude/.audit/tasklist-example/test-output.txt
- **Completion rule:** ALL_TASKS_DONE_AND_FINAL_PROOF_PASS_BEFORE_STATUS_COMPLETE
- **Terminal record:** STATUS=PLANNED; DONE=0/3; NEXT=R_RELIABLE/S1
