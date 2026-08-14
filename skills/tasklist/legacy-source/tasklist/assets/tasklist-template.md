# TASKLIST {{TASKLIST_ID}}

## 0. Control

- **Tasklist ID:** {{TASKLIST_ID}}
- **Created:** {{ISO_8601_TIMESTAMP}}
- **Purpose:** {{EXECUTE_HERE_OR_GOAL_RECORD}}
- **Owner:** {{CURRENT_AGENT_OR_USER}}
- **Canonical path:** {{ABSOLUTE_PERMANENT_TASKLIST_PATH}}
- **Status:** {{PLANNED_IN_PROGRESS_COMPLETE_OR_TRUE_BLOCKER}}
- **Tasklist revision:** TASKLIST_REVISION:{{POSITIVE_INTEGER}}
- **Goal ID:** {{GOAL_ID_OR_NOT_CREATED}}
- **Scope boundary:** IN:{{EXACT_IN_SCOPE}}; OUT:{{EXACT_OUT_OF_SCOPE}}
- **Authority:** {{LATEST_USER_INTENT_AND_SOURCE}}

## 1. Goal Contract

- **State A:** STATE_A:{{EXACT_VERIFIED_CURRENT_STATE}}
- **State B:** STATE_B:{{EXACT_VERIFIABLE_TARGET_STATE}}
- **Success proof:** PROOF_COMMAND:{{EXACT_COMMAND_OR_ACTION}}; EXPECTED:{{EXACT_PASS_STATE}}; EVIDENCE:{{ABSOLUTE_EVIDENCE_PATH}}
- **Non-goals:** {{EXPLICIT_NON_GOALS}}
- **Hard constraints:** AUTHORITY={{RULE}}; SAFETY={{RULE}}; SCOPE={{RULE}}; QUALITY={{RULE}}; COST={{RULE}}

## 2. GoalRoute Binding

- **Goal route artifact:** {{ABSOLUTE_GOAL_ROUTE_JSON}}
- **Goal route receipt:** {{ABSOLUTE_GOAL_ROUTE_RECEIPT}}
- **Goal route schema:** goal-route.v2
- **Selected route:** SELECTED_ROUTE:{{ROUTE_ID}}
- **Expected time to verified B:** EXPECTED_TIME_TO_VERIFIED_B_MS:{{INTEGER}}
- **Total minutes:** TOTAL_MINUTES:{{POSITIVE_INTEGER}}
- **Files touched:** FILES_TOUCHED:{{POSITIVE_INTEGER}}
- **Lines changed:** LINES_CHANGED:{{POSITIVE_INTEGER}}
- **Rate:** LINES_PER_MINUTE:{{POSITIVE_DECIMAL}}
- **Route revision:** ROUTE_REVISION:{{POSITIVE_INTEGER}}
- **Critical path:** CRITICAL_PATH:{{ORDERED_ROUTE_STEP_IDS}}
- **Parallel lanes:** PARALLEL_LANES_JSON:{{MINIFIED_JSON_ARRAY}}
- **Deleted work:** DELETED_WORK_JSON:{{MINIFIED_JSON_ARRAY}}
- **Deferred work:** DEFERRED_WORK_JSON:{{MINIFIED_JSON_ARRAY}}

## 3. Execution Tasks

### Task 1 — {{TASK_NAME}}

- **Task status:** {{TODO_IN_PROGRESS_DONE_OR_TRUE_BLOCKER}}
- **Route step:** ROUTE_STEP:{{ROUTE_ID_AND_STEP}}
- **Action:** ACTION:{{EXACT_OPERATION}}
- **Depends on:** {{START_OR_AFTER_ROUTE_STEP_IDS}}
- **Advances target:** ADVANCES_STATE_B:{{OBSERVABLE_TARGET_DELTA}}
- **Done check:** CHECK:{{EXACT_COMMAND_OR_ACTION}}
- **Expected result:** EXPECTED:{{SPECIFIC_PASS_STATE}}
- **Evidence path:** {{ABSOLUTE_PERMANENT_EVIDENCE_PATH}}
- **On failure:** TRY:{{PRIMARY_RECOVERY}}; FALLBACK:{{SAFE_CONTINUATION}}; RECOMPILE_IF:{{ROUTE_INVALIDATING_CONDITION}}
- **Time span:** minute {{START_OFFSET}}-{{END_OFFSET}} (elapsed clock from 0, not a duration)
- **Basis:** {{LABEL}}={{MINUTES}}, {{LABEL}}={{MINUTES}} (named activities summing to the span; no overhead/buffer/misc)
- **Parallelizable:** {{YES_OR_NO}}

## 4. Recovery & TRUE_BLOCKER

- **Retry contract:** {{ERROR_CLASSES_ATTEMPT_LIMIT_AND_BACKOFF}}
- **Alternative route policy:** RECOMPILE_GOAL_ROUTE_IF:{{CURRENT_ROUTE_CANNOT_REACH_B_OR_BETTER_ROUTE_BECOMES_VALID}}
- **TRUE_BLOCKER allowed only if:** RECOVERY_EXHAUSTED; INDEPENDENT_WORK_COMPLETE; NO_FEASIBLE_ROUTE; ONE_MISSING_EXTERNAL_INPUT
- **Blocked artifact path:** {{ABSOLUTE_PATH_OR_NOT_APPLICABLE_UNLESS_TRUE_BLOCKER}}
- **Blocked artifact fields:** SYMPTOM; ATTEMPTS; MISSING_INPUT; UNBLOCK_CHANGE; RESUME_ACTION; OWNER

## 5. Progress & Change Control

- **Boundary update rule:** BEFORE=IN_PROGRESS; PASS=DONE_WITH_EVIDENCE; RECOVERABLE_FAILURE=IN_PROGRESS_WITH_ATTEMPT
- **Receipt update rule:** REWRITE_RECEIPT_AFTER_EVERY_DURABLE_TASKLIST_CHANGE
- **Semantic correction:** STOP -> PRESERVE_EVIDENCE -> RECOMPILE_ROUTE_FROM_ROOT -> REBUILD_TASKS -> NEW_RECEIPTS
- **Resume rule:** VERIFY_TASKLIST_RECEIPT -> VERIFY_ROUTE_RECEIPT -> CONFIRM_FIRST_NON_DONE_TASK -> CONTINUE

## 6. Completion Contract

- **Final verification:** {{EXACT_STATE_B_PROOF_COMMAND_OR_ACTION}}
- **Final expected result:** {{EXACT_PASS_STATE}}
- **Final evidence path:** {{ABSOLUTE_PERMANENT_EVIDENCE_PATH}}
- **Completion rule:** ALL_TASKS_DONE_AND_FINAL_PROOF_PASS_BEFORE_STATUS_COMPLETE
- **Terminal record:** STATUS={{PLANNED_IN_PROGRESS_COMPLETE_OR_TRUE_BLOCKER}}; DONE={{DONE_COUNT}}/{{TOTAL_COUNT}}; NEXT={{FIRST_NON_DONE_TASK_OR_NONE}}
