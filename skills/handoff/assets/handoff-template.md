# COLD-START HANDOFF: {{HANDOFF_TITLE}}

## 0. Handoff Control

- **Handoff ID:** {{HANDOFF_ID}}
- **Created:** {{ISO_TIMESTAMP_WITH_TIMEZONE}}
- **Source task / chat:** {{SOURCE_THREAD_ID_AND_TITLE}}
- **Target:** {{COLD_CHAT_OR_RECEIVER}}
- **Author:** {{HANDOFF_AUTHOR}}
- **Receiver role:** {{CONTINUATION_DEBUG_EXECUTION_REVIEW_OR_DECISION}}
- **Proceed mode:** {{IMMEDIATE_OR_READBACK_ONLY_OR_REVIEW_ONLY_OR_DECISION}}
- **Readiness:** {{READY_OR_READY_WITH_GAPS_OR_NOT_READY}}
- **Handoff reason:** {{WHY_CONTEXT_TRANSFER_IS_HAPPENING}}
- **Source evidence mode:** {{TRANSCRIPT_INGEST_OR_LIVE_CONTEXT}}
- **Transcript evidence path:** {{ABSOLUTE_COMPILED_EVIDENCE_PATH_OR_NOT_APPLICABLE_REASON}}
- **Source prefix receipt:** {{PLATFORM_SESSION_ID_CUTOFF_SHA256_PARSER_VERSION_OR_NOT_APPLICABLE_REASON}}
- **Packet path:** {{ABSOLUTE_HANDOFF_PATH}}
- **Receipt path:** {{ABSOLUTE_RECEIPT_PATH}}

## 1. Intent & Mission

- **Original user intent verbatim:** {{EXACT_USER_WORDS}}
- **Underlying goal:** {{DURABLE_END_STATE}}
- **Current objective:** {{ACTIVE_OBJECTIVE}}
- **Definition of success:** {{OBSERVABLE_ACCEPTANCE}}
- **Out of scope:** {{EXACT_EXCLUSIONS}}
- **First responsibility:** {{WHAT_RECEIVER_DOES_FIRST}}
- **Must not do first:** {{EXACT_PROHIBITION}}

## 2. Current State

- **Phase:** {{CURRENT_PHASE}}
- **Completed:** {{VERIFIED_COMPLETE_WORK}}
- **In progress:** {{ACTIVE_INCOMPLETE_WORK}}
- **Blocked:** {{TRUE_BLOCKERS_OR_NONE_WITH_EVIDENCE}}
- **Not started:** {{REQUIRED_UNSTARTED_WORK}}
- **Last action:** {{EXACT_COMMAND_OR_OPERATION}}
- **Last observed result:** {{EXIT_RESULT_COUNTS_AND_EVIDENCE}}
- **Active goal / plan:** {{GOAL_AND_NEXT_PLAN_ITEM}}
- **Current hypothesis:** {{ACTIVE_DIAGNOSIS_OR_NOT_APPLICABLE_REASON}}

## 3. Environment & Active Work

- **Work type:** {{CODE_DOCUMENT_RESEARCH_OPERATIONS_OR_MIXED}}
- **Workspace / repo:** {{ABSOLUTE_PATH_OR_SYSTEM}}
- **Branch / version:** {{CURRENT_BRANCH_VERSION_OR_NOT_APPLICABLE_REASON}}
- **Baseline revision:** {{COMMIT_SHA_DOCUMENT_VERSION_OR_TIMESTAMP}}
- **Dirty state:** {{EXACT_STATUS_COMMAND_AND_OUTPUT}}
- **OS / shell:** {{OS_SHELL_AND_VERSIONS}}
- **Tools / dependencies:** {{NAMES_VERSIONS_AND_DISCOVERY_COMMANDS}}
- **Services / processes:** {{ACTIVE_PIDS_PORTS_OR_NONE_CHECKED}}
- **Agents / tasks / threads:** {{ACTIVE_IDS_AND_SCOPES_OR_NONE_CHECKED}}
- **Scheduled work:** {{AUTOMATIONS_CRON_JOBS_OR_NONE_CHECKED}}
- **Credentials / access:** {{NAMES_STORES_PRESENCE_SCOPES_NO_VALUES}}

## 4. Decisions, Invariants & User Corrections

| ID | Decision / invariant / correction | Source / why | Status | Reopen only when |
|---|---|---|---|---|
| {{DECISION_ID}} | {{EXACT_DECISION}} | {{EVIDENCE_AND_RATIONALE}} | {{LOCKED_ACTIVE_ASSUMPTION_OR_REVISIT_ON}} | {{EXACT_CONDITION}} |

## 5. Artifacts & Evidence

| Artifact | Path / URL | Role | State | Version / hash | Validation + last checked |
|---|---|---|---|---|---|
| {{ARTIFACT_NAME}} | {{EXACT_LOCATION}} | {{WHY_IT_MATTERS}} | {{COMPLETE_DRAFT_FAILED_OR_INPUT}} | {{SHA_VERSION_COUNT_OR_NOT_APPLICABLE_REASON}} | {{EXACT_CHECK_RESULT_AND_TIMESTAMP}} |

## 6. Failures, Dead Ends & Attempts

| ID | Attempt / command | Exact symptom / result | Cause / diagnosis | Evidence | DO_NOT_RETRY_UNLESS | Replacement / next diagnostic |
|---|---|---|---|---|---|---|
| {{ATTEMPT_ID_OR_NONE_CHECKED}} | {{EXACT_ATTEMPT}} | {{RAW_ERROR_OR_RESULT}} | {{CAUSE_OR_UNKNOWN_WITH_RECOVERY}} | {{EXACT_EVIDENCE_PATH}} | {{CONDITION_FOR_RETRY}} | {{EXACT_NEXT_ACTION}} |

## 7. Learnings, Gotchas & Landmines

| Signal | Hidden trap / learning | Required safe behavior | Source |
|---|---|---|---|
| {{SIGNAL}} | {{LOAD_BEARING_DETAIL}} | {{EXACT_BEHAVIOR}} | {{RULE_FILE_USER_CORRECTION_TEST_OR_EVIDENCE}} |

## 8. Open Loops & Context Gaps

| Gap / open loop | Severity | Impact | Recovery action | Safe subset | Owner |
|---|---|---|---|---|---|
| {{GAP_OR_NONE_CHECKED}} | {{FATAL_HIGH_MEDIUM_LOW_OR_NONE}} | {{EXACT_IMPACT}} | {{EXACT_RECOVERY}} | {{EXACT_SAFE_SUBSET_OR_NONE}} | {{OWNER}} |

## 9. Safety, Authority & Boundaries

- **May do:** {{AUTHORIZED_ACTIONS}}
- **Do not change:** {{PATHS_SYSTEMS_DECISIONS}}
- **Do not run:** {{COMMANDS_OPERATIONS}}
- **Irreversible / production actions:** {{BOUNDARY_AND_EXISTING_AUTHORITY}}
- **Spend / external effects:** {{COST_NETWORK_MESSAGES_PUBLICATION}}
- **Secrets handling:** {{NAME_ONLY_STORAGE_AND_NO_LOG_RULE}}
- **Reserved decisions:** {{USER_RESERVED_CHOICES_OR_NONE}}

## 10. Exact Resume Sequence

### Resume Step 1 — {{STEP_NAME}}

- **Owner:** {{OWNER}}
- **Working directory / system:** {{ABSOLUTE_PATH_OR_SYSTEM}}
- **Exact action:**

```text
{{EXACT_COMMAND_OR_TOOL_OPERATION}}
```
- **Expected result:** {{OBSERVABLE_RESULT}}
- **Evidence path:** {{EXACT_PATH}}
- **Timeout / retry:** {{NUMERIC_BOUND}}
- **If failure:** {{EXACT_BRANCH_AND_ESCALATION}}
- **Depends on:** {{DEPENDENCY_OR_NONE}}

### Resume Step 2 — {{STEP_NAME}}

- **Owner:** {{OWNER}}
- **Working directory / system:** {{ABSOLUTE_PATH_OR_SYSTEM}}
- **Exact action:**

```text
{{EXACT_COMMAND_OR_TOOL_OPERATION}}
```
- **Expected result:** {{OBSERVABLE_RESULT}}
- **Evidence path:** {{EXACT_PATH}}
- **Timeout / retry:** {{NUMERIC_BOUND}}
- **If failure:** {{EXACT_BRANCH_AND_ESCALATION}}
- **Depends on:** {{DEPENDENCY_OR_NONE}}

### Resume Step 3 — {{STEP_NAME}}

- **Owner:** {{OWNER}}
- **Working directory / system:** {{ABSOLUTE_PATH_OR_SYSTEM}}
- **Exact action:**

```text
{{EXACT_COMMAND_OR_TOOL_OPERATION}}
```
- **Expected result:** {{OBSERVABLE_RESULT}}
- **Evidence path:** {{EXACT_PATH}}
- **Timeout / retry:** {{NUMERIC_BOUND}}
- **If failure:** {{EXACT_BRANCH_AND_ESCALATION}}
- **Depends on:** {{DEPENDENCY_OR_NONE}}

## 11. State Verification & Invalidation

- **Verification command:**

```text
{{EXACT_STATE_VERIFICATION_COMMAND_OR_TOOL_OPERATION}}
```
- **Expected state:** {{EXACT_OUTPUT_HASH_COUNT_STATUS_OR_VERSION}}
- **Invalidated by:** {{STATE_CHANGES_REQUIRING_REFRESH}}
- **Refresh action:** {{EXACT_COMMAND_OR_SOURCE_RELOAD}}
- **Validator command:**

```text
{{EXACT_VALIDATE_AND_WRITE_RECEIPT_COMMAND}}
```

- **Receiver receipt check:**

```text
{{EXACT_VERIFY_RECEIPT_COMMAND}}
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

- **First deliverable after readback:** {{EXACT_OUTPUT}}
- **Gap report format:** `GAP: <severity> | <missing> | <impact> | <recovery> | <safe subset> | <owner>`

## 13. Ready-to-Paste First Message

```text
You are receiving a cold-start handoff with zero prior memory.
Treat only this packet plus its verified artifacts as context.
Verify packet receipt, return READBACK exactly as specified, correct any mismatch from packet, then follow Proceed mode.
Do not infer missing context, reopen LOCKED decisions, expose secrets, overwrite unrelated work, or execute reserved actions.
BEGIN HANDOFF PACKET AT: {{ABSOLUTE_HANDOFF_PATH}}
RECEIPT AT: {{ABSOLUTE_RECEIPT_PATH}}
```

## 14. Context Gap Report

- **Gap summary:** {{NONE_OR_COUNT_BY_SEVERITY}}
- **Safe-to-proceed scope:** {{FULL_SCOPE_OR_EXACT_SUBSET}}
- **Fatal recovery owner:** {{OWNER_OR_NOT_APPLICABLE_REASON}}
- **Exact recovery sequence:** {{ACTIONS_OR_NOT_APPLICABLE_REASON}}

## 15. Handoff Author Gate

- [ ] Original user intent + active goal are exact, not paraphrased away.
- [ ] Source evidence mode is explicit; Membrane context path + prefix receipt are bound.
- [ ] Live state was re-read from workspace/tools this turn.
- [ ] Completed/in-progress/blocked/not-started states are separated.
- [ ] Branch/version/dirty state or non-code equivalent is exact.
- [ ] Active agents/processes/scheduled work were inventoried.
- [ ] Decisions include rationale + reopen conditions.
- [ ] Artifacts include locations + validation freshness.
- [ ] Failures include raw evidence + DO_NOT_RETRY_UNLESS.
- [ ] User corrections, learnings, gotchas, naming locks, & do-not-touch zones are captured.
- [ ] No secret values appear.
- [ ] Every gap has severity, impact, recovery, safe subset, & owner.
- [ ] Readiness matches gap severities.
- [ ] Resume Step 1 is immediately executable.
- [ ] State verification + invalidation rules are exact.
- [ ] Readback detects mission/state/boundary/next-action mismatch.
- [ ] Cold-chat simulation passed with no unseen-context dependency.
- [ ] `validate-handoff.py` PASS receipt matches exact packet bytes.
