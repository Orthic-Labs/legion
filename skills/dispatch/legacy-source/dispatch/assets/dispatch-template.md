# DISPATCH: {{TASK_TITLE}}

## 0. Dispatch Control

- **Dispatch ID:** {{DISPATCH_ID}}
- **Requester:** {{REQUESTER}}
- **Dispatcher:** {{DISPATCH_AUTHOR}}
- **Executor:** {{EXECUTOR_OR_ROLE}}
- **Verifier:** {{VERIFICATION_OWNER}}
- **Receiver:** {{FINAL_HANDOFF_OWNER}}
- **Mode:** {{READ_ONLY_OR_IMPLEMENT_OR_OPERATE_OR_REVIEW}}
- **Execution host / OS:** {{MACHINE_OS_AND_VERSION}}
- **Shell:** {{SHELL_AND_VERSION}}
- **Working directory:** `{{ABSOLUTE_WORKING_DIRECTORY}}`
- **Repository / branch:** {{REPOSITORY_AND_CURRENT_BRANCH_OR_NOT_APPLICABLE}}
- **Baseline revision:** {{COMMIT_SHA_VERSION_OR_TIMESTAMP}}
- **Scoped Git status:** {{EXACT_STATUS_COMMAND_AND_OUTPUT_OR_NOT_APPLICABLE_REASON}}
- **User authorization:** {{EXACT_REQUESTED_AUTHORITY_AND_RESERVED_DECISIONS}}
- **Dependency position:** {{UPSTREAM_INPUTS_AND_DOWNSTREAM_CONSUMER}}
- **Parallel safety:** {{SERIAL_OR_PARALLEL_WITH_EXACT_NON_OVERLAP}}
- **Integration owner:** {{OWNER_WHO_REVIEWS_AND_INTEGRATES}}

| Active dispatch ID | OWN paths | Status | Overlap decision |
|---|---|---|---|
| {{OTHER_DISPATCH_OR_NONE}} | {{EXACT_PATHS_OR_NONE}} | {{ACTIVE_OR_NONE}} | {{NO_OVERLAP_OR_SERIALIZED_WITH_ORDER}} |

## 1. Mission

- **Outcome:** {{ONE_OBSERVABLE_END_STATE}}
- **Definition of done:** {{ALL_REQUIRED_ACCEPTANCE_RESULTS}}
- **Non-goals:** {{EXPLICIT_EXCLUSIONS}}

## 1A. Decision & Experiment Question Lock

- **Task semantics:** {{ROUTINE_EXPERIMENT_BENCHMARK_PERFORMANCE_MODEL_RESEARCH_OR_REPEATED_FAILURE}}
- **Primary decision questions:** {{QUESTION_LOCK_NUMBERED_MINIMUM_QUESTIONS}}
- **Decision rule:** {{DECIDE_BY_EXACT_METRICS_AND_THRESHOLDS}}
- **Acceptance metrics only:** {{METRICS_ONLY_DIRECTLY_NEEDED_FOR_DECISION}}
- **Diagnostics only:** {{DIAGNOSTICS_NEVER_ALLOWED_TO_GATE_COMPLETION}}
- **Explicit forbidden scope:** {{FORBIDDEN_METRICS_LABELS_MODELS_TOOLS_AND_ANALYSES}}
- **Workload / fixture roles:** {{WORKLOAD_ROLE_PER_INPUT_WITHOUT_INVENTED_SEMANTICS}}
- **Ground-truth policy:** {{GROUND_TRUTH_SOURCE_AND_MEASURED_OUTPUT_NOT_PRIOR_LABEL}}
- **Model / tool relevance rule:** {{LOAD_ONLY_IF_IT_PRODUCES_NAMED_ACCEPTANCE_METRIC}}
- **Locked model / runtime route:** {{ROUTE_LOCK_OR_NO_MODEL_ALLOWED}}
- **Recovery scope rule:** {{RECOVERY_RESTORES_REQUIRED_INPUT_BUT_CANNOT_EXPAND_EXPERIMENT}}
- **Forge gate:** {{REQUIRED_RUN_ID_OR_NOT_REQUIRED_WITH_EXACT_REASON}}
- **Forge state reference:** {{FORGE_STATE_REF_OR_NOT_REQUIRED}}
- **Forge verification:** {{VERIFIED_NO_CRITICAL_OPEN_OR_NOT_REQUIRED}}
- **First-action readback:** {{QUESTIONS_METRICS_DIAGNOSTICS_FORBIDDEN_FIRST_ACTION}}
- **Supervision cadence:** {{NUMERIC_TIME_OR_UNIT_CADENCE_PLUS_CHECKPOINTS}}

### Requirement-to-decision trace

| Requirement | Class | Traces to question / metric / safety / execution dependency | Stage owner | Needed for decision? | Remove or reject when unmapped |
|---|---|---|---|---|---|
| `PRODUCER_IDENTITY` | `ACCEPTANCE` | {{PRODUCER_QUESTION_OR_EXECUTION_DEPENDENCY}} | `{{STAGE_ID}}` | YES — {{PRODUCER_DECISION_EFFECT}} | {{REJECT_IF_UNMAPPED_ACTION}} |
| `LIFECYCLE_CHAIN` | `ACCEPTANCE` | {{LIFECYCLE_QUESTION_OR_EXECUTION_DEPENDENCY}} | `{{STAGE_ID}}` | YES — {{LIFECYCLE_DECISION_EFFECT}} | {{REJECT_IF_UNMAPPED_ACTION}} |
| `NO_SUBSTITUTION` | `ACCEPTANCE` | {{DERIVATION_QUESTION_OR_EXECUTION_DEPENDENCY}} | `{{STAGE_ID}}` | YES — {{DERIVATION_DECISION_EFFECT}} | {{REJECT_IF_UNMAPPED_ACTION}} |
| `{{REQUIREMENT_ID}}` | `{{ACCEPTANCE_DIAGNOSTIC_EXECUTION_INPUT_SAFETY_OR_FORBIDDEN}}` | {{EXACT_QUESTION_AND_METRIC}} | `{{STAGE_ID_OR_NONE}}` | {{YES_OR_NO_WITH_DECISION_EFFECT}} | {{REJECT_IF_UNMAPPED_ACTION}} |
| `DIAGNOSTIC_ONLY` | `DIAGNOSTIC` | {{QUESTION_IT_EXPLAINS_WITHOUT_GATING}} | `{{STAGE_ID_OR_NONE}}` | NO — cannot gate completion | {{KEEP_DIAGNOSTIC_OR_DROP_IF_COSTLY}} |
| `EXECUTION_INPUT` | `EXECUTION_INPUT` | {{WHY_NECESSARY_TO_RUN_ACCEPTANCE_MEASUREMENT}} | `{{STAGE_ID}}` | YES — execution only, not ground truth | {{REJECT_INVENTED_INPUT_ACTION}} |
| `FORBIDDEN_SCOPE` | `FORBIDDEN` | {{USER_NON_GOAL_OR_NO_DECISION_VALUE}} | `NONE` | NO — outside user decision | {{STOP_AND_REMOVE_ACTION}} |

### Model, tool & dependency relevance

| Model / tool / dependency | Acceptance metric produced | Locked route / version | Cost / resource effect | Decision | Evidence |
|---|---|---|---|---|---|
| {{MODEL_TOOL_OR_NONE}} | {{EXACT_METRIC_OR_NONE}} | {{EXACT_ROUTE_VERSION_OR_FORBIDDEN}} | {{TIME_VRAM_MEMORY_NETWORK_COST_OR_NONE}} | {{ALLOW_OR_FORBID_WITH_REASON}} | `{{RELEVANCE_EVIDENCE_PATH}}` |

## 1B. Authority, Correction & Global Re-Derivation

- **Authority order:** {{EXACT_LATEST_USER_INTENT_TO_PROGRESS_ORDER}}
- **Correction state:** {{NONE_OR_SEMANTIC_CORRECTION_ID_AND_SOURCE}}
- **Correction audit:** {{INVENTORY_SOURCE_SEMANTIC_DELTA_AND_EVIDENCE_PATH}}
- **Plan invalidation:** {{NOT_APPLICABLE_OR_PLAN_INVALIDATED_ROOT_DOWNSTREAM_STOP_LOCAL_PATCH_FORBIDDEN}}
- **Re-derivation status:** {{FROM_ZERO_OBJECTIVE_REQUIREMENTS_STAGES_COMMANDS_COMPLETE}}
- **Progress disposition:** {{PRESERVE_EVIDENCE_ONLY_REUSE_PROOF_STALE_PROGRESS_REJECT}}
- **Inherited inventory reconciliation:** {{INVENTORY_TOTAL_CLASSIFIED_TOTAL_UNCLASSIFIED_ZERO_AND_EVIDENCE_PATH}}
- **Forge typed-stage binding:** {{SCHEMA_RUN_ID_STATE_REF_AND_TYPED_STAGE_CHECKPOINT}}

### Inherited instruction disposition

| Inherited clause ID | Exact inherited text / source | Source rank | Objective compatibility | Stage owner | Disposition + reason/effect |
|---|---|---|---|---|---|
| `{{INHERITED_CLAUSE_ID}}` | {{EXACT_TEXT_AND_SOURCE}} | `{{LATEST_USER_INTENT_DECISION_OBJECTIVE_STAGE_CONTRACT_INHERITED_DOCUMENT_OR_EXISTING_PROGRESS}}` | `{{ALIGNED_CONFLICTS_OR_NO_DECISION_VALUE}}` | `{{STAGE_ID_OR_NONE}}` | {{KEEP_DELETE_OR_REWRITE_WITH_REQUIRED_REASON}} |

## 1C. Goal Route & Critical Path

- **State A:** {{EXACT_VERIFIED_CURRENT_STATE_A}}
- **State B:** {{EXACT_VERIFIABLE_TARGET_STATE_B}}
- **Goal success proof:** {{EXACT_COMMAND_OR_CHECK_PROVING_B}}
- **Hard route constraints:** {{AUTHORITY_SAFETY_COST_TIME_QUALITY_AND_SCOPE_CONSTRAINTS}}
- **Route mode:** {{COMPARE_OR_SINGLE_FEASIBLE}}
- **Goal route artifact:** {{CHECKOUT_RELATIVE_GOAL_ROUTE_V2_JSON_PATH}}
- **Goal route receipt:** {{CHECKOUT_RELATIVE_GOAL_ROUTE_RECEIPT_PATH}}
- **Goal route schema:** goal-route.v2
- **Selected route:** {{SELECTED_ROUTE_ID}}
- **Expected time to verified B:** EXPECTED_TIME_TO_VERIFIED_B_MS:{{EXPECTED_TIME_TO_VERIFIED_B_MS_INTEGER}}
- **Route revision:** ROUTE_REVISION:{{POSITIVE_ROUTE_REVISION}}
- **Why fastest valid:** {{EXPECTED_TIME_DOMINANCE_PROOF_AGAINST_EVERY_OTHER_ROUTE}}
- **Critical path:** {{ORDERED_ROUTE_STEP_IDS_AND_TOTAL_MIN_WALL_MS}}
- **Bottleneck:** {{BOTTLENECK_STEP_RESOURCE_AND_BOUND}}
- **Parallel lanes:** {{PARALLEL_GROUPS_OR_NONE_WITH_DEPENDENCY_PROOF}}
- **Deleted / deferred work:** {{DELETE_NON_ADVANCING_AND_DEFER_DOWNSTREAM_ITEMS}}
- **Route Forge binding:** {{ROUTE_SCHEMA_RUN_STATE_CHECKPOINT_OR_NOT_REQUIRED_REASON}}

| Route ID | Ordered route steps | Dependencies | Constraint result | Min wall ms | Expected verified-B ms | Cost units | Risk units | Rework units | Status | Rejection / dominance evidence |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| `{{ROUTE_ID}}` | {{ORDERED_ROUTE_STEP_IDS}} | {{EXACT_DEPENDENCY_EDGES}} | {{PASS_OR_FAIL_WITH_CONSTRAINT}} | {{MIN_WALL_MS_INTEGER}} | {{EXPECTED_TIME_TO_VERIFIED_B_MS_INTEGER}} | {{COST_UNITS_INTEGER}} | {{RISK_UNITS_INTEGER}} | {{REWORK_UNITS_INTEGER}} | {{SELECTED_OR_REJECTED}} | {{DOMINATED_TRADEOFF_CONSTRAINT_OR_ONLY_FEASIBLE_EVIDENCE}} |

## 1D. Experiment Topology & Workload Funnel

- **Topology mode:** {{SELECTION_FUNNEL_FULL_COMPARATIVE_DATASET_OR_SINGLE_PATH}}
- **Full-matrix authorization:** {{NOT_AUTHORIZED_OR_FULL_COMPARATIVE_DATASET_AUTHORIZED_SOURCE_AND_REASON}}
- **Value-of-information rule:** {{RUN_ONLY_IF_RESULT_CAN_CHANGE_DECISION_OTHERWISE_SKIP}}
- **Declared launch ceiling:** {{JOB_TOTAL_MAX_NUMERIC_SUM}}
- **Declared minimum wall time:** {{MIN_WALL_MS_TOTAL_NUMERIC_SUM}}
- **Launch estimate status:** {{RESOLVED_RUNS_WALL_TIME_AND_CONCURRENCY_OR_BLOCK}}
- **Launch-count reconciliation:** {{RECONCILE_STAGE_ACTUAL_SUM_AGAINST_DECLARED_TOTAL_AND_EVIDENCE_PATH}}
- **Supervisor topology checkpoint:** {{READBACK_AND_RECHECK_BEFORE_STAGE_BATCH_OR_SCOPE_CHANGE}}
- **Broad selector policy:** {{FORBID_ALL_WILDCARD_FULL_CORPUS_OR_EXACT_AUTHORIZED_SCOPE}}

### Stage decision funnel

| Stage ID | Gate type | Decision question | Input population + max | Entry gate | Workload formula + count | Command selector | Exit gate | Survivor artifact + actual-count ledger | Downstream prohibited until |
|---|---|---|---|---|---|---|---|---|---|
| `{{STAGE_ID}}` | `{{GATE_TYPE}}` | {{STAGE_DECISION_QUESTION}} | {{ALL_CANDIDATES_OR_SURVIVORS_FROM_STAGE_AND_MAX_INPUTS}} | {{START_OR_PASS_FROM_PRIOR_STAGE}} | {{NUMERIC_FACTORS_MAX_JOBS_AND_RUNTIME_COUNT_PATH}} | {{EXACT_SELECTOR_USING_DECLARED_POPULATION}} | {{PASS_IF_EXACT_THRESHOLD}} | {{SURVIVOR_ARTIFACT_AND_ACTUAL_COUNT_PATH}} | {{PROHIBITED_UNTIL_STAGE_PASS_OR_TERMINAL}} |

### Typed stage records

| Stage ID | Decision | Provider binding | Dataset + role | Execution mode | Admission | Pass rule | Explicit exclusions | Estimated runs | Minimum wall-time factors |
|---|---|---|---|---|---|---|---|---|---|
| `{{STAGE_ID}}` | {{STAGE_DECISION_QUESTION}} | {{PROVIDER_AND_REQUIRED_DECISION_METRIC_OR_NO_PROVIDER}} | {{EXACT_DATASET_SOURCE_AND_ROLE}} | {{OFFLINE_LOGICAL_CHUNKS_REALTIME_OR_EXACT_MODE}} | {{ADMIT_IF_EXACT_UPSTREAM_PROOF}} | {{PASS_IF_EXACT_THRESHOLD}} | {{EXCLUDE_PROVIDER_DATASET_MODE_METRICS_OR_NONE_REASON}} | {{ESTIMATED_RUNS_INTEGER}} | {{RUNS_MS_PER_RUN_MIN_MAX_CONCURRENCY_MIN_WALL_MS_AND_EVIDENCE_PATH}} |

### Fixture-stage ownership

| Fixture ID | Exact source | Owning stage | Decision role | Population scope | Use condition | Forbidden outside |
|---|---|---|---|---|---|---|
| `{{FIXTURE_ID}}` | `{{EXACT_FIXTURE_PATH_OR_ID}}` | `{{OWNING_STAGE_ID}}` | {{DECISION_METRIC_OR_GATE}} | {{ALL_CANDIDATES_OR_SURVIVORS_ONLY}} | {{RUN_ONLY_IF_STAGE_ENTRY_PASSES}} | {{OTHER_STAGES_OR_NONE_AUTHORIZED}} |

### Stage command bindings

Provide exactly one fenced command block per declared stage. First line must be `# STAGE_COMMAND:<STAGE_ID>`. Command must consume declared input/survivor & owned fixtures, then write declared survivor artifact plus actual-count ledger.

```powershell
# STAGE_COMMAND:{{STAGE_ID}}
{{EXACT_STAGE_COMMAND_USING_DECLARED_SELECTOR_FIXTURES_SURVIVOR_OUTPUT_AND_ACTUAL_COUNT_LEDGER}}
```

## 2. Source of Truth & Known State

- **Authoritative inputs:** {{EXACT_PATHS_URLS_IDS_SECTIONS_AND_VERSIONS}}
- **Known state:** {{CURRENT_FACTS_ERRORS_COUNTS_HASHES_GIT_STATE}}
- **Assumptions fixed by dispatcher:** {{DECISIONS_EXECUTOR_MUST_NOT_REOPEN}}
- **Context embedded from chat:** {{ESSENTIAL_FACTS_NOT_AVAILABLE_IN_FILES}}
- **Required rules / skills:** {{EXACT_ACCESSIBLE_PATHS_AND_RELEVANT_SECTIONS}}
- **Required producer / actor:** {{PRODUCER_ID_AND_PROOF_FIELD}}
- **Allowed provenance / lineage:** {{ALLOW_ONLY_EXACT_SOURCE_CHAIN}}
- **Forbidden producers / substitutes:** {{FORBID_EXACT_PRODUCERS_TRANSFORMS_OR_NONE_CHECKED}}
- **Existing-work disposition:** {{INVENTORY_REJECT_IF_INCOMPATIBLE_RESUME_ONLY_IF}}
- **Required lifecycle chain:** {{LIFECYCLE_WITH_AT_LEAST_FIVE_ORDERED_STATES}}
- **Substitution policy:** {{NO_SUBSTITUTION_OR_EXACT_AUTHORIZED_EQUIVALENTS}}
- **Allowed result derivation:** {{DIRECT_ONLY_SOURCE_AND_TERMINAL_VALUE}}
- **Forbidden result derivation:** {{FORBID_PROJECTION_DIRECT_CLOSURE_OR_OTHER_INVALID_DERIVATION}}
- **Lifecycle preflight:**

```text
{{EXACT_PRODUCER_PROVENANCE_LIFECYCLE_PREFLIGHT_COMMAND}}
```

| Input ID | Owner | Source / retrieval | Expected format / size / version / hash | Validation | Missing-input action |
|---|---|---|---|---|---|
| {{INPUT_ID}} | {{OWNER}} | {{PATH_URL_OR_EXACT_FETCH_ACTION}} | {{EXPECTED_PROPERTIES}} | {{EXACT_CHECK}} | {{DISCOVERY_OR_FALLBACK_ACTION}} |

## 3. Scope & Ownership

- **OWN — may edit:** {{EXACT_PATHS_OR_NONE}}
- **READ — read only:** {{EXACT_PATHS_OR_DATA_SOURCES}}
- **FORBIDDEN:** {{PATHS_ACTIONS_SYSTEMS_AND_OTHER_AGENT_SCOPES}}
- **Dirty-work policy:** {{HOW_UNRELATED_CHANGES_ARE_PRESERVED}}
- **Side effects / blast radius:** {{FILES_NETWORK_DATABASE_ACCOUNTS_COST_OR_NONE}}

| Task ID | Owner | Depends on | Output | Verification | Parallelizable |
|---|---|---|---|---|---|
| {{TASK_ID}} | {{ONE_OWNER}} | {{TASK_IDS_OR_NONE}} | {{EXACT_OUTPUT_PATH_OR_RESULT}} | {{EXACT_CHECK}} | {{YES_OR_NO_AND_REASON}} |

## 4. Preconditions

- **Required tools / access:** {{TOOLS_VERSIONS_CREDENTIAL_PRESENCE_NO_SECRET_VALUES}}
- **Tool versions:** {{EXACT_REQUIRED_OR_LIVE_DISCOVERY_COMMANDS}}
- **Environment variables:** {{NAMES_PRESENCE_CHECKS_AND_SAFE_MISSING_ACTIONS}}
- **Access / credentials:** {{REQUIRED_SCOPES_PRESENCE_ONLY_NO_SECRET_VALUES}}
- **Required inputs:** {{INPUT_PATHS_AND_MINIMUM_VALID_STATE}}
- **Preflight command:**

```text
{{EXACT_PREFLIGHT_COMMAND_OR_TOOL_ACTION}}
```

| Check | PASS evidence | Failure response |
|---|---|---|
| {{PRECONDITION}} | {{EXACT_EXPECTED_RESULT}} | {{EXACT_RECOVERY_ACTION}} |

## 4A. Execution Path, Reset & Gate Isolation

- **Critical discriminating invariants:** {{INVARIANTS_EMBEDDED_HERE_NOT_DELEGATED_TO_GUIDE}}
- **Resume / reset decision:** {{RESET_REQUIRED_OR_RESUME_ALLOWED_IF_EXACT_COMPATIBILITY_PROOF}}
- **Invalid-window disposition:** {{STOP_PRESERVE_OR_DISCARD_DO_NOT_COMMIT_RULE}}
- **Authority refresh:** {{PULL_OR_REREAD_CORRECTED_AUTHORITY_AND_HASH}}
- **Production path chain:** {{PRODUCTION_PATH_WITH_ENTRY_MORPHER_HOOK_RUNTIME_DELIVERY_VALUE}}
- **Frozen implementation proof:** {{HASH_VERIFY_EXACT_COMPONENTS_CONFIG_HOOKS_AND_RUNTIME}}
- **Trace linkage contract:** {{TRACE_LINK_FIELDS_ACROSS_EXPECTED_STARTED_TERMINAL_DELIVERY_VALUE}}
- **Batch start gate:** {{PROHIBITED_UNTIL_CANARY_PASS}}
- **Defect classification gate:** {{DEFECT_ONLY_IF_PRODUCTION_PATH_PROVEN_CANARY_PASS_AND_CANONICAL_CHECK_FAILS}}
- **Mid-run authority update protocol:** {{STOP_DISCARD_INVALID_WINDOW_PULL_AUTHORITY_REVERIFY_RESTART_PREFLIGHT}}
- **Environment integrity step zero:**

```text
{{EXACT_APPEND_ONLY_DIRTY_STATE_OR_INTEGRITY_COMMAND_AND_EVIDENCE_PATH}}
```

- **Canary / one-unit preflight:**

```text
{{EXACT_ONE_TRACE_OR_ONE_UNIT_COMMAND_ASSERTIONS_AND_EVIDENCE_PATH}}
```

### Production execution path

| Stage | Required component / producer | Identity / hash proof | Required event / output | Link field | Reject when |
|---|---|---|---|---|---|
| `ENTRY_POINT` | {{ENTRY_COMPONENT_OR_CALLER}} | {{ENTRY_IDENTITY_HASH_OR_INVOCATION_PROOF}} | {{ENTRY_EXPECTED_EVENT_OR_INPUT}} | {{ENTRY_TRACE_OR_CORRELATION_KEY}} | {{ENTRY_REJECTION_CONDITION}} |
| `MORPHER_OR_HOOK` | {{MORPHER_HOOK_OR_TRANSFORM}} | {{MORPHER_HOOK_HASH_AND_INVOCATION_PROOF}} | {{MORPHER_EXPECTED_EVENT_OR_OUTPUT}} | {{MORPHER_TRACE_OR_PARENT_KEY}} | {{MORPHER_REJECTION_CONDITION}} |
| `PRODUCER_OR_RUNTIME` | {{REQUIRED_PRODUCER_OR_RUNTIME}} | {{PRODUCER_RUNTIME_IDENTITY_AND_HASH_PROOF}} | {{STARTED_AND_TERMINAL_EVENT_OR_OUTPUT}} | {{ATTEMPT_AND_TERMINAL_LINK_KEYS}} | {{PRODUCER_REJECTION_CONDITION}} |
| `DELIVERY` | {{DELIVERY_COMPONENT_OR_OWNER}} | {{DELIVERY_IDENTITY_OR_RECEIPT_PROOF}} | {{DELIVERED_EVENT_OR_ARTIFACT}} | {{DELIVERY_LINK_KEY}} | {{DELIVERY_REJECTION_CONDITION}} |
| `VALUE_OR_ACCEPTANCE` | {{VALUE_TERMINAL_OR_VERIFIER}} | {{VALUE_VERIFIER_IDENTITY_PROOF}} | {{VALUE_TERMINAL_OR_ACCEPTANCE_RESULT}} | {{VALUE_LINK_KEY}} | {{VALUE_REJECTION_CONDITION}} |

### Gate isolation matrix

| Gate | Proves | Does not prove | Exact validator / check | Evidence path |
|---|---|---|---|---|
| `QUALIFICATION_GATE` | {{NARROW_QUALIFICATION_SCOPE}} | {{EXPLICIT_END_TO_END_NON_SCOPE}} | {{EXACT_QUALIFICATION_CHECK}} | `{{QUALIFICATION_EVIDENCE_PATH}}` |
| `END_TO_END_GATE` | {{FULL_LIFECYCLE_SCOPE}} | {{EXPLICIT_REMAINING_NON_SCOPE_OR_NONE}} | {{EXACT_CANONICAL_END_TO_END_CHECK}} | `{{END_TO_END_EVIDENCE_PATH}}` |

### Phase-scoped substitution matrix

| Phase / gate | Allowed derivation / substitution | Forbidden derivation / substitution | Required receipt / evidence |
|---|---|---|---|
| `CURRENT_GATE` | {{EXACT_ALLOWED_OR_NONE}} | {{EXACT_FORBIDDEN_FOR_CURRENT_GATE}} | `{{CURRENT_GATE_SUBSTITUTION_EVIDENCE_PATH}}` |
| `OTHER_PHASES` | {{EXACT_OTHER_PHASE_ALLOWANCE_OR_NONE}} | {{RULES_THAT_MUST_NOT_LEAK_INTO_CURRENT_GATE}} | `{{OTHER_PHASE_SCOPE_EVIDENCE_PATH}}` |

## 5. Execution Procedure

### Step 1 — {{STEP_NAME}}

- **Route step:** {{SELECTED_ROUTE_AND_STEP_ID}}
- **Advances target:** {{OBSERVABLE_STATE_B_DELTA}}
- **Dependency order:** {{START_OR_AFTER_ROUTE_STEP_IDS}}
- **Purpose:** {{WHY_STEP_EXISTS}}
- **Inputs:** {{EXACT_INPUTS}}
- **Working directory:** `{{STEP_WORKING_DIRECTORY}}`
- **Exact action / command:**

```text
{{EXACT_COMMAND_TOOL_NAME_AND_ARGUMENTS}}
```

- **Expected stdout / state:** {{OBSERVABLE_SUCCESS_STATE}}
- **Expected exit / result:** {{EXIT_CODE_TOOL_STATUS_OR_VALUE}}
- **Timeout / retry:** {{MAX_DURATION_RETRY_COUNT_BACKOFF_AND_FATAL_ERRORS}}
- **Output artifacts:** {{EXACT_PATHS_FORMATS_NAMES_AND_HASH_REQUIREMENTS}}
- **Evidence to record:** {{STDOUT_LOG_ARTIFACT_PATH_COUNT_HASH_OR_SCREENSHOT}}
- **On failure:** {{FAILURE_CLASS_RECOVERY_ACTION_RETRY_LIMIT_AND_PROCEED_CONDITION}}

## 5A. Script & Runner Gate

- **Script involved:** {{YES_OR_NO}}
- **No-script reason:** {{EXACT_REASON_OR_NOT_APPLICABLE_BECAUSE_YES}}
- **Script ownership:** {{ORCHESTRATOR_CREATED_OR_EXISTING_VERIFIED_OR_EXECUTOR_CREATES_OR_NOT_APPLICABLE}}
- **Script path:** {{EXACT_PATH_OR_NOT_APPLICABLE_WITH_REASON}}
- **Creation decision:** {{WHY_ORCHESTRATOR_CREATED_IT_OR_WHY_EXECUTOR_MUST}}
- **Script skill:** `{{ACCESSIBLE_PATH_TO_SCRIPT_SKILL}}`
- **Gate evidence:**

```text
GOAL:  {{STATE_A_TO_STATE_B}}
SELECTED_PATH: {{SELECTED_ROUTE_ID_AND_ORDERED_STEPS}}
WHY_FASTEST_VALID: {{ROUTE_DOMINANCE_PROOF}}
BOTTLENECK: {{CRITICAL_PATH_BOTTLENECK}}
PARALLEL: {{PARALLEL_LANES_OR_DEPENDENCY_BOUND_NONE}}
DEFERRED: {{EXPLICIT_DEFERRED_OR_DELETED_WORK}}
GOAL_ROUTE_ARTIFACT: {{CHECKOUT_RELATIVE_GOAL_ROUTE_V2_JSON_PATH}}
GOAL_ROUTE_RECEIPT: {{CHECKOUT_RELATIVE_GOAL_ROUTE_RECEIPT_PATH}}
EXPECTED_TIME_TO_VERIFIED_B_MS: {{EXPECTED_TIME_TO_VERIFIED_B_MS_INTEGER}}
ROUTE_REVISION: {{POSITIVE_ROUTE_REVISION}}
TIER:  {{S0_S1_S2_OR_S3}}
PRE:   {{ENV_DEPS_INPUTS_PATHS_SPACE_LOCK_RESULT}}
SMOKE: {{EXACT_SHIP_PATH_TINY_RUN_AND_REAL_OUTPUT}}
CHECK: {{CORRECTNESS_ASSERTION_AND_RESULT}}
BLAST: {{FILES_NETWORK_DATABASE_ACCOUNTS_COST_AND_CAP}}
OPT:   {{REQUIRED_IDLE_DUP_OVERLAP_RESUME_IDEMPOTENCY_RETRY_TIMEOUT_ATOMIC_CHECKS}}
SHIP:  {{YES_OR_NO_WITH_BLOCKING_DEFECT}}
```

## 6. Failure Decision & Recovery Matrix

| Failure class | Detect with | Recovery branches | Fallback / degraded continuation | Retry / stop bound | Proceed when | Escalate when |
|---|---|---|---|---|---|---|
| `PATH_OR_INPUT_MISSING` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{CONTINUE_INDEPENDENT_WORK_OR_DISCOVERY}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `TOOL_OR_DEPENDENCY_MISSING` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{EXISTING_EQUIVALENT_OR_PROBE}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `AUTH_OR_PERMISSION_FAILURE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{UNAUTHENTICATED_OR_MOCK_SAFE_SUBSET}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `TRANSIENT_EXTERNAL_FAILURE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{CHECKPOINT_AND_OFFLINE_SAFE_SUBSET}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `INVALID_INPUT_OR_SCHEMA` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{ISOLATE_INVALID_PART_OR_DIAGNOSTIC_FIXTURE}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `INTEGRITY_OR_HASH_MISMATCH` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{QUARANTINE_AND_CONTINUE_UNAFFECTED_WORK}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `DETERMINISTIC_COMMAND_FAILURE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{SMALLEST_REPRO_AND_UNAFFECTED_CHECKS}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `DIRTY_OR_CONFLICTING_STATE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{READ_ONLY_OR_NON_OVERLAPPING_WORK}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `WRONG_PRODUCER_OR_PROVENANCE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{REJECT_INVALID_RUN_AND_CONTINUE_SAFE_INVENTORY}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `RESOURCE_OR_CAPACITY_FAILURE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{REDUCED_BATCH_OR_CPU_LOCAL_SUBSET}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `AMBIGUOUS_REQUIREMENT` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{SMALLEST_REVERSIBLE_INTERPRETATION}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `UNSAFE_OR_OUT_OF_SCOPE_ACTION` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{STOP_UNSAFE_STEP_CONTINUE_SAFE_WORK}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |
| `UNKNOWN_FAILURE` | {{SIGNAL}} | 1. {{PRIMARY_ACTION}}<br>2. {{SECOND_ACTION}} | {{PRESERVE_STATE_AND_CONTINUE_INDEPENDENT_WORK}} | {{BOUND}} | {{CONDITION}} | {{TRUE_BLOCKER_CONDITION}} |

## 7. Verification & Acceptance Map

- **Final verification command:**

```text
{{EXACT_FINAL_VERIFICATION_COMMAND_OR_TOOL_ACTION}}
```

| Requirement | Exact check | Expected result | Evidence path | Owner |
|---|---|---|---|---|
| `PRODUCER_IDENTITY` | {{EXACT_PRODUCER_AND_PROVENANCE_CHECK}} | {{REQUIRED_PRODUCER_AND_LINEAGE_VALUE}} | `{{PRODUCER_EVIDENCE_PATH}}` | {{OWNER}} |
| `LIFECYCLE_CHAIN` | {{EXACT_ORDERED_LIFECYCLE_CHECK}} | {{ALL_REQUIRED_STATES_TERMINAL_AND_DELIVERY_VALUE}} | `{{LIFECYCLE_EVIDENCE_PATH}}` | {{OWNER}} |
| `NO_SUBSTITUTION` | {{EXACT_DERIVATION_CHECK}} | {{NO_FORBIDDEN_PRODUCER_PROJECTION_OR_DIRECT_CLOSURE}} | `{{DERIVATION_EVIDENCE_PATH}}` | {{OWNER}} |
| {{REQUIREMENT_ID}} | {{COMMAND_OR_INSPECTION}} | {{VALUE_THRESHOLD_SCHEMA_HASH_OR_STATE}} | `{{ARTIFACT_PATH}}` | {{OWNER}} |

## 8. Evidence & Artifact Contract

- **Output paths:** {{EXACT_PATHS}}
- **Logs / raw evidence:** {{EXACT_PATHS}}
- **Hashes / counts / versions:** {{REQUIRED_ALGORITHM_FIELDS_AND_RECEIPTS}}
- **Checkpoint / resume state:** {{EXACT_PATH_AND_RESUME_BEHAVIOR}}
- **Evidence retention:** {{WHAT_MUST_NOT_BE_OVERWRITTEN_OR_DELETED}}
- **Validated artifact path:** {{EXACT_DISPATCH_PATH}}
- **Receipt path:** {{EXACT_SIDECAR_RECEIPT_PATH}}
- **Validator command:**

```powershell
{{EXACT_VALIDATE_AND_WRITE_RECEIPT_COMMAND}}
```

- **Receiver hash check:**

```powershell
{{EXACT_VERIFY_RECEIPT_COMMAND}}
```

## 9. Return & Integration Contract

Return:

```text
STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER
SUMMARY: <result>
ACCEPTANCE: <criterion -> check -> result -> evidence>
ARTIFACTS: <paths + counts/sizes/hashes>
CHANGES: <files + purpose>
COMMANDS: <commands/actions + exit/result>
RECOVERY: <failures + attempts + checkpoint>
DEVIATIONS: <none | authorized deviation + source>
BLOCKER: <none | failed step + timestamp + attempts + raw error + evidence + affected outputs + preserved state + one missing input + 3 unblock options + recommended owner>
NEXT: <integration action | exact resume command>
```

`COMPLETE_WITH_NOTES` requires every acceptance criterion to pass. `PARTIAL`, `NEEDS_CONTEXT`, & vague `BLOCKED` are forbidden.

## 10. TRUE_BLOCKER Conditions

Return `TRUE_BLOCKER` only after:

1. requested outcome cannot advance safely;
2. blocker is external or non-inferable;
3. every applicable recovery action above ran;
4. all independent safe work completed;
5. evidence + one exact missing input + resume command are recorded.

Otherwise continue.

Required blocker record must include all tokens: `RECOVERY_EXHAUSTED`, `INDEPENDENT_WORK_COMPLETE`, `RAW_EVIDENCE`, `MISSING_INPUT`, `RESUME_COMMAND`.

## 11. Dispatcher Author Gate

- [ ] Every input has exact accessible location.
- [ ] Authority order places latest user intent above inherited text, implementation, checkpoints, & progress.
- [ ] Semantic correction invalidates plan from ROOT, stops/quarantines active work, & completes from-zero re-derivation; no local patch survives.
- [ ] Every inherited clause is KEEP, DELETE, or REWRITE; deleted match text is absent from executable commands.
- [ ] Exact A/B, hard constraints, route candidates, minimum-wall selection, critical path, parallel lanes, deleted work, & Forge binding pass.
- [ ] Every execution step binds selected route, advances B, & follows dependency order.
- [ ] Every acceptance/input criterion has exactly one declared stage owner.
- [ ] Topology mode matches actual decision: staged selection, explicitly authorized full comparison, or single path.
- [ ] Every stage has typed decision, necessary provider, owned dataset, exact mode, admission, pass, exclusions, run estimate, & minimum wall-time factors.
- [ ] Offline logical qualification contains no physical sleep/realtime pacing; no downstream dataset appears before admission.
- [ ] `ESTIMATED_RUNS == MAX_JOBS`; wall arithmetic, total floor, concurrency, & launch status are resolved.
- [ ] Every fixture has one owning stage; stage entry/exit gates, population, selector, workload factors, survivor artifact, & downstream prohibition are exact.
- [ ] `JOB_TOTAL_MAX` equals stage maxima; supervisor reconciles actual launches before each batch/scope change.
- [ ] Selection commands consume prior survivor artifacts; no broad `--all`, wildcard, or full-corpus selector bypasses elimination.
- [ ] Every step has cwd, action, expected result, evidence, & failure branch.
- [ ] Every acceptance criterion maps to executable check + artifact.
- [ ] Required producer, provenance, allowed derivation, & forbidden substitutes are exact.
- [ ] Existing work is inventoried; incompatible producer/provenance is rejected before resume.
- [ ] Lifecycle preflight proves required ordered states through delivery + value terminal.
- [ ] All thirteen failure classes have two branches, degraded continuation, bounds, proceed condition, & escalation threshold.
- [ ] Missing files, tools, auth, dirty state, partial output, & failed tests do not cause premature stop.
- [ ] OWN / READ / FORBIDDEN scopes cannot overlap another active dispatch.
- [ ] User authority, destructive boundaries, spend, & production effects are explicit.
- [ ] Executor can distinguish COMPLETE from plausible-looking output.
- [ ] TRUE_BLOCKER requires attempts, raw evidence, preserved state, missing input, & resume command.
- [ ] Fresh-agent simulation found no unstated judgment.
- [ ] `validate-dispatch.py` returns PASS on exact dispatched bytes.
- [ ] No dispatch, derived handoff, or execution packet is called ready before validator PASS + receipt.
