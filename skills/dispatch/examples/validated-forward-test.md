<!-- dependency-class: HISTORICAL_EVIDENCE — a record of the 2026-07-28 forward test. The paths below describe that past run and are never resolved. -->

# DISPATCH: Handoff Skill Independence & Validation

## 0. Dispatch Control

- **Dispatch ID:** dispatch-handoff-final-forward-20260728
- **Requester:** the requesting user via primary Codex orchestrator
- **Dispatcher:** Codex dispatch author
- **Executor:** smaller read-only validation executor
- **Verifier:** primary Codex orchestrator
- **Receiver:** primary Codex orchestrator
- **Mode:** READ_ONLY validation; artifact-only output
- **Execution host / OS:** Windows 11 workstation
- **Shell:** PowerShell 7 compatible shell
- **Working directory:** `<workspace>`
- **Repository / branch:** <workspace> at `absorption/phase1-6`
- **Baseline revision:** `2e162e538bfd577504cb98148615e9c7f4aac58b`
- **Scoped Git status:** Run `git -C <workspace> status --short`; baseline contains unrelated modified workspace files plus untracked `tools/skills/dispatch/` & `tools/skills/handoff/`.
- **User authorization:** Verify handoff independence, run named read-only validation commands, write only named report artifacts; source edits, staging, commits, branches, worktrees, installs, deploys, network calls, & deletion are forbidden.
- **Dependency position:** Input is handoff skill tree; output is an evidence report for primary Codex integration.
- **Parallel safety:** PARALLEL_SAFE only against source because OWN is isolated review artifact directory; serialize with any writer in that exact directory.
- **Integration owner:** primary Codex orchestrator reads report & reruns acceptance commands.

| Active dispatch ID | OWN paths | Status | Overlap decision |
|---|---|---|---|
| dispatch-handoff-final-forward-20260728 | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | ACTIVE_READONLY | NO_OVERLAP: source skill paths are read-only |

## 1. Mission

- **Outcome:** Establish with command-backed evidence whether `D:\workspace\tools\skills\handoff` operates independently from `/dispatch`, then record named validator, test, syntax, JSON, & scoped static-eval results.
- **Definition of done:** Report contains source evidence for independence; every named acceptance command exits `0`; report includes exact stdout, timestamps, command paths, SHA-256 hashes, initial/final scoped Git status, & terminal return contract.
- **Non-goals:** Do not change source; do not invoke dispatch validator against handoff content; do not create a handoff packet; do not install packages; do not use network; do not stage, commit, branch, reset, revert, stash, worktree, deploy, render, or call paid services.

## 1A. Decision & Experiment Question Lock

- **Task semantics:** ROUTINE
- **Primary decision questions:** QUESTION_1: Does handoff remain operationally independent from dispatch while its validator, template, eval route, source integrity, & packet receipt remain valid?
- **Decision rule:** DECIDE_BY: every Section 7 acceptance command exits 0 with named evidence & no executor-attributable source mutation.
- **Acceptance metrics only:** METRICS_ONLY: independence marker, validator PASS, template PASS, eval assertion PASS, stable source hashes, unchanged scoped status, & receipt verification PASS.
- **Diagnostics only:** DIAGNOSTIC_ONLY: source search matches, command duration, & environment versions may explain failure but cannot replace acceptance.
- **Explicit forbidden scope:** FORBID: WER | reference transcript | external ASR
- **Workload / fixture roles:** WORKLOAD_ROLE: handoff source files are read-only validation subjects; report is evidence output; dispatch packet plus receipt are integrity fixtures only.
- **Ground-truth policy:** GROUND_TRUTH_SOURCE: committed handoff source, eval JSON, validator, template, & current Git status; MEASURED_OUTPUT_NOT_GROUND_TRUTH: command output, hashes, duration, & report status.
- **Model / tool relevance rule:** LOAD_ONLY_IF_METRIC: tool directly produces a named Section 7 acceptance result.
- **Locked model / runtime route:** NO_MODEL_ALLOWED: no model inference contributes to static validation.
- **Recovery scope rule:** NO_SCOPE_EXPANSION: recover only named local validation inputs or commands; never add models, transcription, network, source edits, or new acceptance criteria.
- **Forge gate:** NOT_REQUIRED: routine bounded static validation with no experiment, benchmark, performance claim, model decision, research claim, or repeated-failure recovery.
- **Forge state reference:** NOT_REQUIRED
- **Forge verification:** NOT_REQUIRED
- **First-action readback:** READBACK_REQUIRED: decision question, acceptance metrics, diagnostics, forbidden scope, fixture roles, & Step 1 exact action.
- **Supervision cadence:** SUPERVISE: after first action, after every 1 step, & before any new tool, dependency, scope change, or batch.

### Requirement-to-decision trace

| Requirement | Class | Traces to question / metric / safety / execution dependency | Stage owner | Needed for decision? | Remove or reject when unmapped |
|---|---|---|---|---|---|
| `PRODUCER_IDENTITY` | `ACCEPTANCE` | QUESTION_1 report must come from named executor commands & source hashes | `SINGLE_PATH_EXECUTION` | YES — rejects substituted report | Reject report & rerun named commands |
| `LIFECYCLE_CHAIN` | `ACCEPTANCE` | QUESTION_1 requires expected through terminal value markers | `SINGLE_PATH_EXECUTION` | YES — rejects incomplete run | Reject incomplete lifecycle |
| `NO_SUBSTITUTION` | `ACCEPTANCE` | QUESTION_1 requires direct command evidence | `SINGLE_PATH_EXECUTION` | YES — rejects projected result | Remove projection & use raw output |
| `Purpose boundary` | `ACCEPTANCE` | QUESTION_1 independence marker | `SINGLE_PATH_EXECUTION` | YES — proves no operational route | Reject when boundary marker is absent |
| `Validator adversarial test` | `ACCEPTANCE` | QUESTION_1 validator validity | `SINGLE_PATH_EXECUTION` | YES — proves negative controls | Reject when test is nonzero |
| `Validator template smoke` | `ACCEPTANCE` | QUESTION_1 template validity | `SINGLE_PATH_EXECUTION` | YES — proves template compiles | Reject when smoke is nonzero |
| `Eval routing assertion` | `ACCEPTANCE` | QUESTION_1 route independence | `SINGLE_PATH_EXECUTION` | YES — proves routing expectation | Reject when assertion fails |
| `Source preservation` | `ACCEPTANCE` | QUESTION_1 safety & integrity | `SINGLE_PATH_EXECUTION` | YES — proves no source mutation | Reject when executor changes source |
| `Packet integrity` | `ACCEPTANCE` | QUESTION_1 exact-byte auditability | `SINGLE_PATH_EXECUTION` | YES — proves canonical bytes | Reject when receipt differs |
| `DIAGNOSTIC_ONLY` | `DIAGNOSTIC` | Explains command failures without deciding QUESTION_1 | `SINGLE_PATH_EXECUTION` | NO — cannot gate completion | Drop when collection adds cost |
| `EXECUTION_INPUT` | `EXECUTION_INPUT` | Named source files are required to run acceptance checks | `SINGLE_PATH_EXECUTION` | YES — execution only, not ground truth | Reject invented labels or fixtures |
| `FORBIDDEN_SCOPE` | `FORBIDDEN` | No decision value for static validation | `NONE` | NO — outside user decision | Stop & remove proposed scope |

### Model, tool & dependency relevance

| Model / tool / dependency | Acceptance metric produced | Locked route / version | Cost / resource effect | Decision | Evidence |
|---|---|---|---|---|---|
| MODEL: external ASR | NONE — produces no acceptance metric | NO_MODEL_ALLOWED: static validation only | Unnecessary compute, memory, & attention | FORBID: produces no acceptance metric | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` |

## 1B. Authority, Correction & Global Re-Derivation

- **Authority order:** LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS
- **Correction state:** NONE: fresh read-only validation dispatch
- **Correction audit:** INVENTORY_SOURCE:current user mission plus prior independence assumptions; SEMANTIC_DELTA:NO; EVIDENCE:D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\correction-audit.json
- **Plan invalidation:** NOT_APPLICABLE:NO_SEMANTIC_CORRECTION
- **Re-derivation status:** FROM_ZERO:COMPLETE; OBJECTIVE_RESTATED:COMPLETE; REQUIREMENTS_RECLASSIFIED:COMPLETE; STAGES_REBUILT:COMPLETE; COMMANDS_REBOUND:COMPLETE
- **Progress disposition:** PRESERVE_EVIDENCE_ONLY; REUSE_ONLY_IF:source hashes, producer, lifecycle, & typed stage contract match; STALE_PROGRESS:REJECT
- **Inherited inventory reconciliation:** INVENTORY_TOTAL:2; CLASSIFIED_TOTAL:2; UNCLASSIFIED:0; EVIDENCE:D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\inherited-inventory.json
- **Forge typed-stage binding:** NOT_REQUIRED: routine bounded static validation

### Inherited instruction disposition

| Inherited clause ID | Exact inherited text / source | Source rank | Objective compatibility | Stage owner | Disposition + reason/effect |
|---|---|---|---|---|---|
| `latest-objective` | Prove handoff independence with named local checks; current mission | `LATEST_USER_INTENT` | `ALIGNED` | `SINGLE_PATH_EXECUTION` | KEEP: DECISION_EFFECT:QUESTION_1 independence decision |
| `dispatch-runtime-route` | Prior assumption that handoff must invoke dispatch validator | `INHERITED_DOCUMENT` | `NO_DECISION_VALUE` | `NONE` | DELETE: MATCH_TEXT:validate-dispatch; EXCLUDE_FROM:SINGLE_PATH_EXECUTION; NO_DECISION_EFFECT:handoff has independent validator |

## 1C. Goal Route & Critical Path

- **State A:** STATE_A: handoff skill exists but independent validation evidence has not been compiled into owned report.
- **State B:** STATE_B: owned report contains passing independence, validator, template, eval, hash, status, & receipt evidence.
- **Goal success proof:** PROOF: run named Section 7 commands & verify <workspace>/tools/review/.council-runs/dispatch-handoff-final/forward/handoff-independence-report.md.
- **Hard route constraints:** CONSTRAINTS: AUTHORITY=read-only validation; SAFETY=no source/Git mutation; COST=zero paid/network cost; QUALITY=all named checks pass; SCOPE=one owned report plus named local inputs.
- **Route mode:** SINGLE_FEASIBLE
- **Goal route artifact:** <workspace>/tools/skills/dispatch/examples/validated-forward-test.route.json
- **Goal route receipt:** <workspace>/tools/skills/dispatch/examples/validated-forward-test.route.receipt.json
- **Goal route schema:** goal-route.v2
- **Selected route:** SELECTED_ROUTE:R_VALIDATE
- **Expected time to verified B:** EXPECTED_TIME_TO_VERIFIED_B_MS:4
- **Route revision:** ROUTE_REVISION:1
- **Why fastest valid:** EXPECTED_TIME_PROOF: direct four-check local route is sole route satisfying read-only authority while producing every acceptance metric.
- **Critical path:** CRITICAL_PATH:R_VALIDATE/S1>R_VALIDATE/S2>R_VALIDATE/S3>R_VALIDATE/S4; TOTAL_MIN_WALL_MS:4
- **Bottleneck:** BOTTLENECK: R_VALIDATE/S3 validator/test execution is serialized at 4 ms minimum wall time.
- **Parallel lanes:** NONE_DEPENDENCY_BOUND: each step appends evidence to one atomic report & final non-mutation check requires prior commands.
- **Deleted / deferred work:** DELETE: model review, network lookup, source mutation, & duplicated validators; DEFER: none because all four acceptance checks are critical path.
- **Route Forge binding:** SCHEMA:goal-route.v2; NOT_REQUIRED: routine bounded static validation has one evidence-proven feasible route.

| Route ID | Ordered route steps | Dependencies | Constraint result | Min wall ms | Expected verified-B ms | Cost units | Risk units | Rework units | Status | Rejection / dominance evidence |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| `R_VALIDATE` | STEPS:R_VALIDATE/S1>R_VALIDATE/S2>R_VALIDATE/S3>R_VALIDATE/S4 | EDGES:R_VALIDATE/S1->R_VALIDATE/S2->R_VALIDATE/S3->R_VALIDATE/S4 | PASS: every read-only authority, safety, cost, quality, & scope constraint passes | 4 | 4 | 0 | 0 | 0 | SELECTED | ONLY_FEASIBLE:EVIDENCE: <workspace>/tools/review/.council-runs/dispatch-handoff-final/forward/route-proof.json |

## 1D. Experiment Topology & Workload Funnel

- **Topology mode:** SINGLE_PATH
- **Full-matrix authorization:** NOT_AUTHORIZED: one bounded validation path answers QUESTION_1
- **Value-of-information rule:** RUN_ONLY_IF: named check produces a Section 7 acceptance result; SKIP: check cannot change QUESTION_1 decision
- **Declared launch ceiling:** JOB_TOTAL_MAX: 4
- **Declared minimum wall time:** MIN_WALL_MS_TOTAL: 4
- **Launch estimate status:** RESOLVED:RUNS_WALL_TIME_CONCURRENCY
- **Launch-count reconciliation:** RECONCILE: STAGE_ACTUAL_SUM must equal JOB_TOTAL_MAX; BLOCK_IF_MISMATCH before acceptance; write `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\launch-count.json`
- **Supervisor topology checkpoint:** READBACK_REQUIRED: stage, population, selector, & expected count; BEFORE_STAGE: every 1 stage plus before batch or scope change
- **Broad selector policy:** FORBID_BROAD_SELECTORS: single named validation path only

### Stage decision funnel

| Stage ID | Gate type | Decision question | Input population + max | Entry gate | Workload formula + count | Command selector | Exit gate | Survivor artifact + actual-count ledger | Downstream prohibited until |
|---|---|---|---|---|---|---|---|---|---|
| `SINGLE_PATH_EXECUTION` | `SINGLE_PATH` | QUESTION_1: Does handoff remain independently valid? | ALL_CANDIDATES: named handoff skill; MAX_INPUTS: 1 | START: named source paths exist | FACTORS: 1x4; MAX_JOBS: 4; ACTUAL_COUNT: `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\launch-count.json` | SELECTOR: four named Section 7 commands against exact handoff paths | PASS_IF: all four named checks exit 0 | SURVIVORS: `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`; ACTUAL_COUNT: `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\launch-count.json` | TERMINAL: return evidence to orchestrator |

### Typed stage records

| Stage ID | Decision | Provider binding | Dataset + role | Execution mode | Admission | Pass rule | Explicit exclusions | Estimated runs | Minimum wall-time factors |
|---|---|---|---|---|---|---|---|---|---|
| `SINGLE_PATH_EXECUTION` | QUESTION_1: Does handoff remain independently valid? | NO_PROVIDER:QUESTION_1 static local validation requires no provider | DATASET:D:\workspace\tools\skills\handoff; ROLE:read-only validation source tree | MODE:STATIC_VALIDATION | ADMIT_IF:named handoff source paths exist | PASS_IF:all four named checks exit 0 | EXCLUDE:network, models, source edits, dispatch runtime dependency | ESTIMATED_RUNS:4 | WALL_FACTORS:RUNS=4; MS_PER_RUN_MIN=1; MAX_CONCURRENCY=1; MIN_WALL_MS=4; EVIDENCE:D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\wall-floor.json |

### Fixture-stage ownership

| Fixture ID | Exact source | Owning stage | Decision role | Population scope | Use condition | Forbidden outside |
|---|---|---|---|---|---|---|
| `handoff-skill-tree` | `D:\workspace\tools\skills\handoff` | `SINGLE_PATH_EXECUTION` | execution input for QUESTION_1 | one named source tree | RUN_ONLY_IF:SINGLE_PATH_EXECUTION:ENTRY_PASS | FORBID: unrelated repos, models, network, or generated labels |

### Stage command bindings

```powershell
# STAGE_COMMAND:SINGLE_PATH_EXECUTION
Write-Output STATIC_VALIDATION
py -3.11 D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py
py -3.11 D:\workspace\tools\skills\handoff\scripts\validate-handoff.py D:\workspace\tools\skills\handoff\assets\handoff-template.md --template-self-check
py -3.11 -c "import json; json.load(open(r'D:\workspace\tools\skills\handoff\evals\evals.json', encoding='utf-8'))"
rg -n "Neither skill depends|validate-handoff" D:\workspace\tools\skills\handoff
Set-Content -LiteralPath D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\launch-count.json -Value '{"stage":"SINGLE_PATH_EXECUTION","actual":4}'
Set-Content -LiteralPath D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md -Value 'Populate with exact command evidence from Steps 1-4.'
```

## 2. Source of Truth & Known State

- **Authoritative inputs:** `D:\workspace\tools\skills\handoff\SKILL.md` lines 1-27; `D:\workspace\tools\skills\handoff\scripts\validate-handoff.py`; `D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py`; `D:\workspace\tools\skills\handoff\evals\evals.json`; `D:\workspace\tools\skills\handoff\assets\handoff-template.md`; `D:\workspace\tools\skills\dispatch\SKILL.md` lines 1-25.
- **Known state:** Handoff description says cold-start context transplant; Handoff boundary says `/dispatch` sends bounded executor work & neither skill depends on other; handoff owns `validate-handoff.py` plus `test_validate_handoff.py`.
- **Assumptions fixed by dispatcher:** Independence means distinct purpose, distinct validator/test paths, & no mandatory dispatch invocation in handoff skill instructions, validator, test, template, or eval fixture. A textual `/dispatch` boundary reference is expected evidence, not dependency.
- **Context embedded from chat:** Existing test path uses hyphenated validator filename: `scripts\validate-handoff.py`; test is `scripts\test_validate_handoff.py`. Do not infer underscore paths.
- **Required rules / skills:** `D:\workspace\AGENTS.md` primary-checkout & dirty-work rules; `D:\workspace\tools\skills\script\SKILL.md` S1 gate; `D:\workspace\tools\skills\handoff\SKILL.md` boundary & validation sections; `D:\workspace\tools\skills\dispatch\SKILL.md` zero-context evidence contract.
- **Required producer / actor:** PRODUCER: Executor-role | PROOF_FIELD: `STATUS` return plus recorded command evidence
- **Allowed provenance / lineage:** ALLOW_ONLY: named local source files -> exact read-only commands -> owned report -> orchestrator verification
- **Forbidden producers / substitutes:** FORBID: invented source evidence, dispatcher-memory projection, direct acceptance closure, or another agent's unverified summary
- **Existing-work disposition:** INVENTORY: inspect owned report plus active-dispatch table; REJECT_IF_INCOMPATIBLE: producer, source hashes, or step markers differ; RESUME_ONLY_IF: producer identity, baseline hashes, & completed lifecycle markers match
- **Required lifecycle chain:** LIFECYCLE: dispatch.expected -> executor.started -> checks.terminal -> report.delivery -> acceptance.value_terminal
- **Substitution policy:** NO_SUBSTITUTION — source commands, validator results, & report evidence cannot be replaced by summaries or projections
- **Allowed result derivation:** DIRECT_ONLY: exact command output plus source hashes recorded in owned report
- **Forbidden result derivation:** FORBID: direct closure, projected result, synthetic PASS, or unverified agent summary
- **Lifecycle preflight:**

```powershell
# Run lifecycle identity checks.
Get-Item -LiteralPath D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md; Get-FileHash -Algorithm SHA256 D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md; Get-Item -LiteralPath D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward -ErrorAction SilentlyContinue | Out-File D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\lifecycle-preflight.log
```

| Evidence ID | Input path | Exact inspection or command | Expected observable | Evidence destination | Owner |
|---|---|---|---|---|---|
| Evidence-01 | `D:\workspace\tools\skills\handoff\SKILL.md` | `rg -n -C 2 "Boundary from"; rg -n "Neither skill depends"; rg -n "validate-handoff"` | Boundary text plus validator route | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |
| Evidence-02 | `D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py` | `py -3.11 D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py` | PASS line & exit code 0 | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |
| Evidence-03 | `D:\workspace\tools\skills\handoff\scripts\validate-handoff.py` | `py -3.11 D:\workspace\tools\skills\handoff\scripts\validate-handoff.py D:\workspace\tools\skills\handoff\assets\handoff-template.md --template-self-check` | PASS line & SHA-256 | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |
| Evidence-04 | `D:\workspace\tools\skills\handoff\evals\evals.json` | `py -3.11 -c "import json; json.load(open(r'D:\workspace\\tools\\skills\\handoff\\evals\\evals.json'))"` | JSON load succeeds & required routing assertion exists | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |
| Evidence-05 | `D:\workspace\tools\skills\handoff` | `rg -n "validate-dispatch" D:\workspace\tools\skills\handoff; rg -n "dispatch/scripts" D:\workspace\tools\skills\handoff; rg -n "tools/skills/dispatch" D:\workspace\tools\skills\handoff` | Exit 1 with no mandatory dispatch route outside boundary prose | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |
| Evidence-06 | `<workspace>` | `git -C <workspace> status --short` before & after | No source-path delta attributable to executor | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor-role |

## 3. Scope & Ownership

- **OWN — may edit:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` only; create parent directory only if missing.
- **READ — read only:** `D:\workspace\AGENTS.md`; `D:\workspace\tools\skills\handoff\`; `D:\workspace\tools\skills\dispatch\SKILL.md`; `D:\workspace\tools\skills\script\SKILL.md`; `D:\workspace\.claude\rules\agent-routing.md`; Git metadata via `git -C <workspace> status --short` & `rev-parse`.
- **FORBIDDEN:** Every file outside OWN; all handoff & dispatch source writes; `.git` writes; dependency installs; network; process launch outside named short Python commands; staging; commit; branch; worktree; reset; revert; stash; delete; deployment; paid actions.
- **Dirty-work policy:** Capture exact before/after Git status; preserve every pre-existing line; write no source path; do not clean or reinterpret other workers' modifications.
- **Side effects / blast radius:** Reads source plus Git metadata; creates or overwrites only one owned Markdown report atomically through temporary sibling then rename; no network, database, account, paid cost, or production effect.

| Task ID | Outcome | Depends on | OWN | READ | FORBIDDEN |
|---|---|---|---|---|---|
| Validation-01 | Independence proof plus local validation report | Handoff files accessible | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | `D:\workspace\tools\skills\handoff\` & named rules | Source edits, Git mutation, installs, network, destructive actions |

## 4. Preconditions

| Check | Exact command or action | Pass condition |
|---|---|---|
| Python runtime & files | `py -3.11 --version; Test-Path D:\workspace\tools\skills\handoff\scripts\validate-handoff.py; Test-Path D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py` | Python reports 3.11 & both paths return True |
| Read-only source baseline | `git -C <workspace> status --short; git -C <workspace> rev-parse HEAD` | Status captured verbatim; revision reports a 40-character hash |
| Output isolation | `Test-Path D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward` | Existing path is inspected; only report path is eligible for write |

- **Required tools / access:** Windows PowerShell, `py -3.11`, `rg`, `git`, local read/write access to exact OWN artifact path.
- **Tool versions:** Record `py -3.11 --version`, `git --version`, & `rg --version` first line in report.
- **Environment variables:** No environment variables required; record `NOT_APPLICABLE: local read-only commands have no credential or variable input`.
- **Access / credentials:** No credential route; record `NOT_APPLICABLE: no network or protected API action`.
- **Required inputs:** Six E1-E6 source paths listed in Section 2 must exist before test execution.
- **Preflight command:**

```powershell
# Run preflight checks.
py -3.11 --version; git --version; rg --version | Select-Object -First 1; Test-Path D:\workspace\tools\skills\handoff\SKILL.md; Test-Path D:\workspace\tools\skills\handoff\scripts\validate-handoff.py; Test-Path D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py; Test-Path D:\workspace\tools\skills\handoff\evals\evals.json
```

## 4A. Execution Path, Reset & Gate Isolation

- **Critical discriminating invariants:** INVARIANT: handoff owns distinct validator/test/template/evals; INVARIANT: source evidence comes from exact local commands & hashes; INVARIANT: no dispatch runtime dependency may appear outside documented boundary prose
- **Resume / reset decision:** RESUME_ALLOWED_IF: existing report producer is Executor-role, baseline source hashes match, & lifecycle markers are ordered; otherwise reset report window
- **Invalid-window disposition:** STOP current validation; PRESERVE incompatible report as evidence; DO_NOT_COMMIT or accept incompatible results
- **Authority refresh:** AUTHORITY_REFRESH: reread `D:\workspace\tools\skills\handoff\SKILL.md` plus validator/test/evals & record current SHA-256 values
- **Production path chain:** PRODUCTION_PATH: dispatch receipt -> Executor-role -> handoff validator/test commands -> report delivery -> orchestrator acceptance
- **Frozen implementation proof:** HASH_VERIFY: run `Get-FileHash` on handoff SKILL, validator, test, template, & eval JSON before concluding
- **Trace linkage contract:** TRACE_LINK: dispatch ID -> report step marker -> command ledger entry -> delivered report path -> acceptance row
- **Batch start gate:** PROHIBITED_UNTIL_CANARY_PASS — run one handoff template self-check before remaining validation commands
- **Defect classification gate:** DEFECT_ONLY_IF: PRODUCTION_PATH_PROVEN and CANARY_PASS and CANONICAL_CHECK_FAILS with matching source hashes & command evidence
- **Mid-run authority update protocol:** STOP -> DISCARD_INVALID_WINDOW -> PULL_AUTHORITY -> REVERIFY -> RESTART_PREFLIGHT
- **Environment integrity step zero:**

```powershell
# Run environment integrity capture.
git -C <workspace> status --short | Out-File D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\environment-integrity.log; git -C <workspace> rev-parse HEAD | Add-Content D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\environment-integrity.log
```

- **Canary / one-unit preflight:**

```powershell
py -3.11 D:\workspace\tools\skills\handoff\scripts\validate-handoff.py D:\workspace\tools\skills\handoff\assets\handoff-template.md --template-self-check | Out-File D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\one-unit-canary.log
```

### Production execution path

| Stage | Required component / producer | Identity / hash proof | Required event / output | Link field | Reject when |
|---|---|---|---|---|---|
| `ENTRY_POINT` | Validated dispatch + adjacent receipt | Dispatch validator receipt SHA-256 | Executor receives exact bytes | Dispatch ID | Receipt absent or bytes mismatch |
| `MORPHER_OR_HOOK` | PowerShell/Python command entrypoints | Exact command string + executable version | Named handoff source/test invocation | Command ledger index | Different path or unrecorded wrapper |
| `PRODUCER_OR_RUNTIME` | Executor-role running handoff-owned validator/test | `STATUS` producer field + source hashes | PASS/FAIL plus raw stdout/stderr | Step marker + command index | Another producer or projected result |
| `DELIVERY` | Owned Markdown report | Report path + SHA-256 | Atomic report delivery | Dispatch ID + report path | Report missing, wrong path, or partial write |
| `VALUE_OR_ACCEPTANCE` | Primary Codex orchestrator | Independent rerun + receipt verification | Acceptance rows reach terminal results | Report hash + acceptance ID | Summary replaces rerun evidence |

### Gate isolation matrix

| Gate | Proves | Does not prove | Exact validator / check | Evidence path |
|---|---|---|---|---|
| `QUALIFICATION_GATE` | Handoff template structure parses under handoff validator | Skill independence, test behavior, or source preservation | One template self-check canary | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\one-unit-canary.log` |
| `END_TO_END_GATE` | Boundary, validator tests, eval routing, hashes, report delivery, & no executor source mutation | Unrelated repo correctness | Full Section 7 acceptance map + orchestrator rerun | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` |

### Phase-scoped substitution matrix

| Phase / gate | Allowed derivation / substitution | Forbidden derivation / substitution | Required receipt / evidence |
|---|---|---|---|
| `CURRENT_GATE` | NONE: all independence claims require direct source/command evidence | Projected PASS, agent summary, copied stale hash, or dispatch validator substitution | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` |
| `OTHER_PHASES` | Diagnostic fixture only when clearly labeled outside acceptance | Any diagnostic allowance leaking into current independence acceptance | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\environment-integrity.log` |

## 5. Execution Procedure

### Step 1 — Capture immutable read baseline

- **Route step:** ROUTE_STEP:R_VALIDATE/S1
- **Advances target:** ADVANCES_STATE_B: records source hashes & initial status required to prove subsequent non-mutation.
- **Dependency order:** START: selected route begins from verified STATE_A.
- **Purpose:** Preserve dirty state & baseline revision before any owned report write.
- **Inputs:** `<workspace>` Git metadata plus named handoff tree paths.
- **Working directory:** `<workspace>`
- **Exact action / command:**

```powershell
# Run baseline capture.
git -C <workspace> status --short; git -C <workspace> rev-parse --abbrev-ref HEAD; git -C <workspace> rev-parse HEAD; Get-ChildItem -Recurse -File D:\workspace\tools\skills\handoff | Select-Object -ExpandProperty FullName
```

- **Expected stdout / state:** Status, branch, 40-character revision, & six handoff file paths print without source modification.
- **Expected exit / result:** Exit 0; preserve stdout verbatim in `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`.
- **Timeout / retry:** 20 seconds; one retry after rerunning exact command.
- **Output artifacts:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` receives baseline section.
- **Evidence to record:** Command, UTC timestamp, status output, branch, revision, & file count in `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`.
- **On failure:** Run `Get-Location; Test-Path <workspace>; git -C <workspace> rev-parse --show-toplevel`; stop only after both discovery commands fail & record raw error.

### Step 2 — Prove interface boundary & absence of operational coupling

- **Route step:** ROUTE_STEP:R_VALIDATE/S2
- **Advances target:** ADVANCES_STATE_B: adds direct independence evidence to owned report.
- **Dependency order:** AFTER: R_VALIDATE/S1
- **Purpose:** Distinguish documented boundary mention from mandatory dispatch execution.
- **Inputs:** `D:\workspace\tools\skills\handoff\SKILL.md`, scripts, template, eval fixture.
- **Working directory:** `<workspace>`
- **Exact action / command:**

```powershell
# Run boundary proof.
rg -n -C 2 "Boundary from" D:\workspace\tools\skills\handoff\SKILL.md; rg -n "Neither skill depends" D:\workspace\tools\skills\handoff\SKILL.md; rg -n "validate-handoff" D:\workspace\tools\skills\handoff\SKILL.md; rg -n "validate-dispatch" D:\workspace\tools\skills\handoff; $code=$LASTEXITCODE; if ($code -eq 1) { "NO_OPERATIONAL_DISPATCH_ROUTE"; exit 0 }; exit $code
```

- **Expected stdout / state:** Boundary language prints; final marker is `NO_OPERATIONAL_DISPATCH_ROUTE`; no source modification occurs.
- **Expected exit / result:** Exit 0; report contains raw search output & normalized final marker.
- **Timeout / retry:** 20 seconds; one retry after `rg --files D:\workspace\tools\skills\handoff` confirms inputs.
- **Output artifacts:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` receives independence section.
- **Evidence to record:** Both command outputs, exit code, file paths searched, & conclusion tied to fixed definition in `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`.
- **On failure:** If search finds an operational route, quote matching lines, mark independence acceptance failed, continue all safe tests, & return COMPLETE_WITH_NOTES only if every command ran.

### Step 3 — Run handoff validator test & template smoke

- **Route step:** ROUTE_STEP:R_VALIDATE/S3
- **Advances target:** ADVANCES_STATE_B: adds validator, template, syntax, & receipt PASS evidence.
- **Dependency order:** AFTER: R_VALIDATE/S2
- **Purpose:** Execute existing adversarial validator tests plus exact validator template self-check.
- **Inputs:** Handoff validator, test file, & template paths listed in Section 2.
- **Working directory:** `<workspace>`
- **Exact action / command:**

```powershell
# Run validator smoke.
py -3.11 -m py_compile D:\workspace\tools\skills\handoff\scripts\validate-handoff.py D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py; py -3.11 D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py; py -3.11 D:\workspace\tools\skills\handoff\scripts\validate-handoff.py D:\workspace\tools\skills\handoff\assets\handoff-template.md --template-self-check
```

- **Expected stdout / state:** Compile emits no error; test prints `PASS:`; template check prints `PASS:` plus SHA-256.
- **Expected exit / result:** Exit 0; complete stdout copied into `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`.
- **Timeout / retry:** 60 seconds total; one retry only for a transient interpreter launch error, zero retries for assertion or syntax failure.
- **Output artifacts:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` records test & smoke outputs.
- **Evidence to record:** Runtime version, command string, exit code, PASS lines, template SHA-256, & test file SHA-256 in `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md`.
- **On failure:** Preserve raw stdout/stderr; rerun only failing individual command once; inspect first failing source line with `Get-Content`; never edit; continue Step 4.

### Step 4 — Validate scoped eval routing & final non-mutation state

- **Route step:** ROUTE_STEP:R_VALIDATE/S4
- **Advances target:** ADVANCES_STATE_B: closes eval, hash, status, & final report acceptance state.
- **Dependency order:** AFTER: R_VALIDATE/S3
- **Purpose:** Prove eval JSON parses, contains expected dispatch-routing negative case, & source status remains preserved.
- **Inputs:** `D:\workspace\tools\skills\handoff\evals\evals.json` plus baseline status from Step 1.
- **Working directory:** `<workspace>`
- **Exact action / command:**

```powershell
# Run scoped eval validation.
py -3.11 -c "import json; p=r'D:\workspace\tools\skills\handoff\evals\evals.json'; d=json.load(open(p,encoding='utf-8')); x=[e for e in d['should_not_trigger'] if e['id']=='handoff-not-dispatch'][0]; assert x['expected_skill']=='dispatch' and 'handoff' in x['forbidden_skills']; print('EVAL_PASS: handoff-not-dispatch routes dispatch and forbids handoff')"; Get-FileHash D:\workspace\tools\skills\handoff\SKILL.md,D:\workspace\tools\skills\handoff\scripts\validate-handoff.py,D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py,D:\workspace\tools\skills\handoff\evals\evals.json -Algorithm SHA256; git -C <workspace> status --short
```

- **Expected stdout / state:** `EVAL_PASS` line, four SHA-256 hashes, & final Git status print; no source-path delta is introduced.
- **Expected exit / result:** Exit 0; report lists baseline/final status comparison & hash table.
- **Timeout / retry:** 30 seconds; one retry after exact JSON path exists check.
- **Output artifacts:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` receives eval, hashes, final status, & final verdict.
- **Evidence to record:** JSON assertion output, hashes, initial/final status, report SHA-256, & `Get-Date -AsUTC` timestamp.
- **On failure:** Capture exception text; inspect JSON with `Get-Content -Raw`; do not correct it; complete final status capture & state failure in verdict.

## 5A. Script & Runner Gate

- **Script involved:** YES
- **No-script reason:** NOT_APPLICABLE: existing Python test & validator scripts execute during this bounded local validation.
- **Script ownership:** EXISTING_VERIFIED
- **Script path:** `D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py` and `D:\workspace\tools\skills\handoff\scripts\validate-handoff.py`
- **Creation decision:** No helper creation: existing source-owned entrypoints directly satisfy test & validator requirements.
- **Script skill:** `D:\workspace\tools\skills\script\SKILL.md`
- **Gate evidence:**

```text
GOAL: STATE_A uncompiled handoff independence -> STATE_B owned validated evidence report
SELECTED_PATH: R_VALIDATE with R_VALIDATE/S1>R_VALIDATE/S2>R_VALIDATE/S3>R_VALIDATE/S4
WHY_FASTEST_VALID: direct four-check local route is sole passing read-only path & contains no duplicated acceptance work
BOTTLENECK: R_VALIDATE/S3 validator/test execution under 60-second command cap
PARALLEL: NONE_DEPENDENCY_BOUND because one report is appended serially & final status depends on prior hashes
DEFERRED: none; model review, network lookup, source mutation, & duplicate checks are deleted
GOAL_ROUTE_ARTIFACT: <workspace>/tools/skills/dispatch/examples/validated-forward-test.route.json
GOAL_ROUTE_RECEIPT: <workspace>/tools/skills/dispatch/examples/validated-forward-test.route.receipt.json
EXPECTED_TIME_TO_VERIFIED_B_MS: 4
ROUTE_REVISION: 1
TIER: S1
Local read-only validator plus adversarial test.
PRE: Python 3.11.0, named scripts, template, rg, and Git were present; no credentials, network, or lock required.
SMOKE: py -3.11 D:\workspace\tools\skills\handoff\scripts\test_validate_handoff.py printed PASS: handoff validator accepts cold-start packet plus rejects readiness, secret, context, resume, table, checklist, and receipt bypasses.
CHECK: py_compile completed without stderr; template self-check printed PASS: handoff is cold-start complete with SHA-256 c212772f64ad7b7b5cc4f54c5b5aa42d69758d6663185d63b30bda798cd26364.
BLAST: Reads named local source files; executor writes one owned report atomically; no network, DB, accounts, deletion, spend, or production action.
OPT: a.idle n.a. local sub-second checks; b.dup single test and validator pass; c.overlap n.a. serialized to preserve report; d.resume report sections permit rerun; e.idempotent report replacement is atomic; f.retry-classes transient launch once versus deterministic zero; g.timeout+heartbeat 60-second command cap plus step markers; h.atomic temporary sibling then rename.
SHIP: YES
```

## 6. Failure Decision & Recovery Matrix

| Class | Trigger | Primary & second branch | Degraded continuation | Retry / stop bound | Proceed condition | TRUE_BLOCKER threshold |
|---|---|---|---|---|---|---|
| PATH_OR_INPUT_MISSING | Named source path absent | 1. Run `rg --files D:\workspace\tools\skills\handoff` then inspect parent. 2. Run `rg -l "validate-handoff" D:\workspace\tools\skills` to locate rename. | Record discovered path or continue all checks that do not consume missing file. | 2 discovery commands; 0 source edits. | Exact required path exists or authoritative renamed file matches. | TRUE_BLOCKER only after all recovery branches fail, evidence log records both searches, & exact missing input is named. |
| TOOL_OR_DEPENDENCY_MISSING | `py`, `rg`, or `git` unavailable | 1. Run `Get-Command py,rg,git`. 2. Inspect `py -3.11 --version` & repository lockfiles without install. | Capture text-only boundary evidence with available `Get-Content`. | 1 command discovery plus 1 version command. | Required local tool returns executable path & version. | TRUE_BLOCKER only after all recovery branches fail, evidence log records discovery, & exact missing input is named. |
| AUTH_OR_PERMISSION_FAILURE | Read or OWN report write denied | 1. Test exact path read/write access with temporary OWN sibling. 2. Inspect ACL with `Get-Acl` for exact path. | Continue all readable checks; record inaccessible evidence. | 1 safe write test & 1 ACL inspection. | Required source reads & OWN write return exit 0. | TRUE_BLOCKER only after all recovery branches fail, evidence log records ACL checks, & exact missing input is named. |
| TRANSIENT_EXTERNAL_FAILURE | Local command unexpectedly times out | 1. Capture timeout & rerun failing command once. 2. Run smallest command against exact file. | Continue all commands unrelated to timed-out entrypoint. | One retry; 60 seconds maximum per test step. | Rerun exit code is 0 with expected PASS marker. | TRUE_BLOCKER only after all recovery attempts fail, evidence log records both timeouts, & exact missing input is named. |
| INVALID_INPUT_OR_SCHEMA | Eval JSON or template assertion fails | 1. Parse with `py -3.11 -c` & capture exception. 2. Inspect exact failing key using `Get-Content -Raw`. | Run boundary, syntax, status, & hash evidence. | 0 mutation retries; 2 diagnostic reads. | JSON parse returns expected route assertion. | TRUE_BLOCKER forbidden: all recovery branches still run, evidence log records failure, & no external missing input exists. |
| INTEGRITY_OR_HASH_MISMATCH | Source hash changes during run | 1. Recompute named SHA-256 hashes. 2. Compare `git diff --no-index` only against copied report evidence. | Record race evidence & retain both hash samples. | 2 hash passes; 0 checkout manipulation. | Before/after hashes match or change status is documented external activity. | TRUE_BLOCKER only after all recovery attempts fail, evidence log records both hashes, & exact missing input is named. |
| DETERMINISTIC_COMMAND_FAILURE | Test assertion or compile exits nonzero | 1. Preserve stderr & rerun exact failing command once. 2. Inspect named source line with `Get-Content`. | Execute remaining read-only checks & record failure. | 1 rerun; 0 code fix. | Exact command exit code is 0 with stated PASS line. | TRUE_BLOCKER forbidden: all recovery branches still run, evidence log records failure, & no external missing input exists. |
| DIRTY_OR_CONFLICTING_STATE | Git status differs beyond owned report | 1. Capture initial/final `git status --short`. 2. Inspect `git diff --name-only` without mutation. | Check OWN path isolation then write report. | 2 status snapshots; 0 cleanup actions. | `git status` shows no executor-attributable source path delta. | TRUE_BLOCKER only after all recovery branches fail, evidence log records conflict, & exact missing input is named. |
| WRONG_PRODUCER_OR_PROVENANCE | Producer is not Executor-role or report lineage lacks exact commands/hashes | 1. Reject incompatible report/run & inventory its producer field. 2. Restart only invalid report step from last compatible hash checkpoint. | Preserve incompatible artifact separately; continue source inventory without accepting its result. | 1 inventory plus 1 bounded restart. | Producer matches Executor-role, source hashes match baseline, & report lifecycle is ordered. | TRUE_BLOCKER only after all recovery branches fail, evidence log records producer mismatch, & exact missing external input is named. |
| RESOURCE_OR_CAPACITY_FAILURE | Disk or process limit blocks report | 1. Run `Get-PSDrive D` & record free space. 2. Save concise console evidence in memory then retry owned atomic report. | Capture terminal evidence through orchestrator channel without source alteration. | 2 checks; 1 MB report maximum. | Drive free-space count is at least 1 MB & Python command starts. | TRUE_BLOCKER only after all recovery attempts fail, evidence log records capacity checks, & exact missing input is named. |
| AMBIGUOUS_REQUIREMENT | Boundary text has more than one interpretation | 1. Inspect fixed independence definition in Section 2. 2. Quote exact boundary plus eval assertion. | Record interpretation & run objective checks. | 2 source citations; 0 scope expansion. | Evidence matches purpose, distinct tools, & no mandatory route. | TRUE_BLOCKER forbidden: all recovery branches still run, evidence log records interpretation, & no external missing input exists. |
| UNSAFE_OR_OUT_OF_SCOPE_ACTION | Command would alter source or call network | 1. Stop unsafe command & record it. 2. Substitute named read-only inspection command. | Run every safe acceptance command. | 0 unsafe retries; 1 safe substitute. | Substitute command returns status 0 within READ/OWN boundaries. | TRUE_BLOCKER only after all recovery branches fail, evidence log records unsafe step, & exact missing input is named. |
| UNKNOWN_FAILURE | Unclassified error occurs | 1. Capture UTC time, command, cwd, stdout, stderr, & last step. 2. Run `Get-Location; Get-Command py` smallest diagnostic. | Run all unaffected entries & record raw evidence. | 1 diagnostic sequence; 1 bounded rerun. | Diagnostic identifies a known class or required command passes. | TRUE_BLOCKER only after all recovery attempts fail, evidence log records diagnostics, & exact missing input is named. |

## 7. Verification & Acceptance Map

| Requirement | Verification command or action | Expected result | Evidence path | Owner |
|---|---|---|---|---|
| PRODUCER_IDENTITY | Inspect `STATUS`, command ledger, & producer field in report | Executor-role produced report directly from named commands & source hashes | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Orchestrator |
| LIFECYCLE_CHAIN | Verify ordered report markers for expected, started, terminal, delivery, & value terminal | Five states occur once in declared order with terminal command results | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\lifecycle-preflight.log` | Orchestrator |
| NO_SUBSTITUTION | Search report for producer, raw outputs, hashes, & forbidden projection markers | Zero projected/direct closures; every conclusion cites command output or hash | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Orchestrator |
| Purpose boundary | Step 2 exact `rg` command | Boundary quote plus `NO_OPERATIONAL_DISPATCH_ROUTE` marker | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor |
| Validator adversarial test | Step 3 test command | Exit 0 & `PASS: handoff validator accepts` | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor |
| Validator template smoke | Step 3 validator command | Exit 0 & `PASS: handoff is cold-start complete` | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor |
| Eval routing assertion | Step 4 Python JSON assertion | Exit 0 & `EVAL_PASS: handoff-not-dispatch` | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor |
| Source preservation | Step 1/4 Git status plus hashes | No executor-attributable source delta & four SHA-256 values | `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` | Executor |
| Packet integrity | Dispatch validator & receipt commands in Section 8 | `PASS: dispatch is structurally complete` & `RECEIPT_PASS` | `D:\workspace\tools\skills\dispatch\examples\validated-forward-test.receipt.json` | Dispatcher |

## 8. Evidence & Artifact Contract

- **Final verification command:**

```powershell
py -3.11 D:\workspace\tools\skills\dispatch\scripts\validate-dispatch.py D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md --verify-receipt D:\workspace\tools\skills\dispatch\examples\validated-forward-test.receipt.json
```

- **Output paths:** `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\handoff-independence-report.md` & `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\dispatch-sample.receipt.json`.
- **Logs / raw evidence:** Embed verbatim stdout/stderr in report; do not write logs outside `D:\workspace\tools\review\.council-runs\dispatch-handoff-final\forward\`.
- **Hashes / counts / versions:** Record four source SHA-256 hashes, report SHA-256, Python/Git/rg versions, exact handoff file count, & initial/final Git status.
- **Checkpoint / resume state:** After each step, atomically replace owned report with completed sections; resume at first absent section after status/hash reread.
- **Evidence retention:** Retain dispatch, receipt, & report under exact forward directory until primary Codex integrates result.
- **Validated artifact path:** `D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md`
- **Receipt path:** `D:\workspace\tools\skills\dispatch\examples\validated-forward-test.receipt.json`
- **Validator command:**

```powershell
py -3.11 D:\workspace\tools\skills\dispatch\scripts\validate-dispatch.py D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md --write-receipt D:\workspace\tools\skills\dispatch\examples\validated-forward-test.receipt.json
```

- **Receiver hash check:**

```powershell
py -3.11 D:\workspace\tools\skills\dispatch\scripts\validate-dispatch.py D:\workspace\tools\skills\dispatch\examples\validated-forward-test.md --verify-receipt D:\workspace\tools\skills\dispatch\examples\validated-forward-test.receipt.json
```

## 9. Return & Integration Contract

Return exactly:

```text
STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER
SUMMARY: one sentence on independence conclusion and completed checks
ACCEPTANCE: requirement -> command/check -> result -> evidence path
ARTIFACTS: absolute report path plus report SHA-256, source hashes, and file count
CHANGES: only owned report path or none when report write was blocked
COMMANDS: exact commands plus exit codes
RECOVERY: failures, bounded attempts, and resumed step
DEVIATIONS: none or dispatcher-authorized exact deviation
BLOCKER: none or exact blocker packet with UTC timestamp, raw error, evidence, state preserved, missing input, three unblock options, and resume command
NEXT: primary Codex reruns Section 7 acceptance map
```

`COMPLETE` means all six acceptance rows pass. `COMPLETE_WITH_NOTES` means every safe command completed but one or more acceptance rows failed with evidence. `TRUE_BLOCKER` is permitted only under Section 10.

## 10. TRUE_BLOCKER Conditions

Use `TRUE_BLOCKER` only after all applicable Section 6 branches finish, every independent safe check completes, & exact report write cannot occur because: (1) required source plus renamed-source discovery both fail, (2) Python cannot execute required test/validator after tool discovery, (3) permissions deny every owned report write path, (4) disk remains below 1 MB, or (5) external concurrent writer makes exact OWN artifact unsafe. Include failed command, raw output, UTC timestamp, preserved Git status, single missing input, three viable unblock options, recommended owner, & exact resume command.

Proof record: `RECOVERY_EXHAUSTED`, `INDEPENDENT_WORK_COMPLETE`, `RAW_EVIDENCE`, `MISSING_INPUT`, `RESUME_COMMAND`.

## 11. Dispatcher Author Gate

- [x] Fresh executor can locate all source, test, eval, validator, report, & receipt paths.
- [x] Authority order places current user mission above inherited dispatch assumptions or existing report progress.
- [x] No semantic correction exists; packet was still re-derived from zero & every inherited clause is classified.
- [x] Every acceptance/input criterion belongs to `SINGLE_PATH_EXECUTION`.
- [x] SINGLE_PATH matches one bounded decision; full comparative execution is not authorized.
- [x] Typed stage binds no-provider static mode, handoff source tree, admission/pass/exclusions, four runs, & 4 ms minimum wall floor.
- [x] Static validation command has no physical sleep, realtime pacing, downstream dataset, or unresolved estimate.
- [x] Fixture ownership, stage population, 1x4 workload, exact selector, terminal state, & launch-count ledger are explicit.
- [x] JOB_TOTAL_MAX 4 equals stage maximum; supervisor readback occurs before stage, batch, or scope change.
- [x] Broad selectors cannot bypass named validation commands.
- [x] OWN, READ, FORBIDDEN, dirty-work, primary-checkout, & no-network boundaries are exact.
- [x] User authorization covers local read-only validation plus named artifact write only.
- [x] Existing scripts are classified S1 with clean preflight, smoke, correctness, blast, optimization, & SHIP evidence.
- [x] Every execution step has purpose, inputs, command, success state, bound, artifacts, evidence, & recovery.
- [x] Independence definition separates documented boundary mention from operational dependence.
- [x] Validator test, template self-check, Python compile, eval JSON assertion, hashes, & Git preservation have executable acceptance rows.
- [x] Producer, provenance, allowed derivation, & forbidden substitutes are exact.
- [x] Existing work is inventoried & rejected unless producer, hashes, & lifecycle markers match.
- [x] Lifecycle preflight proves expected through value-terminal states with owned evidence.
- [x] Thirteen failure classes each state two branches, degraded work, bounds, observable proceeding, & TRUE_BLOCKER condition.
- [x] No source edits, installs, network, paid cost, deployment, Git mutation, or deletion are authorized.
- [x] Initial/final status plus source hashes make executor-attributable mutation auditable.
- [x] Return format distinguishes COMPLETE, COMPLETE_WITH_NOTES, & TRUE_BLOCKER with evidence.
- [x] Exact dispatch bytes require validator PASS plus sidecar receipt verification before send.
- [x] No dispatch or derived handoff is called ready before validator PASS plus receipt.
