#!/usr/bin/env python3
"""Adversarial smoke checks for validate-dispatch.py."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parents[2]
SKILL_DIR = PACKAGE_ROOT / "skills" / "dispatch"
VALIDATOR = HERE / "validate-dispatch.py"
TEMPLATE = SKILL_DIR / "assets" / "dispatch-template.md"
EXAMPLES = SKILL_DIR / "examples"
CASES = EXAMPLES / "cases"
ROUTE_FIXTURE = EXAMPLES / "dispatch-route-fixture.json"
ROUTE_FIXTURE_RECEIPT = EXAMPLES / "dispatch-route-fixture.receipt.json"
MINIMIZE_FIXTURE = EXAMPLES / "validated-forward-test.minimize.json"
MINIMIZE_VALIDATOR = PACKAGE_ROOT / "src" / "lib" / "minimize" / "minimize_gate.py"
CONCRETE_GIT_SHA = "0123456789abcdef0123456789abcdef01234567"
REAL_PROMPT_DIGEST = "sha256:" + hashlib.sha256(
    b"exact captured dispatch prompt"
).hexdigest()


def authority_context(root: Path) -> dict[str, str]:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "dispatch-test@example.test"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Dispatch Test"], cwd=root, check=True)
    prompt = root / "captured-prompt.txt"
    prompt.write_text("exact captured dispatch prompt", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture source"], cwd=root, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    return {
        "repositoryRoot": str(root),
        "sourceRevision": revision,
        "promptArtifact": str(prompt),
        "promptDigest": "sha256:" + hashlib.sha256(prompt.read_bytes()).hexdigest(),
    }


def bind_paths(
    text: str, path: Path, receipt: Path, bind_commands: bool = True
) -> str:
    if not bind_commands:
        return text
    text = re.sub(
        r"(?m)^- \*\*Validated artifact path:\*\* .*$",
        lambda _: f"- **Validated artifact path:** {path.resolve()}",
        text,
    )
    text = re.sub(
        r"(?m)^- \*\*Receipt path:\*\* .*$",
        lambda _: f"- **Receipt path:** {receipt.resolve()}",
        text,
    )
    text = re.sub(
        r"(- \*\*Validator command:\*\*\s*```[^\n]*\n).*?(\n```)",
        lambda match: (
            match.group(1)
            + f"{sys.executable} {VALIDATOR} {path.resolve()} --write-receipt {receipt.resolve()}"
            + match.group(2)
        ),
        text,
        count=1,
        flags=re.S,
    )
    return re.sub(
        r"(- \*\*Receiver hash check:\*\*\s*```[^\n]*\n).*?(\n```)",
        lambda match: (
            match.group(1)
            + f"{sys.executable} {VALIDATOR} {path.resolve()} --verify-receipt {receipt.resolve()}"
            + match.group(2)
        ),
        text,
        count=1,
        flags=re.S,
    )


def run(
    text: str, bind_commands: bool = True
) -> subprocess.CompletedProcess[str]:
    CASES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=CASES) as directory:
        path = Path(directory).resolve() / "dispatch-case.md"
        receipt = path.with_name("dispatch-case.receipt.json")
        path.write_text(
            bind_paths(text, path, receipt, bind_commands=bind_commands),
            encoding="utf-8",
        )
        minimize = path.with_suffix(".minimize.json")
        minimize_receipt = path.with_suffix(".minimize.receipt.json")
        minimize.write_bytes(MINIMIZE_FIXTURE.read_bytes())
        subprocess.run(
            [
                sys.executable,
                str(MINIMIZE_VALIDATOR),
                "decision",
                "receipt",
                str(minimize),
                str(minimize_receipt),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(path),
                "--write-receipt",
                str(receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
        )


def concrete_fixture() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    stage_row = (
        "| `{{STAGE_ID}}` | `{{GATE_TYPE}}` | {{STAGE_DECISION_QUESTION}} | "
        "{{ALL_CANDIDATES_OR_SURVIVORS_FROM_STAGE_AND_MAX_INPUTS}} | "
        "{{START_OR_PASS_FROM_PRIOR_STAGE}} | "
        "{{NUMERIC_FACTORS_MAX_JOBS_AND_RUNTIME_COUNT_PATH}} | "
        "{{EXACT_SELECTOR_USING_DECLARED_POPULATION}} | "
        "{{PASS_IF_EXACT_THRESHOLD}} | "
        "{{SURVIVOR_ARTIFACT_AND_ACTUAL_COUNT_PATH}} | "
        "{{PROHIBITED_UNTIL_STAGE_PASS_OR_TERMINAL}} |"
    )
    stage_rows = "\n".join(
        [
            "| `TECHNICAL_RUNNABILITY` | `TECHNICAL` | QUESTION_1: Which candidates load and execute on locked runtime? | ALL_CANDIDATES; MAX_INPUTS:20 | START: candidate manifest hash passes | FACTORS:20x1; MAX_JOBS:20; ACTUAL_COUNT:D:/workspace/evidence/stage-1-count.json | SELECTOR: --candidates-from D:/workspace/candidates/all.json | PASS_IF: candidate loads and one probe exits 0 | SURVIVORS:D:/workspace/survivors/technical.json; ACTUAL_COUNT:D:/workspace/evidence/stage-1-count.json | PROHIBITED_UNTIL:TECHNICAL_RUNNABILITY:PASS |",
            "| `BEHAVIORAL_UTILITY` | `BEHAVIORAL` | QUESTION_1: Which runnable candidates trigger all 14 positives? | SURVIVORS_FROM:TECHNICAL_RUNNABILITY; MAX_INPUTS:20 | PASS_FROM:TECHNICAL_RUNNABILITY | FACTORS:20x14; MAX_JOBS:280; ACTUAL_COUNT:D:/workspace/evidence/stage-2-count.json | SELECTOR: --candidates-from D:/workspace/survivors/technical.json --fixtures D:/workspace/fixtures/positives.json | PASS_IF: positive triggers equal 14/14 | SURVIVORS:D:/workspace/survivors/behavioral.json; ACTUAL_COUNT:D:/workspace/evidence/stage-2-count.json | PROHIBITED_UNTIL:BEHAVIORAL_UTILITY:PASS |",
            "| `PERFORMANCE_SHORTLIST` | `PERFORMANCE` | QUESTION_2: Which behavioral survivors rank fastest on DML? | SURVIVORS_FROM:BEHAVIORAL_UTILITY; MAX_INPUTS:20 | PASS_FROM:BEHAVIORAL_UTILITY | FACTORS:20x2x2; MAX_JOBS:80; ACTUAL_COUNT:D:/workspace/evidence/stage-3-count.json | SELECTOR: --candidates-from D:/workspace/survivors/behavioral.json --runtime-arms 2 --scores 2 | PASS_IF: deterministic rank emits top 3 | SURVIVORS:D:/workspace/survivors/performance-top3.json; ACTUAL_COUNT:D:/workspace/evidence/stage-3-count.json | PROHIBITED_UNTIL:PERFORMANCE_SHORTLIST:PASS |",
            "| `SAFETY_NEGATIVES` | `SAFETY_VALIDATION` | QUESTION_1: Which top 3 candidates produce zero controls on 238 negatives? | SURVIVORS_FROM:PERFORMANCE_SHORTLIST; MAX_INPUTS:3 | PASS_FROM:PERFORMANCE_SHORTLIST | FACTORS:3x238; MAX_JOBS:714; ACTUAL_COUNT:D:/workspace/evidence/stage-4-count.json | SELECTOR: --candidates-from D:/workspace/survivors/performance-top3.json --fixtures D:/workspace/fixtures/negatives.json | PASS_IF: false triggers equal 0/238 and winner count equals 1 | SURVIVORS:D:/workspace/survivors/safety-winner.json; ACTUAL_COUNT:D:/workspace/evidence/stage-4-count.json | PROHIBITED_UNTIL:SAFETY_NEGATIVES:PASS |",
            "| `SYSTEM_INTERFERENCE` | `SYSTEM_INTERFERENCE` | QUESTION_2: Does final winner preserve TDT latency under four probe arms? | SURVIVORS_FROM:SAFETY_NEGATIVES; MAX_INPUTS:1 | PASS_FROM:SAFETY_NEGATIVES | FACTORS:1x4; MAX_JOBS:4; ACTUAL_COUNT:D:/workspace/evidence/stage-5-count.json | SELECTOR: --candidates-from D:/workspace/survivors/safety-winner.json --recording D:/workspace/fixtures/58.22s.wav | PASS_IF: declared final latency and interference thresholds pass | SURVIVORS:D:/workspace/survivors/final-winner.json; ACTUAL_COUNT:D:/workspace/evidence/stage-5-count.json | TERMINAL: final winner selected |",
        ]
    )
    fixture_row = (
        "| `{{FIXTURE_ID}}` | `{{EXACT_FIXTURE_PATH_OR_ID}}` | "
        "`{{OWNING_STAGE_ID}}` | {{DECISION_METRIC_OR_GATE}} | "
        "{{ALL_CANDIDATES_OR_SURVIVORS_ONLY}} | "
        "{{RUN_ONLY_IF_STAGE_ENTRY_PASSES}} | {{OTHER_STAGES_OR_NONE_AUTHORIZED}} |"
    )
    fixture_rows = "\n".join(
        [
            "| `candidate-artifacts` | `D:/workspace/candidates/all.json` | `TECHNICAL_RUNNABILITY` | Runtime load and probe execution | ALL_CANDIDATES | RUN_ONLY_IF:TECHNICAL_RUNNABILITY:ENTRY_PASS | FORBID: behavioral or winner claim from runtime-only result |",
            "| `positive-14` | `D:/workspace/fixtures/positives.json` | `BEHAVIORAL_UTILITY` | 14/14 positive trigger gate | SURVIVORS_ONLY:TECHNICAL_RUNNABILITY | RUN_ONLY_IF:BEHAVIORAL_UTILITY:ENTRY_PASS | FORBID: technical, safety, or interference stage |",
            "| `performance-arms` | `D:/workspace/fixtures/performance.json` | `PERFORMANCE_SHORTLIST` | DML latency rank | SURVIVORS_ONLY:BEHAVIORAL_UTILITY | RUN_ONLY_IF:PERFORMANCE_SHORTLIST:ENTRY_PASS | FORBID: candidates failing behavioral gate |",
            "| `negative-238` | `D:/workspace/fixtures/negatives.json` | `SAFETY_NEGATIVES` | 0/238 false-trigger gate | SURVIVORS_ONLY:PERFORMANCE_SHORTLIST | RUN_ONLY_IF:SAFETY_NEGATIVES:ENTRY_PASS | FORBID: broad all-candidate run |",
            "| `recording-58.22s` | `D:/workspace/fixtures/58.22s.wav` | `SYSTEM_INTERFERENCE` | Final-TDT latency under probe arms | SURVIVORS_ONLY:SAFETY_NEGATIVES | RUN_ONLY_IF:SYSTEM_INTERFERENCE:ENTRY_PASS | FORBID: semantic, transcript, or pre-winner use |",
        ]
    )
    typed_row = (
        "| `{{STAGE_ID}}` | {{STAGE_DECISION_QUESTION}} | "
        "{{PROVIDER_AND_REQUIRED_DECISION_METRIC_OR_NO_PROVIDER}} | "
        "{{EXACT_DATASET_SOURCE_AND_ROLE}} | "
        "{{OFFLINE_LOGICAL_CHUNKS_REALTIME_OR_EXACT_MODE}} | "
        "{{ADMIT_IF_EXACT_UPSTREAM_PROOF}} | {{PASS_IF_EXACT_THRESHOLD}} | "
        "{{EXCLUDE_PROVIDER_DATASET_MODE_METRICS_OR_NONE_REASON}} | "
        "{{ESTIMATED_RUNS_INTEGER}} | "
        "{{RUNS_MS_PER_RUN_MIN_MAX_CONCURRENCY_MIN_WALL_MS_AND_EVIDENCE_PATH}} |"
    )
    typed_rows = "\n".join(
        [
            "| `TECHNICAL_RUNNABILITY` | QUESTION_1: Which candidates load and execute on locked runtime? | PROVIDER:DML; REQUIRED_FOR:QUESTION_1:runtime execution | DATASET:D:/workspace/candidates/all.json; ROLE:runtime artifacts | MODE:OFFLINE_LOGICAL_CHUNKS | ADMIT_IF:candidate manifest hash passes | PASS_IF:candidate loads and one probe exits 0 | EXCLUDE:CPU replay, physical sleep, behavior claims, negatives | ESTIMATED_RUNS:20 | WALL_FACTORS:RUNS=20; MS_PER_RUN_MIN=10; MAX_CONCURRENCY=4; MIN_WALL_MS=50; EVIDENCE:D:/workspace/evidence/stage-1-wall.json |",
            "| `BEHAVIORAL_UTILITY` | QUESTION_1: Which runnable candidates trigger all 14 positives? | PROVIDER:DML; REQUIRED_FOR:QUESTION_1:positive trigger count | DATASET:D:/workspace/fixtures/positives.json; ROLE:binary positive gate | MODE:OFFLINE_LOGICAL_CHUNKS | ADMIT_IF:TECHNICAL_RUNNABILITY survivor artifact passes | PASS_IF:positive triggers equal 14/14 | EXCLUDE:CPU replay, physical sleep, negatives, transcripts, latency ranking | ESTIMATED_RUNS:280 | WALL_FACTORS:RUNS=280; MS_PER_RUN_MIN=5; MAX_CONCURRENCY=4; MIN_WALL_MS=350; EVIDENCE:D:/workspace/evidence/stage-2-wall.json |",
            "| `PERFORMANCE_SHORTLIST` | QUESTION_2: Which behavioral survivors rank fastest on DML? | PROVIDER:DML; REQUIRED_FOR:QUESTION_2:DML latency rank | DATASET:D:/workspace/fixtures/performance.json; ROLE:DML performance arms | MODE:OFFLINE_LOGICAL_CHUNKS | ADMIT_IF:BEHAVIORAL_UTILITY survivor artifact passes | PASS_IF:deterministic rank emits top 3 | EXCLUDE:CPU replay, physical sleep, negatives, final recording | ESTIMATED_RUNS:80 | WALL_FACTORS:RUNS=80; MS_PER_RUN_MIN=20; MAX_CONCURRENCY=4; MIN_WALL_MS=400; EVIDENCE:D:/workspace/evidence/stage-3-wall.json |",
            "| `SAFETY_NEGATIVES` | QUESTION_1: Which top 3 candidates produce zero controls on 238 negatives? | PROVIDER:DML; REQUIRED_FOR:QUESTION_1:negative trigger count | DATASET:D:/workspace/fixtures/negatives.json; ROLE:false-trigger safety gate | MODE:OFFLINE_LOGICAL_CHUNKS | ADMIT_IF:PERFORMANCE_SHORTLIST survivor artifact passes | PASS_IF:false triggers equal 0/238 and winner count equals 1 | EXCLUDE:all-candidate replay, physical sleep, transcripts, final recording | ESTIMATED_RUNS:714 | WALL_FACTORS:RUNS=714; MS_PER_RUN_MIN=5; MAX_CONCURRENCY=4; MIN_WALL_MS=893; EVIDENCE:D:/workspace/evidence/stage-4-wall.json |",
            "| `SYSTEM_INTERFERENCE` | QUESTION_2: Does final winner preserve TDT latency under four probe arms? | PROVIDER:TDT_RUNTIME; REQUIRED_FOR:QUESTION_2:final-TDT latency | DATASET:D:/workspace/fixtures/58.22s.wav; ROLE:final interference workload | MODE:REALTIME | ADMIT_IF:SAFETY_NEGATIVES winner artifact passes | PASS_IF:declared final latency and interference thresholds pass | EXCLUDE:non-winners, transcripts, WER, semantic scoring | ESTIMATED_RUNS:4 | WALL_FACTORS:RUNS=4; MS_PER_RUN_MIN=100; MAX_CONCURRENCY=1; MIN_WALL_MS=400; EVIDENCE:D:/workspace/evidence/stage-5-wall.json |",
        ]
    )
    inherited_row = (
        "| `{{INHERITED_CLAUSE_ID}}` | {{EXACT_TEXT_AND_SOURCE}} | "
        "`{{LATEST_USER_INTENT_DECISION_OBJECTIVE_STAGE_CONTRACT_INHERITED_DOCUMENT_OR_EXISTING_PROGRESS}}` | "
        "`{{ALIGNED_CONFLICTS_OR_NO_DECISION_VALUE}}` | "
        "`{{STAGE_ID_OR_NONE}}` | {{KEEP_DELETE_OR_REWRITE_WITH_REQUIRED_REASON}} |"
    )
    inherited_rows = "\n".join(
        [
            "| `latest-objective` | Select model by binary control utility then latency; current user correction | `LATEST_USER_INTENT` | `ALIGNED` | `BEHAVIORAL_UTILITY` | KEEP: DECISION_EFFECT:QUESTION_1 binary trigger qualification |",
            "| `cpu-replay` | CPU + DML inherited plan clause | `INHERITED_DOCUMENT` | `NO_DECISION_VALUE` | `NONE` | DELETE: MATCH_TEXT:cpu; EXCLUDE_FROM:GLOBAL; NO_DECISION_EFFECT:suitability requires locked DML route |",
            "| `cadence-sleep` | 250 ms physical cadence inherited plan clause | `INHERITED_DOCUMENT` | `CONFLICTS` | `NONE` | DELETE: MATCH_TEXT:Start-Sleep; EXCLUDE_FROM:GLOBAL; NO_DECISION_EFFECT:offline qualification uses logical chunks |",
            "| `negative-safety` | 238 negatives only after shortlist | `STAGE_CONTRACT` | `ALIGNED` | `SAFETY_NEGATIVES` | KEEP: DECISION_EFFECT:QUESTION_1 final safety selection |",
        ]
    )
    route_row = (
        "| `{{ROUTE_ID}}` | {{ORDERED_ROUTE_STEP_IDS}} | "
        "{{EXACT_DEPENDENCY_EDGES}} | {{PASS_OR_FAIL_WITH_CONSTRAINT}} | "
        "{{MIN_WALL_MS_INTEGER}} | {{EXPECTED_TIME_TO_VERIFIED_B_MS_INTEGER}} | "
        "{{COST_UNITS_INTEGER}} | "
        "{{RISK_UNITS_INTEGER}} | {{REWORK_UNITS_INTEGER}} | "
        "{{SELECTED_OR_REJECTED}} | "
        "{{DOMINATED_TRADEOFF_CONSTRAINT_OR_ONLY_FEASIBLE_EVIDENCE}} |"
    )
    route_rows = "\n".join(
        [
            "| `R_FAST` | STEPS:R_FAST/S1>R_FAST/S2 | EDGES:R_FAST/S1->R_FAST/S2 | PASS: authority, safety, cost, quality, and scope constraints pass | 900 | 900 | 1 | 1 | 1 | SELECTED | SELECTED_EXPECTED_TIME:EVIDENCE:D:/workspace/evidence/route-fast.json |",
            "| `R_SLOW` | STEPS:R_SLOW/S1>R_SLOW/S2>R_SLOW/S3 | START:R_SLOW/S1,R_SLOW/S2; EDGES:R_SLOW/S1->R_SLOW/S3,R_SLOW/S2->R_SLOW/S3 | PASS: authority, safety, cost, quality, and scope constraints pass | 1200 | 1200 | 2 | 2 | 2 | REJECTED | DOMINATED_BY:R_FAST slower expected completion plus higher cost, risk, and rework; EVIDENCE:D:/workspace/evidence/route-slow.json |",
        ]
    )
    text = (
        text.replace(stage_row, stage_rows)
        .replace(typed_row, typed_rows)
        .replace(fixture_row, fixture_rows)
        .replace(inherited_row, inherited_rows)
        .replace(route_row, route_rows)
    )
    stage_commands = """### Stage command bindings

```powershell
# STAGE_COMMAND:TECHNICAL_RUNNABILITY
Run-Stage -Provider DML -Mode OFFLINE_LOGICAL_CHUNKS -CandidatesFrom D:/workspace/candidates/all.json -Fixtures D:/workspace/candidates/all.json -SurvivorsOut D:/workspace/survivors/technical.json -ActualCountOut D:/workspace/evidence/stage-1-count.json
```

```powershell
# STAGE_COMMAND:BEHAVIORAL_UTILITY
Run-Stage -Provider DML -Mode OFFLINE_LOGICAL_CHUNKS -CandidatesFrom D:/workspace/survivors/technical.json -Fixtures D:/workspace/fixtures/positives.json -SurvivorsOut D:/workspace/survivors/behavioral.json -ActualCountOut D:/workspace/evidence/stage-2-count.json
```

```powershell
# STAGE_COMMAND:PERFORMANCE_SHORTLIST
Run-Stage -Provider DML -Mode OFFLINE_LOGICAL_CHUNKS -CandidatesFrom D:/workspace/survivors/behavioral.json -Fixtures D:/workspace/fixtures/performance.json -SurvivorsOut D:/workspace/survivors/performance-top3.json -ActualCountOut D:/workspace/evidence/stage-3-count.json
```

```powershell
# STAGE_COMMAND:SAFETY_NEGATIVES
Run-Stage -Provider DML -Mode OFFLINE_LOGICAL_CHUNKS -CandidatesFrom D:/workspace/survivors/performance-top3.json -Fixtures D:/workspace/fixtures/negatives.json -SurvivorsOut D:/workspace/survivors/safety-winner.json -ActualCountOut D:/workspace/evidence/stage-4-count.json
```

```powershell
# STAGE_COMMAND:SYSTEM_INTERFERENCE
Run-Stage -Provider TDT_RUNTIME -Mode REALTIME -CandidatesFrom D:/workspace/survivors/safety-winner.json -Fixtures D:/workspace/fixtures/58.22s.wav -SurvivorsOut D:/workspace/survivors/final-winner.json -ActualCountOut D:/workspace/evidence/stage-5-count.json
```"""
    text = re.sub(
        r"### Stage command bindings.*?(?=\n## 2. Source of Truth & Known State)",
        stage_commands,
        text,
        count=1,
        flags=re.S,
    )

    def replacement(match: re.Match[str]) -> str:
        token = match.group(0)[2:-2]
        identity_values = {
            "ROUTINE_EXPERIMENT_BENCHMARK_PERFORMANCE_MODEL_RESEARCH_OR_REPEATED_FAILURE": "EXPERIMENT PERFORMANCE MODEL REPEATED_FAILURE",
            "QUESTION_LOCK_NUMBERED_MINIMUM_QUESTIONS": "QUESTION_1: Does EOU plus production parser fire on 14/14 positives and 0/238 negatives? QUESTION_2: Does continuous EOU probing change final-TDT latency on the exact 58.22-second recording?",
            "DECIDE_BY_EXACT_METRICS_AND_THRESHOLDS": "DECIDE_BY: 14/14 positive triggers, 0/238 negative triggers, and measured final-TDT latency delta across declared runtime arms",
            "METRICS_ONLY_DIRECTLY_NEEDED_FOR_DECISION": "METRICS_ONLY: positive trigger count, negative trigger count, probe cadence and backlog, and final-TDT latency",
            "DIAGNOSTICS_NEVER_ALLOWED_TO_GATE_COMPLETION": "DIAGNOSTIC_ONLY: decoded EOU text, parsed control intent, and measured onset",
            "FORBIDDEN_METRICS_LABELS_MODELS_TOOLS_AND_ANALYSES": "FORBID: exact intent labels | onset ground truth | reference transcript | WER | Whisper | external ASR",
            "WORKLOAD_ROLE_PER_INPUT_WITHOUT_INVENTED_SEMANTICS": "WORKLOAD_ROLE: 14 clips are binary positives only; 238 canonical clips are binary negatives only; exact 58.22-second recording is latency workload only",
            "GROUND_TRUTH_SOURCE_AND_MEASURED_OUTPUT_NOT_PRIOR_LABEL": "GROUND_TRUTH_SOURCE: canonical positive and negative membership only; MEASURED_OUTPUT_NOT_GROUND_TRUTH: onset, decoded text, parsed intent, and latency",
            "LOAD_ONLY_IF_IT_PRODUCES_NAMED_ACCEPTANCE_METRIC": "LOAD_ONLY_IF_METRIC: model or tool directly produces a named trigger or latency acceptance metric",
            "ROUTE_LOCK_OR_NO_MODEL_ALLOWED": "NO_MODEL_ALLOWED: transcription is outside experiment",
            "RECOVERY_RESTORES_REQUIRED_INPUT_BUT_CANNOT_EXPAND_EXPERIMENT": "NO_SCOPE_EXPANSION: recover only required trigger or latency inputs; never invent labels, transcription, or models",
            "REQUIRED_RUN_ID_OR_NOT_REQUIRED_WITH_EXACT_REASON": "REQUIRED: run_id=0d4ce380-d482-41bc-b65c-1049448502b6",
            "ALCHEMIST_STATE_REF_OR_NOT_REQUIRED": "alchemist://run/0d4ce380-d482-41bc-b65c-1049448502b6/state",
            "VERIFIED_NO_CRITICAL_OPEN_OR_NOT_REQUIRED": "VERIFIED_NO_CRITICAL_OPEN",
            "QUESTIONS_METRICS_DIAGNOSTICS_FORBIDDEN_FIRST_ACTION": "READBACK_REQUIRED: questions, metrics, diagnostics, forbidden scope, fixture roles, and exact first action",
            "NUMERIC_TIME_OR_UNIT_CADENCE_PLUS_CHECKPOINTS": "SUPERVISE: after first action, every 5 minutes, and before each model or tool load, scope change, or batch",
            "EXACT_LATEST_USER_INTENT_TO_PROGRESS_ORDER": "LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS",
            "NONE_OR_SEMANTIC_CORRECTION_ID_AND_SOURCE": "SEMANTIC_CORRECTION: ID:eou-scope-20260728; SOURCE:USER_REQUEST",
            "INVENTORY_SOURCE_SEMANTIC_DELTA_AND_EVIDENCE_PATH": "INVENTORY_SOURCE:current user correction plus inherited experiment plan; SEMANTIC_DELTA:YES; EVIDENCE:D:/workspace/evidence/correction-audit.json",
            "NOT_APPLICABLE_OR_PLAN_INVALIDATED_ROOT_DOWNSTREAM_STOP_LOCAL_PATCH_FORBIDDEN": "PLAN_INVALIDATED:ALL; DOWNSTREAM_INVALIDATED_FROM:ROOT; ACTIVE_WORK:STOP_AND_QUARANTINE; LOCAL_PATCH:FORBIDDEN",
            "FROM_ZERO_OBJECTIVE_REQUIREMENTS_STAGES_COMMANDS_COMPLETE": "FROM_ZERO:COMPLETE; OBJECTIVE_RESTATED:COMPLETE; REQUIREMENTS_RECLASSIFIED:COMPLETE; STAGES_REBUILT:COMPLETE; COMMANDS_REBOUND:COMPLETE",
            "PRESERVE_EVIDENCE_ONLY_REUSE_PROOF_STALE_PROGRESS_REJECT": "PRESERVE_EVIDENCE_ONLY; REUSE_ONLY_IF:new typed stage provider, dataset, mode, admission, and pass contract match; STALE_PROGRESS:REJECT",
            "INVENTORY_TOTAL_CLASSIFIED_TOTAL_UNCLASSIFIED_ZERO_AND_EVIDENCE_PATH": "INVENTORY_TOTAL:4; CLASSIFIED_TOTAL:4; UNCLASSIFIED:0; EVIDENCE:D:/workspace/evidence/inherited-inventory.json",
            "SCHEMA_RUN_ID_STATE_REF_AND_TYPED_STAGE_CHECKPOINT": "SCHEMA:dispatch.stage.v1; RUN_ID:0d4ce380-d482-41bc-b65c-1049448502b6; STATE:alchemist://run/0d4ce380-d482-41bc-b65c-1049448502b6/state; CHECKPOINT:TYPED_STAGES",
            "EXACT_VERIFIED_CURRENT_STATE_A": "STATE_A: inherited experiment plan has unqualified candidate matrix and no executable survivor route",
            "EXACT_VERIFIABLE_TARGET_STATE_B": "STATE_B: validated survivor funnel emits one production-path winner with trigger and latency evidence",
            "EXACT_COMMAND_OR_CHECK_PROVING_B": "PROOF: run D:/workspace/tools/verify-final.ps1 and require D:/workspace/evidence/final-pass.json",
            "AUTHORITY_SAFETY_COST_TIME_QUALITY_AND_SCOPE_CONSTRAINTS": "CONSTRAINTS: AUTHORITY=current user; SAFETY=production path; COST=bounded local; QUALITY=acceptance thresholds; SCOPE=declared experiment only",
            "COMPARE_OR_SINGLE_FEASIBLE": "COMPARE",
            "CHECKOUT_RELATIVE_GOAL_ROUTE_V2_JSON_PATH": str(ROUTE_FIXTURE.resolve()),
            "CHECKOUT_RELATIVE_GOAL_ROUTE_RECEIPT_PATH": str(
                ROUTE_FIXTURE_RECEIPT.resolve()
            ),
            "SELECTED_ROUTE_ID": "SELECTED_ROUTE:R_FAST",
            "EXPECTED_TIME_TO_VERIFIED_B_MS_INTEGER": "900",
            "POSITIVE_ROUTE_REVISION": "1",
            "EXPECTED_TIME_DOMINANCE_PROOF_AGAINST_EVERY_OTHER_ROUTE": "EXPECTED_TIME_PROOF: R_FAST has minimum expected time to verified B and R_SLOW is slower with higher cost, risk, and rework",
            "ORDERED_ROUTE_STEP_IDS_AND_TOTAL_MIN_WALL_MS": "CRITICAL_PATH:R_FAST/S1>R_FAST/S2; TOTAL_MIN_WALL_MS:900",
            "BOTTLENECK_STEP_RESOURCE_AND_BOUND": "BOTTLENECK: R_FAST/S2 DML scoring is bounded to 900 minimum wall milliseconds",
            "PARALLEL_GROUPS_OR_NONE_WITH_DEPENDENCY_PROOF": "PARALLEL: fixture hash and runtime identity checks overlap before R_FAST/S2",
            "DELETE_NON_ADVANCING_AND_DEFER_DOWNSTREAM_ITEMS": "DELETE: transcripts, WER, CPU replay, and broad negative matrix; DEFER: safety negatives and interference until survivor gates pass",
            "ROUTE_SCHEMA_RUN_STATE_CHECKPOINT_OR_NOT_REQUIRED_REASON": "SCHEMA:goal-route.v2; RUN_ID:0d4ce380-d482-41bc-b65c-1049448502b6; STATE:alchemist://run/0d4ce380-d482-41bc-b65c-1049448502b6/state; CHECKPOINT:GOAL_ROUTE_V2",
            "SELECTED_ROUTE_AND_STEP_ID": "ROUTE_STEP:R_FAST/S1",
            "OBSERVABLE_STATE_B_DELTA": "ADVANCES_STATE_B: creates verified candidate manifest required by selected route",
            "START_OR_AFTER_ROUTE_STEP_IDS": "START: selected route begins from verified STATE_A",
            "STATE_A_TO_STATE_B": "STATE_A inherited invalid matrix -> STATE_B validated production-path winner",
            "SELECTED_ROUTE_ID_AND_ORDERED_STEPS": "R_FAST with R_FAST/S1>R_FAST/S2",
            "ROUTE_DOMINANCE_PROOF": "R_FAST has minimum expected time to verified B",
            "CRITICAL_PATH_BOTTLENECK": "R_FAST/S2 DML scoring bounded to 900 milliseconds",
            "PARALLEL_LANES_OR_DEPENDENCY_BOUND_NONE": "fixture hash and runtime identity checks overlap before scoring",
            "EXPLICIT_DEFERRED_OR_DELETED_WORK": "transcripts and broad matrix deleted; safety and interference deferred to survivor gates",
            "PRODUCER_QUESTION_OR_EXECUTION_DEPENDENCY": "QUESTION_1 production parser trigger must come from required producer",
            "PRODUCER_DECISION_EFFECT": "reject trigger result from any other producer",
            "LIFECYCLE_QUESTION_OR_EXECUTION_DEPENDENCY": "QUESTION_1 trigger and QUESTION_2 latency require linked production lifecycle",
            "LIFECYCLE_DECISION_EFFECT": "reject orphan or incomplete measurement",
            "DERIVATION_QUESTION_OR_EXECUTION_DEPENDENCY": "QUESTION_1 and QUESTION_2 require direct measured results",
            "DERIVATION_DECISION_EFFECT": "reject projections or reconstructed acceptance",
            "REQUIREMENT_ID": "TRIGGER_AND_LATENCY_METRICS",
            "ACCEPTANCE_DIAGNOSTIC_EXECUTION_INPUT_SAFETY_OR_FORBIDDEN": "ACCEPTANCE",
            "EXACT_QUESTION_AND_METRIC": "QUESTION_1 positive and negative trigger counts plus QUESTION_2 final-TDT latency",
            "YES_OR_NO_WITH_DECISION_EFFECT": "YES — directly selects pass or fail",
            "REJECT_IF_UNMAPPED_ACTION": "Remove requirement before release when no question or safety trace exists",
            "QUESTION_IT_EXPLAINS_WITHOUT_GATING": "Explains QUESTION_1 trigger failures only",
            "KEEP_DIAGNOSTIC_OR_DROP_IF_COSTLY": "Keep only when already emitted; drop when it adds load",
            "WHY_NECESSARY_TO_RUN_ACCEPTANCE_MEASUREMENT": "Binary clip membership and exact latency workload are required execution inputs",
            "REJECT_INVENTED_INPUT_ACTION": "Reject intent labels, onset labels, and transcripts",
            "USER_NON_GOAL_OR_NO_DECISION_VALUE": "No decision value for trigger count or latency delta",
            "STOP_AND_REMOVE_ACTION": "Stop proposed load and remove requirement",
            "MODEL_TOOL_OR_NONE": "MODEL: Whisper",
            "EXACT_METRIC_OR_NONE": "NONE — produces no acceptance metric",
            "EXACT_ROUTE_VERSION_OR_FORBIDDEN": "NO_MODEL_ALLOWED: transcription outside scope",
            "TIME_VRAM_MEMORY_NETWORK_COST_OR_NONE": "VRAM, time, memory, and attention cost",
            "ALLOW_OR_FORBID_WITH_REASON": "FORBID: produces no acceptance metric",
            "RELEVANCE_EVIDENCE_PATH": "D:/workspace/evidence/model-relevance.md",
            "SELECTION_FUNNEL_FULL_COMPARATIVE_DATASET_OR_SINGLE_PATH": "SELECTION_FUNNEL",
            "NOT_AUTHORIZED_OR_FULL_COMPARATIVE_DATASET_AUTHORIZED_SOURCE_AND_REASON": "NOT_AUTHORIZED: user requested winner selection, not complete comparative dataset",
            "RUN_ONLY_IF_RESULT_CAN_CHANGE_DECISION_OTHERWISE_SKIP": "RUN_ONLY_IF: result can change advance, reject, rank, winner, or safety decision; SKIP: result cannot change remaining decision",
            "JOB_TOTAL_MAX_NUMERIC_SUM": "JOB_TOTAL_MAX:1098",
            "MIN_WALL_MS_TOTAL_NUMERIC_SUM": "MIN_WALL_MS_TOTAL:2093",
            "RESOLVED_RUNS_WALL_TIME_AND_CONCURRENCY_OR_BLOCK": "RESOLVED:RUNS_WALL_TIME_CONCURRENCY",
            "RECONCILE_STAGE_ACTUAL_SUM_AGAINST_DECLARED_TOTAL_AND_EVIDENCE_PATH": "RECONCILE: STAGE_ACTUAL_SUM must equal launched jobs and remain within JOB_TOTAL_MAX; BLOCK_IF_MISMATCH; EVIDENCE:D:/workspace/evidence/launch-reconcile.json",
            "READBACK_AND_RECHECK_BEFORE_STAGE_BATCH_OR_SCOPE_CHANGE": "READBACK_REQUIRED: topology, stage order, survivor source, stage MAX_JOBS, and actual jobs; BEFORE_STAGE: every 1 stage and before batch or scope change",
            "FORBID_ALL_WILDCARD_FULL_CORPUS_OR_EXACT_AUTHORIZED_SCOPE": "FORBID_BROAD_SELECTORS: --all, wildcard candidates, full corpus, or all-candidate downstream runs",
            "PRODUCER_ID_AND_PROOF_FIELD": "PRODUCER: membrane_planner | PROOF_FIELD: producer",
            "ALLOW_ONLY_EXACT_SOURCE_CHAIN": "ALLOW_ONLY: provider.expected -> membrane_planner -> delivered value",
            "FORBID_EXACT_PRODUCERS_TRANSFORMS_OR_NONE_CHECKED": "FORBID: producer=design, direct closures, substitution projections",
            "INVENTORY_REJECT_IF_INCOMPATIBLE_RESUME_ONLY_IF": "INVENTORY: inspect D:/workspace/evidence/runs.json; REJECT_IF_INCOMPATIBLE: producer != membrane_planner; RESUME_ONLY_IF: producer and lifecycle match",
            "LIFECYCLE_WITH_AT_LEAST_FIVE_ORDERED_STATES": "LIFECYCLE: provider.expected -> started -> terminal -> delivery -> value_terminal",
            "NO_SUBSTITUTION_OR_EXACT_AUTHORIZED_EQUIVALENTS": "NO_SUBSTITUTION — direct closures and projections are forbidden",
            "DIRECT_ONLY_SOURCE_AND_TERMINAL_VALUE": "DIRECT_ONLY: delivered value from membrane_planner terminal record",
            "FORBID_PROJECTION_DIRECT_CLOSURE_OR_OTHER_INVALID_DERIVATION": "FORBID: direct closure, design producer, projection, or synthetic stand-in",
            "EXACT_PRODUCER_PROVENANCE_LIFECYCLE_PREFLIGHT_COMMAND": "Run Get-Content -LiteralPath D:/workspace/evidence/runs.json and record D:/workspace/evidence/lifecycle-preflight.log",
            "EXACT_PRODUCER_AND_PROVENANCE_CHECK": "Run producer check and record producer field",
            "REQUIRED_PRODUCER_AND_LINEAGE_VALUE": "producer=membrane_planner and lineage matches",
            "EXACT_ORDERED_LIFECYCLE_CHECK": "Run ordered state check over receipt events",
            "ALL_REQUIRED_STATES_TERMINAL_AND_DELIVERY_VALUE": "expected, started, terminal, delivery, and value_terminal each occur once in order",
            "EXACT_DERIVATION_CHECK": "Run derivation check over terminal records",
            "NO_FORBIDDEN_PRODUCER_PROJECTION_OR_DIRECT_CLOSURE": "zero design producers, projections, direct closures, or substitutes",
            "INVARIANTS_EMBEDDED_HERE_NOT_DELEGATED_TO_GUIDE": "INVARIANT: producer=membrane_planner; INVARIANT: provider.expected links through value_terminal; INVARIANT: P3 forbids substitutions",
            "RESET_REQUIRED_OR_RESUME_ALLOWED_IF_EXACT_COMPATIBILITY_PROOF": "RESET_REQUIRED: current producer=design is incompatible",
            "STOP_PRESERVE_OR_DISCARD_DO_NOT_COMMIT_RULE": "STOP current run; DISCARD invalid window; DO_NOT_COMMIT incompatible evidence",
            "PULL_OR_REREAD_CORRECTED_AUTHORITY_AND_HASH": "AUTHORITY_REFRESH: read D:/workspace/authority.md and record SHA-256",
            "PRODUCTION_PATH_WITH_ENTRY_MORPHER_HOOK_RUNTIME_DELIVERY_VALUE": "PRODUCTION_PATH: CLI -> root hook -> membrane_planner -> delivery -> value_terminal",
            "HASH_VERIFY_EXACT_COMPONENTS_CONFIG_HOOKS_AND_RUNTIME": "HASH_VERIFY: run Get-FileHash on D:/workspace/hook.ps1, D:/workspace/config.json, and D:/workspace/runtime.exe",
            "TRACE_LINK_FIELDS_ACROSS_EXPECTED_STARTED_TERMINAL_DELIVERY_VALUE": "TRACE_LINK: expected.id -> started.attempt_of -> terminal.terminal_of -> delivered.trace_id -> value.trace_id",
            "PROHIBITED_UNTIL_CANARY_PASS": "PROHIBITED_UNTIL_CANARY_PASS — zero batch calls before one trace passes",
            "DEFECT_ONLY_IF_PRODUCTION_PATH_PROVEN_CANARY_PASS_AND_CANONICAL_CHECK_FAILS": "DEFECT_ONLY_IF: PRODUCTION_PATH_PROVEN and CANARY_PASS and CANONICAL_CHECK_FAILS with matching trace",
            "STOP_DISCARD_INVALID_WINDOW_PULL_AUTHORITY_REVERIFY_RESTART_PREFLIGHT": "STOP -> DISCARD_INVALID_WINDOW -> PULL_AUTHORITY -> REVERIFY -> RESTART_PREFLIGHT",
            "EXACT_APPEND_ONLY_DIRTY_STATE_OR_INTEGRITY_COMMAND_AND_EVIDENCE_PATH": "Run git -C D:/workspace status --short and record D:/workspace/evidence/environment-integrity.log",
            "EXACT_ONE_TRACE_OR_ONE_UNIT_COMMAND_ASSERTIONS_AND_EVIDENCE_PATH": "Run D:/workspace/tools/one-trace.ps1 and record D:/workspace/evidence/one-trace.json",
            "STAGE_ID": "SYSTEM_INTERFERENCE",
            "STAGE_ID_OR_NONE": "SYSTEM_INTERFERENCE",
        }
        if token in identity_values:
            return identity_values[token]
        if token == "YES_OR_NO":
            return "YES"
        if "SCRIPT_SKILL" in token:
            return "D:/workspace/tools/skills/script/SKILL.md"
        if "SCRIPT" in token and ("PATH" in token or "CREATED" in token):
            return "D:/workspace/tools/run-task.ps1"
        if "ORCHESTRATOR_CREATED" in token:
            return "ORCHESTRATOR_CREATED"
        if "NO_SCRIPT" in token or "REASON_OR_NOT_APPLICABLE" in token:
            return "NOT_APPLICABLE — orchestrator created script"
        if "S0_S1" in token:
            return "S1"
        if "YES_OR_NO_WITH" in token:
            return "YES"
        if "BOUND" in token or "MAX_DURATION" in token:
            return "2 attempts within 30 seconds"
        if "SIGNAL" in token:
            return "command exits 2 and stderr contains missing"
        if "TRUE_BLOCKER" in token:
            return "Return TRUE_BLOCKER only after all recovery branches fail, evidence log exists, and missing input is named"
        if token in {"PRIMARY_ACTION", "EXACT_RECOVERY_ACTION"}:
            return "Run Get-Item -LiteralPath D:/workspace/input.txt"
        if token == "SECOND_ACTION":
            return "Search with rg --files D:/workspace and record D:/workspace/evidence/search.log"
        if "CONDITION" in token or "EXPECTED_RESULT" in token:
            return "command exits 0 and D:/workspace/evidence/pass.log exists"
        if any(word in token for word in ("CONTINUE", "FALLBACK", "SUBSET", "FIXTURE", "QUARANTINE", "UNAFFECTED", "PROBE", "INTERPRETATION", "READ_ONLY")):
            return "Continue read-only checks and record D:/workspace/evidence/degraded.log"
        if any(word in token for word in ("COMMAND", "ACTION", "CHECK", "VALIDATION", "RETRIEVAL", "FETCH")):
            return "Run Get-Item -LiteralPath D:/workspace/input.txt and record exit code"
        if any(word in token for word in ("PATH", "DIRECTORY", "LOCATION")):
            return "D:/workspace/artifacts/result.json"
        if "OWNER" in token or token in {"REQUESTER", "DISPATCH_AUTHOR", "EXECUTOR_OR_ROLE", "VERIFICATION_OWNER"}:
            return "executor"
        if "ACTIVE_OR_NONE" in token:
            return "NONE — no active dispatch"
        if "OTHER_DISPATCH_OR_NONE" in token:
            return "NONE — no other active dispatch"
        if "NO_OVERLAP" in token:
            return "NO_OVERLAP — inventory is empty"
        if "PRE" in token and "RESULT" in token:
            return "Run preflight; exit code 0 and D:/workspace/evidence/pre.log exists"
        if "SMOKE" in token:
            return "Run D:/workspace/tools/run-task.ps1 on 2 files; stdout processed=2"
        if "CORRECTNESS" in token:
            return "Check output count equals 2; D:/workspace/evidence/smoke.log"
        if "BLAST" in token:
            return "Reads D:/workspace/input; writes D:/workspace/artifacts; no network or cost"
        if "OPT" in token:
            return "No duplicate work; bounded retry; atomic D:/workspace/artifacts/result.json"
        if "EXIT_CODE" in token:
            return "exit code 0"
        if "EXPECTED_PROPERTIES" in token:
            return "UTF-8 JSON, at least 1 byte, SHA-256 recorded"
        if "STATUS" in token:
            return "NONE — no active dispatch"
        return "documented concrete task value"

    text = re.sub(r"\{\{[^{}\n]+\}\}", replacement, text)
    text = text.replace("- [ ]", "- [x]")
    step_match = re.search(
        r"(### Step 1 —.*?)(?=\n## 5A\. Script & Runner Gate)",
        text,
        re.S,
    )
    assert step_match
    step_two = (
        step_match.group(1)
        .replace("### Step 1 —", "### Step 2 —", 1)
        .replace("ROUTE_STEP:R_FAST/S1", "ROUTE_STEP:R_FAST/S2", 1)
        .replace(
            "ADVANCES_STATE_B: creates verified candidate manifest required by selected route",
            "ADVANCES_STATE_B: emits verified final winner evidence required by STATE_B",
            1,
        )
        .replace(
            "START: selected route begins from verified STATE_A",
            "AFTER: R_FAST/S1",
            1,
        )
    )
    return text.replace(step_match.group(1), step_match.group(1) + "\n\n" + step_two, 1)


def full_comparative_fixture(selection_fixture: str) -> str:
    text = selection_fixture.replace(
        "**Inherited inventory reconciliation:** INVENTORY_TOTAL:4; CLASSIFIED_TOTAL:4; UNCLASSIFIED:0; EVIDENCE:D:/workspace/evidence/inherited-inventory.json",
        "**Inherited inventory reconciliation:** INVENTORY_TOTAL:3; CLASSIFIED_TOTAL:3; UNCLASSIFIED:0; EVIDENCE:D:/workspace/evidence/inherited-inventory.json",
    ).replace(
        "**Topology mode:** SELECTION_FUNNEL",
        "**Topology mode:** FULL_COMPARATIVE_DATASET",
    ).replace(
        "**Full-matrix authorization:** NOT_AUTHORIZED: user requested winner selection, not complete comparative dataset",
        "**Full-matrix authorization:** FULL_COMPARATIVE_DATASET_AUTHORIZED: SOURCE:USER_REQUEST; REASON: user explicitly requires complete arm-by-arm public dataset",
    ).replace(
        "**Declared launch ceiling:** JOB_TOTAL_MAX:1098",
        "**Declared launch ceiling:** JOB_TOTAL_MAX:20160",
    ).replace(
        "**Declared minimum wall time:** MIN_WALL_MS_TOTAL:2093",
        "**Declared minimum wall time:** MIN_WALL_MS_TOTAL:25200",
    ).replace(
        "**Broad selector policy:** FORBID_BROAD_SELECTORS: --all, wildcard candidates, full corpus, or all-candidate downstream runs",
        "**Broad selector policy:** AUTHORIZED_SCOPE: --all is limited to declared 20 candidates, 2 runtimes, 2 scores, and 252 fixtures",
    )
    for stage_id in (
        "TECHNICAL_RUNNABILITY",
        "BEHAVIORAL_UTILITY",
        "PERFORMANCE_SHORTLIST",
        "SAFETY_NEGATIVES",
        "SYSTEM_INTERFERENCE",
    ):
        text = text.replace(
            f"| `{stage_id}` |",
            "| `FULL_COMPARATIVE_MATRIX` |",
        )
    stage_table = """### Stage decision funnel

| Stage ID | Gate type | Decision question | Input population + max | Entry gate | Workload formula + count | Command selector | Exit gate | Survivor artifact + actual-count ledger | Downstream prohibited until |
|---|---|---|---|---|---|---|---|---|---|
| `FULL_COMPARATIVE_MATRIX` | `FULL_MATRIX` | QUESTION_1: What is every declared arm result across complete corpus? | ALL_CANDIDATES; MAX_INPUTS:20 | START: explicit comparative authorization and manifest hash pass | FACTORS:20x2x2x252; MAX_JOBS:20160; ACTUAL_COUNT:D:/workspace/evidence/full-count.json | SELECTOR: --all --fixtures D:/workspace/fixtures/full-corpus.json | PASS_IF: every declared matrix cell has terminal evidence | SURVIVORS:D:/workspace/results/full-matrix.json; ACTUAL_COUNT:D:/workspace/evidence/full-count.json | TERMINAL: complete comparative dataset emitted |"""
    text = re.sub(
        r"### Stage decision funnel.*?(?=\n### Typed stage records)",
        stage_table,
        text,
        count=1,
        flags=re.S,
    )
    typed_table = """### Typed stage records

| Stage ID | Decision | Provider binding | Dataset + role | Execution mode | Admission | Pass rule | Explicit exclusions | Estimated runs | Minimum wall-time factors |
|---|---|---|---|---|---|---|---|---|---|
| `FULL_COMPARATIVE_MATRIX` | QUESTION_1: What is every declared arm result across complete corpus? | PROVIDER:MATRIX_RUNNER; REQUIRED_FOR:QUESTION_1:complete arm-by-arm dataset | DATASET:D:/workspace/fixtures/full-corpus.json; ROLE:complete comparative corpus | MODE:OFFLINE_LOGICAL_CHUNKS | ADMIT_IF:explicit full-comparison authorization and manifest hash pass | PASS_IF:every declared matrix cell has terminal evidence | EXCLUDE:physical sleep, undeclared candidates, undeclared fixtures | ESTIMATED_RUNS:20160 | WALL_FACTORS:RUNS=20160; MS_PER_RUN_MIN=5; MAX_CONCURRENCY=4; MIN_WALL_MS=25200; EVIDENCE:D:/workspace/evidence/full-wall.json |"""
    text = re.sub(
        r"### Typed stage records.*?(?=\n### Fixture-stage ownership)",
        typed_table,
        text,
        count=1,
        flags=re.S,
    )
    fixture_table = """### Fixture-stage ownership

| Fixture ID | Exact source | Owning stage | Decision role | Population scope | Use condition | Forbidden outside |
|---|---|---|---|---|---|---|
| `full-corpus-252` | `D:/workspace/fixtures/full-corpus.json` | `FULL_COMPARATIVE_MATRIX` | Complete public arm-by-arm comparison | ALL_CANDIDATES_AUTHORIZED | RUN_ONLY_IF:FULL_COMPARATIVE_MATRIX:ENTRY_PASS | NONE_AUTHORIZED: fixture use is confined to declared full matrix |"""
    text = re.sub(
        r"### Fixture-stage ownership.*?(?=\n### Stage command bindings)",
        fixture_table,
        text,
        count=1,
        flags=re.S,
    )
    inherited_table = """### Inherited instruction disposition

| Inherited clause ID | Exact inherited text / source | Source rank | Objective compatibility | Stage owner | Disposition + reason/effect |
|---|---|---|---|---|---|
| `latest-objective` | User requires complete arm-by-arm public dataset | `LATEST_USER_INTENT` | `ALIGNED` | `FULL_COMPARATIVE_MATRIX` | KEEP: DECISION_EFFECT:QUESTION_1 complete matrix delivery |
| `cpu-dml-matrix` | CPU + DML inherited matrix clause | `STAGE_CONTRACT` | `ALIGNED` | `FULL_COMPARATIVE_MATRIX` | KEEP: DECISION_EFFECT:QUESTION_1 complete runtime comparison |
| `stale-labels` | Intent and onset labels from superseded plan | `INHERITED_DOCUMENT` | `NO_DECISION_VALUE` | `NONE` | DELETE: MATCH_TEXT:intent labels; EXCLUDE_FROM:GLOBAL; NO_DECISION_EFFECT:complete runtime comparison needs no labels |"""
    text = re.sub(
        r"### Inherited instruction disposition.*?(?=\n## 1C. Goal Route & Critical Path)",
        inherited_table,
        text,
        count=1,
        flags=re.S,
    )
    full_command = """### Stage command bindings

```powershell
# STAGE_COMMAND:FULL_COMPARATIVE_MATRIX
Run-Stage -Provider MATRIX_RUNNER -Mode OFFLINE_LOGICAL_CHUNKS --all -Fixtures D:/workspace/fixtures/full-corpus.json -SurvivorsOut D:/workspace/results/full-matrix.json -ActualCountOut D:/workspace/evidence/full-count.json
```"""
    return re.sub(
        r"### Stage command bindings.*?(?=\n## 2. Source of Truth & Known State)",
        full_command,
        text,
        count=1,
        flags=re.S,
    )


def main() -> int:
    spec = importlib.util.spec_from_file_location("dispatch_validator", VALIDATOR)
    assert spec and spec.loader
    validator_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator_module)
    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        artifact = repo / "tasks" / "dispatches" / "portable.md"
        artifact.parent.mkdir(parents=True)
        assert (
            validator_module.canonical_locator(artifact)
            == "tasks/dispatches/portable.md"
        )
        assert validator_module.resolve_declared_path(
            "tasks/dispatches/portable.md", artifact
        ) == artifact.resolve()
    assert validator_module.normalized_path(
        "/Volumes/Example/Workspace/Packet.md", "posix"
    ) != validator_module.normalized_path(
        "/Volumes/Example/Workspace/packet.md", "posix"
    )

    template_check = subprocess.run(
        [sys.executable, str(VALIDATOR), "--template-self-check", str(TEMPLATE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert template_check.returncode == 0, template_check.stdout + template_check.stderr

    good = concrete_fixture()
    result = run(good)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "sha256=" in result.stdout

    managed_routes = (
        "```sh\n"
        "rightkit cargo test --workspace\n"
        "rightkit rustc --version\n"
        "rightkit rustdoc --version\n"
        "rightkit build cargo -- test --workspace\n"
        "```\n"
    )
    assert not validator_module.managed_rust_route_errors(managed_routes)
    for bypass in (
        "cargo test --workspace",
        "/usr/local/bin/cargo test",
        "rustup run stable cargo test",
        "command cargo test",
        "env CARGO_TARGET_DIR=/tmp cargo test",
        "$cargo test",
        "alias c='cargo test'",
        "rustc --version",
        "rustdoc --version",
    ):
        route_errors = validator_module.managed_rust_route_errors(
            f"```sh\n{bypass}\n```"
        )
        assert route_errors, bypass
        assert "managed Rust route violation" in route_errors[0]

    fenced_direct_cargo = run(re.sub(
        r"(- \*\*Exact action / command:\*\*\s*```[^\n]*\n).*?(\n```)",
        r"\1cargo test --workspace\2",
        good,
        count=1,
        flags=re.S,
    ))
    assert fenced_direct_cargo.returncode == 1
    assert "managed Rust route violation in fenced block" in fenced_direct_cargo.stdout

    inline_direct_cargo = validator_module.managed_rust_route_errors(
        "Use `cargo test --workspace` before delivery."
    )
    assert any("inline code" in error for error in inline_direct_cargo)
    table_direct_cargo = validator_module.managed_rust_route_errors(
        "| command | cargo test --workspace |"
    )
    assert any("table cell" in error for error in table_direct_cargo)
    label_direct_cargo = validator_module.managed_rust_route_errors(
        "- **Final verification command:** cargo test --workspace"
    )
    assert any("label value" in error for error in label_direct_cargo)

    route_document = json.loads(ROUTE_FIXTURE.read_text(encoding="utf-8"))
    route_document["state_b"]["proof"][0]["command"] = "cargo test --workspace"
    route_direct_cargo = validator_module.managed_rust_route_errors(
        good, route_document=route_document
    )
    assert any("GoalRoute state_b.proof[1].command" in error for error in route_direct_cargo)

    route_mirror_tamper = run(
        good.replace(
            "| 1200 | 1200 | 2 | 2 | 2 | REJECTED | DOMINATED_BY:R_FAST",
            "| 800 | 800 | 2 | 2 | 2 | REJECTED | TRADEOFF:EVIDENCE:D:/workspace/evidence/route-slow.json",
            1,
        )
    )
    assert route_mirror_tamper.returncode == 1
    assert "must match GoalRoute artifact" in route_mirror_tamper.stdout

    critical_path_mismatch = run(
        good.replace("TOTAL_MIN_WALL_MS:900", "TOTAL_MIN_WALL_MS:901", 1)
    )
    assert critical_path_mismatch.returncode == 1
    assert "must equal selected route wall" in critical_path_mismatch.stdout

    wrong_route_step = run(
        good.replace("ROUTE_STEP:R_FAST/S1", "ROUTE_STEP:R_SLOW/S1", 1)
    )
    assert wrong_route_step.returncode == 1
    assert "binds non-selected route" in wrong_route_step.stdout

    missing_selected_step = run(
        re.sub(
            r"\n\n### Step 2 —.*?(?=\n## 5A\. Script & Runner Gate)",
            "",
            good,
            count=1,
            flags=re.S,
        )
    )
    assert missing_selected_step.returncode == 1
    assert "exactly cover selected route steps" in missing_selected_step.stdout

    false_route_edge = run(
        good.replace(
            "EDGES:R_FAST/S1->R_FAST/S2",
            "EDGES:R_FAST/S2->R_FAST/S1",
            1,
        )
    )
    assert false_route_edge.returncode == 1
    assert "dependency DAG must match GoalRoute artifact" in false_route_edge.stdout

    non_advancing_step = run(
        good.replace("ADVANCES_STATE_B:", "DIAGNOSTIC_ONLY:", 1)
    )
    assert non_advancing_step.returncode == 1
    assert "lacks observable ADVANCES_STATE_B delta" in non_advancing_step.stdout

    unbound_route = run(
        good.replace(
            "SCHEMA:goal-route.v2; RUN_ID:0d4ce380-d482-41bc-b65c-1049448502b6",
            "SCHEMA:goal-route.v2; NOT_REQUIRED: route was not frozen",
            1,
        )
    )
    assert unbound_route.returncode == 1
    assert "Route Alchemist binding must match GoalRoute artifact" in unbound_route.stdout

    uncorrected_good = good.replace(
        "**Correction state:** SEMANTIC_CORRECTION: ID:eou-scope-20260728; SOURCE:USER_REQUEST",
        "**Correction state:** NONE: fresh dispatch derived from current user request",
        1,
    ).replace(
        "SEMANTIC_DELTA:YES",
        "SEMANTIC_DELTA:NO",
        1,
    ).replace(
        "**Plan invalidation:** PLAN_INVALIDATED:ALL; DOWNSTREAM_INVALIDATED_FROM:ROOT; ACTIVE_WORK:STOP_AND_QUARANTINE; LOCAL_PATCH:FORBIDDEN",
        "**Plan invalidation:** NOT_APPLICABLE:NO_SEMANTIC_CORRECTION",
        1,
    )
    uncorrected_result = run(uncorrected_good)
    assert uncorrected_result.returncode == 1
    assert (
        "dispatch correction state must match GoalRoute artifact"
        in uncorrected_result.stdout
    )

    wrong_authority_order = run(good.replace(
        "LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS",
        "INHERITED_DOCUMENT > LATEST_USER_INTENT > EXISTING_IMPLEMENTATION_OR_PROGRESS",
        1,
    ))
    assert wrong_authority_order.returncode == 1
    assert "**Authority order:** must be LATEST_USER_INTENT" in wrong_authority_order.stdout

    correction_local_patch = run(good.replace(
        "PLAN_INVALIDATED:ALL; DOWNSTREAM_INVALIDATED_FROM:ROOT; ACTIVE_WORK:STOP_AND_QUARANTINE; LOCAL_PATCH:FORBIDDEN",
        "PLAN_PATCHED:LOCAL; DOWNSTREAM_PRESERVED",
        1,
    ))
    assert correction_local_patch.returncode == 1
    assert "semantic correction requires PLAN_INVALIDATED:ALL" in correction_local_patch.stdout

    false_no_correction = run(good.replace(
        "**Correction state:** SEMANTIC_CORRECTION: ID:eou-scope-20260728; SOURCE:USER_REQUEST",
        "**Correction state:** NONE: no correction declared",
        1,
    ))
    assert false_no_correction.returncode == 1
    assert "Correction audit semantic delta must match Correction state" in false_no_correction.stdout

    incomplete_rederivation = run(good.replace(
        "; COMMANDS_REBOUND:COMPLETE",
        "",
        1,
    ))
    assert incomplete_rederivation.returncode == 1
    assert "Re-derivation status missing COMMANDS_REBOUND:COMPLETE" in incomplete_rederivation.stdout

    inherited_keep_without_owner = run(good.replace(
        "| `LATEST_USER_INTENT` | `ALIGNED` | `BEHAVIORAL_UTILITY` | KEEP:",
        "| `LATEST_USER_INTENT` | `ALIGNED` | `NONE` | KEEP:",
        1,
    ))
    assert inherited_keep_without_owner.returncode == 1
    assert "KEEP requires ALIGNED + stage owner" in inherited_keep_without_owner.stdout

    omitted_inherited_clause = run(good.replace(
        "INVENTORY_TOTAL:4; CLASSIFIED_TOTAL:4; UNCLASSIFIED:0",
        "INVENTORY_TOTAL:5; CLASSIFIED_TOTAL:4; UNCLASSIFIED:1",
        1,
    ))
    assert omitted_inherited_clause.returncode == 1
    assert "inherited inventory totals must equal classified rows with UNCLASSIFIED:0" in omitted_inherited_clause.stdout

    missing_latest_intent = run(re.sub(
        r"(?m)^\| `latest-objective` \|.*\r?\n",
        "",
        good,
        count=1,
    ))
    assert missing_latest_intent.returncode == 1
    assert "requires at least one LATEST_USER_INTENT row" in missing_latest_intent.stdout

    deleted_token_survives = run(good.replace(
        "-Provider DML -Mode OFFLINE_LOGICAL_CHUNKS",
        "-Provider DML -Mode OFFLINE_LOGICAL_CHUNKS -ReplayProvider CPU",
        1,
    ))
    assert deleted_token_survives.returncode == 1
    assert "deleted inherited match text survives active contract: cpu-replay" in deleted_token_survives.stdout

    deleted_text_survives_stage_contract = run(
        good.replace(
            "QUESTION_2: Which behavioral survivors rank fastest on DML?",
            "QUESTION_2: Which behavioral survivors rank fastest on CPU and DML?",
        )
    )
    assert deleted_text_survives_stage_contract.returncode == 1
    assert "deleted inherited match text survives active contract: cpu-replay" in deleted_text_survives_stage_contract.stdout

    criterion_without_stage_owner = run(good.replace(
        "| `PRODUCER_IDENTITY` | `ACCEPTANCE` | QUESTION_1 production parser trigger must come from required producer | `SYSTEM_INTERFERENCE` |",
        "| `PRODUCER_IDENTITY` | `ACCEPTANCE` | QUESTION_1 production parser trigger must come from required producer | `NONE` |",
        1,
    ))
    assert criterion_without_stage_owner.returncode == 1
    assert "requirement PRODUCER_IDENTITY lacks declared stage owner" in criterion_without_stage_owner.stdout

    wrong_provider_decision = run(good.replace(
        "PROVIDER:DML; REQUIRED_FOR:QUESTION_2:DML latency rank",
        "PROVIDER:DML; REQUIRED_FOR:QUESTION_1:DML latency rank",
        1,
    ))
    assert wrong_provider_decision.returncode == 1
    assert "provider justification targets wrong question" in wrong_provider_decision.stdout

    same_id_decision_drift = run(good.replace(
        "| `PERFORMANCE_SHORTLIST` | QUESTION_2: Which behavioral survivors rank fastest on DML? | PROVIDER:DML;",
        "| `PERFORMANCE_SHORTLIST` | QUESTION_2: Rank every inherited runtime equally. | PROVIDER:DML;",
        1,
    ))
    assert same_id_decision_drift.returncode == 1
    assert "decision text differs from funnel decision" in same_id_decision_drift.stdout

    provider_absent_from_command = run(good.replace(
        "Run-Stage -Provider DML -Mode OFFLINE_LOGICAL_CHUNKS",
        "Run-Stage -Mode OFFLINE_LOGICAL_CHUNKS",
        1,
    ))
    assert provider_absent_from_command.returncode == 1
    assert "command lacks required provider binding" in provider_absent_from_command.stdout

    physical_sleep_offline = run(good.replace(
        "# STAGE_COMMAND:BEHAVIORAL_UTILITY",
        "# STAGE_COMMAND:BEHAVIORAL_UTILITY\nStart-Sleep -Milliseconds 250",
        1,
    ))
    assert physical_sleep_offline.returncode == 1
    assert "offline stage BEHAVIORAL_UTILITY command contains physical sleep" in physical_sleep_offline.stdout

    downstream_fixture_early = run(good.replace(
        "-Fixtures D:/workspace/fixtures/positives.json",
        "-Fixtures D:/workspace/fixtures/positives.json,D:/workspace/fixtures/negatives.json",
        1,
    ))
    assert downstream_fixture_early.returncode == 1
    assert "fixture negative-238 leaks into non-owning stage command BEHAVIORAL_UTILITY" in downstream_fixture_early.stdout

    estimated_runs_mismatch = run(good.replace(
        "ESTIMATED_RUNS:280 | WALL_FACTORS:RUNS=280",
        "ESTIMATED_RUNS:279 | WALL_FACTORS:RUNS=280",
        1,
    ))
    assert estimated_runs_mismatch.returncode == 1
    assert "ESTIMATED_RUNS must equal stage MAX_JOBS" in estimated_runs_mismatch.stdout

    wall_arithmetic_mismatch = run(good.replace(
        "WALL_FACTORS:RUNS=280; MS_PER_RUN_MIN=5; MAX_CONCURRENCY=4; MIN_WALL_MS=350",
        "WALL_FACTORS:RUNS=280; MS_PER_RUN_MIN=5; MAX_CONCURRENCY=4; MIN_WALL_MS=349",
        1,
    ))
    assert wall_arithmetic_mismatch.returncode == 1
    assert "MIN_WALL_MS does not equal expanded wall-time formula" in wall_arithmetic_mismatch.stdout

    zero_wall_floor = run(good.replace(
        "WALL_FACTORS:RUNS=20; MS_PER_RUN_MIN=10; MAX_CONCURRENCY=4; MIN_WALL_MS=50",
        "WALL_FACTORS:RUNS=20; MS_PER_RUN_MIN=0; MAX_CONCURRENCY=4; MIN_WALL_MS=0",
        1,
    ))
    assert zero_wall_floor.returncode == 1
    assert "wall factors require positive duration + concurrency" in zero_wall_floor.stdout

    wall_floor_without_evidence = run(good.replace(
        "; EVIDENCE:D:/workspace/evidence/stage-1-wall.json",
        "",
        1,
    ))
    assert wall_floor_without_evidence.returncode == 1
    assert "wall factors require evidence path" in wall_floor_without_evidence.stdout

    unresolved_launch_estimate = run(good.replace(
        "**Launch estimate status:** RESOLVED:RUNS_WALL_TIME_CONCURRENCY",
        "**Launch estimate status:** UNRESOLVED: wall time unknown",
        1,
    ))
    assert unresolved_launch_estimate.returncode == 1
    assert "**Launch estimate status:** must be RESOLVED" in unresolved_launch_estimate.stdout

    wall_total_mismatch = run(good.replace(
        "**Declared minimum wall time:** MIN_WALL_MS_TOTAL:2093",
        "**Declared minimum wall time:** MIN_WALL_MS_TOTAL:9999",
        1,
    ))
    assert wall_total_mismatch.returncode == 1
    assert "MIN_WALL_MS_TOTAL 9999 does not equal typed stage wall sum 2093" in wall_total_mismatch.stdout

    invalid_typed_alchemist = run(good.replace(
        "CHECKPOINT:TYPED_STAGES",
        "CHECKPOINT:PROSE_SUMMARY",
        1,
    ))
    assert invalid_typed_alchemist.returncode == 1
    assert "requires typed Alchemist binding schema" in invalid_typed_alchemist.stdout

    missing_behavioral_gate = run(re.sub(
        r"(?m)^\| `BEHAVIORAL_UTILITY` \|.*\r?\n",
        "",
        good,
        count=1,
    ))
    assert missing_behavioral_gate.returncode == 1
    assert "selection funnel requires exact ordered stages" in missing_behavioral_gate.stdout

    flattened_all = run(re.sub(
        r"(- \*\*Exact action / command:\*\*\s*```[^\n]*\n).*?(\n```)",
        r"\1Run D:/workspace/tools/bakeoff.ps1 --all --fixtures D:/workspace/fixtures/full-corpus.json\2",
        good,
        count=1,
        flags=re.S,
    ))
    assert flattened_all.returncode == 1
    assert "selection funnel command contains forbidden broad --all selector" in flattened_all.stdout

    relative_validator_paths = run(re.sub(
        r"(- \*\*Exact action / command:\*\*\s*```[^\n]*\n)",
        (
            r'\1$Packet="tasks\\dispatches\\packet.md"\n'
            r'$Receipt="tasks\\dispatches\\packet.receipt.json"\n'
            r"py -3.11 tools\\skills\\dispatch\\scripts\\validate-dispatch.py "
            r"$Packet --verify-receipt $Receipt\n"
        ),
        good,
        count=1,
    ))
    assert relative_validator_paths.returncode == 1
    assert "exact action uses checkout-relative validator paths" in relative_validator_paths.stdout

    absolute_validator_paths = run(re.sub(
        r"(- \*\*Exact action / command:\*\*\s*```[^\n]*\n)",
        (
            r'\1$Root="D:\\workspace"\n'
            r'$Packet=Join-Path $Root "tasks\\dispatches\\packet.md"\n'
            r'$Receipt=Join-Path $Root "tasks\\dispatches\\packet.receipt.json"\n'
            r'$Input="tasks\\fixtures\\input.json"\n'
            r'py -3.11 "$Root\\tools\\skills\\dispatch\\scripts\\validate-dispatch.py" '
            r"$Packet --verify-receipt $Receipt\n"
        ),
        good,
        count=1,
    ))
    assert absolute_validator_paths.returncode == 0, absolute_validator_paths.stdout

    wrong_stage_population = run(good.replace(
        "SURVIVORS_FROM:TECHNICAL_RUNNABILITY; MAX_INPUTS:20",
        "ALL_CANDIDATES; MAX_INPUTS:20",
        1,
    ))
    assert wrong_stage_population.returncode == 1
    assert "stage BEHAVIORAL_UTILITY must consume SURVIVORS_FROM:TECHNICAL_RUNNABILITY" in wrong_stage_population.stdout

    wrong_survivor_selector = run(good.replace(
        "SELECTOR: --candidates-from D:/workspace/survivors/technical.json --fixtures",
        "SELECTOR: --candidates-from D:/workspace/candidates/all.json --fixtures",
        1,
    ))
    assert wrong_survivor_selector.returncode == 1
    assert "stage BEHAVIORAL_UTILITY selector must use upstream survivor artifact" in wrong_survivor_selector.stdout

    broad_stage_selector = run(good.replace(
        "SELECTOR: --candidates-from D:/workspace/survivors/performance-top3.json --fixtures",
        "SELECTOR: --all --candidates-from D:/workspace/survivors/performance-top3.json --fixtures",
        1,
    ))
    assert broad_stage_selector.returncode == 1
    assert "stage SAFETY_NEGATIVES selector contains forbidden broad --all" in broad_stage_selector.stdout

    missing_stage_command = run(good.replace(
        "# STAGE_COMMAND:BEHAVIORAL_UTILITY",
        "# COMMAND_WITHOUT_STAGE_BINDING",
        1,
    ))
    assert missing_stage_command.returncode == 1
    assert "stage BEHAVIORAL_UTILITY requires exactly one STAGE_COMMAND block" in missing_stage_command.stdout

    command_skips_upstream_survivor = run(good.replace(
        "-CandidatesFrom D:/workspace/survivors/behavioral.json -Fixtures D:/workspace/fixtures/performance.json",
        "-CandidatesFrom D:/workspace/candidates/all.json -Fixtures D:/workspace/fixtures/performance.json",
        1,
    ))
    assert command_skips_upstream_survivor.returncode == 1
    assert "stage PERFORMANCE_SHORTLIST command does not consume upstream survivor artifact" in command_skips_upstream_survivor.stdout

    fixture_absent_from_owner_command = run(good.replace(
        "-CandidatesFrom D:/workspace/survivors/performance-top3.json -Fixtures D:/workspace/fixtures/negatives.json",
        "-CandidatesFrom D:/workspace/survivors/performance-top3.json -Fixtures D:/workspace/fixtures/positives.json",
        1,
    ))
    assert fixture_absent_from_owner_command.returncode == 1
    assert "fixture negative-238 source is absent from owning stage command" in fixture_absent_from_owner_command.stdout

    workload_arithmetic_mismatch = run(good.replace(
        "FACTORS:3x238; MAX_JOBS:714",
        "FACTORS:3x238; MAX_JOBS:713",
        1,
    ))
    assert workload_arithmetic_mismatch.returncode == 1
    assert "stage SAFETY_NEGATIVES MAX_JOBS does not equal factor product" in workload_arithmetic_mismatch.stdout

    total_mismatch = run(good.replace(
        "**Declared launch ceiling:** JOB_TOTAL_MAX:1098",
        "**Declared launch ceiling:** JOB_TOTAL_MAX:19040",
        1,
    ))
    assert total_mismatch.returncode == 1
    assert "JOB_TOTAL_MAX 19040 does not equal stage MAX_JOBS sum 1098" in total_mismatch.stdout

    duplicate_fixture = run(good.replace(
        "| `positive-14` |",
        "| `candidate-artifacts` |",
        1,
    ))
    assert duplicate_fixture.returncode == 1
    assert "fixture-stage ownership contains duplicate fixture IDs" in duplicate_fixture.stdout

    wrong_fixture_owner = run(good.replace(
        "| `negative-238` | `D:/workspace/fixtures/negatives.json` | `SAFETY_NEGATIVES` |",
        "| `negative-238` | `D:/workspace/fixtures/negatives.json` | `TECHNICAL_RUNNABILITY` |",
        1,
    ))
    assert wrong_fixture_owner.returncode == 1
    assert "fixture negative-238 use condition must bind owning stage entry" in wrong_fixture_owner.stdout

    no_launch_reconciliation = run(good.replace(
        "RECONCILE: STAGE_ACTUAL_SUM must equal launched jobs and remain within JOB_TOTAL_MAX; BLOCK_IF_MISMATCH; EVIDENCE:D:/workspace/evidence/launch-reconcile.json",
        "Record totals after run",
        1,
    ))
    assert no_launch_reconciliation.returncode == 1
    assert "**Launch-count reconciliation:** requires STAGE_ACTUAL_SUM" in no_launch_reconciliation.stdout

    full_good = full_comparative_fixture(good)
    full_result = run(full_good)
    assert full_result.returncode == 0, full_result.stdout + full_result.stderr

    unauthorized_full = run(full_good.replace(
        "FULL_COMPARATIVE_DATASET_AUTHORIZED: SOURCE:USER_REQUEST; REASON: user explicitly requires complete arm-by-arm public dataset",
        "NOT_AUTHORIZED: generic benchmark fairness",
        1,
    ))
    assert unauthorized_full.returncode == 1
    assert "full comparative dataset requires FULL_COMPARATIVE_DATASET_AUTHORIZED" in unauthorized_full.stdout

    self_authorized_full = run(full_good.replace(
        "SOURCE:USER_REQUEST; REASON: user explicitly requires complete arm-by-arm public dataset",
        "SOURCE:DISPATCHER; REASON: generic benchmark fairness",
        1,
    ))
    assert self_authorized_full.returncode == 1
    assert "SOURCE:USER_REQUEST or SOURCE:AUTHORITATIVE_SPEC" in self_authorized_full.stdout

    invented_intent_labels = run(good.replace(
        "**Required inputs:** D:/workspace/artifacts/result.json",
        "**Required inputs:** 14 audio clips plus exact intent labels",
    ))
    assert invented_intent_labels.returncode == 1
    assert (
        "forbidden scope leaked into input/acceptance contract: exact intent labels"
        in invented_intent_labels.stdout
    )

    invented_onset_ground_truth = run(good.replace(
        "GROUND_TRUTH_SOURCE: canonical positive and negative membership only; MEASURED_OUTPUT_NOT_GROUND_TRUTH: onset, decoded text, parsed intent, and latency",
        "GROUND_TRUTH_SOURCE: user-supplied onset labels",
    ))
    assert invented_onset_ground_truth.returncode == 1
    assert "**Ground-truth policy:** lacks enforceable decision-scope contract" in invented_onset_ground_truth.stdout

    semantic_asr_acceptance = run(good.replace(
        "| TRIGGER_AND_LATENCY_METRICS |",
        "| WER and reference transcript |",
        1,
    ))
    assert semantic_asr_acceptance.returncode == 1
    assert "forbidden scope leaked into input/acceptance contract: reference transcript" in semantic_asr_acceptance.stdout

    diagnostic_promoted = run(good.replace(
        "| `DIAGNOSTIC_ONLY` | `DIAGNOSTIC` |",
        "| `DIAGNOSTIC_ONLY` | `ACCEPTANCE` |",
    ))
    assert diagnostic_promoted.returncode == 1
    assert "requirement trace missing DIAGNOSTIC_ONLY class DIAGNOSTIC" in diagnostic_promoted.stdout

    diagnostic_in_acceptance = run(good.replace(
        "METRICS_ONLY: positive trigger count, negative trigger count, probe cadence and backlog, and final-TDT latency",
        "METRICS_ONLY: positive trigger count, negative trigger count, final-TDT latency, and decoded EOU text",
    ))
    assert diagnostic_in_acceptance.returncode == 1
    assert "diagnostic-only item leaked into acceptance contract: decoded eou text" in diagnostic_in_acceptance.stdout

    measured_output_as_input = run(good.replace(
        "**Required inputs:** D:/workspace/artifacts/result.json",
        "**Required inputs:** D:/workspace/artifacts/result.json plus measured onset",
    ))
    assert measured_output_as_input.returncode == 1
    assert "measured output treated as prior input/acceptance requirement: onset" in measured_output_as_input.stdout

    irrelevant_model_allowed = run(good.replace(
        "FORBID: produces no acceptance metric",
        "ALLOW: use cached large-v3-turbo to derive labels",
    ))
    assert irrelevant_model_allowed.returncode == 1
    assert "model/tool relevance cannot ALLOW a load that produces no acceptance metric" in irrelevant_model_allowed.stdout

    untraced_model_metric = run(
        good.replace(
            "NONE — produces no acceptance metric",
            "semantic transcript quality",
            1,
        ).replace(
            "FORBID: produces no acceptance metric",
            "ALLOW: use cached ASR",
        )
    )
    assert untraced_model_metric.returncode == 1
    assert "allowed model/tool metric is not named in acceptance metrics" in untraced_model_metric.stdout

    recovery_scope_creep = run(good.replace(
        "NO_SCOPE_EXPANSION: recover only required trigger or latency inputs; never invent labels, transcription, or models",
        "derive missing labels with any cached local ASR",
    ))
    assert recovery_scope_creep.returncode == 1
    assert "**Recovery scope rule:** lacks enforceable decision-scope contract" in recovery_scope_creep.stdout

    missing_alchemist = run(good.replace(
        "REQUIRED: run_id=0d4ce380-d482-41bc-b65c-1049448502b6",
        "NOT_REQUIRED: packet is structurally complete",
    ))
    assert missing_alchemist.returncode == 1
    assert "non-routine semantic work requires REQUIRED run_id=<uuid>" in missing_alchemist.stdout

    no_readback = run(good.replace(
        "READBACK_REQUIRED: questions, metrics, diagnostics, forbidden scope, fixture roles, and exact first action",
        "start execution immediately",
    ))
    assert no_readback.returncode == 1
    assert "**First-action readback:** lacks enforceable decision-scope contract" in no_readback.stdout

    no_numeric_supervision = run(good.replace(
        "SUPERVISE: after first action, every 5 minutes, and before each model or tool load, scope change, or batch",
        "SUPERVISE: occasionally",
    ))
    assert no_numeric_supervision.returncode == 1
    assert "**Supervision cadence:** lacks enforceable decision-scope contract" in no_numeric_supervision.stdout

    missing_class = run(good.replace("`UNKNOWN_FAILURE`", "`OTHER_FAILURE`"))
    assert missing_class.returncode == 1
    assert "missing failure class: UNKNOWN_FAILURE" in missing_class.stdout

    vague_recovery = run(good.replace(
        "| `PATH_OR_INPUT_MISSING` | command exits 2 and stderr contains missing |",
        "| `PATH_OR_INPUT_MISSING` | x |",
    ))
    assert vague_recovery.returncode == 1
    assert "recovery row PATH_OR_INPUT_MISSING cell 2 is too vague" in vague_recovery.stdout

    vague = run(good.replace("documented concrete task value", "as discussed", 1))
    assert vague.returncode == 1
    assert "chat-context dependency" in vague.stdout

    unchecked = run(good.replace("- [x]", "- [ ]", 1))
    assert unchecked.returncode == 1
    assert "unchecked item" in unchecked.stdout

    blocked = run(good.replace(
        "STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER",
        "STATUS: BLOCKED",
    ))
    assert blocked.returncode == 1
    assert "forbidden terminal status" in blocked.stdout

    missing_status = run(good.replace(
        "STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER",
        "TERMINAL_VALUES: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER",
    ))
    assert missing_status.returncode == 1
    assert "requires exactly one STATUS line" in missing_status.stdout

    generic = run(good.replace(
        "**Outcome:** documented concrete task value",
        "**Outcome:** fixture-value",
    ))
    assert generic.returncode == 1
    assert "generic filler value" in generic.stdout

    malformed_first = run(good.replace(
        "| documented concrete task value | executor |",
        "| malformed |",
        1,
    ))
    assert malformed_first.returncode == 1
    assert "row 1 must contain" in malformed_first.stdout

    script_ship = run(good.replace("SHIP:  YES", "SHIP:  NO"))
    assert script_ship.returncode == 1
    assert "script gate SHIP must be YES" in script_ship.stdout

    early_blocker = run(good.replace(
        "Return TRUE_BLOCKER only after all recovery branches fail, evidence log exists, and missing input is named",
        "Return TRUE_BLOCKER after first failure",
        1,
    ))
    assert early_blocker.returncode == 1
    assert "lacks exhausted-recovery proof" in early_blocker.stdout

    unnamed_producer = run(good.replace(
        "PRODUCER: membrane_planner | PROOF_FIELD: producer",
        "generate genuine candidate traffic",
    ))
    assert unnamed_producer.returncode == 1
    assert "Required producer / actor" in unnamed_producer.stdout

    unconditional_resume = run(good.replace(
        "INVENTORY: inspect D:/workspace/evidence/runs.json; REJECT_IF_INCOMPATIBLE: producer != membrane_planner; RESUME_ONLY_IF: producer and lifecycle match",
        "Continue existing P3 run",
    ))
    assert unconditional_resume.returncode == 1
    assert "Existing-work disposition" in unconditional_resume.stdout

    incomplete_lifecycle = run(good.replace(
        "LIFECYCLE: provider.expected -> started -> terminal -> delivery -> value_terminal",
        "LIFECYCLE: started -> terminal",
    ))
    assert incomplete_lifecycle.returncode == 1
    assert "at least five ordered states" in incomplete_lifecycle.stdout

    substitution_projection = run(good.replace(
        "NO_SUBSTITUTION — direct closures and projections are forbidden",
        "Use direct closures and substitution projections",
    ))
    assert substitution_projection.returncode == 1
    assert "Substitution policy" in substitution_projection.stdout

    acceptance_start = good.index("## 7. Verification & Acceptance Map")
    missing_identity_text = (
        good[:acceptance_start]
        + good[acceptance_start:].replace(
            "| `PRODUCER_IDENTITY` |",
            "| `PRODUCER_CHECK` |",
            1,
        )
    )
    missing_identity_acceptance = run(missing_identity_text)
    assert missing_identity_acceptance.returncode == 1
    assert "acceptance map missing identity gate: PRODUCER_IDENTITY" in missing_identity_acceptance.stdout

    resume_without_reset = run(good.replace(
        "RESET_REQUIRED: current producer=design is incompatible",
        "Resume P3 round 1",
    ))
    assert resume_without_reset.returncode == 1
    assert "Resume / reset decision" in resume_without_reset.stdout

    component_only_path = run(good.replace(
        "PRODUCTION_PATH: CLI -> root hook -> membrane_planner -> delivery -> value_terminal",
        "PRODUCTION_PATH: candidate tag -> binary hash -> schema",
    ))
    assert component_only_path.returncode == 1
    assert "at least five ordered stages" in component_only_path.stdout

    orphan_trace = run(good.replace(
        "TRACE_LINK: expected.id -> started.attempt_of -> terminal.terminal_of -> delivered.trace_id -> value.trace_id",
        "TRACE_LINK: started.id -> terminal.id",
    ))
    assert orphan_trace.returncode == 1
    assert "expected, started, terminal, delivery, & value" in orphan_trace.stdout

    batch_before_canary = run(good.replace(
        "PROHIBITED_UNTIL_CANARY_PASS — zero batch calls before one trace passes",
        "Start ten flows then inspect",
    ))
    assert batch_before_canary.returncode == 1
    assert "Batch start gate" in batch_before_canary.stdout

    false_defect = run(good.replace(
        "DEFECT_ONLY_IF: PRODUCTION_PATH_PROVEN and CANARY_PASS and CANONICAL_CHECK_FAILS with matching trace",
        "Fresh window has gaps, so candidate is defective",
    ))
    assert false_defect.returncode == 1
    assert "Defect classification gate" in false_defect.stdout

    guide_delegation = run(good.replace(
        "**Critical discriminating invariants:** INVARIANT:",
        "**Critical discriminating invariants:** Read the guide. INVARIANT:",
    ))
    assert guide_delegation.returncode == 1
    assert "externalized critical meaning" in guide_delegation.stdout

    missing_end_to_end_gate = run(re.sub(
        r"(?m)^\| `END_TO_END_GATE` \|.*\r?\n",
        "",
        good,
        count=1,
    ))
    assert missing_end_to_end_gate.returncode == 1
    assert "gate isolation matrix missing gate: END_TO_END_GATE" in missing_end_to_end_gate.stdout

    phase_leakage = run(re.sub(
        r"(?m)^\| `OTHER_PHASES` \|.*\r?\n",
        "",
        good,
        count=1,
    ))
    assert phase_leakage.returncode == 1
    assert "phase-scoped substitution matrix missing row: OTHER_PHASES" in phase_leakage.stdout

    bearer = run(good.replace(
        "**Access / credentials:** documented concrete task value",
        "**Access / credentials:** Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    ))
    assert bearer.returncode == 1
    assert "possible secret detected" in bearer.stdout

    markdown_secret = run(good.replace(
        "**Access / credentials:** documented concrete task value",
        "**Access / credentials:** token: `abcdefghijklmnopqrstuv`",
    ))
    assert markdown_secret.returncode == 1
    assert "possible secret detected" in markdown_secret.stdout

    slack_secret = run(good.replace(
        "**Access / credentials:** documented concrete task value",
        "**Access / credentials:** xoxb-" + "1" * 40,
    ))
    assert slack_secret.returncode == 1
    assert "possible secret detected" in slack_secret.stdout

    prior_context = run(good.replace(
        "**Outcome:** documented concrete task value",
        "**Outcome:** Use prior-thread context for current branch and credentials",
    ))
    assert prior_context.returncode == 1
    assert "chat-context dependency" in prior_context.stdout

    prior_session = run(good.replace(
        "**Outcome:** documented concrete task value",
        "**Outcome:** Read old messages from prior session before execution",
    ))
    assert prior_session.returncode == 1
    assert "chat-context dependency" in prior_session.stdout

    cache_artifact = (EXAMPLES / "cache" / "dispatch.md").resolve()
    cache_receipt = cache_artifact.with_name("dispatch.receipt.json")
    cache_errors = validator_module.storage_errors(
        bind_paths(good, cache_artifact, cache_receipt),
        cache_artifact,
        cache_receipt,
        None,
    )
    assert any("temporary/cache/review-run storage" in error for error in cache_errors)

    validator_artifact = (EXAMPLES / ".validator-case" / "dispatch.md").resolve()
    validator_receipt = validator_artifact.with_name("dispatch.receipt.json")
    validator_errors = validator_module.storage_errors(
        bind_paths(good, validator_artifact, validator_receipt),
        validator_artifact,
        validator_receipt,
        None,
    )
    assert any("temporary/cache/review-run storage" in error for error in validator_errors)

    prose_receipt = run(re.sub(
        r"(- \*\*Receiver hash check:\*\*\s*```[^\n]*\n).*?(\n```)",
        r"\1verify receipt per team process\2",
        good,
        count=1,
        flags=re.S,
    ), bind_commands=False)
    assert prose_receipt.returncode == 1
    assert "Receiver hash check must execute" in prose_receipt.stdout

    with tempfile.TemporaryDirectory(prefix="case-", dir=CASES) as directory:
        dispatch = Path(directory).resolve() / "dispatch.md"
        receipt = Path(directory).resolve() / "dispatch.receipt.json"
        bound_good = bind_paths(good, dispatch, receipt)
        dispatch.write_bytes(bound_good.encode("utf-8"))
        minimize = dispatch.with_suffix(".minimize.json")
        minimize_receipt = dispatch.with_suffix(".minimize.receipt.json")
        minimize.write_bytes(MINIMIZE_FIXTURE.read_bytes())
        subprocess.run(
            [
                sys.executable,
                str(MINIMIZE_VALIDATOR),
                "decision",
                "receipt",
                str(minimize),
                str(minimize_receipt),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        neither = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert neither.returncode == 1
        assert "exactly one receipt mode is required" in neither.stdout
        dual = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(dispatch),
                "--write-receipt",
                str(receipt),
                "--verify-receipt",
                str(receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert dual.returncode == 2
        written = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--write-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert written.returncode == 0, written.stdout + written.stderr
        verified = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--verify-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert verified.returncode == 0

        alternate = Path(directory).resolve() / "alternate" / "dispatch.receipt.json"
        alternate.parent.mkdir()
        alternate.write_bytes(receipt.read_bytes())
        nonadjacent = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--verify-receipt", str(alternate)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert nonadjacent.returncode == 1
        assert "receipt must be adjacent" in nonadjacent.stdout

        wrong_declared = bound_good.replace(
            f"- **Receipt path:** {receipt}",
            f"- **Receipt path:** {dispatch.with_name('wrong.receipt.json')}",
        )
        dispatch.write_bytes(wrong_declared.encode("utf-8"))
        mismatched_declared = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--verify-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert mismatched_declared.returncode == 1
        assert "declared receipt path does not match" in mismatched_declared.stdout

        dispatch.write_bytes(bound_good.replace("\n", "\r\n").encode("utf-8"))
        newline_tampered = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--verify-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert newline_tampered.returncode == 1
        assert "bytes do not match receipt" in newline_tampered.stdout

        dispatch.write_bytes((bound_good + "\nchanged").encode("utf-8"))
        tampered = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--verify-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert tampered.returncode == 1
        assert "do not match receipt" in tampered.stdout

    with tempfile.TemporaryDirectory() as directory:
        dispatch = Path(directory).resolve() / "dispatch.md"
        receipt = Path(directory).resolve() / "dispatch.receipt.json"
        dispatch.write_text(bind_paths(good, dispatch, receipt), encoding="utf-8")
        temporary = subprocess.run(
            [sys.executable, str(VALIDATOR), str(dispatch), "--write-receipt", str(receipt)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert temporary.returncode == 1
        assert "temporary/cache/review-run storage" in temporary.stdout

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        lens = root / "lens.md"; lens.write_text("sealed lens", encoding="utf-8")
        oracle = root / "oracle.json"; oracle.write_text("{}", encoding="utf-8")
        context = authority_context(root)
        digest = lambda path: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        packet = {
            "schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "oracle",
            "sourceRevision": CONCRETE_GIT_SHA, "promptDigest": REAL_PROMPT_DIGEST,
            "modelRouting": {"modelTier": "MID", "workerProfile": "standard", "routingRationale": "sealed"},
            "lens": {"id": "audit", "path": str(lens), "digest": digest(lens)},
            "scope": {"read": ["src"], "forbidden": ["secrets"]},
            "oracle": {"path": str(oracle), "digest": digest(oracle)},
        }
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert any("source revision does not resolve" in error for error in errors), errors
        packet.update(context)
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert not errors, errors
        packet["scope"]["forbidden"] = ["src"]
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert "Oracle scope overlaps forbidden paths" in errors
        packet["scope"]["forbidden"] = ["secrets"]
        packet["lens"]["digest"] = "sha256:" + "f" * 64
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert "Oracle lens digest mismatch" in errors
        packet["lens"]["digest"] = digest(lens)
        # "seer" is a retired read_only_alias and must still validate identically, so an
        # in-flight predecessor packet is accepted while "oracle" is the canonical spelling.
        packet["packetType"] = "seer"
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert not errors, errors
        packet["packetType"] = "bogus"
        errors, _ = validator_module.authority_packet_errors(packet, root / "packet.json")
        assert "authority packet type must be direct, sage, oracle, alchemist, or worker" in errors
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        artifacts_dir = root / "tasks" / "dispatches"
        artifacts_dir.mkdir(parents=True)
        capsule = artifacts_dir / "capsule.json"
        capsule.write_text("{}", encoding="utf-8")
        contract = artifacts_dir / "contract.json"
        contract.write_text("{}", encoding="utf-8")
        task_proj = artifacts_dir / "task-projection.json"
        task_proj.write_text("{}", encoding="utf-8")
        artifact_proj = artifacts_dir / "artifact-projection.json"
        artifact_proj.write_text("{}", encoding="utf-8")
        oracle = artifacts_dir / "oracle.json"
        oracle.write_text("{}", encoding="utf-8")
        sage_route = artifacts_dir / "sage-adjudication.json"
        sage_route.write_text("{}", encoding="utf-8")
        context = authority_context(root)
        sha = lambda path: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

        sage_packet = {
            "schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "sage",
            "sourceRevision": CONCRETE_GIT_SHA, "promptDigest": REAL_PROMPT_DIGEST,
            "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict", "routingRationale": "material ownership conflict"},
            "routeBundle": {"path": str(sage_route), "digest": sha(sage_route)},
        }
        sage_packet_path = artifacts_dir / "sage-packet.json"
        sage_packet.update(context)
        sage_packet_path.write_text(json.dumps(sage_packet), encoding="utf-8")
        sage_receipt = sage_packet_path.with_suffix(".receipt.json")
        sage_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(sage_packet_path), "--packet-type", "authority",
             "--write-receipt", str(sage_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert sage_result.returncode == 0, sage_result.stdout + sage_result.stderr
        sage_receipt_value = json.loads(sage_receipt.read_text(encoding="utf-8"))
        assert sage_receipt_value["sha256"] == hashlib.sha256(sage_packet_path.read_bytes()).hexdigest()
        assert sage_receipt_value["authority_binding"] == {
            "packet_sha256": sage_receipt_value["sha256"],
            "source_revision": context["sourceRevision"],
            "prompt_digest": context["promptDigest"],
        }
        assert any(entry["sha256"] == sha(sage_route) for entry in sage_receipt_value["referenced_artifacts"])

        alchemist_packet = {
            "schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "alchemist",
            "sourceRevision": CONCRETE_GIT_SHA, "promptDigest": REAL_PROMPT_DIGEST,
            "modelRouting": {"modelTier": "MID", "workerProfile": "standard", "routingRationale": "transform"},
            "executionContract": {"id": "EC-44", "path": str(contract), "digest": sha(contract),
                                  "sealed": True, "executable": True},
            "scope": {"own": ["src/foo.js"], "contractOwn": ["src/foo.js", "src/bar.js"]},
        }
        alchemist_packet_path = artifacts_dir / "alchemist-packet.json"
        alchemist_packet.update(context)
        alchemist_packet_path.write_text(json.dumps(alchemist_packet), encoding="utf-8")
        alchemist_receipt = alchemist_packet_path.with_suffix(".receipt.json")
        alchemist_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(alchemist_packet_path), "--packet-type", "authority",
             "--write-receipt", str(alchemist_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert alchemist_result.returncode == 0, alchemist_result.stdout + alchemist_result.stderr
        alchemist_receipt_value = json.loads(alchemist_receipt.read_text(encoding="utf-8"))
        assert alchemist_receipt_value["sha256"] == hashlib.sha256(alchemist_packet_path.read_bytes()).hexdigest()
        assert any(entry["sha256"] == sha(contract) for entry in alchemist_receipt_value["referenced_artifacts"])

        alchemist_overscope = json.loads(json.dumps(alchemist_packet))
        alchemist_overscope["scope"]["own"] = ["src/other.js"]
        errors, _ = validator_module.authority_packet_errors(alchemist_overscope, alchemist_packet_path)
        assert any("OWN scope must be contract subset" in err for err in errors), errors

        worker_packet = {
            "schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "worker",
            "sourceRevision": CONCRETE_GIT_SHA, "promptDigest": REAL_PROMPT_DIGEST,
            "modelRouting": {"modelTier": "CHEAP_STRICT", "workerProfile": "strict", "routingRationale": "execute"},
            "workerCapsule": {"path": str(capsule), "digest": sha(capsule)},
            "taskProjection": {"path": str(task_proj), "digest": sha(task_proj)},
            "artifactProjection": {"path": str(artifact_proj), "digest": sha(artifact_proj)},
            "oracle": {"path": str(oracle), "digest": sha(oracle)},
        }
        worker_packet_path = artifacts_dir / "worker-packet.json"
        worker_packet.update(context)
        worker_packet_path.write_text(json.dumps(worker_packet), encoding="utf-8")
        worker_receipt = worker_packet_path.with_suffix(".receipt.json")
        worker_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(worker_packet_path), "--packet-type", "worker",
             "--write-receipt", str(worker_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert worker_result.returncode == 0, worker_result.stdout + worker_result.stderr
        worker_receipt_value = json.loads(worker_receipt.read_text(encoding="utf-8"))
        assert worker_receipt_value["sha256"] == hashlib.sha256(worker_packet_path.read_bytes()).hexdigest()
        assert len(worker_receipt_value["referenced_artifacts"]) >= 3

        tamper_packet = json.loads(worker_packet_path.read_text(encoding="utf-8"))
        tamper_packet["sourceRevision"] = "tampered"
        tamper_path = artifacts_dir / "tampered-packet.json"
        tamper_path.write_text(json.dumps(tamper_packet), encoding="utf-8")
        tamper_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(tamper_path), "--packet-type", "worker",
             "--verify-receipt", str(worker_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert tamper_result.returncode == 1
        assert "source revision must be an immutable" in tamper_result.stdout

        missing_routing = json.loads(json.dumps(worker_packet))
        del missing_routing["modelRouting"]["routingRationale"]
        errors, _ = validator_module.authority_packet_errors(missing_routing, worker_packet_path)
        assert any("modelTier, workerProfile, routingRationale" in err for err in errors), errors

        missing_prompt_digest = json.loads(json.dumps(worker_packet))
        missing_prompt_digest["promptDigest"] = "not-a-digest"
        errors, _ = validator_module.authority_packet_errors(missing_prompt_digest, worker_packet_path)
        assert any("prompt digest must be a non-placeholder" in err for err in errors), errors

        unknown_type = json.loads(json.dumps(worker_packet))
        unknown_type["packetType"] = "unknown-authority"
        errors, _ = validator_module.authority_packet_errors(unknown_type, worker_packet_path)
        assert any("authority packet type must be" in err for err in errors), errors

        wrong_kind = json.loads(json.dumps(worker_packet))
        wrong_kind["kind"] = "legion-wrong-kind"
        errors, _ = validator_module.authority_packet_errors(wrong_kind, worker_packet_path)
        assert any("authority packet base shape is invalid" in err for err in errors), errors

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "AGENTS.md").write_text("authority", encoding="utf-8")
        (root / "tasks").mkdir()
        (root / "tasks" / "plan.md").write_text("plan", encoding="utf-8")
        (root / "path-ownership-ledger.json").write_text("{}", encoding="utf-8")
        context = authority_context(root)
        counts = (4, 45, 24, 13, 35, 28, 26)
        worker_ids = ("OR-SUPERVISOR", "MB-IO", "MB-RETRIEVAL", "MB-PLANNER", "MB-LIFECYCLE", "CX-HARDEN", "CX-STATE")
        cursor = 0
        workers = []
        planned_files = []
        for worker_id, count in zip(worker_ids, counts):
            own = [f"owned/path-{value:03d}" for value in range(cursor, cursor + count)]
            cursor += count
            planned_files.extend(own)
            workers.append({
                "id": worker_id,
                "dispatch": "A",
                "executor": "deepseek",
                "allowlist": own,
                "read": ["AGENTS.md", "tasks/plan.md"],
                "forbidden": [".git", "secrets"],
                "checks": [f"verify {worker_id} focused suite"],
                "dependencies": [],
            })
        direct_packet = {
            "schemaVersion": 1,
            "kind": "legion-authority-dispatch",
            "packetType": "direct",
            "sourceRevision": CONCRETE_GIT_SHA,
            "promptDigest": REAL_PROMPT_DIGEST,
            "modelRouting": {"modelTier": "MID", "workerProfile": "parallel", "routingRationale": "seven independent owners"},
            "objective": "Complete Phase A through seven frozen owners.",
            "authority": ["AGENTS.md", "tasks/plan.md", "path-ownership-ledger.json"],
            "integrationOwner": "codex",
            "fileTouchPolicy": {
                "mode": "once-end-to-end",
                "plannedFiles": planned_files,
                "allowUnplannedFiles": False,
            },
            "dispatches": [{
                "id": "A",
                "dependsOn": [],
                "lanes": list(worker_ids),
                "completionChecks": ["all seven lane checks pass and changed paths reconcile"],
            }],
            "workers": workers,
            "oracleAudit": {
                "required": True,
                "mode": "adversarial",
                "status": "required-before-execution",
                "checks": [
                    "allowlist-completeness",
                    "lane-disjointness",
                    "dependency-validity",
                    "maximum-safe-parallelization",
                    "end-to-end-lane-closure",
                ],
            },
            "recovery": {
                "maxRetries": 2,
                "stopConditions": ["owned path is already dirty"],
                "returnFields": ["changedPaths", "checks", "blockers", "baselineRevision", "patchDigest"],
            },
        }
        assert cursor == 175
        direct_path = root / "orthic-suite-phase-a.json"
        direct_receipt = root / "orthic-suite-phase-a.receipt.json"
        direct_packet.update(context)
        direct_path.write_text(json.dumps(direct_packet), encoding="utf-8")
        direct_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(direct_path), "--packet-type", "authority", "--write-receipt", str(direct_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert direct_result.returncode == 0, direct_result.stdout + direct_result.stderr
        direct_receipt_value = json.loads(direct_receipt.read_text(encoding="utf-8"))
        assert len(direct_receipt_value["referenced_artifacts"]) == 4
        assert {entry["path"] for entry in direct_receipt_value["referenced_artifacts"]} == {
            "captured-prompt.txt",
            "AGENTS.md",
            "tasks/plan.md",
            "path-ownership-ledger.json",
        }
        assert direct_receipt_value["sha256"] == hashlib.sha256(direct_path.read_bytes()).hexdigest()
        assert direct_receipt_value["authority_binding"] == {
            "packet_sha256": direct_receipt_value["sha256"],
            "source_revision": context["sourceRevision"],
            "prompt_digest": context["promptDigest"],
        }

        forged_binding = json.loads(json.dumps(direct_receipt_value))
        forged_binding["authority_binding"]["prompt_digest"] = "sha256:" + "f" * 64
        direct_receipt.write_text(json.dumps(forged_binding), encoding="utf-8")
        replay_result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(direct_path), "--packet-type", "authority", "--verify-receipt", str(direct_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert replay_result.returncode == 1
        assert "source/prompt binding" in replay_result.stdout
        direct_receipt.write_text(json.dumps(direct_receipt_value), encoding="utf-8")

        (root / "AGENTS.md").write_text("tampered authority", encoding="utf-8")
        authority_replay = subprocess.run(
            [sys.executable, str(VALIDATOR), str(direct_path), "--packet-type", "authority", "--verify-receipt", str(direct_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert authority_replay.returncode == 1
        assert "referenced artifacts" in authority_replay.stdout
        (root / "AGENTS.md").write_text("authority", encoding="utf-8")

        (root / "captured-prompt.txt").write_text("tampered prompt", encoding="utf-8")
        prompt_replay = subprocess.run(
            [sys.executable, str(VALIDATOR), str(direct_path), "--packet-type", "authority", "--verify-receipt", str(direct_receipt)],
            check=False, capture_output=True, text=True,
        )
        assert prompt_replay.returncode == 1
        assert "prompt digest does not bind prompt artifact bytes" in prompt_replay.stdout
        (root / "captured-prompt.txt").write_text("exact captured dispatch prompt", encoding="utf-8")

        collision = json.loads(json.dumps(direct_packet))
        collision["workers"][1]["allowlist"].append(collision["workers"][0]["allowlist"][0])
        errors, _ = validator_module.authority_packet_errors(collision, direct_path)
        assert any("direct OWN collision" in error for error in errors), errors

        ancestor_collision = json.loads(json.dumps(direct_packet))
        ancestor_collision["workers"][1]["allowlist"] = ["owned"]
        errors, _ = validator_module.authority_packet_errors(ancestor_collision, direct_path)
        assert any("direct OWN collision" in error for error in errors), errors

        glob_collision = json.loads(json.dumps(direct_packet))
        glob_collision["workers"][1]["allowlist"] = ["owned/**"]
        errors, _ = validator_module.authority_packet_errors(glob_collision, direct_path)
        assert any("allowlist forbids globs" in error for error in errors), errors

        alias_collision = json.loads(json.dumps(direct_packet))
        alias_collision["workers"][1]["allowlist"].append(
            "owned\\path-000/../path-000"
        )
        errors, _ = validator_module.authority_packet_errors(alias_collision, direct_path)
        assert any("direct OWN collision" in error for error in errors), errors

        invalid_scope = json.loads(json.dumps(direct_packet))
        invalid_scope["workers"][0]["allowlist"] = ["../outside-repository"]
        errors, _ = validator_module.authority_packet_errors(invalid_scope, direct_path)
        assert any("allowlist forbids globs" in error for error in errors), errors

        overlap = json.loads(json.dumps(direct_packet))
        overlap["workers"][0]["forbidden"].append(overlap["workers"][0]["allowlist"][0])
        errors, _ = validator_module.authority_packet_errors(overlap, direct_path)
        assert any("OWN overlaps FORBIDDEN" in error for error in errors), errors

        incomplete_inventory = json.loads(json.dumps(direct_packet))
        incomplete_inventory["fileTouchPolicy"]["plannedFiles"].append("owned/unassigned-file")
        errors, _ = validator_module.authority_packet_errors(incomplete_inventory, direct_path)
        assert any("planned files lack lane allowlist" in error for error in errors), errors

        duplicate_lane_membership = json.loads(json.dumps(direct_packet))
        duplicate_lane_membership["dispatches"].append({
            "id": "B",
            "dependsOn": ["A"],
            "lanes": [worker_ids[0]],
            "completionChecks": ["B complete"],
        })
        errors, _ = validator_module.authority_packet_errors(duplicate_lane_membership, direct_path)
        assert any("lanes appear in multiple dispatches" in error for error in errors), errors

        unnecessary_root_wave = json.loads(json.dumps(direct_packet))
        unnecessary_root_wave["dispatches"].append({
            "id": "B",
            "dependsOn": [],
            "lanes": ["lane-b"],
            "completionChecks": ["B complete"],
        })
        errors, _ = validator_module.authority_packet_errors(unnecessary_root_wave, direct_path)
        assert any("move its lanes into first eligible wave" in error for error in errors), errors

        missing_oracle = json.loads(json.dumps(direct_packet))
        del missing_oracle["oracleAudit"]
        errors, _ = validator_module.authority_packet_errors(missing_oracle, direct_path)
        assert any("adversarial Oracle" in error for error in errors), errors

        unknown_dependency = json.loads(json.dumps(direct_packet))
        unknown_dependency["workers"][0]["dependencies"] = ["MISSING"]
        errors, _ = validator_module.authority_packet_errors(unknown_dependency, direct_path)
        assert any("unknown dependency" in error for error in errors), errors

        for invalid_revision in ("", "HEAD", "main", "latest", "0" * 40, "REPLACE_WITH_IMMUTABLE_GIT_SHA"):
            invalid_source = json.loads(json.dumps(direct_packet))
            invalid_source["sourceRevision"] = invalid_revision
            errors, _ = validator_module.authority_packet_errors(invalid_source, direct_path)
            assert any("source revision must be an immutable" in error for error in errors), errors

        invalid_prompt = json.loads(json.dumps(direct_packet))
        invalid_prompt["promptDigest"] = "sha256:" + "0" * 64
        errors, _ = validator_module.authority_packet_errors(invalid_prompt, direct_path)
        assert any("prompt digest must be a non-placeholder" in error for error in errors), errors

        content_bound_source = json.loads(json.dumps(direct_packet))
        content_bound_source["sourceArtifact"] = "AGENTS.md"
        content_bound_source["sourceRevision"] = "sha256:" + hashlib.sha256(
            (root / "AGENTS.md").read_bytes()
        ).hexdigest()
        errors, _ = validator_module.authority_packet_errors(content_bound_source, direct_path)
        assert not errors, errors

        default_asset = json.loads((SKILL_DIR / "assets" / "direct-packet.json").read_text(encoding="utf-8"))
        errors, _ = validator_module.authority_packet_errors(default_asset, SKILL_DIR / "assets" / "direct-packet.json")
        assert any("source revision must be an immutable" in error for error in errors), errors
        assert any("prompt digest must be a non-placeholder" in error for error in errors), errors
        skill_text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        assert "assets/direct-packet.json" in skill_text
        assert "--packet-type legacy` only for explicit legacy compatibility" in skill_text
    print("PASS: dispatch validator accepts durable packet + rejects structural, semantic, status, script, path, temporary-storage, receipt, and typed-authority bypasses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
