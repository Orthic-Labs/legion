# Legion — worker-capsule/relay doctrine bundle

**What this is:** the recovered method manual for the discipline that governs how Legion (the
coordinator) constructs a dispatch packet to any executor — a native subagent, a cheap OmniRoute
worker, or a human handoff. Recovered verbatim from git history — deleted at workspace commit
`d810d827` (claimed "absorbed" into the new agent definitions; it was not). Source:
`git show d810d827^:tools/skills/dispatch/references/manual.md` (505 lines). Loaded by: Legion
(the coordinator), and by Sage/Alchemist/Seer when any of them constructs a sub-dispatch — a
packet to a cheap worker, a fan-out lane, or a handoff — during their own execution.

**Read `doctrine/legion.md` first.** This bundle is the craft underneath that constitution, not a
replacement for it. Where this manual's routing language conflicts with current doctrine, a
`> **Superseded:**` note marks the change inline; everything else is preserved as originally
written, including its own internal skill name (`dispatch`), the retired `/handoff` skill it
references, and file paths from its era.

**G22/G24 note.** This manual predates G22 (lossless relay to a dispatched executor) and G24
(dispatch pre-validation for the coordinator itself). Read this document's compression-adjacent
language — anywhere it describes summarizing, condensing, or paraphrasing a brief for an
executor — as now **forbidden** by G22: a dispatch packet must carry the full context an executor
needs, verbatim, not a compressed digest of it. Flagged inline below at the exact passages
affected, per instruction, rather than silently dropped.

---

# Dispatch advanced manual

```text
MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Validated zero-context dispatch packet.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One bounded packet names scope, acceptance, recovery, ownership, and validation evidence.
```

Create operator runbooks, not summaries. Executor must succeed without chat history, dispatcher memory, or unstated judgment.

> **Superseded:** "Create operator runbooks, not summaries" is exactly the G22 lossless-relay
> principle stated three days early. Any later passage in this document that appears to permit
> condensing a brief is overridden by this line and by G22 — never compress a contract to a worker.

## Iron law

```text
NO AGENT TASK SHIPS UNTIL:
1. target can execute it from zero context;
2. every expected failure has a bounded next action;
3. completion is proven by named evidence;
4. TRUE_BLOCKER requires exhausted recovery + proof;
5. script-bearing work passes the execution-preflight tool with executable evidence;
6. validate-dispatch.py returns PASS.
```

Clear prose is not executable. A referenced plan is not transferred context. A command without cwd, expected result, failure branch, & evidence path is incomplete.

> **Superseded:** items 5–6 name the retired `dispatch` skill's own preflight/validator scripts
> (`tools/skills/dispatch/scripts/validate-dispatch.py`, `tools/skills/execution-preflight` tooling
> era). `docs/rules/execution-preflight.md` is confirmed still live and should still gate any
> script-bearing worker capsule. The standalone `validate-dispatch.py` no longer exists under
> `tools/skills/dispatch/` (the skill was retired); this is the structural gap J-2 exists to close —
> until then, apply this manual's checklist by hand rather than treating "validator PASS" as a
> literal command that currently runs.

## Step 0 — Decide whether dispatch should exist

Dispatch only when delegation adds useful parallelism, isolation, machine access, or focused execution. Keep orchestration, architecture, synthesis, tiny edits, & user-reserved decisions in current session.

When request explicitly asks for dispatch, create it. Compactness never removes required fields.

## Step 0A — Create canonical audit artifact

Before validation or spawn, create permanent packet under:

- existing project packet directory, when declared by project rules; else
- `<project>/tasks/dispatches/<YYYY-MM-DD>/<dispatch-id>.md`; or
- `D:/Claude/tasks/dispatches/<YYYY-MM-DD>/<dispatch-id>.md` for cross-project studio work.

Receipt lives beside packet as `<dispatch-id>.receipt.json`. Never use OS Temp, `.cache`, `.council-runs`, scratch, or disposable validation path as canonical artifact. Include packet + receipt in scoped commit when task operates in tracked repo & packet has no sensitive content.

> **Superseded:** `.council-runs` → the current Covenant engine's run directory under
> `tools/skills/covenant/`; verify the live path before reuse rather than assuming the old name.

## Step 1 — Ground task before writing

Read:

1. user request, including granted authority & reserved decisions;
2. nearest `AGENTS.md` / workspace rules;
3. exact source documents, plans, files, errors, & current state;
4. relevant skill bodies or runbooks executor must follow;
5. current scoped Git status for edit tasks;
6. live launcher, model, tool, API, or environment config when routing can drift.

In `D:\Claude`, read `tools/skills/dispatch/references/agent-routing.md` before dispatching. Preserve its primary-checkout, model-tier, structured-prompt, parallel-safety, anti-hang, & integration rules.

Never write "use existing context," "as discussed," "follow plan," or equivalent. Cite exact accessible paths + required sections. Embed essential facts which exist only in chat.

> **Superseded:** `tools/skills/dispatch/references/agent-routing.md` no longer exists (the
> `dispatch` skill was retired). Its primary-checkout / model-tier / structured-prompt /
> parallel-safety / anti-hang / integration rules have no confirmed current home — treat this as a
> content gap rather than a live pointer. The nearest living equivalents are `docs/agent-rules/*.md`
> (workspace + legion routing rules) and the per-role model selection referenced in
> `docs/plans/legion/BRIEFING-LAYER.md` §5 ("Knobs that exist"). "Embed essential facts which exist
> only in chat" is the literal G22 lossless-relay requirement — never paraphrase this away.

## Step 1A — Freeze decision semantics before adding evidence

For experiments, benchmarks, performance work, model work, research, or repeated failures, reduce request to:

1. smallest numbered decision questions;
2. exact metrics + thresholds which answer them;
3. role of every fixture/workload;
4. diagnostics which may explain results but never gate completion;
5. explicit forbidden metrics, labels, tools, models, analyses, & scope;
6. exact prior ground truth, if any;
7. outputs measured by runner which must not be invented as prior labels.

> **Superseded:** "reduce request to" reads as compression at a glance; the intent is *structuring*
> the request into typed fields, not shortening or dropping content. Under G22, every field below
> must still carry the original request's full substance — structuring is allowed, lossy reduction
> is not.

Then create requirement-to-decision trace. Class every proposed requirement:

- `ACCEPTANCE` — directly answers named question;
- `DIAGNOSTIC` — explains acceptance result but cannot gate it;
- `EXECUTION_INPUT` — necessary to run measurement, not ground truth;
- `SAFETY` — bounds harm, mutation, cost, or access;
- `FORBIDDEN` — does not affect decision or violates scope.

Delete any unmapped requirement. Template completeness cannot create experiment requirements. Useful evidence is not automatically required evidence.

Lock fixture roles literally. Binary positive/negative clips do not acquire per-item intent labels. Latency workload does not acquire transcript, WER, semantic-correctness, or equivalence requirements. Measured onset, decoded text, parsed intent, latency, & resource readings are outputs unless authoritative source declares them prior ground truth.

Before any model, tool, dependency, label-generation, or new analysis:

```text
ALLOW only when it directly produces a named acceptance metric or required safety evidence.
FORBID when acceptance metric = NONE.
```

Record exact locked route/version when allowed. Recovery restores required input or measurement path; it cannot invent labels, introduce unrelated models/tools, convert diagnostics into gates, or broaden experiment.

### Authority & correction invalidation

Apply authority in exact order:

```text
LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT >
INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS
```

Concrete inherited text, running processes, completed files, checkpoints, sunk cost, & prior validation never outrank corrected objective.

For every dispatch, inventory inherited requirements & classify each `KEEP`, `DELETE`, or `REWRITE`. Reconcile source inventory count to classified rows with zero unclassified clauses & durable evidence path. `KEEP` requires named decision effect + one stage owner. `DELETE` requires exact match text, explicit no-decision-value/conflict reason, & exclusion scope. `REWRITE` requires old match text, replacement text, decision effect, & new stage owner. Purge deleted/rewritten old text from active decision, stage, fixture, acceptance, model/tool, & command contracts. Unclassified inheritance fails release.

Audit latest request against prior plan & record semantic delta with evidence. `SEMANTIC_DELTA:YES` must use semantic-correction path; `NO` must use fresh/no-correction path. A semantic user correction triggers global re-derivation:

1. stop active execution;
2. mark entire current plan invalid;
3. invalidate every downstream stage from `ROOT`;
4. quarantine existing outputs as evidence-only;
5. restate decision from latest user intent;
6. reclassify every inherited requirement from zero;
7. rebuild all stage records, commands, fixtures, acceptance, & recovery;
8. reuse old output only after exact new-contract compatibility proof.

Local clause patching is forbidden. A corrected dispatch must not preserve an instruction merely because it is explicit, already implemented, expensive, validated under old plan, or present after compaction.

### Universal goal route & critical path

Before GoalRoute, compile `<dispatch-stem>.minimize.json` plus
`<dispatch-stem>.minimize.receipt.json` with `tools/lib/minimize/minimize_gate.py`. Select first safe
canonical rung, reject every earlier rung with evidence, and declare every new file/dependency.
These are internal sidecars, never user-visible dispatch sections. `validate-dispatch.py` fail-closes
when either sidecar is missing, invalid, stale, or policy-bound to different bytes.

Before task decomposition or experiment topology, compile GoalRoute v2 through
`tools/lib/goalroute` from exact
current state A to verified state B. This applies to routine work too.

Required route contract:

1. freeze `STATE_A`, `STATE_B`, success proof, & hard constraints;
2. enumerate 2–3 feasible routes, or declare `SINGLE_FEASIBLE` with evidence proving alternatives invalid;
3. expand ordered steps, dependencies, nominal critical path, retry/failure probability, cost, risk, & rework per route;
4. reject every route violating hard constraint;
5. calculate expected time to verified B = nominal path + weighted retry cost + weighted failure rework;
6. select minimum-expected-time valid route; equal-time route must not dominate cost/risk/rework;
7. delete work that does not advance B; defer downstream work until dependency gate passes;
8. bind each execution step to one selected route step & observable B-state delta;
9. order steps by dependencies, never source-document order;
10. validate durable route artifact + receipt and freeze it in Forge for non-routine work.

Route comparison is not permission to add speculative alternatives. Search only bounded feasible space. A route which is faster but unsafe or outside authority is `FAIL` under hard constraints, not valid shortcut.

Validator rejects generic A/B, invalid/missing GoalRoute receipt, unproven singleton, selected
constraint failure, lower-expected-time passing route, equal-time dominance, unresolved duration,
unjustified serialization, unbound step, non-advancing work, dependency disorder, or mismatched
Forge/route binding.

### Experiment topology & workload economics

Classify topology before writing commands:

- `SELECTION_FUNNEL` — goal is choose winner/shortlist or optimize deployment. Use successive elimination; later work runs only on upstream survivors.
- `FULL_COMPARATIVE_DATASET` — deliverable requires comparable results for every arm across every fixture. Requires `FULL_COMPARATIVE_DATASET_AUTHORIZED: SOURCE:USER_REQUEST|AUTHORITATIVE_SPEC:<path>; REASON:<decision need>`.
- `SINGLE_PATH` — no competing candidate population; state exact reason.

"Benchmark," "bakeoff," fairness, complete evidence, & identical inputs do not authorize full matrix. Decide from actual output: complete arm-by-arm dataset versus efficient winner selection.

For `SELECTION_FUNNEL`, declare these distinct stages in order:

1. `TECHNICAL_RUNNABILITY` — loads/executes on locked runtime; proves no behavioral utility.
2. `BEHAVIORAL_UTILITY` — minimum positive/utility gate; rejects candidates incapable of winning.
3. `PERFORMANCE_SHORTLIST` — ranks only behavioral survivors on decision-relevant performance.
4. `SAFETY_NEGATIVES` — runs negative/safety corpus only on plausible winners.
5. `SYSTEM_INTERFERENCE` — runs final end-to-end workload only on safety survivors.

Every stage must name decision question, bounded input population, entry gate, numeric workload factors + maximum jobs, exact command selector, exit gate, survivor artifact, actual-count ledger, & downstream prohibition. Downstream stage must consume exact upstream survivor artifact; `--all`, full corpus, wildcard candidate selectors, or reconstructed survivor sets are forbidden.

Also emit one typed record per stage:

```text
stage, decision, provider + necessity, dataset + role, execution mode,
admission, pass rule, explicit exclusions, estimated runs,
minimum wall-time factors
```

Provider must be required by stage decision; inherited provider lists do not create authority. Dataset must belong to exactly one stage. Offline logical qualification forbids physical sleep, realtime pacing, & wall-clock cadence simulation. Downstream dataset cannot appear in any earlier command.

Every fixture belongs to exactly one stage. Winner-only, safety-only, interference-only, or expensive fixture cannot appear in earlier/broad command.

Table claims must bind executable work: every stage has exactly one tagged `STAGE_COMMAND` block that consumes declared input/survivor plus owned fixtures & writes declared survivor artifact plus actual-count ledger. Missing, duplicate, or mismatched command binding fails release.

Apply value-of-information test before every stage:

```text
RUN_ONLY_IF: this result can change advance/reject/rank/winner/safety decision.
SKIP: result cannot change remaining decision.
```

Expand workload before release. For each stage record numeric factors, `MAX_JOBS`, actual-count ledger path, `ESTIMATED_RUNS`, positive integer `MS_PER_RUN_MIN`, maximum concurrency, computed `MIN_WALL_MS`, wall-floor evidence path, & sums as `JOB_TOTAL_MAX` plus `MIN_WALL_MS_TOTAL`. Typed decision text must exactly match funnel decision, not merely share question ID. Unresolved estimate blocks launch. Supervisor recomputes launched jobs before launch, after each stage, & before any batch; mismatch stops downstream launch. Runtime loadability never satisfies behavioral qualification. Winner safety never forces negatives across candidates already unable to win.

Full matrix is valid only when topology is `FULL_COMPARATIVE_DATASET`, packet attributes authorization to user request or exact authoritative spec, all fixtures are intentionally shared/owned, formula sum is explicit, & deliverable needs every row. Dispatcher, "fairness," or structural completeness cannot self-authorize it. Otherwise flattened matrix is dispatch defect.

### Mandatory Forge semantics gate

Use Forge for `EXPERIMENT`, `BENCHMARK`, `PERFORMANCE`, `MODEL`, `RESEARCH`, & `REPEATED_FAILURE` dispatches:

1. `assess` before authoring with user question, authority order, correction state, decision rule, acceptance-only metrics, inherited-instruction disposition, typed stage records, diagnostics, forbidden scope, fixture roles, & ground-truth policy;
2. record returned `run_id` + `forge://run/<run_id>/state`;
3. `checkpoint` after requirement-to-decision trace, inherited-instruction disposition, typed stage records, & model/tool relevance table;
4. resolve every critical semantic claim, then `verify` before release;
5. write `VERIFIED_NO_CRITICAL_OPEN` only when verification has no critical open claim;
6. checkpoint executor readback before any model/tool load, batch, paid call, or scope change;
7. let trusted host hook/operator close run only after acceptance is independently integrated.

Model must never spoof `FORGE_TRUSTED_CALLER`, operator authority, passing-check attestation, or close around signoff deficit. When trusted host cannot attest/close, retain actual MCP `verify` decision + unresolved list, then rely on dispatch validator, receipt, decision trace, & integration checks as hard release gates.

Forge claims must use typed stage fields, not freeform plan prose. Forge records & challenges scope traceability; it does not decide experiment meaning or replace deterministic validator. Dispatcher remains responsible for correct questions, classifications, & source binding. Routine bounded work may use `NOT_REQUIRED: <exact reason>`.

Executor first output must read back decision questions, acceptance metrics, diagnostics, forbidden scope, fixture roles, & exact first action. Orchestrator rejects wrong readback before execution. Declare numeric supervision cadence plus mandatory checkpoint before new model/tool/dependency, batch, cost, or recovery-induced scope change.

> **Superseded:** "Forge" here means the workspace's Forge assess/checkpoint/verify system named in
> `docs/agent-rules/workspace.md` ("Mandatory systems") — still live, unrelated to `packages/sentinel`
> or the `forge` repo name collision noted in this task's own instructions. No rename needed; this
> usage was already correct.

## Step 2 — Design ownership & dependency graph

For each executor, define:

- one outcome;
- `OWN` paths it may edit;
- `READ` paths it may inspect;
- `FORBIDDEN` paths/actions;
- upstream inputs;
- downstream consumer;
- dependency position;
- whether task is parallel-safe;
- integration owner.

Multiple agents receive separate complete dispatches. Never give overlapping `OWN` scopes. Serialize shared-state edits, builds, installs, renders, deploys, migrations, paid calls, & production writes.

Use this coordination table before multi-agent dispatch:

| ID | Outcome | Depends on | OWN | READ | FORBIDDEN | Parallel with | Integrator |
|---|---|---|---|---|---|---|---|

If independence is uncertain, investigate first. Do not dispatch ambiguity.

## Step 2A — Materialize scripts before delegation

When work needs a new script, runner, command sequence, or pipeline, orchestrator creates smallest correct helper before dispatch whenever it has required workspace, runtime, inputs, & authority. Do not make executor reinvent mechanics dispatcher can package deterministically.

Apply the execution-preflight tool to every new or existing script-bearing path:

1. read `docs/rules/execution-preflight.md`;
2. classify `S0`–`S3`;
3. prove preflight;
4. smoke exact ship path on tiny representative input;
5. check output correctness, not presence;
6. declare blast radius;
7. complete required optimization checks;
8. verify GoalRoute v2 receipt and record binary `SHIP: yes` before dispatch.

If a script can run only on the executor machine or requires executor-only hardware/access, dispatcher still provides exact path/spec, creation owner, preflight, smoke fixture, correctness assertion, side effects, recovery, & required evidence. Executor must pass execution preflight before a full run. "Write a script to do it" without interface + checks is forbidden.

Set `Script involved: YES` for scripts, runners, pipelines, batch loops, generated commands, remote jobs, paid calls, destructive actions, or production mutations. `NO` requires exact reason. Validator enforces script gate fields.

## Step 3 — Author from required template

Copy [dispatch template](../assets/dispatch-template.md). Fill every placeholder. Use exact paths, commands/tool actions, cwd, expected outputs, checks, artifacts, & limits.

> **Superseded:** the referenced dispatch template no longer exists under
> `tools/skills/dispatch/assets/`. No current equivalent template was located; treat this as a
> content gap (template needs re-authoring, not merely re-pointing) rather than a stale link to
> silently drop, since Step 3's field checklist below still applies without one.

### Execution identity & provenance gate

Before executor may resume or generate work, packet must:

1. name exact required producer/actor plus field, log, receipt, or command proving identity;
2. declare allowed provenance/lineage & forbidden producers, transforms, projections, direct closures, substitutes, or synthetic stand-ins;
3. inventory existing work with exact command;
4. reject/quarantine existing work when producer, provenance, derivation, or lifecycle differs;
5. permit resume only after compatibility proof;
6. define ordered lifecycle with at least five observable states, including start, terminal execution, delivery, & terminal value;
7. preflight entire chain before main run;
8. map `PRODUCER_IDENTITY`, `LIFECYCLE_CHAIN`, & `NO_SUBSTITUTION` to exact acceptance checks + evidence paths.

"Continue existing run," "generate genuine traffic," or "use equivalent output" is invalid without these fields. Existing progress never overrides dispatch invariants.

### Reset, full-path & classification controls

Every dispatch must also define:

- `RESET_REQUIRED:` or `RESUME_ALLOWED_IF:` with exact live compatibility proof. Mid-run corrected authority defaults to stop, preserve/discard invalid window as specified, refresh authority, reverify, & restart preflight.
- `PRODUCTION_PATH:` from actual entry through adapter/hook/config, required producer/runtime, terminal execution, delivery, & value/acceptance. Binary/tag/schema identity alone never proves product-path execution.
- `HASH_VERIFY:` for every frozen component affecting semantics, including hooks, adapters, config, launcher, runtime, & binary where applicable.
- `TRACE_LINK:` keys joining expected → started → terminal → delivery → value/feedback. Counts without links do not prove lifecycle.
- environment-integrity step zero before installs, capture, mutation, or batch work. Dirty/append-only/canonical-state failure is host evidence, not candidate defect.
- one-unit canary before batch. Batch is `PROHIBITED_UNTIL_CANARY_PASS`.
- gate isolation matrix stating what each validator proves & explicitly does not prove. Qualification/latency/schema gates never inherit lifecycle claims absent matching checks.
- phase-scoped substitution matrix. Permission in one phase/gate never transfers to another.
- `DEFECT_ONLY_IF:` production path is proven, canary passed, exact provenance/links hold, environment integrity passed, & canonical check still fails.
- mid-run update protocol exactly: `STOP -> DISCARD_INVALID_WINDOW -> PULL_AUTHORITY -> REVERIFY -> RESTART_PREFLIGHT`.

Critical discriminating invariants must be embedded in packet. "Read/follow guide," "follow recovery ladder," or component hashes without end-to-end path proof cannot carry essential semantics.

If thread guard is `CRITICAL`, do not abbreviate or bypass dispatch construction. Create validated durable `/handoff` to fresh chat, then author + validate dispatch there. Never present summary prompts as zero-context dispatches.

> **Superseded:** `/handoff` is retired per this task's own instructions ("superseded by native
> continuation"). Read "create validated durable `/handoff` to fresh chat" as: use the harness's
> native session-continuation mechanism instead. "Never present summary prompts as zero-context
> dispatches" remains the operative rule regardless of mechanism — it is exactly G22 again.

Every execution step must answer:

1. Why does this step exist?
2. What exact inputs does it consume?
3. Where does it run?
4. What exact command or tool action runs?
5. What stdout/state + exit/result proves success?
6. What timeout + retry bound applies?
7. Where are outputs + evidence stored?
8. What happens for each failure?

If command differs by OS, provide both branches & selection rule. If executor lacks shell access, name exact tool call, arguments, & expected response.

## Step 4 — Build failure-complete recovery

Include all failure classes below, even when response is "not applicable — reason":

| Class | Mandatory recovery behavior |
|---|---|
| `PATH_OR_INPUT_MISSING` | Search exact filename/key, inspect declared parent paths, check moved/renamed sources, then record search commands + results. |
| `TOOL_OR_DEPENDENCY_MISSING` | Check repo-native runner, lockfile, installed runtime, alternate existing tool, then report exact missing prerequisite. Never install unasked dependency. |
| `AUTH_OR_PERMISSION_FAILURE` | Confirm credential presence without printing it, check supported auth route/scope, retry once after non-destructive correction, then emit missing access. |
| `TRANSIENT_EXTERNAL_FAILURE` | Capture status/error, bounded retry with backoff, honor rate limits, resume from checkpoint, never restart completed work. |
| `INVALID_INPUT_OR_SCHEMA` | Validate format/schema, isolate invalid portion, recover from authoritative source, or generate clearly labeled diagnostic fixture without claiming real acceptance. |
| `INTEGRITY_OR_HASH_MISMATCH` | Quarantine suspect artifact, re-fetch/rebuild from authoritative source, compare receipt, & never consume unverified data. |
| `DETERMINISTIC_COMMAND_FAILURE` | Preserve stdout/stderr, isolate smallest reproduction, inspect source/config, fix in scope, rerun failed check then enclosing check. |
| `DIRTY_OR_CONFLICTING_STATE` | Preserve unrelated work, inspect diff, narrow edits, avoid reset/revert/branch/worktree, escalate only on unavoidable overlap. |
| `WRONG_PRODUCER_OR_PROVENANCE` | Reject/quarantine incompatible run, prove required producer + lineage, restart only invalid slice, preserve compatible completed work. Never project or directly close required producer output. |
| `RESOURCE_OR_CAPACITY_FAILURE` | Measure disk/memory/GPU/API quota, reduce safe concurrency/batch, resume, then report exact unavailable capacity. |
| `AMBIGUOUS_REQUIREMENT` | Resolve from source-of-truth files, nearby patterns, tests, locked decisions, & smallest reversible interpretation. |
| `UNSAFE_OR_OUT_OF_SCOPE_ACTION` | Stop only unsafe step, finish every independent safe deliverable, identify authority or decision required. |
| `UNKNOWN_FAILURE` | Capture raw error, timestamp, command, cwd, environment, last successful checkpoint, reproduction, & next diagnostic. |

Each failure row needs:

- primary recovery branch;
- second executable branch;
- degraded/independent continuation;
- retry/stop bound;
- exact proceed condition;
- exact TRUE_BLOCKER threshold.

If branch is genuinely unavailable, replace it with exact reason + discovery action. Never leave it blank.

### Recovery ladder

Use in order until progress resumes:

1. Re-read exact error & failing artifact.
2. Re-discover paths/config from live workspace.
3. Re-run smallest deterministic reproduction.
4. Apply smallest in-scope correction.
5. Retry transient failure within declared limit.
6. Use documented existing fallback with equivalent acceptance criteria.
7. Split failed step so unaffected work continues.
8. Escalate only under TRUE_BLOCKER law.

Do not stop at "file missing," "command failed," "tests fail," "tool unavailable," "need context," or "unclear." Those are diagnoses to resolve.

## Step 5 — Enforce TRUE_BLOCKER law

Executor may return `TRUE_BLOCKER` only when all are true:

1. requested outcome cannot advance safely;
2. blocker is external or non-inferable: missing secret/private input, unavailable required service/hardware, explicit user-reserved decision, unauthorized destructive/production action, or unavoidable conflict with preserved user work;
3. every applicable recovery action ran;
4. all independent safe work completed;
5. blocker packet includes exact failed step, commands/actions attempted, raw error, evidence paths, state preserved, single missing input, & exact resume command.

If any condition is false, executor continues. `PARTIAL`, `NEEDS_CONTEXT`, & vague `BLOCKED` are forbidden terminal statuses.

> **Superseded:** this is the direct ancestor of Alchemist's own blocker discipline
> (`doctrine/alchemist.md` "New engineering decision" and BLOCKER_CONSULT rows) — the same law,
> now stated as Alchemist's constitution rather than a dispatch-manual clause. Apply both
> consistently; they do not conflict.

## Step 6 — Make acceptance executable

Map each requirement to:

- exact verification command/action;
- expected value, threshold, schema, visual state, or hash;
- evidence artifact path;
- responsible owner.

"Tests pass," "looks correct," "reviewed," & "done" are not evidence without command/output or artifact. Delegated work is not proof of completion; dispatcher/integrator reruns relevant final checks after integration.

For real-data gates, synthetic or partial diagnostics cannot satisfy acceptance unless user explicitly changed criterion.

> **Superseded:** "Delegated work is not proof of completion; dispatcher/integrator reruns relevant
> final checks after integration" is the direct ancestor of G16 ("worker output is untrusted until
> locally verified") named in `doctrine/legion.md` and `doctrine/alchemist.md`.

## Step 7 — Zero-context simulation

Before dispatch, simulate fresh executor encountering:

1. source path missing;
2. dirty checkout;
3. required tool absent;
4. auth failure;
5. transient timeout/rate limit;
6. invalid schema/input;
7. hash/integrity mismatch;
8. existing run from wrong producer or provenance;
9. missing producer/provenance proof;
10. incomplete expected → started → terminal → delivery → value-terminal chain;
11. direct closure, projection, synthetic stand-in, or unauthorized substitute;
12. deterministic test failure;
13. partial output/checkpoint;
14. unsafe next action;
15. conflicting instructions;
16. no safe degraded path.

For each, dispatch must identify next action, retry bound, evidence, & escalation threshold without asking dispatcher to reconstruct intent.

Then answer:

- Can executor locate every input?
- Can executor choose first action?
- Can executor distinguish pass from plausible output?
- Can executor state exact user decision questions without adding one?
- Does every acceptance row map to named question + metric?
- Are diagnostics impossible to promote into completion gates?
- Are measured outputs kept separate from prior ground truth?
- Is every model/tool load forbidden when it produces no acceptance metric?
- Is task winner-selection funnel or full comparative dataset?
- Does authority order place latest user intent above inherited text & progress?
- If correction exists, was whole plan invalidated & rebuilt from objective rather than locally patched?
- Was every inherited clause explicitly kept, deleted, or rewritten?
- Does every stage consume only upstream survivors?
- Does every acceptance criterion have exactly one stage owner?
- Does each stage provider directly serve its decision?
- Does each typed stage bind dataset, mode, admission, pass, exclusions, runs, & minimum wall time?
- Is offline qualification free of physical sleep/realtime pacing?
- Can every launched evaluation still change a decision?
- Are stage factors, ceilings, actual counts, run estimates, wall-time floors, & totals reconciled?
- Does each fixture have one stage owner?
- Is any broad selector or full matrix explicitly authorized?
- Can recovery proceed without expanding experiment?
- Can executor recover without inventing scope?
- Can integrator audit every claim?
- Can executor prove a true blocker?

Any "no" means revise.

## Step 8 — Validate before sending

Write dispatch to a durable, named `.md` artifact before validation. Temporary-only & inline-only dispatches are forbidden. This file remains canonical audit, execution, & integration source. If executor cannot access filesystem, paste exact validated bytes inline while retaining canonical file + receipt.

For tracked cross-machine authority, declare dispatch, receipt, GoalRoute, and Minimize paths
relative to Git root. Receipts bind those portable locators plus exact bytes; host-absolute paths
belong only in executable commands after resolving checkout root. Never mint Mac-absolute authority
for Windows or Windows-absolute authority for Mac.

Windows:

```powershell
py -3.11 D:/Claude/tools/skills/dispatch/scripts/validate-dispatch.py <dispatch.md> --write-receipt <dispatch.receipt.json>
```

macOS:

```bash
python3 /Volumes/D/claude/tools/skills/dispatch/scripts/validate-dispatch.py <dispatch.md> --write-receipt <dispatch.receipt.json>
```

Do not spawn/send or call dispatch/derived handoff ready, executable, or zero-context until exit code is `0`, output begins `PASS:`, & adjacent receipt exists. Validator checks structure, producer/provenance/lifecycle contract, required failure classes, step contracts, checked author gate, placeholders, bypass language, durable paths, & raw-byte digest. Fix every error, rerun, then send exact dispatch + receipt together. Any derived handoff must independently pass `/handoff`.

Receiver recomputes digest before execution:

```powershell
py -3.11 D:/Claude/tools/skills/dispatch/scripts/validate-dispatch.py <dispatch.md> --verify-receipt <dispatch.receipt.json>
```

Embedded self-hash is forbidden because changing document to add its hash changes hash. Sidecar binds exact bytes without circularity.

> **Superseded:** `validate-dispatch.py` and `/handoff` as invoked here no longer exist as live
> commands — this is exactly the machinery J-2 (adapt the preserved dispatch validator to agent
> dispatches) is scoped to rebuild. `tools/lib/dispatch-validator/` was deliberately preserved for
> this purpose per `docs/plans/legion/BRIEFING-LAYER.md` §7 item J-2. Until J-2 lands, apply this
> step's checklist by hand: write the packet to a durable path, reconstruct the checks below
> manually, and do not claim "validator PASS" as a literal executed command.

## Executor return & integration contract

Require exactly:

```text
STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER
SUMMARY: <what changed or established>
ACCEPTANCE: <criterion -> command/check -> result -> evidence path>
ARTIFACTS: <absolute/checkout-relative paths + size/count/hash where required>
CHANGES: <files changed + purpose>
COMMANDS: <exact commands/actions run + exit/result>
RECOVERY: <failures encountered + attempts + resumed checkpoint>
DEVIATIONS: <none | authorized deviation + source>
BLOCKER: <none | exact blocker packet + timestamp + affected outputs + 3 unblock options + recommended owner>
NEXT: <integration action or exact resume command>
```

`COMPLETE_WITH_NOTES` still requires every acceptance criterion to pass. Notes are non-blocking observations only.

## Hard rules

- Every dispatch exists as permanent named Markdown file + sidecar receipt before send or spawn; inline content is transport copy only.
- User decision questions, acceptance-only metrics, diagnostic-only fields, fixture roles, ground-truth policy, forbidden scope, & requirement trace are frozen before operational detail.
- Latest user intent outranks objective, stage contract, inherited documents, implementation, checkpoints, & progress; semantic correction invalidates whole plan from ROOT & forces from-zero re-derivation.
- Every inherited instruction is KEEP, DELETE, or REWRITE with decision effect, stage ownership, & exclusion/replacement evidence.
- Selection work uses staged elimination with explicit survivor artifacts, fixture ownership, numeric workload ceilings, actual-count reconciliation, & downstream prohibitions; full matrix requires explicit comparative-dataset authorization.
- Every stage has typed provider/dataset/mode/admission/pass/exclusion/run/wall-time record; offline mode forbids physical sleep & unresolved estimates block launch.
- No model, tool, dependency, label, transcript, or analysis is allowed unless it produces a named acceptance metric or required safety evidence through locked route.
- Forge is mandatory for experiment, benchmark, performance, model, research, & repeated-failure dispatches; executor readback is checked before execution.
- Required producer, provenance, ordered lifecycle, existing-work disposition, & substitution policy are explicit & acceptance-tested.
- Dispatch is self-contained relative to executor-accessible workspace, not dispatcher memory.
- User request supplies authority for requested steps; dispatch records it explicitly.
- No placeholder, inferred path, unnamed command, silent assumption, or "figure it out."
- No vague "review," "handle," "ensure," "robust," or "secure" instruction without exact operation + check.
- No terminal partial state. Continue or prove TRUE_BLOCKER.
- No acceptance by agent summary alone; require raw artifacts & rerun integration checks.
- No parallel overlap in owned files, shared mutable state, or costly operations.
- No script-bearing dispatch without execution-preflight evidence & a named creation owner.
- Every dispatch binds a validated GoalRoute v2 artifact/receipt; inline route table is transport summary, not route authority.
- No task send before validator PASS.
- Dispatcher owns prompt completeness. Executor failure caused by missing dispatch context is dispatcher defect.
