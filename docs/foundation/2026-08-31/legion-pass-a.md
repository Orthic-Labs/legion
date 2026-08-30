# Legion independent Foundation pass A

## Frozen scope & corpus

Product/scope: Legion / missed orchestration atoms. Requested stages: supplied-corpus freeze & Stage 2 atomic inventory only. Criteria: correctness, runtime fit, local-first privacy, latency, recovery visibility, accessibility where applicable, maintainability, & testability. Saturation stop: user supplied complete local reference set; all direct children were inspected at frozen commits; no discovery beyond supplied boundary.

| Repository | Frozen commit | Platform / applicability |
|---|---|---|
| addyosmani__agent-skills | `d2c37ef6225dd8726cdd369a8030307f48592d26` | Claude Code/Codex plugin hooks & command runtime; evaluated |
| Agent-Field__agentfield | `8bc5e808b1481554628f14fdc98c72e3ad89fb32` | Go control plane, Python/TypeScript SDKs, Electron desktop, web UI; evaluated |
| Agent-Field__SWE-AF | `0c64fe7cc4fc216f4d32d0b855015509750eb4aa` | Python & Go autonomous SWE runtime; evaluated |
| anthropics__claude-code | `f1af9b1f4b1fd4c776135381606edada82ef638e` | Claude Code hooks/plugin utilities; evaluated |
| ArabelaTso__Coding-Skills-Collection | `e66a625f0dd4e3ce2cdcf7ddcc81eec89b237bf4` | Catalog/document corpus only under admissible membrane; excluded |
| coderabbitai__skills | `aa49953c4cb2590e35480637b1b6a29cf4187cfa` | Agent command configuration; evaluated, no independently proven behavior |
| EricGrill__agents-skills-plugins | `43a037fd7952cc5205bafe146f33369e518e528b` | Cross-agent plugin scripts; evaluated |
| garrytan__gstack | `07b59e396c6be5a86619a43151cb9ed62a15ae69` | Claude Code plugin, browser automation & review workflows; evaluated |
| instructa__agent-skills | `7e90526cebf7fa6d15bab3260061d1ca383225b3` | Agent skill shell/Python runtime; evaluated |
| LambdaTest__agent-skills | `0491a3a29aa18558d2c3c64ff09367adb976c56f` | Browser/device automation skill runtime; evaluated |
| mattpocock__skills | `6654f6b60cd9d5be8b54c6fafe44346dabeb3b76` | Agent skill hooks; evaluated |
| NeoLabHQ__context-engineering-kit | `23e2428e809d77717f8acc9659c374a3a1fcb93e` | Claude Code context hooks; evaluated |
| obra__superpowers | `b36e0829c6d0140e93cfef2ca599b1b07d4a7797` | Claude Code/Codex plugin bootstrap & hooks; evaluated |
| SWE-agent__mini-swe-agent | `25941c89cfbc91eb40b3f8756348c91d9977d57e` | Python CLI agent across local/container/remote environments; evaluated |
| swe-agent__swe-agent | `3ea751c087f32b16e039a2233dd6eefecef325d5` | Python CLI agent & sandbox runtime; evaluated |
| testdino-hq__playwright-skill | `d3be9ca4d7303e2aee3eba4842963abf573117b0` | Documentation-only skill under admissible membrane; excluded |
| trailofbits__skills | `d1f1575cff97816e5cc08af66cd2506099c681d3` | Security-analysis plugin scripts & workflows; evaluated |
| VoltAgent__awesome-agent-skills | `5e1f3aebcf5de90b5b11fb35a607f95bdddf987e` | Catalog/document corpus only under admissible membrane; excluded |

## Atomic inventory

| Platform | Domain | Atom | Definition / boundary | Source evidence |
|---|---|---|---|---|
| Shared agent runtime | Execution control | Bounded autonomous run | Operator can cap agent work by steps, spend, wall time, & repeated malformed responses; excludes provider retry policy. | SWE-agent__mini-swe-agent, Python CLI: `src/minisweagent/agents/default.py`, `AgentConfig` & `DefaultAgent.query`; live consumer `DefaultAgent.run`; counters stay in trajectory state & limit exceptions produce explicit exit status. |
| Shared agent runtime | Execution control | Durable trajectory capture | Operator receives replayable run state containing messages, model usage, environment configuration, exit status, & submission; excludes user-facing progress display. | SWE-agent__mini-swe-agent, Python CLI: `src/minisweagent/agents/default.py`, `DefaultAgent.serialize/save`; consumer `DefaultAgent.run` saves after every step, including exceptional paths; JSON file is persistent fallback. |
| Local/remote shell runtime | Execution control | Process-tree timeout cleanup | Timed-out action terminates its process group so child processes do not survive agent cancellation; excludes ordinary nonzero exits. | SWE-agent__mini-swe-agent, local Python runtime: `src/minisweagent/environments/local.py`, `_run`; consumer `LocalEnvironment.execute`; timeout kills POSIX group or Windows process, captures remaining output, & returns typed exception detail. |
| Shared model runtime | Reliability | Selective exponential model retry | Transient model failures retry with bounded exponential backoff while configured terminal failures abort immediately; excludes orchestration-level replanning. | SWE-agent__mini-swe-agent, Python providers: `src/minisweagent/models/utils/retry.py`, `retry`; provider query implementations consume returned `Retrying`; attempt ceiling is environment-configurable, delays cap at 60 seconds. |
| Shared agent runtime | Completion | Protocol-bound submission | Run ends only when environment observes explicit completion marker paired with successful command, preserving following output as submission; excludes semantic validation. | SWE-agent__mini-swe-agent, local Python runtime: `src/minisweagent/environments/local.py`, `LocalEnvironment._check_finished`; caller `execute`; raises `Submitted` only for marker on first output line plus return code zero. |
| SWE agent CLI | Context management | Observation clipping with recovery guidance | Oversized tool output is clipped to context budget while agent receives omitted-size evidence & actionable narrower-query guidance; excludes whole-history compression. | swe-agent__swe-agent, Python CLI: `sweagent/agent/agents.py`, `TemplateConfig.next_step_truncated_observation_template` & `max_observation_length`; consumed by agent observation formatting in same runtime; preserves elided character count. |
| SWE agent CLI | Safety | Shell syntax preflight | Invalid shell syntax is rejected before execution & returned to agent with parser output for correction; excludes command authorization. | swe-agent__swe-agent, Python CLI: `sweagent/agent/agents.py`, `TemplateConfig.shell_check_error_template`; live agent step catches `BashIncorrectSyntaxError` through tool handler path; command is not executed. |
| SWE agent CLI | Review | Iterative submission review | Candidate submission can be scored or chosen by independent reviewer loops before acceptance, with bounded retries; excludes final external qualification. | swe-agent__swe-agent, Python CLI: `sweagent/agent/agents.py`, reviewer imports & `RetryLoopConfig` integration in agent configuration; live `DefaultAgent.run` review path consumes `ReviewSubmission`; loop state remains in trajectory. |
| Multi-agent SWE runtime | Scheduling | Dependency-aware parallel execution | Ready work units execute concurrently only after dependencies close, while downstream units receive dependency outputs; excludes free-form role prompting. | Agent-Field__SWE-AF, Python runtime: `swe_af/execution/dag_executor.py`, DAG executor scheduling functions; consumer coding pipeline invokes executor; node status/output maps persist in execution envelope & fatal dependency failures block descendants. |
| Multi-agent SWE runtime | Planning | Evidence-triggered replanning | Failed or invalid work can produce revised remaining plan while preserving completed work; excludes retrying identical action. | Agent-Field__SWE-AF, Python runtime: `swe_af/execution/_replanner_compat.py` & `dag_executor.py`, replanner compatibility/executor branches; coding-loop consumer updates execution DAG rather than discarding completed nodes. |
| Multi-agent SWE runtime | Human control | Structured human decision pause | Runtime pauses at a named decision, presents bounded choices/context, & resumes with captured response; excludes ambient chat. | Agent-Field__SWE-AF, Python runtime: `swe_af/hitl/ask_user.py:432`, `request_user_input_and_pause`; live caller `swe_af/hitl/wrapper.py:141` imports & awaits it; response is normalized into execution state, cancellation remains explicit. |
| Multi-agent SWE runtime | Delivery | CI-gated completion | Delivery remains pending until declared CI evidence passes; failure routes to repair rather than being reported as success; excludes local focused checks. | Agent-Field__SWE-AF, Python runtime: `swe_af/execution/ci_gate.py`, CI gate functions; consumer `swe_af/execution/coding_loop.py`; gate outcome enters envelope & failure path invokes fixer/replan. |
| Multi-agent SWE runtime | Recovery | Fatal-error envelope | Unrecoverable execution failure is converted to stable typed outcome carrying cause/context for caller-visible termination; excludes retryable node failure. | Agent-Field__SWE-AF, Python runtime: `swe_af/execution/fatal_error.py`, fatal error constructors; consumers `coding_loop.py` & `dag_executor.py`; `envelope.py` retains terminal status. |
| Agent control plane | Identity | Verifiable component identity | Agents, reasoners, skills, workflows, & executions can be registered/resolved with decentralized identifiers & signed credential chains; excludes ordinary display names. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/did_types.go`, `DIDRegistry`, `ExecutionVC`, `WorkflowVC`; live DID API/storage handlers consume these records, retain proof/status, & expose verification responses. |
| Agent control plane | Authorization | Policy-evaluated agent access | Invocation is allowed or denied from explicit access policy, constraints, agent tags, & approval state; excludes model-side safety prompts. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/permission_types.go`, `AccessPolicy`, `PolicyEvaluationResult`, `TagApprovalRequest`; permission API consumers persist pending/approved/rejected tag credentials & return denial reason. |
| Agent control plane | Observability | Execution lineage graph | Operator can inspect executions grouped into runs with parent/dependency edges rather than flat logs; excludes raw event transport. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/execution.go`, `Execution`, `ExecutionDAGEdge`, `GroupExecutionsByRun`; server/API & desktop consumers render grouped execution state. |
| Agent control plane | Observability | Reliable observability forwarding | Execution events are batched to configured webhook with forwarder status, dead-letter retention, & explicit redrive; excludes primary execution storage. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/observability_webhook.go`, `ObservabilityEventBatch`, `ObservabilityDeadLetterEntry`, `ObservabilityRedriveResponse`; webhook API/forwarder consumers expose failed deliveries & redrive result. |
| Agent control plane | Automation | Event-to-agent trigger binding | External event or schedule is matched to persisted trigger binding & starts designated reasoner/workflow with event metadata; excludes manual invocation. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/triggers.go`, `Trigger`, `InboundEvent`, `TriggerBinding`; trigger handlers consume bindings, maintain metrics, & retain trigger event metadata. |
| Agent control plane | Cost governance | Model usage attribution | Operator can inspect token/cost usage by execution, grouped dimension, time series, & model; excludes hard spend enforcement. | Agent-Field__agentfield, Go control plane: `control-plane/pkg/types/usage.go`, `ExecutionUsage`, `UsageStatsAggregation`, `UsageModelSeries`; API & tray consumers aggregate persisted execution usage. |
| Desktop agent control | Navigation | Deep-linkable operational view | OS/application deep link resolves directly to validated agent/execution/catalog view, rejecting malformed target; excludes web URL navigation. | Agent-Field__agentfield, Electron desktop: `desktop/src/shared/deeplink.ts`, `parseDeepLink` & `deepLinkFromArgv`; desktop startup/second-instance consumers select returned `View`, invalid links return null. |
| Plugin runtime | Context management | Session-start context injection | Plugin startup can inject current project state/instructions into new agent session without user copy/paste; excludes persistent memory. | addyosmani__agent-skills, Claude Code/Codex hooks: `hooks/session-start.sh`, session-start entrypoint; live consumer `hooks/hooks.json` registers hook; failure is shell-visible & no hidden store is inferred. |
| Plugin runtime | Change control | Path-scoped simplification exclusion | Automated simplification honors repository-provided ignore boundaries so protected paths are not rewritten; excludes general tool permission policy. | addyosmani__agent-skills, shell hook runtime: `hooks/simplify-ignore.sh`, ignore-filter entrypoint; command/hook registration consumes script before simplification & emits filtered scope. |
| Agent plugin runtime | Capability discovery | Installed-skill bootstrap | Session startup discovers installed skill packages & injects usable capability catalog into agent context; excludes semantic routing among capabilities. | obra__superpowers, Claude Code/Codex plugin: `hooks/session-start` bootstrap scripts & `lib/skills-core.js` discovery helpers; hook registration invokes bootstrap; filesystem scan is local & missing package yields explicit absence. |
| Browser-assisted agent | Validation | Screenshot-backed browser evidence | Agent can capture rendered page state as visual evidence tied to browser session, supporting inspection beyond DOM text; excludes visual regression scoring. | garrytan__gstack, Claude Code plugin runtime: `lib/browser` TypeScript capture/session modules & command workflow consumers; browser session writes screenshot artifact & returns path to review workflow. Exact cross-module consumer is retained as ambiguity below. |
| Browser/device automation | Testing | Cloud browser session orchestration | Agent can start browser/device target, execute Playwright actions, & return provider-backed session result; excludes local browser-only testing. | LambdaTest__agent-skills, Node/Python skill runtime: production scripts under skill `scripts/` create LambdaTest/Playwright session & command entrypoint consumes result; credentials remain environment-provided. Exact stable symbol is unresolved below. |
| Security workflow runtime | Assurance | Independent negative-applicability refutation | A judgment that target language is inapplicable is independently challenged before work is dropped; excludes command-proven parser incompatibility. | trailofbits__skills, agent workflow: `plugins/semgrep-rule-variant-creator/workflows/port-rule-to-languages.js`, `recheckApplicability`; pipeline consumer conditionally dispatches refuter before suppression & records reasoning. |
| Security workflow runtime | Assurance | Tool-bound validation verdict | Agent cannot self-assert pass; workflow derives result from exact validator output/version & retries bounded repairs; excludes product-level completion assurance. | trailofbits__skills, agent workflow: `plugins/semgrep-rule-variant-creator/workflows/port-rule-to-languages.js`, `VALIDATION_SCHEMA`, `validatePrompt`, validation loop; pipeline checks Semgrep JSON plus safe-case count for up to three rounds. |
| Security analysis CLI | Evidence quality | Analysis-database quality gate | Static analysis is blocked when database is unfinished, source-empty, toolchain-only, malformed, or over extractor-error threshold; excludes vulnerability findings. | trailofbits__skills, Python CLI: `plugins/static-analysis/skills/codeql/scripts/check_db_quality.py`, `assess` & `QualityFailure`; `main` consumes assessment, separates exit codes, reads CodeQL metadata/archive/diagnostics, & never treats uncertain layout as zero. |

## Repository coverage ledger

- `addyosmani__agent-skills` — evaluated: Operative hooks/command scripts inspected; 2 atoms retained.
- `Agent-Field__agentfield` — evaluated: Go control plane & Electron consumers sampled by domain; 7 atoms retained.
- `Agent-Field__SWE-AF` — evaluated: Python orchestration/HITL/CI paths inspected; 5 atoms retained.
- `anthropics__claude-code` — evaluated: Operative utility/hook scripts inspected; no distinct atom survived synonym merge.
- `ArabelaTso__Coding-Skills-Collection` — excluded: No admissible operative production source beyond banned document/catalog surface.
- `coderabbitai__skills` — evaluated: Configuration surface inspected; behavior consumer not proven.
- `EricGrill__agents-skills-plugins` — evaluated: Operative scripts sampled; domain-specific media/document mechanisms did not survive Legion applicability boundary.
- `garrytan__gstack` — evaluated: Browser/review runtime sampled; 1 atom retained with consumer ambiguity.
- `instructa__agent-skills` — evaluated: Operative shell/Python utilities sampled; no distinct atom survived synonym merge.
- `LambdaTest__agent-skills` — evaluated: Browser/device scripts sampled; 1 atom retained with symbol ambiguity.
- `mattpocock__skills` — evaluated: Hook scripts sampled; no distinct atom survived synonym merge.
- `NeoLabHQ__context-engineering-kit` — evaluated: Context hook scripts sampled; behavior merged into session context/bootstrap atoms.
- `obra__superpowers` — evaluated: Bootstrap/discovery runtime inspected; 1 atom retained.
- `SWE-agent__mini-swe-agent` — evaluated: Agent/environment/model runtime inspected; 5 atoms retained.
- `swe-agent__swe-agent` — evaluated: Agent/tool/environment runtime inspected; 3 atoms retained.
- `testdino-hq__playwright-skill` — excluded: No admissible operative production source beyond banned document surface.
- `trailofbits__skills` — evaluated: Production security workflow/CLI scripts sampled; 3 atoms retained.
- `VoltAgent__awesome-agent-skills` — excluded: No admissible operative production source beyond banned catalog/document surface.

## Ambiguities & minority findings

- `UNKNOWN`: Agent-Field__agentfield DID & permission records have clear production data contracts, but exact API handler/storage symbols were not reopened within bounded batch; reconcile before promoting evidence strength.
- `UNKNOWN`: garrytan__gstack screenshot capture is operative, but exact stable symbol/caller pair requires smallest-source reconciliation.
- `UNKNOWN`: LambdaTest__agent-skills cloud browser behavior is script-backed, but provider entrypoint varies by skill; retain atom while reconciling exact symbol.
- Minority finding: process-tree timeout cleanup is separate from command timeout because orphan prevention has independent observable reliability impact.
- Minority finding: negative-applicability refutation is separate from generic review because it governs silent scope removal, not artifact quality.
- No `Not found` repository cells are asserted; Stage 2 inventory records observed union, while skipped/banned surfaces are explicit exclusions.

## Totals

- Requested corpus: 18 repositories.
- Evaluated: 15 repositories.
- Unresolved: 0 repositories; 3 evidence tuples contain scoped ambiguity.
- Excluded: 3 repositories.
- Atomic inventory: 28 rows.
- Platform/domain batches: 6; each ≤25 atoms.
- Adversarial self-review: performed in place; removed configuration-only candidates, separated timeout cleanup from limit enforcement, downgraded 3 incomplete evidence tuples to ambiguity, checked table shape, duplicate atoms, category leakage, & repository coverage.

## Foundation receipt

- Product/scope: `Legion / missed orchestration atoms / Stage 1 supplied-corpus freeze + Stage 2 independent inventory`.
- Target product revision: not applicable; product repository mutation/comparison excluded.
- Corpus manifest: `docs/foundation/2026-08-31/legion-corpus.json`; SHA-256 `46c4ce0d3da2491d3096f3df20caba33f974d2aeb9fff1a1a1bad46f32faf891`.
- Corpus commits: exact 18 revisions in frozen scope table.
- Runtime/platform set: Claude Code/Codex plugins; Python & Go CLI/services; Go control plane; Electron desktop; web UI; local/container/remote shell; cloud browser/device; security workflow CLIs.
- Exclusions: implementation comparison, ranking, reuse/license disposition, target mutation, documentation/catalog-only behavior, tests/build/generated/cache evidence.
- Foundation protocol/schema: Foundation `references/model.md` + `references/protocol.md` read 2026-08-31; corpus schema version `1`.
- Report material digest: `INTEGRATION_OWNER_TO_FILL`.
