# Legion Foundation reconciliation

## Frozen scope

- Product: Legion.
- Requested work: 2 blind Sol Foundation passes over supplied Legion corpus, then missed-atom integration.
- Corpus: 18 repositories frozen in `legion-corpus.json`; manifest SHA-256 `46c4ce0d3da2491d3096f3df20caba33f974d2aeb9fff1a1a1bad46f32faf891`.
- Pass A: 28 rows; 15 evaluated, 0 unresolved, 3 excluded; validator PASS.
- Pass B: 32 rows; 16 evaluated, 0 unresolved, 2 excluded; validator PASS.
- Isolation: each pass received same packet, unique output, sibling/prior-output ban & no shared report read.
- Reconciled coverage: 18 requested; 15 evaluated; 0 unresolved; 3 excluded from operative-source proof. `testdino-hq__playwright-skill` joins 2 catalog-only exclusions because frozen target contains Markdown instruction surfaces only under packet's root-Markdown restriction.

## Consolidated dispositions

| Semantic cluster | Independent findings | Disposition | Canon target |
|---|---|---|---|
| Durable resume | durable trajectory capture; durable resumable execution; resumable batch ledger | Promote distinct resume contract; keep inspectability separate | LEG-017 |
| Operator intervention | approval-gated plan transition; structured decision pause; interactive steering | Merge shared pause/response state machine | LEG-018 |
| Execution bounds | bounded autonomous run; cost/call/wall-time limits; process-tree timeout cleanup | Merge limit & clean termination contract | LEG-019 |
| Recovery planning | evidence-triggered replanning; bounded retry with advisory replanning | Promote replan while retaining generic retry under LEG-012 | LEG-020, LEG-012 |
| Executor protocol | action parsing recovery; shell preflight; protocol submission; fatal envelope | Promote malformed-action correction; absorb terminal/error mechanics | LEG-021, LEG-010, LEG-012, GRD-003 |
| Trajectory evidence | trajectory capture; lineage graph; trajectory inspection | Promote inspectable lineage contract | LEG-022 |
| Usage governance | model usage attribution | Promote operator-visible attribution | LEG-023 |
| Event activation | event-to-agent trigger binding | Promote schedule/event binding | LEG-024 |
| Runtime shutdown | graceful service drain | Promote drain contract | LEG-025 |
| Observation delivery | reliable observability forwarding | Promote dead-letter/redrive contract | LEG-026 |
| Publication trust | verifiable component identity; capability publication identity | Merge verifiable publication contract | LEG-027 |
| Credential isolation | execution-scoped credential exposure | Promote under deterministic authorization owner | GRD-013 |
| Dependency execution | dependency-aware parallel execution; controlled integration; role delegation | Already counted | LEG-003, LEG-004, LEG-005, LEG-007 |
| Executor diversity | environment-pluggable execution; provider-selectable routing | Existing executor-binding contract | LEG-008 |
| Context shaping | observation clipping; history compaction; multimodal normalization | Existing context-envelope contract; mechanisms remain non-counted | ARC-001, ARC-009 |
| Candidate challenge | iterative review; candidate trajectory selection | Existing independent challenge/validation contracts | COV-005, ORA-003, ORA-006 |
| CI readiness | CI-gated completion; CI status gate | Already counted | LEG-010, LEG-015 |
| Review remediation | review-thread remediation; automated corrective review | Existing bounded remediation capability | SKL-007 |
| Capability catalog | installed-skill bootstrap; catalog search/publication; progressive loading; package validation | Existing catalog/resolution/projection capabilities | SKL-001, SKL-002, SKL-003 |
| Engineering workflow | spec-plan-build; test-first loop; isolated worktree delegation | Existing architecture, QA & dispatch capabilities | SKL-004, SKL-009, SKL-021 |
| Browser assurance | screenshot evidence; cloud browser session; browser workflow validation | Existing visual audit & QA capabilities | SKL-008, SKL-009 |
| Security assurance | applicability refutation; tool-bound verdict; database quality gate; variant/default audits | Existing falsification, audit & Oracle boundaries | ARC-005, SKL-006, ORA-005, ORA-006 |
| Session priming | session context injection/priming | Existing host projection mechanism | LEG-013, LEG-I005 |
| Path exclusions | simplification ignore boundary | Donor-specific mechanism, not independent Legion atom | EXCLUDED |
| Deep links | deep-linkable operational view | Client-integration mechanism | LEG-014 |
| Evidence language | evidence-gated completion language | Existing evidence & Oracle gates | LEG-010, LEG-011 |

## Reconciliation notes

- No inventory row was decided by vote. Synonyms were merged by observable boundary; different state/failure contracts remain split.
- Skill bundles remain counted once through existing `SKL-*` capabilities; donor workflow details stay mechanisms to avoid bundle-plus-descendant double counts.
- Newly promoted rows use `UNKNOWN / RECONCILE / LOCAL`: reference source proves candidate behavior, not Legion implementation, qualification, or delivery.
- Existing uncommitted LEG-016 work remains intact & outside this corpus reconciliation.
- Requested/evaluated/unresolved/excluded repositories: `18 / 15 / 0 / 3`.
- Independent rows evaluated: `60 / 60`; promoted: 12; absorbed/excluded clusters: 15; unresolved: 0.

## Promoted atom inventory

| Platform | Domain | Atom | Definition / boundary | Source evidence |
|---|---|---|---|---|
| Legion runtime | Continuity | Fingerprinted execution resume | Resume interrupted execution without repeating completed effects; excludes transcript replay. | Agent-Field__SWE-AF: `swe_af/app.py` `resume_build`; `swe_af/execution/coding_loop.py` `_save_iteration_state` / `_load_iteration_state`. |
| Legion runtime | Human control | Named operator decision checkpoint | Pause planning or execution at named decision & resume with captured response; excludes ambient chat. | Agent-Field__SWE-AF: `swe_af/hitl/ask_user.py` `request_user_input_and_pause`; live caller `swe_af/hitl/wrapper.py` awaits it; `swe_af/app.py` `plan`, `execute`, `_format_plan_for_approval`. |
| Legion runtime | Resource governance | Bounded run with descendant cleanup | Enforce step/call/spend/time limits & terminate descendant processes after timeout or cancellation. | SWE-agent__mini-swe-agent: `src/minisweagent/agents/default.py` `AgentConfig`; `src/minisweagent/environments/local.py` `_run`; swe-agent__swe-agent: `sweagent/exceptions.py`. |
| Legion runtime | Recovery | Evidence-directed remaining-work replanning | Revise remaining dependency work after failure while preserving completed outputs. | Agent-Field__SWE-AF: `swe_af/execution/dag_executor.py`; `swe_af/execution/_replanner_compat.py`; `swe_af/prompts/replanner.py`. |
| Legion runtime | Execution protocol | Malformed-action correction | Parse executor actions & return explicit format feedback permitting bounded correction. | SWE-agent__mini-swe-agent: `src/minisweagent/models/utils/actions_text.py` `parse_regex_actions`; swe-agent__swe-agent: `sweagent/agent/agents.py` `DefaultAgent`. |
| Legion runtime | Observability | Inspectable execution trajectory & lineage | Preserve parent/dependency, terminal & submission state for operator inspection. | Agent-Field__agentfield: `control-plane/pkg/types/execution.go` `ExecutionDAGEdge`; swe-agent__swe-agent: `sweagent/inspector/server.py`; SWE-agent__mini-swe-agent: `src/minisweagent/agents/default.py` `serialize`. |
| Legion runtime | Cost governance | Per-execution model usage attribution | Attribute calls, tokens & cost to work units/executions & expose aggregates. | Agent-Field__agentfield: `control-plane/pkg/types/usage.go` `ExecutionUsage`, `UsageStatsAggregation`. |
| Legion runtime | Automation | Persisted event/schedule trigger binding | Start designated workflow from external event or schedule while retaining trigger metadata. | Agent-Field__agentfield: `control-plane/pkg/types/triggers.go` `Trigger`, `InboundEvent`, `TriggerBinding`. |
| Legion runtime | Lifecycle | Graceful active-work drain | Stop accepting new work & drain active operations before process shutdown. | Agent-Field__agentfield: `control-plane/cmd/af/main.go` `drainOnShutdown`, `waitForShutdown`. |
| Legion runtime | Telemetry | Dead-lettered observation forwarding | Batch observation delivery, retain failed deliveries & permit explicit redrive. | Agent-Field__agentfield: `control-plane/pkg/types/observability_webhook.go` `ObservabilityDeadLetterEntry`, `ObservabilityRedriveResponse`. |
| Legion distribution | Trust | Verifiable capability publication | Publish capability trust identity when available & explicitly report unavailable identity. | Agent-Field__agentfield: `control-plane/internal/ard/ard.go` `trustManifest`, `buildPublicationView`. |
| Guard runtime | Credentials | Execution-scoped credential isolation | Expose credentials only during authorized execution & exclude secret material from public receipts. | Agent-Field__SWE-AF: `swe_af/app.py` `_harness_with_scoped_credentials`; Agent-Field__agentfield trust/access evidence supports explicit unavailable/denied state. |

## Foundation receipt

- Product/scope: `Legion / supplied reference corpus / missed-atom capture`.
- Target revision before integration: `ad3d27c6d3d0d04fd7cb850416baa9793db6c9c4` plus preserved local edits.
- Corpus protocol/schema: Foundation model & protocol read 2026-08-31; corpus schema 1.
- Runtime/platform set: plugin hosts, Python/Go agent runtimes, control plane, desktop, local/container/remote execution & browser/security workflow surfaces.
- Exclusions: implementation comparison, ranking, reuse/license disposition, target implementation claims, prohibited docs/root Markdown, tests/build/cache/generated evidence.
- Pass A SHA-256: `bb952f89239ecb64b5968dd34191fc029dcb2308798a4f1982f10378b41c8081`.
- Pass B SHA-256: `0256dfac6cd2506678d5449c563e0a8293f02d5edc90eda9aadf6a2b97dd6db`.
- Completion state: 2 independent reports produced; 2 inventories structurally validated; 60 rows reconciled; 12 atoms promoted; canon checks pass; Oracle result is recorded in delivery response.
