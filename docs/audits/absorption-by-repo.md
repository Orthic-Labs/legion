# Absorption Candidates — Per-Repository Top 10

Date: 2026-08-29. Source repos at `\\192.168.1.7\d\claude\repos\legion`, all at upstream HEAD as of 2026-08-29. Format: item — where — maps to. Consolidated rankings: `absorption-by-subsystem.md`.

## Agent-Field__SWE-AF
1. Entrypoint/internal reasoner tagging (forced "do not call directly" descriptions) — `swe_af/surface.py`, `app.py` — plugin-core/dispatch.
2. Risk-proportional QA routing with auditable `risk_rationale` — `docs/ARCHITECTURE.md`, `execution/schemas.py` — Sage.
3. Hierarchical escalation biased accept-debt/escalate on last attempt; crashed replanner defaults CONTINUE — `execution/dag_executor.py` — Alchemist/Sage.
4. Typed severity-rated debt schema propagated to dependents and PR body — `IssueAdaptation` — Arcane/Oracle.
5. In-body skill applicability gate ("delegate only when ALL hold") — `.claude/skills/delegate-issue/SKILL.md` — plugin-core.
6. CI fix-loop anti-cheating denylist (no skip/xfail/loosen; never fakes green) — `execution/ci_gate.py` — Oracle/Arcane.
7. Checkpointed resumable DAG state — `.artifacts/execution/checkpoint.json` — Arcane.
8. Flat role→model config with precedence — README "Model Role Keys" — plugin-core.
9. Typed pausable HITL form (pause without burning budget; "DO NOT RE-ASK" on resume) — `hitl/ask_user.py` — Sage/Arcane.
10. Package manifest `require_one_of` secrets + `superseded_by` redirect — `agentfield-package.yaml` — plugin-core.

## Agent-Field__agentfield
1. Multi-target skill installer (`Target` interface; symlink/marker-block/manual) — `control-plane/internal/skillkit/` — plugin-core.
2. Alias-orphan reconciliation on rename/merge — `skillkit/reconcile.go` — plugin-core.
3. Golden fixture per manifest `config_version` (append-only, CI-enforced) — `packages/config_version_fixtures_test.go` — plugin-core.
4. Tag-based access policy engine, fail-closed (deny-before-allow, missing-param=deny) — `services/access_policy_service.go` — Arcane.
5. Three-mode tag approval with state preservation — `services/tag_approval_service.go` — Sage.
6. Signed per-agent VC + offline audit verification (failure → empty tags, never unverified fallback) — `docs/VC_AUTHORIZATION_ARCHITECTURE.md` §4 — Arcane.
7. Cached policy verification with explicit degrade table — same doc §6 — Arcane.
8. MCP discover→schema→execute→poll surface with named recovery paths — `docs/mcp-integration.md` — Sage/Alchemist.
9. Static harness "doctor" preflight before paid dispatch — `docs/harness-providers.md` — Alchemist/Oracle.
10. Provider-neutral precedence chain (config → env → default) — same doc — Alchemist.

## SWE-agent__mini-swe-agent
1. Save-trajectory-in-`finally` — `agents/default.py:96-124` — Arcane.
2. Typed exit-status exception hierarchy — `exceptions.py` — Arcane/plugin-core.
3. Config resolution search path — `config/__init__.py:12-28` — plugin-core.
4. Short-name-or-import-path dual registry with helpful errors — `models/__init__.py:78-113` — Sage/Alchemist.
5. Layered config merge with `UNSET` sentinel — `utils/serialize.py` — plugin-core.
6. Retry with declared do-not-retry allowlist — `models/utils/retry.py` — Alchemist.
7. Config-driven skip-confirmation allowlist at one chokepoint (human/confirm/yolo) — `agents/interactive.py` — Arcane.
8. Two-scope pre-flight limit enforcement (typed exception before the action) — `models/__init__.py:13-42`, `agents/default.py:130-147` — Arcane.
9. Doc-source snippet inclusion (`--8<--`) so docs can't drift — `docs/advanced/yaml_configuration.md:17` — plugin-core.
10. Strict-undefined Jinja templating (unknown variable fails loudly) — `agents/default.py:52-67` — plugin-core.

## swe-agent__swe-agent
1. Trajectory-to-demonstration few-shot pipeline — `sweagent traj-to-demo`, `agents.py:617-656` — Sage/Alchemist.
2. Structured tool manifest compiled into system prompt — `tools.py:167-224` — plugin-core.
3. Cross-bundle duplicate-tool-name detection (raises with both paths) — `tools.py:176-190` — plugin-core.
4. Layered declarative action blocklist enforced inline before every action — `tools.py:29-72`, `agents.py:946` — Arcane.
5. Per-tool declared `state_command`, auto-collected — `docs/config/tools.md:46-78` — Arcane.
6. Budget-isolated Reviewer + cheap-filter-then-expensive-judge — `reviewer.py` — Oracle.
7. Typed-exception → bounded-recovery state machine — `agents.py:1062-1218` — Alchemist.
8. Two-tier cost circuit breakers (soft recoverable / hard propagate) — `models.py` — Alchemist.
9. Deterministic/scripted model backends for harness testing — `docs/config/models.md:135-141` — plugin-core.
10. Use-case-organized config gallery — `config/{demo,human,exotic,benchmarks}/` — plugin-core.

## obra__superpowers
1. Forced skill-invocation bootstrap at SessionStart (`additionalContext` injection, per-platform branching, rationalization table) — `hooks/session-start`, `skills/using-superpowers/` — plugin-core/Arcane.
2. Skill Discovery Optimization rules (description = triggers only; token budgets by tier) — `skills/writing-skills/SKILL.md` — plugin-core.
3. Rationalization tables + Red Flags lists — pervasive — Sage/Oracle doctrine.
4. "Match the Form to the Failure" guidance-design framework — `skills/writing-skills/` — Sage.
5. Ledger-based recovery for long subagent runs — `skills/subagent-driven-development/` — Alchemist.
6. Fixed fix-loop with escalation + hard adjudication cap (5 rounds) — same — Alchemist/Oracle.
7. Model-selection-by-complexity + "turn count beats token price" — same — Alchemist/Arcane.
8. Diff-as-file review packaging (pass paths, not pasted diffs) — `scripts/review-package` — Alchemist/Oracle.
9. PR gate with 94%-rejection policy + pre-submission checklist — `CLAUDE.md` — plugin-core/Oracle.
10. Multi-harness hook portability (one script, host-detected JSON shapes; parallel per-host plugin dirs) — `hooks/session-start` — plugin-core.

## NeoLabHQ__context-engineering-kit
1. Anchor-relative judge/meta-judge scoring (score_2/score_4 anchors, reasoning-before-score, anti-sycophancy) — `agents/{meta-judge,judge}.md` — Oracle.
2. Five-Whys rule-candidacy filter + Recurrence Test before persistent rules — `agents/judge.md` STAGE 7 — gotchas/Sage.
3. Contrastive Incorrect/Correct rule format with quality gates — same — doctrine authoring.
4. Reflect→Curate→Memorize with context-collapse prevention — `plugins/reflexion/skills/memorize/` — plugin-core.
5. Reliability-vs-cost benchmarked dispatch-pattern table — `README.md` — Sage/Arcane.
6. Trigger-word Stop-hook force-invoking a skill (`decision: "block"`, cycle detection) — `plugins/reflexion/hooks/onStopHandler.ts` — Arcane.
7. Multi-agent pattern catalog with the "Telephone Game Problem" (verbatim handoff over paraphrase) — `skills/multi-agent-patterns/` — Sage/Covenant.
8. do-and-judge vs do-in-steps as separable reliability primitives — `plugins/sadd/` — Alchemist.
9. Layered memory taxonomy with DMR benchmarks — `skills/multi-agent-patterns/` — plugin-core (Cortex).
10. Fine-grained single-purpose plugins sharing common judge agents — `.claude-plugin/marketplace.json` — plugin-core.

## garrytan__gstack
1. Hash-chained content-free egress receipt ledger (receipt-before-send; named fail-open/closed sinks) — `lib/egress-receipt.ts` — Arcane.
2. `guard` skill: composable PreToolUse hooks, hard-deny/soft-warn split + directory freeze — `guard/SKILL.md` — Arcane.
3. Cross-session learnings store with dedup/contradiction/staleness pruning — `learn/SKILL.md` — gotchas.
4. Durable decision log with supersession, surfaced at session start — same — Sage.
5. Decision-brief question format (recommendation, completeness scores, dual-scale effort, fallback tiers) — same — Sage.
6. Auto-decide preferences with profile-poisoning defense — same — Sage/Arcane.
7. Declarative multi-host packaging (`defineHost()`, 10 hosts, zero generator changes) — `docs/ADDING_A_HOST.md`, `hosts/*.ts` — plugin-core.
8. Skill-start preamble with protocol-versioned degraded mode (`SKILL_START_PROTO`) — pervasive — Arcane/plugin-core.
9. Completion-status vocabulary (DONE/DONE_WITH_CONCERNS/BLOCKED/NEEDS_CONTEXT + 3-strikes) — pervasive — Alchemist/Oracle.
10. Mandatory self-improvement step with explicit null result ("No durable learnings this session") — pervasive — gotchas.

## anthropics__claude-code (plugins/, .claude-plugin/, examples/)
1. hookify: markdown-declared hook rules read by generic per-event handlers — `plugins/hookify/` — Arcane.
2. plugin-dev toolkit: plugin-validator/skill-reviewer agents + hook linter scripts — `plugins/plugin-dev/` — plugin-core.
3. plugin.json manifest reference with strict validation rules and error table — `plugin-structure/references/manifest-reference.md` — plugin-core.
4. Multi-stage PR review with independent per-issue validation subagents — `plugins/code-review/commands/code-review.md` — Oracle.
5. ralph-wiggum bounded Stop-hook loop with verifiable completion promise — `plugins/ralph-wiggum/hooks/stop-hook.sh` — Alchemist/Arcane.
6. security-guidance single-purpose reminder hook — marketplace entry — Arcane.
7. System-prompt design vs triggering-examples as separate authoring concerns — `agent-development/references/` — Sage/Alchemist/Oracle cards.
8. Minimal bash-command validator hook example — `examples/hooks/bash_command_validator_example.py` — Arcane.
9. Agent-assumption boilerplate ("do not test tools or make exploratory calls") — code-review command — dispatch templates.
10. Full-SHA permalink evidence-citation discipline — same — Oracle.

## trailofbits__skills
1. Validator-enforced skill-authoring quality bar (trigger phrasing, third-person, unquoted-colon trap, README-names-everything) — `AGENTS.md` — plugin-core.
2. Tool-scope-as-control (workers structurally denied Bash) — `plugins/c-review/agents/c-review-worker.md` — Oracle/Arcane.
3. Coverage recomputed from ground truth; zero-item checks must fail — `plugins/c-review/AGENTS.md` — Oracle/Arcane.
4. Six mandatory gate reviews with PASS/FAIL rubric before any verdict — `plugins/fp-check/.../gate-reviews.md` — Oracle.
5. Seven falsifiable triage brocards pre-filter — `plugins/vulnerability-triage-brocards/` — Sage.
6. Bounded-executor verdict contract with `structural: true` escalation — `plugins/code-improver/agents/fixer.md` — Alchemist.
7. Behavioral eval harness (per-case graders, ablation, contamination checks) — `plugins/code-improver/evals/`, `audit-context-building/evals/` — plugin-core.
8. Risk-tiered conditional escalation to a heavier adversarial agent — `plugins/differential-review/agents/adversarial-modeler.md` — Covenant/Oracle.
9. Lettered attack-vector catalogue with quick checks + amplifier rules — `plugins/agentic-actions-auditor/` — Arcane.
10. Category-regex PreToolUse interception, fast-fail-first, contextual deny — `plugins/gh-cli/hooks/` — Arcane.

## coderabbitai__skills
1. Regex-based fuzzy trigger list in frontmatter (`coderabbit.?fix`, aliases) — `skills/autofix/SKILL.md:4-19` — plugin-core.
2. Dual-mode "explicit AND autonomous" description phrasing — `skills/code-review/SKILL.md:3` — Sage/Alchemist cards.
3. Per-skill Use-when/Triggers/Capabilities README index — `README.md` — plugin-core.
4. Untrusted-input/prompt-injection contract in skill bodies — `skills/autofix/SKILL.md` — Arcane.
5. One-approval-per-fix, no bulk apply, single consolidated commit — same — Alchemist.
6. Self-referential merge gate for skill/agent/command behavioral alignment — `.coderabbit.yaml` custom checks — Arcane/CI.
7. Path-scoped review instructions keyed by glob — `.coderabbit.yaml` — Arcane.
8. Severity taxonomy with action-derivation rule — autofix + code-reviewer — Oracle.
9. Session-state-aware prerequisite skip — `commands/coderabbit-review.md:22-24` — Alchemist.
10. Distribution-channel ledger + maintenance checklist — `DISTRIBUTION_CHANNELS.md` — plugin-core.

## mattpocock__skills
1. Model-invoked vs user-invoked split enforced per harness — `.agents/invocation.md` — plugin-core.
2. Description-as-context-pointer discipline (front-load the leading word; one trigger per branch) — `skills/productivity/writing-for-agents/` — plugin-core.
3. Literal "Call the Skill tool with X" invocation convention — `.agents/invocation.md` — Alchemist/plugin-core.
4. Router skill with living-map sync invariant ("a router that lies") — `skills/engineering/ask-matt/` — Sage/plugin-core.
5. Leading words / token-anchoring for trigger vocabulary — writing-for-agents — authority descriptions.
6. Out-of-scope decision ledger + triage cross-check — `.out-of-scope/`, `skills/engineering/triage/` — Sage.
7. Docs-sync governance tied to skill changes — `CLAUDE.md` — plugin-core.
8. Packaging ADR: Claude array-of-paths vs Codex single path; Codex drops symlinks; version lockstep; marketplace pins SHA — `.claude-plugin/`, `.agents/adr/0002` — plugin-core.
9. Phase-gated hard completion criteria ("No red-capable command, no Phase 2") — `skills/engineering/diagnosing-bugs/` — Oracle/Arcane.
10. Context-load vs cognitive-load framework + no-op pruning test — writing-for-agents — doctrine authoring.

## testdino-hq__playwright-skill
1. Agent-native trace post-mortem CLI protocol with anti-fixes-to-reject — `core/trace-analysis.md` — qa skill; Oracle evidence discipline.
2. Flaky-test taxonomy + diagnosis decision tree — `core/flaky-tests.md` — qa skill.
3. Tiered locator-strategy fallback ladder — `core/locator-strategy.md` — qa skill.
4. Testing-trophy decision matrix with runtime math — `core/test-architecture.md` — qa skill.
5. When-to-mock flowchart + fixture toggle + mock-contract validation — `core/when-to-mock.md` — qa skill.
6. Symptom-keyed error/pitfall lookup format — `core/error-index.md` — Alchemist.
7. "Start simple, promote on threshold" escalation ladder — `pom/pom-vs-fixtures-vs-helpers.md` — Sage/Alchemist boundary.
8. Multi-pack installable skill architecture (five packs, own descriptions) — root + pack SKILL.md files — plugin-core.
9. Scenario-phrased "When to use" blockquote on every pattern — pervasive — authority/skill descriptions.
10. Explicit Security Trust Boundary section per skill — `SKILL.md:18-24` etc. — Arcane.

## addyosmani__agent-skills
1. SessionStart meta-skill auto-injection hook — `hooks/`, `skills/using-agent-skills/` — Arcane/plugin-core.
2. "Personas don't invoke personas" + 4 named anti-patterns — `docs/agents.md`, `references/orchestration-patterns.md` — Sage.
3. Three-tier discoverability evals (lint / TF-IDF collision / headless behavioral) — `evals/`, `scripts/run-evals.js` — plugin-core.
4. Mandatory Composition block per agent file — `agents/*.md` — authority cards + lint.
5. /ship fan-out with numeric skip rule — `commands/ship.toml` — Oracle/Sage heuristics.
6. Plugin-agent frontmatter allowlist (hooks/mcpServers/permissionMode silently dropped) — `docs/agents.md` — plugin-core audit item.
7. Per-persona model tiering by cost/judgment — docs — Alchemist.
8. references/ checklist pull-in (progressive disclosure) — `references/*.md` — plugin-core.
9. Agent Teams vs Subagents decision table — docs — Sage/Covenant.
10. Multi-platform install matrix in one README — `README.md` — plugin-core.

## instructa__agent-skills (8 concrete items; repo thin)
1. architecture-ownership 5-slot mandatory output schema — `skills/engineering/architecture-ownership/` — Sage.
2. find-duplicate-ownership SSOT taxonomy — same family — Sage.
3. hard-cut compatibility ladder + 10 hard rules — `skills/engineering/hard-cut/` — Alchemist.
4. root-cause-finder causal chain + Hidden Write Checks — same family — Alchemist/Oracle.
5. Usage-star + session-count adoption metrics — README — plugin-core.
6. Delegation review-vs-implement mode split (default review when ambiguous) — `delegate-*` skills — Alchemist/Arcane.
7. Hard-coded refusal list in delegation bodies — same — Arcane.
8. Public/internal split lint (`check-public-skills.sh`) — `scripts/` — plugin-core.

## LambdaTest__agent-skills (5 structural items; rest is repetitive per-framework content)
1. `skills_index.json` trigger-phrase-rich machine catalog — repo root — plugin-core.
2. "Triggers on:" clause in every description — all SKILL.md — plugin-core.
3. First-step decision tables with defer-to-sibling rows — skill bodies — plugin-core/Sage.
4. `shared/` cross-cutting reference file pattern at 70-skill scale — `shared/testmu-cloud-reference.md` — plugin-core.
5. Two-stage source/target detection tables (classify-then-act) — `test-framework-migration-skill/` — plugin-core.

## EricGrill__agents-skills-plugins (8 concrete items)
1. anthropic-hookify natural-language-to-hook-rule compiler — `plugins/hookify-style` (`.claude/hookify.*.local.md`, `core/rule_engine.py`) — Arcane.
2. conversation-analyzer proposing rules from transcript mining — same — Arcane + gotchas.
3. JSON-Schema-validated plugin manifest with `conflicts` array — `schemas/plugin-manifest.json` — plugin-core.
4. Named persona bundles composing plugins+skills into one install — `bundles/bundles.json` — plugin-core.
5. Generated categorized marketplace index (note: its own index undercounts its README — drift caution) — `plugins-index.json` — plugin-core.
6. Negative-trigger convention naming the sibling owner — `multi-agent-patterns` skill — plugin-core/Sage.
7. Token-multiplier cost table + single-agent-baseline rule — same — Sage.
8. Fixed 3-agent panel per command (pattern recurs across authors) — `comprehensive-review` — Oracle/Sage.

## VoltAgent__awesome-agent-skills (link catalog; README+LICENSE only)
1. Skill Quality Standards table (README:1972-1979) — plugin-core. 2. Curation bar (10-word descriptions, proven only) — plugin-core. 3. hedralab/eskill meta-skill with eval loop (:1755) — plugin-core. 4. hqhq1025/skill-optimizer using real session data (:1813) — plugin-core. 5. lindblomstefan/skills-library guided discovery + feedback (:1835) — plugin-core/Sage. 6. skillreaper + skills-janitor pruning from transcripts (:1862,1865) — Arcane/plugin-core. 7. multi-agent-patterns orchestration reference (:1848) — Sage/Alchemist. 8. obra dispatch/subagent patterns + NeoLab sadd (:1722,1775,1801) — Sage/Alchemist. 9. Deterministic pre-classification router skills (:757,1908) — Sage/plugin-core. 10. model-hierarchy cost routing (:1793) — Alchemist/plugin-core.

## ArabelaTso__Coding-Skills-Collection (link catalog; README+LICENSE only)
1. 6-category SDLC taxonomy (README:64-405) — plugin-core. 2. Requirement-to-Constraints / traceability / coverage checkers (:76-80) — Sage. 3. Regression/behavior-preservation/semantic-equivalence checkers (:275-277) — Oracle. 4. Flaky Test Detector (:208,372) — Alchemist/Arcane. 5. CVE reachability chain (:361-364) — Arcane. 6. Config Consistency Checker (:304) — Arcane/plugin-core. 7. Non-blocking advisory security hook (:158) — Arcane. 8. Confidence-scored review finding filtering (:154) — Oracle/Covenant. 9. Debloating/dead-code/deprecated-API repair catalog (:117,120,369) — Alchemist. 10. Per-connector automation packs (:313-331) — plugin-core.

## compshop (not a duplicate of the packaged skill — four architecture-synthesis docs from a prior Legion self-analysis; several proposals never landed; `doctrine/architecture/` confirmed absent)
1. Empty-record-is-BLOCK rule — `legion-final.md:339` — Oracle.
2. Requirement-split validation (one agent per requirement) — `LEGION-FINAL-SIMPLIFIED-IMPLEMENTATION.md` §23 — Oracle.
3. Authority-pressure adversarial eval suite — synthesis Part VI.3 — Oracle/tests.
4. Hook-enforced mechanical cycle guard — Part V L4 — Arcane.
5. Typed four-number budget struct with computed BUDGET_STOP — Part IV, SIMPLIFIED §17 — Alchemist/Arcane.
6. Scope Adversary mandatory pre-freeze gate + candidate-card templates — Part VI.4, SIMPLIFIED §11-13 — Sage/Covenant (largest unlanded item).
7. Skill promotion buckets; manifest determines what ships — synthesis:265 — plugin-core.
8. Routing rank-1 ratchet + description-collision CI guard — synthesis:273 — plugin-core/Sage.
9. Non-author refutation on demand, including PASS — synthesis:338 — Oracle.
10. Doctrine-mass conformance metric (doctrine LOC vs engine LOC ratchet) — synthesis:456 — plugin-core/Arcane.
