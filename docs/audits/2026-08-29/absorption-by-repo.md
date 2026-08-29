# Absorption Candidates by Repository — 2026-08-29

Source: `\\192.168.1.7\d\claude\repos\legion\` (19 mirrored repos) plus `ruvnet/ruflo` (cloned on request). All third-party content treated as untrusted data. Tags: which Legion subsystem each item strengthens. Per-subsystem consolidation: `absorption-by-subsystem.md`.

**Note on `compshop`:** not a third-party repo — it is Legion's own Aug-2026 architecture-research corpus (mined an 18-repo set overlapping this mirror). Treated as a reconciliation source, not an absorption target; its still-open proposals are listed for verification against current doctrine/code.

---

## anthropics/claude-code
1. Three-layer security review escalation (regex warn → cheap-LLM diff review on Stop → agentic reviewer on commit, each with its own kill switch) — `plugins/security-guidance/hooks/` — **ARCANE/ORACLE**
2. hookify: markdown-defined dynamic hook rules (`.claude/hookify.*.local.md`, YAML frontmatter, `warn|block`, read fresh per call, no rebuild) — `plugins/hookify/` — **ARCANE**
3. conversation-analyzer agent: mines transcripts for corrections/frustration and proposes new hook rules — `plugins/hookify/agents/conversation-analyzer.md` — **ARCANE/HARNESS**
4. plugin-validator agent: checklist audit of manifest/commands/agents/skills/hooks/MCP with severity-tiered report — `plugins/plugin-dev/agents/plugin-validator.md` — **HARNESS/PACKAGING**
5. skill-reviewer agent: scores SKILL.md trigger-phrase strength, word count, progressive disclosure — `plugins/plugin-dev/agents/skill-reviewer.md` — **HARNESS**
6. Deterministic offline hook validators (jq-based schema/linter/test scripts) — `plugins/plugin-dev/skills/hook-development/scripts/` — **ARCANE**
7. Tiered triage → parallel review → per-issue independent verifier pipeline with false-positive exclusion list — `plugins/code-review/commands/code-review.md` — **ORACLE/ALCHEMIST**
8. ralph-wiggum Stop-hook loop: blocks Stop until a literal pre-registered `<promise>` tag appears; iteration state + hard cap — `plugins/ralph-wiggum/hooks/stop-hook.sh` — **ALCHEMIST**
9. Marketplace schema + one-repo-many-plugins layout — `.claude-plugin/marketplace.json` — **HARNESS/PACKAGING**
10. OS/network-layer gating: native `sandbox.network.allowedDomains` settings + iptables default-deny devcontainer firewall — `examples/settings/`, `.devcontainer/init-firewall.sh` — **ARCANE**

## obra/superpowers
1. SessionStart hook injecting mandatory skill-check doctrine (`<EXTREMELY_IMPORTANT>`, "1% chance a skill applies → YOU DO NOT HAVE A CHOICE", Red Flags rationalization table) — `hooks/session-start`, `skills/using-superpowers/SKILL.md` — **SAGE/ALCHEMIST/HARNESS**
2. Skill Discovery Optimization rules: description = ONLY triggering conditions, never workflow summary; keyword coverage; verb-first naming — `skills/writing-skills/SKILL.md` — **HARNESS/PACKAGING**
3. TDD-for-skills: baseline a subagent without the skill, capture verbatim rationalizations, write the skill to counter exactly those, re-test under combined pressure — `skills/writing-skills/testing-skills-with-subagents.md` — **SAGE/ALCHEMIST**
4. Ledger-driven subagent loop: `progress.md` rulings ledger, 5-round fix loop with rounds 4–5 escalating to a fresh implementer on a stronger model, final "breaker" adjudication — `skills/subagent-driven-development/SKILL.md` — **ALCHEMIST**
5. Explicit model-tier routing heuristics incl. "turn count beats token price" and always-specify-model — same skill — **ALCHEMIST**
6. Cross-harness porting playbook with one falsifiable acceptance test (fixed prompt must auto-trigger a skill; transcript required in PR) — `docs/porting-to-a-new-harness.md` — **HARNESS/PACKAGING**
7. Polyglot hook dispatcher: one file valid as both cmd.exe batch and POSIX sh; env-var harness detection emitting per-host JSON shapes — `hooks/run-hook.cmd`, `hooks/session-start` — **ARCANE**
8. External LLM-judged behavioral eval harness (real tmux sessions, before/after eval results required for skill-wording PRs) — `evals/` (Drill) — **ORACLE/HARNESS**
9. Agent-addressed contributor gating doctrine (94% rejection rate, auto-reject categories) — `CLAUDE.md` — **ARCANE/HARNESS**
10. Cross-skill reference markers (`**REQUIRED SUB-SKILL:**`) instead of force-loading `@file` includes; verification-before-completion "Iron Law" claim→evidence table — `skills/writing-skills/SKILL.md`, `skills/verification-before-completion/SKILL.md` — **HARNESS + ORACLE**

## NeoLabHQ/context-engineering-kit
1. Stop-hook forced-skill-invocation with cycle detection (`{decision:"block", reason:"You MUST use Skill tool…"}`) — `plugins/reflexion/hooks/src/onStopHandler.ts` — **ARCANE/HARNESS**
2. Cross-provider sync pipeline with CI drift enforcement (regenerate per-provider bundles, diff, auto-fix or fail) — `.github/workflows/sync-provider-formats.yml` — **HARNESS/PACKAGING**
3. Meta-judge → judge two-phase evaluation with contrastive BAD/GOOD anchors; judge never told the pass threshold — `agents/meta-judge.md`, `skills/judge/SKILL.md` — **ORACLE**
4. LLM-judge bias mitigation + self-calibration suite (position swap; known-good >4.0, known-bad <2.5, variance <0.5 before trusting an evaluator) — `skills/agent-evaluation/SKILL.md` — **ORACLE**
5. Reliability-vs-cost decision table (strategy × file-count → accuracy probability × token overhead) — `README.md` — **SAGE**
6. Commands-over-skills token-economy doctrine: reliability-critical routing in commands/hooks, never probabilistic skill matching — `CONTRIBUTING.md`, `docs/concepts.md` — **HARNESS**
7. Structured dogfooding rule cards (frontmatter + mandatory Incorrect/Correct pair from real mistakes) — `.claude/rules/*.md` — **SAGE/HARNESS**
8. Hard subagent invariants (never parallel implementers on one repo; never manually fix a failed subagent's work — dispatch a fix subagent) — `skills/subagent-driven-development/SKILL.md` — **ALCHEMIST**
9. Per-plugin token-budget metadata (`tokens: {estimated, description}`) — `CONTRIBUTING.md` — **HARNESS/PACKAGING**
10. Context-degradation diagnostics (lost-in-middle compliance-rate classifier; distractor scoring) — `skills/context-engineering/SKILL.md` — **ALCHEMIST/HARNESS**

## trailofbits/skills
1. Self-testing metadata validator with anti-vacuity guards ("a checker that inspects zero items must fail") — `.github/scripts/validate_plugin_metadata.py` — **HARNESS/PACKAGING**
2. README-must-name-every-component CI check — same validator — **HARNESS/PACKAGING**
3. `type: prompt` Stop/SubagentStop hooks as mechanically enforced completion gates (LLM prompt scans conversation for required phases, blocks premature stop) — `plugins/fp-check/hooks/hooks.json` — **ARCANE/ORACLE**
4. Refuting-verifier pattern: verifier starts at `refuted: true`, flips only on surviving a documented kill-step ladder — `plugins/insecure-defaults/`, `plugins/spec-to-code-compliance/` — **ORACLE**
5. Eval-contamination checker (grader filenames/answer-key leaks in traces) — `plugins/code-improver/evals/check_contamination.py` — **ORACLE/HARNESS**
6. Frontmatter-key inversion + subagent-dispatch namespace lints (`tools:` vs `allowed-tools:` trap; unnamespaced `subagent_type`) — validator — **ALCHEMIST**
7. Dynamic workflows as executable scripts, not prose ("if a SKILL.md has 'Phase 1'… the plan belongs in a script") — `workflows/*.js` — **ALCHEMIST**
8. `disable-model-invocation: true` as a hard autonomy gate on destructive commands — `plugins/git-cleanup/` — **ARCANE**
9. Tool-call interception hooks with bats-tested matchers (curl→gh redirect) — `plugins/gh-cli/hooks/` — **ARCANE**
10. House doctrine: no verification-scaffolding in prompts (put checks in deterministic validators); never tell a reviewer to pre-filter severity — `AGENTS.md` — **SAGE/ORACLE**

## SWE-agent/mini-swe-agent
1. Pre-query budget gate: step/cost/wall-time checked BEFORE every model call, typed exits — `src/minisweagent/agents/default.py:130-147` — **ARCANE**
2. Format-error tolerance with billing honesty (failed calls still cost-counted) — `default.py:99-114` — **ALCHEMIST**
3. Unconditional trajectory persistence (`finally: self.save(...)` on every step) — `default.py:118-190` — **HARNESS/PACKAGING**
4. Three-mode interactive control (human/confirm/yolo + regex whitelist for auto-approved safe commands) — `agents/interactive.py` — **ARCANE**
5. Sentinel-string completion protocol (works in any bash-only env) — `environments/docker.py:140-151` — **ALCHEMIST**
6. Retry with explicit abort list (never retry auth/context/permission errors) — `models/utils/retry.py` — **ALCHEMIST**
7. Cost tracking whose lookup failure is a hard error by default — `models/litellm_model.py:108-126` — **ARCANE/ORACLE**
8. Standalone trajectory TUI inspector over a portable `.traj.json` format — `run/utilities/inspector.py` — **HARNESS/PACKAGING**
9. One-YAML-defines-a-behavior-variant config merge (Jinja/Pydantic recursive merge) — `config/mini.yaml` — **HARNESS/PACKAGING**
10. ~160-line fully-auditable sandbox surface — `environments/docker.py` — **ARCANE**

## swe-agent/swe-agent
1. Score-based retry loop with budget-isolated reviewer model, max-score submission selection — `sweagent/agent/reviewer.py:559-659` — **ORACLE**
2. Two-stage Preselector→Chooser selection with graceful parse-failure fallback — `reviewer.py:242-372` — **ORACLE**
3. `min_budget_for_new_attempt`: don't start a doomed attempt — `reviewer.py:536-546` — **ARCANE**
4. Composable pure-function history-processor pipeline (discriminated-union config) — `agent/history_processors.py` — **ALCHEMIST/HARNESS**
5. Tag-based observation retention overrides (`keep_output`/`remove_output`) — `history_processors.py:124-176` — **ALCHEMIST**
6. Nine interchangeable action parsers, each with a tailored self-correcting error template — `tools/parsing.py` — **ALCHEMIST**
7. Decoupled ~30-line status-hook emitting live "Step 3 ($0.42)" via plain callback — `agent/hooks/status.py` — **HARNESS/PACKAGING**
8. Self-contained tool bundle format (bin/ + config.yaml + install.sh) — `tools/registry/` etc. — **ALCHEMIST/HARNESS**
9. Web-based trajectory inspector (second viewer for the same evidence format) — `sweagent/inspector/server.py` — **HARNESS/PACKAGING**
10. `exit_forfeit`: an honest, cheap way to admit defeat instead of grinding to limits — `tools/forfeit/config.yaml` — **ARCANE/ALCHEMIST**

## Agent-Field/SWE-AF
1. Multi-role planning pipeline with bounded review loops (PM→Scout→Architect→Tech Lead→Sprint Planner, typed schema-validated reasoners) — `swe_af/reasoners/pipeline.py:373-584` — **SAGE**
2. Webhook-paused human plan-approval gate with bounded revision loop + `approval_state.json` audit trail — `go/internal/orch/approval_gate.go:54-200` — **SAGE/ARCANE**
3. Budgeted `ask_user_via_form` primitive (typed form, `AskUserBudget`, prior answers injected) — `swe_af/hitl/ask_user.py` — **SAGE**
4. Deterministic-first, LLM-fallback git operations (eliminated 23/88 agent calls in one run) — `swe_af/execution/git_fast_path.py` — **ALCHEMIST**
5. Fatal-vs-retryable error classification short-circuiting all retry layers — `swe_af/execution/fatal_error.py:17-119` — **ALCHEMIST/ARCANE**
6. Empty-completion vs schema-invalid distinction, naming provider+model — `fatal_error.py:59-215` — **ORACLE**
7. Topological leveling + same-level write-write conflict detection before dispatch — `reasoners/pipeline.py:56-135` — **SAGE**
8. Per-role model tiers via env cascade (`SWE_MODEL_LOW/MED/HIGH`) — `go/internal/config/modeltiers_test.go` — **ARCANE/HARNESS**
9. SHA-anchored CI-check polling (refuse verdicts on checks without expected headSha) — `swe_af/execution/ci_gate.py:137-316` — **ORACLE**
10. Pluggable per-role harness-provider adapter — `swe_af/runtime/providers.py` — **ALCHEMIST/HARNESS**

## Agent-Field/agentfield
1. Two-step VC authorization: tag approval + first-match-wins policy engine with parameter constraints, fail-closed — `docs/VC_AUTHORIZATION_ARCHITECTURE.md` — **ARCANE**
2. Signed, revocable capability credentials (Ed25519 W3C VCs; verification fails closed to empty tags) — same doc §4 — **ARCANE**
3. Multi-provider harness abstraction with paid-call-free preflight (`af harness doctor`) and per-provider concurrency caps — `docs/harness-providers.md` — **ALCHEMIST/HARNESS**
4. `model#effort` reasoning-effort suffix convention translated per provider — `harness-providers.md:186-219` — **ALCHEMIST/HARNESS**
5. Self-provisioning pinned binary: SHA-256 verified, gzip-bomb-capped download, identical from CLI/desktop/Docker — `control-plane/internal/aforge/ensure.go` — **HARNESS/PACKAGING**
6. Webhook-resumed pause primitive (suspend for days without budget accrual; no polling) — design §4.6 — **SAGE**
7. Agent capability registry/discovery ("ard") with same-origin-capped HTTP client — `control-plane/internal/ard/ard.go` — **HARNESS/PACKAGING**
8. Explicit agent lifecycle state machine (`pending_approval` → hard 503, never silent allow) — VC doc:284-311 — **ARCANE**
9. Env-overrides-YAML precedence documented per feature, consistently — same doc — **HARNESS/PACKAGING**
10. Replay-protected signed-request middleware (DID-Auth before authz, ordered pipeline) — same doc — **ARCANE**

## coderabbitai/skills *(thin: 2 skills; 9 honest items)*
1. Untrusted-content firewall for autofix loops (enumerated forbidden actions; sanitize bot text before echo) — `skills/autofix/SKILL.md` — **ARCANE**
2. One-approval-per-change, no-bulk-apply loop — same — **ALCHEMIST**
3. Repo-local review-policy config with custom blocking pre-merge checks per path glob — `.coderabbit.yaml` — **ORACLE**
4. Behavioral-alignment invariant across parallel packaging surfaces (drift checked in the same PR) — `CONTRIBUTING.md` — **HARNESS/PACKAGING**
5. Multi-host manifest set: one source, four thin adapters (claude/cursor/gemini/plain) — root manifests — **HARNESS/PACKAGING**
6. `DISTRIBUTION_CHANNELS.md` channel-status ledger with last-verified dates — root — **HARNESS/PACKAGING**
7. Required-approver gate where approval's `commit.oid` must match HEAD (stale approvals don't count) — `.github/workflows/required-approver.yml` — **ARCANE**
8. Tag-triggered release: tarball + sha256 + release-manifest.json — `.github/workflows/release.yml` — **HARNESS/PACKAGING**
9. CLI-prerequisite verification (binary + semantic version + copy-paste remediation) — `skills/code-review/SKILL.md` — **ALCHEMIST**

## testdino-hq/playwright-skill
1. Hierarchical progressive-disclosure packaging: router SKILL.md + independently installable sub-packs (`npx skills add …/core`) — `SKILL.md`, `core|ci|pom|migration|playwright-cli/SKILL.md` — **HARNESS/PACKAGING**
2. Task-indexed Guide Index tables ("what you're doing" → guide → deep dive) — `SKILL.md:39-148` — **HARNESS/PACKAGING**
3. Error-index reverse lookup: exact error string → cause → triggers → fix — `core/error-index.md` — **ALCHEMIST**
4. Agent-native trace/evidence CLI discipline (never hallucinate IDs; cite command+output; reject anti-fixes like `waitForTimeout`) — `core/trace-analysis.md` — **ORACLE**
5. Flakiness taxonomy + diagnosis decision tree — `core/flaky-tests.md:33-80,818-849` — **ORACLE**
6. Anti-pattern tables (Don't / Problem / Do Instead) — `core/flaky-tests.md:851-861` et al. — **SAGE/ALCHEMIST**
7. Decision-framework guides (Quick Answer → flowchart → matrix → worked examples → anti-patterns) — `core/when-to-mock.md`, `pom/pom-vs-fixtures-vs-helpers.md` — **SAGE**
8. Security Trust Boundary boilerplate (page content = untrusted; pin CI deps to SHAs) — `SKILL.md:18-24` — **ARCANE/ALCHEMIST**
9. Annotated copy-paste CI starter workflows with cache/artifact/failure discipline — `ci/ci-github-actions.md:17-88` — **HARNESS/PACKAGING**
10. `errorContext` state-at-failure evidence attachment for unreproducible failures — `core/flaky-tests.md:101-122` — **ARCANE**

## LambdaTest/agent-skills
1. Formal contribution template + validator gate (`validate_skills.py`, SKILL.md <500 lines, 10+ debugging-table entries) — `CONTRIBUTING.md` — **HARNESS/PACKAGING**
2. Per-skill behavioral eval suites including **negative-trigger** cases (skill must NOT activate) — `evals/*.json` (40+) — **ORACLE**
3. Machine-readable skill registry for tooling — `skills_index.json` — **HARNESS/PACKAGING**
4. Preflight doctor script (CLI, config, env vars, ignore files, then official `--validate`) — `hyperexecute-skill/scripts/doctor.js` — **ALCHEMIST**
5. Static secret-leak linter for CI config, run before anything else — `hyperexecute-skill/scripts/validate-config.js` — **ARCANE**
6. Idempotent frontmatter-driven skill installer — `api-skill/installer/` — **HARNESS/PACKAGING**
7. Nested skill-of-skills bundle with its own installer — `api-skill/` — **HARNESS/PACKAGING**
8. Honest capability-boundary callout ("know the one hard limit up front") — `accessibility-skill/SKILL.md` — **SAGE**
9. Reference-file routing table inside a skill (File | When to Read) — `cypress-skill/SKILL.md` — **HARNESS/PACKAGING**
10. Single external-credential env-var contract reused across dozens of skills — `.env.example` — **ARCANE**

## garrytan/gstack
1. Hash-chained, tamper-evident egress receipt ledger with per-sink fail-open/fail-closed polarity + CI wiring scanner for unregistered sinks — `bin/gstack-egress`, `test/egress-receipt-wiring.test.ts` — **ARCANE**
2. Stop-hook verification gate bound to a per-repo trust store (sha256 of the declared command; edits invalidate trust; bounded re-entry) — `bin/gstack-verify-gate` — **ARCANE**
3. Sole sanctioned path for untrusted tracker/PR content, CI-enforced — `bin/gstack-issue-guard`, `test/tracker-guard-wiring.test.ts` — **ARCANE**
4. Layered ensemble-gated prompt-injection defense (strip → local BERT classifier → canary token → two-classifier agreement before block) — `ARCHITECTURE.md` — **ARCANE**
5. Event-sourced decision ledger with supersede/redact/compact (immutable append; replacement-before-retirement) — `bin/gstack-decision-log` — **SAGE**
6. Structured decision-brief protocol (ELI10, stakes, per-option 0-10 completeness, "Net:" line; re-ask on ambiguous irreversible confirmations) — `autoplan/SKILL.md` — **SAGE**
7. Persistent per-project taste profile with Laplace-smoothed confidence and weekly decay; drift flags — `bin/gstack-taste-update` — **SAGE**
8. Docs generated from source with CI freshness (`gen-skill-docs --dry-run` + `git diff --exit-code`) — `ARCHITECTURE.md` — **HARNESS/PACKAGING**
9. Consolidated preamble runtime (one binary at skill start/end replacing ~18KB duplicated bash) — `bin/gstack-skill-start|end` — **HARNESS/PACKAGING**
10. Tiered cost-aware test suite (free static → paid E2E → LLM judge, gated behind `EVALS=1`) — `ARCHITECTURE.md` — **ORACLE**

## addyosmani/agent-skills
1. Three-tier skill eval framework: structural → deterministic TF-IDF trigger/routing (rank-1 rate + 75% description-collision check) → behavioral — `evals/README.md` — **ORACLE/HARNESS**
2. SKILL.md authoring contract (frontmatter rules + recommended section set incl. Common Rationalizations, Red Flags, Verification) — `docs/skill-anatomy.md` — **HARNESS/PACKAGING**
3. Common Rationalizations table (excuse → factual rebuttal) in every skill — same — **ALCHEMIST**
4. Context-efficiency rules (500-line cap; shared vs per-skill references; scripts over inline code) — same — **HARNESS/PACKAGING**
5. `sdd-cache` hook pair: WebFetch cache served only after HTTP 304 revalidation — `hooks/sdd-cache-*.sh` — **ARCANE**
6. `simplify-ignore` PostToolUse hook: hook-level scope skip-lists — `hooks/simplify-ignore.sh` — **ARCANE**
7. `session-start.sh` hook injecting the skill catalog at session start — `hooks/` — **HARNESS**
8. `using-agent-skills` meta-skill: ASCII decision-tree router + core operating behaviors (surface assumptions, stop-and-name confusion, quantified pushback) — `skills/using-agent-skills/SKILL.md` — **SAGE/HARNESS**
9. Review-persona agents with fixed 5-dimension framework and Critical/Required/Optional/Nit severities — `agents/code-reviewer.md` — **ORACLE**
10. Pre-flight dedup checklist before adding a skill — `CONTRIBUTING.md` — **HARNESS/PACKAGING**

## instructa/agent-skills
1. Usage telemetry per skill in the catalog (`★★★★★ · 408 sessions`) — `README.md` — **HARNESS/PACKAGING**
2. Granular single-skill install CLI (`npx skills add … --skill <name>`) — `README.md` — **HARNESS/PACKAGING**
3. `architecture-ownership` forced output contract (Runtime / First-fix / Canonical owner / Wrong competitors / Cleanup direction) — `skills/engineering/architecture-ownership/SKILL.md` — **SAGE**
4. SSOT-drift taxonomy before flagging duplicates — `skills/engineering/find-duplicate-ownership/SKILL.md` — **SAGE**
5. `root-cause-finder` "prove intended vs symptom" + Hidden Write Checks — `skills/engineering/root-cause-finder/SKILL.md` — **ALCHEMIST/ORACLE**
6. Delegation skills with explicit review-vs-implement mode contract ("take a look" never implies edit permission) — `skills/delegation/delegate-*/SKILL.md` — **ALCHEMIST**
7. `package-security-check` traffic-light read-first gate before any mutating install — `skills/security/package-security-check/SKILL.md` — **ARCANE**
8. `hard-cut` delete-the-second-path transformation skill (highest usage) — `skills/engineering/hard-cut/SKILL.md` — **ALCHEMIST**
9. `gitwhat` cheap ambient pre-flight status skill — `skills/git/gitwhat/SKILL.md` — **HARNESS**
10. Fully self-contained per-skill directories enabling à-la-carte installs — repo layout — **HARNESS/PACKAGING**

## mattpocock/skills
1. User-invoked vs model-invoked frontmatter axis (`disable-model-invocation` + Codex `allow_implicit_invocation`, kept in sync) — `.agents/invocation.md` — **HARNESS**
2. Skill lifecycle buckets (promoted vs misc/in-progress/deprecated with README/plugin.json rules) — `CLAUDE.md` — **HARNESS/PACKAGING**
3. `ask-matt` flow-map router + "a router that lies" resync rule; dependency steps must say "Call the Skill tool with X" — `skills/engineering/ask-matt/SKILL.md` — **HARNESS**
4. Phase-boundary decision tree (Continue / clear / handoff / subagent / compact; ~150k "smart zone") — `docs/productivity/handoff.md` — **HARNESS**
5. `/wizard`: generates an interactive script at human-only walls instead of just stopping — `skills/engineering/wizard` — **ARCANE**
6. Single canonical install-block doc propagated verbatim — `.agents/install-block.md` — **HARNESS/PACKAGING**
7. Per-change changesets recording skill-behavior rationale — `.changeset/` — **HARNESS/PACKAGING**
8. Triage vs to-tickets queue-entry sequencing rule — `docs/engineering/triage.md` — **SAGE**
9. "Refuse to theorize" gate: no hypothesis before a red repro command; explicit handoff when no seam exists — `docs/engineering/diagnosing-bugs.md` — **ALCHEMIST**
10. Fixed four-section human docs template auto-resynced on behavior change — `.agents/writing-docs.md` — **HARNESS**

## ArabelaTso/Coding-Skills-Collection *(catalog-only: single README linking ~234 external skills; 5 honest items)*
1. Full-SDLC phase taxonomy for catalog navigation — `README.md` — **HARNESS**
2. Verification Boundary Reporter concept: label claims verified / assumed / unverified, not flat pass/fail — Verification section — **ORACLE**
3. SZZ / semantic-SZZ bug-origin analysis before repair — Maintenance section — **ALCHEMIST/ORACLE**
4. CVE reachability filtering (actionable only if actually reachable) — Maintenance section — **ORACLE**
5. Pointer-only cataloging as a low-cost external watchlist pattern — repo layout — **HARNESS/PACKAGING**

## VoltAgent/awesome-agent-skills *(catalog-only; value is the curation)*
1. Skill Quality Standards rubric (third-person keyword descriptions; progressive disclosure budgets; no absolute paths; scoped tools) — `README.md` §Quality Standards — **ALCHEMIST/HARNESS**
2. Trail of Bits narrow-skill-per-defect-class catalog pattern — §Security Skills — **ORACLE**
3. CodeRabbit find-vs-fix skill split — line ~990 — **ALCHEMIST**
4. Sentry SDK-per-platform decomposition + meta-skill generator — line ~542 — **HARNESS/PACKAGING**
5. gstack multi-role review chain (CEO/Eng/Design lenses with "what a 10 looks like") — line ~1292 — **SAGE**
6. Addy Osmani deterministic routing evals + rank-1 ratchet — line ~1361 — **HARNESS/PACKAGING**
7. mattpocock user- vs model-invoked doctrine — line ~1804 — **HARNESS/PACKAGING**
8. Browserbase adversarial diff-driven UI testing — line ~977 — **ORACLE/HARNESS**
9. hedralab/eskill end-to-end skill-authoring meta-tool — line ~1755 — **HARNESS/PACKAGING**
10. dankofly/perfectify cross-CLI hook-portable governance kernel (worth studying) — line ~1856 — **ARCANE**

## EricGrill/agents-skills-plugins *(real marketplace, ~60 plugins, many re-bundles; original items only)*
1. `anthropic-hookify` markdown-defined hooks, no restart (Python rule engine on every event) — `plugins/anthropic-hookify/` — **ARCANE**
2. `anthropic-ralph-loop` Stop-hook with pre-registered `<promise>` completion contract, session-ID isolation, corrupted-state handling — `plugins/anthropic-ralph-loop/hooks/stop-hook.sh` — **ARCANE/ORACLE**
3. MCP multi-agent delegation to ephemeral VMs with typed job manifest + lifecycle state machine + heartbeat stale-job detection — `plugins/mcp-multi-agent-server-delegation/` — **ALCHEMIST**
4. Narrow single-axis review agents with enumerated non-negotiable rules and fixed output schemas — `plugins/anthropic-pr-review-toolkit/agents/` — **ORACLE**
5. Multi-agent dispatch failure-mode catalog with concrete numbers (3–5 worker cap, ~15x token multiplier, sycophantic consensus) — `plugins/multi-agent-patterns/SKILL.md` §Gotchas — **SAGE**
6. Parallel workers returning distilled metric dicts to one coordinator — `plugins/agent-orchestration/commands/multi-agent-optimize.md` — **ALCHEMIST**
7. `mindex` `doctor` health-check skill (installation, index integrity, locks, privacy) — `plugins/mindex/README.md` — **HARNESS/PACKAGING**
8. `plugin-finder` vetting/onboarding agent role (adapt the role, not its hardcoded-path implementation) — `.claude-plugin/agents/plugin-finder.md` — **HARNESS/PACKAGING**
9. `/full-review` fanning out to three model-tiered concern agents — `plugins/comprehensive-review/` — **SAGE/ORACLE**
10. Marketplace category taxonomy as a discovery axis — `.claude-plugin/marketplace.json` — **HARNESS/PACKAGING**

## compshop *(first-party research corpus — reconcile, don't absorb; still-open proposals to verify)*
1. Bound-schema evidence records for Oracle findings (searches/patterns tried recorded on absent verdicts) — `00-architecture-synthesis.md` §3.3 — **ORACLE**
2. Per-requirement context-split for large Completion Validations — §3.2 — **ORACLE**
3. Numeric, not narrative, execution limits for Alchemist loops — §4 — **ALCHEMIST**
4. Graceful no-op degradation for optional gates ("a gate that blocks forever when its substrate is missing is a bug") — §4 — **ARCANE**
5. New-boundary/reuse/ladder test applied reflexively to Legion's own doctrine changes — `legion-final.md` §5.2 — **SAGE**
6. Deterministic routing evals / rank-1 ratchet for skill discovery — synthesis "Skill routing + evals" — **HARNESS/PACKAGING**
7. Entrypoint/internal registry tagging (SWE-AF pattern) — §1, §6 item 8 — **HARNESS/PACKAGING**
8. Checkpoint/resume beyond the remediation path — §2 (`checkpoint.mjs` exists; verify scope) — **ALCHEMIST**
9. Review-policy-as-config (path-conditional validation depth) — §6 item 7 — **ORACLE/SAGE**
10. Sage D0/D1/D2 routing-depth table with "best shape always routes D2" — `legion-final.md` §3 — **SAGE**

## ruvnet/ruflo *(cloned on request; marketing-heavy — only code-verified mechanisms listed)*
1. Cryptographically-signed witness manifests: per-fix SHA-256 + marker substring + Ed25519 attestation, per-OS, CI-blocking, with history.jsonl for bisection — `verification/` — **ARCANE/ORACLE**
2. Regression-driven static audit scripts, one per real incident, issue-linked and self-documenting — `scripts/audit-*.mjs` (~30) — **ARCANE/HARNESS**
3. Deterministic PageRank/Jaccard context memory injected at UserPromptSubmit, sub-15ms, no model call — `.claude/helpers/intelligence.cjs` — **ALCHEMIST/SAGE**
4. Hooks designed to never block or hang: 5s global force-exit timer + forced exit 0 (non-zero exit makes Claude Code skip ALL subsequent hooks for the event) — `hook-handler.cjs` ~314-320, ~588-595 — **ARCANE**
5. Idempotent side-effect dedup via exclusive-create lock files keyed on (repo, event, tool_use_id/time bucket) — `claimSideEffectEvent()` — **ARCANE**
6. Per-OS append-only performance baseline ledger in-repo (durationMs/baselineMs/deltaPct at commit SHA) — `verification/<os>/performance.jsonl` — **ORACLE/HARNESS**
7. Cross-platform hook shim convention (.cjs over bash; `_platform: posix` audited exemptions) — `hook-handler.cjs`, `scripts/audit-plugin-hooks-cross-platform.mjs` — **ARCANE/HARNESS**
8. Real Raft/Byzantine consensus classes as deterministic quorum objects (pattern candidate for Covenant seat reconciliation) — `v3/@claude-flow/swarm/src/consensus/` — **SAGE/ORACLE**
9. NEGATIVE finding: the advertised "auto-routing" is 8 hardcoded regexes printing a suggestion box — never dispatches. Confirms Legion's lesson: doctrine-level mandates beat advisory routers. — `.claude/helpers/router.cjs`
10. NEGATIVE finding: 108 agent-persona files are prompt-only role-play with no tool bindings or backing code; agent-count is not capability. Keep Legion's small role-bounded set. — `.claude/agents/**`
