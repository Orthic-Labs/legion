# Consolidated Absorption Lists — One per Subsystem — 2026-08-29

Consolidated from `absorption-by-repo.md` (20 repos). Ranked by leverage against the gaps documented in this folder's subsystem audits. Cross-cutting harness/packaging items get their own list at the end.

---

## SAGE — top 10

The Sage audit's core finding: every mechanism points *away* from dispatching Sage. These items either create affirmative triggers or give Sage durable machinery.

1. **Hook-forced skill/authority check at SessionStart** with a rationalization-rebuttal table ("This is just a simple question" → "Questions are tasks. Check for routing.") — obra/superpowers `hooks/session-start`. The single most direct fix for "never organically dispatched."
2. **Event-sourced decision ledger** (append-only, supersede/redact/compact, replacement-before-retirement) as Sage's precedent memory — gstack `bin/gstack-decision-log`.
3. **Reliability-vs-cost decision table** turning "should I escalate?" into a lookup by task-complexity tier — NeoLabHQ `README.md`; pairs with compshop's D0/D1/D2 routing-depth table ("best shape always routes D2") as a mechanical Sage trigger.
4. **Structured decision-brief protocol** (ELI10, stakes, per-option 0-10 scores, "Net:" line; re-ask on ambiguous irreversible confirmations) for how Sage frames unresolved decisions — gstack `autoplan/SKILL.md`.
5. **Forced ownership-output contract** (Runtime owner / First-fix owner / Canonical owner / Wrong competitors / Cleanup direction — never collapsed) as Sage's adjudication template — instructa `architecture-ownership`.
6. **Ledger-of-rulings with a closed escalation list**: only 4 things stop to ask a human; every other judgment recorded as `Ruling: what — why — cost if wrong` and proceed — obra/superpowers `subagent-driven-development`. Makes skipped escalation auditable instead of silent.
7. **Webhook-paused human approval gate** with bounded revision loop and audit trail — SWE-AF `approval_gate.go` / agentfield pause primitive. Gives Sage an async escalation primitive (currently synchronous-only).
8. **Multi-agent dispatch failure-mode catalog with numbers** (3-5 worker cap, ~15x token multiplier, sycophantic consensus) as citable thresholds for dispatch decisions — EricGrill `multi-agent-patterns` §Gotchas.
9. **Persistent taste/preference profile with confidence decay and drift flags** so accumulated judgment carries across sessions — gstack `gstack-taste-update`.
10. **Same-level write-write conflict detection before parallel dispatch** (Kahn leveling + file-overlap flagging) — SWE-AF `pipeline.py:56-135`. A concrete, mechanical sequencing decision Sage can own.

Also apply to Sage directly: **TDD-for-doctrine** (superpowers `writing-skills`) — pressure-test the Sage trigger wording itself with subagents until dispatch actually happens; and Oracle's replicable pattern from the Oracle audit: give Sage a **read-only `tools:` grant** and a **concrete checkpoint trigger**.

## ALCHEMIST — top 10

The Alchemist audit's core finding: "cost-route the muscle" has no reachable implementation. These items build the bounded-executor discipline that would make routing to it worthwhile.

1. **Deterministic-first, LLM-fallback for mechanical operations** (plain git/subprocess first; model only on conflict) — SWE-AF `git_fast_path.py` (measured: eliminated 23/88 agent calls). Directly implements "cost-route the muscle."
2. **Fatal-vs-retryable error classification** short-circuiting every retry layer on unrecoverable provider errors — SWE-AF `fatal_error.py` + mini-swe-agent's retry abort list. Cheap; stops budget burn.
3. **Numeric execution limits, typed exits**: step/cost/wall-time checked before every model call; consecutive-format-error caps with billing honesty — mini-swe-agent `default.py`; matches compshop's "numeric, not narrative" proposal.
4. **Escalation-aware fix loop**: 5 rounds max, rounds 4-5 to a fresh implementer on a stronger model, final breaker adjudication — obra/superpowers `subagent-driven-development`. A concrete retry contract for the OmniRoute worker.
5. **Review-vs-implement delegation mode contract** ("take a look" never implies edit permission; owner independently re-verifies) — instructa `delegate-*` skills. A working answer to when Alchemist-style delegation applies.
6. **Hard subagent invariants**: never parallel implementers on one repo; never manually fix a failed subagent's work — dispatch a fix subagent — NeoLabHQ `subagent-driven-development`.
7. **Workflows as executable scripts, not prose** ("if a SKILL.md has 'Phase 1'… the plan belongs in a script") + dispatch-namespace lints catching silently-broken `subagent_type` strings — trailofbits `workflows/*.js`, validator.
8. **Error-index reverse lookup** (exact error string → cause → fix) as a known-failure playbook for mechanical repair — testdino `core/error-index.md`; pair with "refuse to theorize" gate (mattpocock: no hypothesis before a red repro).
9. **Sentinel-string completion protocol + honest `exit_forfeit`** — mini-swe-agent / swe-agent. Termination proof the worker can't fake, plus a cheap way to admit defeat instead of grinding to limits.
10. **Multi-provider preflight doctor + `model#effort` suffix convention** (installability/auth checked without a paid call; per-provider concurrency caps) — agentfield `harness-providers.md`. Hardens the OmniRoute relay's degradation story.

Local fixes from the audit that unlock these: declare `python-runtime`, wire the Python tests into CI, and add one affirmative routing cue in doctrine.

## ORACLE — top 10

Oracle works; these items make it stronger, cheaper, and auditable — and address the audit's "honor system" and "aspirational schema" findings.

1. **Mechanically enforced completion gates via Stop/SubagentStop hooks** (LLM-prompt hook scans for required phases/verdicts and blocks premature stop) — trailofbits `fp-check`; NeoLabHQ `reflexion` (with cycle detection); ralph-loop's pre-registered `<promise>` contract. Fixes the critical "Stop is unconditionally allowed" gap.
2. **Refuting-verifier pattern**: verifier starts at `refuted: true` and flips only on surviving a documented kill-step ladder — trailofbits. Stricter than PASS-unless-wrong.
3. **Score-based retry/reviewer loop with budget isolation** (reviewer model's cost never shares the worker's budget; max-score selection; don't-start-doomed-attempt check) — swe-agent `reviewer.py`.
4. **Meta-judge → judge with contrastive anchors; judge never told the pass threshold** + judge self-calibration suite (known-good/known-bad/variance bounds before trusting an evaluator) — NeoLabHQ.
5. **Negative-trigger eval cases** (assert the skill/authority must NOT activate) + three-tier eval framework with deterministic TF-IDF routing checks — LambdaTest `evals/*.json`, addyosmani `evals/`.
6. **Verified / assumed / unverified claim labeling** instead of flat PASS/BLOCK — ArabelaTso "Verification Boundary Reporter" concept; pairs with compshop's bound-schema evidence records (record searches tried on absent verdicts).
7. **SHA-anchored verdicts**: refuse to certify against checks/approvals that don't carry the expected HEAD SHA — SWE-AF `ci_gate.py`, coderabbit `required-approver.yml`.
8. **Trace-evidence discipline codified** (never hallucinate IDs; cite command+output per conclusion; reject anti-fixes) — testdino `trace-analysis.md`; plus flakiness taxonomy + decision tree for classifying nondeterministic failures.
9. **Tiered cost-aware verification** (free static → cheap semantic → full opus pass; expensive tiers gated behind flags) — claude-code security-guidance's three layers, gstack's EVALS=1 tiers.
10. **Review-policy-as-config**: path-conditional validation depth declared in versioned data, not per-session judgment — coderabbit `.coderabbit.yaml`; compshop item 9.

Local fix that unlocks several: actually wire `oracle-completion-validation-v1` — produce the receipt, store it, and let the Stop gate check for it.

## ARCANE — top 10

The Arcane audit found the gate is largely inert (policy never loads, MCP/Task ungated, "strong" mislabeling). These items are the rebuild kit.

1. **Fail-closed policy loading with honest health labels** — agentfield's VC model fails closed to empty capabilities; ruflo's witness system blocks CI on attestation failure. Apply to gap 1: ship a default `LEGION_NATIVE_APPLICATION_CONFIG`, or label ambient-allow `"advisory"`, never `"strong"`.
2. **Hooks that never block or hang**: global force-exit timer + exit-0 discipline (non-zero exit makes Claude Code skip all subsequent hooks for the event) + idempotent side-effect dedup via lock-file digests (duplicate hook events are real) — ruflo `hook-handler.cjs`. Directly applicable hardening for `legion-hook`.
3. **Markdown/data-defined hook rules, no rebuild** — claude-code `hookify` / EricGrill `anthropic-hookify`. New Arcane gates as user-authorable data files instead of Rust rebuilds; plus one-audit-script-per-real-incident convention (ruflo `scripts/audit-*.mjs`).
4. **Hash-chained egress receipt ledger with per-sink fail-open/fail-closed polarity and a CI scanner that fails the build on unwired sinks** — gstack `gstack-egress`. The most complete realization of what Arcane receipts reach for.
5. **Trust-store-bound Stop verification gate** (sha256 of the declared command; edits invalidate trust; bounded re-entry against infinite hook loops) — gstack `gstack-verify-gate`.
6. **Two-step tag+policy authorization with parameter constraints and signed revocable credentials** — agentfield VC architecture. A richer model than flat allow/deny for classified effects, fail-closed by construction.
7. **MCP/untrusted-content gating patterns**: sole sanctioned path for untrusted tracker content (gstack issue-guard), untrusted-content firewall with enumerated forbidden actions (coderabbit autofix), ensemble prompt-injection defense (gstack L1-L6). Feeds the "MCP tools entirely ungated" fix.
8. **`disable-model-invocation: true` on destructive commands** + tool-call interception hooks with regression-tested matchers — trailofbits. Cheap declarative primitives for classified-effect skills.
9. **Pre-query budget gates and cost-lookup-failure-is-a-hard-error** — mini-swe-agent. Arcane-side spend enforcement that doesn't trust the model's self-report.
10. **Witness manifests + per-OS append-only performance baselines in-repo** (fix-persistence attestation without re-execution; commit-pinned latency drift ledger) — ruflo `verification/`. Cheap standing regression gates for qualification/release evidence.

Also: cross-platform polyglot hook shims (superpowers `run-hook.cmd`, ruflo `_platform: posix` audited exemptions) for the Windows/POSIX split; OS/network-layer enforcement (claude-code sandbox settings + firewall) as a complement to hook gating.

## HARNESS / PACKAGING — top 10 (cross-cutting)

1. **SessionStart doctrine injection** (`additionalContext` with the routing summary) — superpowers, addyosmani, hookify all do it; Legion's hook emits nothing. Fixes both discoverability and the bare-install orphan problem.
2. **Deterministic routing evals with a rank-1 ratchet in CI** (TF-IDF trigger tests + 75% description-collision check + negative triggers) — addyosmani, LambdaTest. The cheap, CI-safe fix for skills discoverability.
3. **Skill Discovery Optimization rules**: descriptions state ONLY triggering conditions; keyword coverage; verb-first names — superpowers `writing-skills`. Audit all 25+ Legion skill descriptions against this.
4. **User-invoked vs model-invoked invocation axis** (`disable-model-invocation` kept in sync across harnesses) + skill lifecycle buckets (promoted/misc/deprecated) — mattpocock. Formalizes Legion's `discoverability: explicit` class and prevents catalog sprawl.
5. **Cross-provider sync with CI drift enforcement** (regenerate per-host bundles, diff, fail) — NeoLabHQ; single canonical install-block doc — mattpocock; multi-host thin-adapter manifests — coderabbit. Directly applicable to `.claude-plugin`/`.codex-plugin` parity (currently unenforced).
6. **Self-provisioning pinned binary** (SHA-256-verified download, decompression caps, identical across entry points) — agentfield `ensure.go`; plus `DISTRIBUTION_CHANNELS.md` status ledger and checksum release manifests — coderabbit. The template for closing the plugin-install ↔ `legion-hook` binary gap.
7. **Anti-vacuity validator discipline** ("a checker that inspects zero items must fail") + README-must-name-every-component check + validator self-tests — trailofbits. Would have caught `verify-plugin-parity.mjs`'s blind spot on bare commands.
8. **Progressive-disclosure packaging**: router SKILL.md + task-indexed guide tables + independently installable sub-packs + reference-file routing tables — testdino, LambdaTest. Model for restructuring Legion's larger skills.
9. **Docs generated from source with CI freshness** (`--dry-run` + `git diff --exit-code`) + consolidated preamble runtime replacing duplicated per-skill boilerplate — gstack. Extends Legion's digest-manifest system from "detect drift" to "prevent drift."
10. **Usage telemetry per skill + per-plugin token-budget metadata + machine-readable skill index** — instructa, NeoLabHQ, LambdaTest. Gives the registry a pruning/discovery signal it currently lacks.
