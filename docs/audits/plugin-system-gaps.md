# Plugin System Gap Analysis — Packaging, Harness, Agents

Date: 2026-08-29. Companion to the four subsystem audits in this directory. Findings verified against source with file:line evidence.

## A. Packaging perspective

1. **[Critical] Authority doctrine is unreachable outside this repo.** `agents/{sage,alchemist,oracle,covenant-seat}.md` point at `doctrine/*.md` and `src/roster/*.md` as bare relative paths — never `${CLAUDE_PLUGIN_ROOT}`-anchored. Subagent Read/Glob resolves against the session cwd, so a standalone install leaves all four authority agents with dangling pointers. It works today only because dev sessions run with cwd = plugin root. Skills already solve this correctly by self-packaging doctrine (e.g. `skills/architect/doctrine/...`).
2. **[Critical] `legion` / `legion-hook` are undeclared, unprobed host capabilities.** The MCP server (`.claude-plugin/plugin.json:14-19`) and all eight hook events run bare binaries that appear nowhere in `src/registry/capabilities.json`; `verify-plugin-parity.mjs:67-81` only extracts `${CLAUDE_PLUGIN_ROOT}/` targets, so bare commands produce an empty target set and pass. No existence, PATH, or degradation check exists.
3. **[Critical] No working public channel ships the required binaries.** `release/distribution-contract.json:13`: nativeRelease `blocked` (the sole public channel); npm is private-development-tooling (enforced by `tests/standalone-checkout.test.mjs:31-45`); `packaging/homebrew/` and `packaging/winget/` are empty. A fresh `claude plugin install` structurally lacks the Arcane gate and MCP server.
4. **[High] Audit-family skills invoke the `legion` CLI without declaring it** (`skills/audit/SKILL.md:47-48,58`, `audit-fix:55`; `hostRequirements` list only `blueprint-graph`; `commit` declares nothing). They *cannot* declare it: `dependency-closure.mjs:83-88` rejects host capabilities absent from `capabilities.json` — which lacks `legion` (gap 2).
5. **[High] The closure gate never inspects `agents/`, `doctrine/`, or `src/roster/`** — only `skills/manifests/*.json` → `skills/<id>/dependencies.json`. This is the QA blind spot that lets gap 1 ship undetected through `pnpm legion:check`.
6. **[Medium] No file allowlist on the git-sourced marketplace channel.** `.claude-plugin/marketplace.json:8` uses `"source": "./"` with no excludes — an install pulls `.audit/` run directories, `docs/research/`, the full `engine/` Rust tree, `tests/`, `.agent/`, `.right-release/`. The npm channel has both a `files` allowlist and `forbiddenContentMarkers`; the marketplace channel has neither.
7. **[Medium] `.codex-plugin` silently drops MCP + hooks** — intentional per `docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md:107-111`, but nothing colocated with `.codex-plugin/` says the four authorities and Arcane are unavailable under Codex; it reads as drift.
8. **[Low] Empty `packaging/homebrew|winget/` with no "deliberately unpopulated" note; marketplace metadata thinner than plugin metadata** (no version/category/keywords/icon).

## B. Harness perspective

Detail lives in `docs/audits/arcane-audit.md`; the headline items:

1. **[Critical] Fail-open default** — with no `LEGION_NATIVE_APPLICATION_CONFIG` (nothing sets it), every effect class is allowed; only two hardcoded gates (destructive command, force-push) can ever deny.
2. **[Critical] Event vocabulary likely wrong** — `SubagentStart`/`PostCompact`/`PostToolUseFailure` registered; Claude Code fires `SubagentStop`/`PreCompact` and delivers failures as `PostToolUse`. Verify against the live schema, then fix.
3. **[Critical] `Stop` is structurally unblockable** (lifecycle short-circuit) — no delivery-time Oracle enforcement is possible; `README.md:57` overstates Completion Validation as harness-verified.
4. **[Critical] `mcp__*` tools entirely unmatched** — MCP write actions bypass Arcane completely; `ExternalSideEffect` class exists but is never emitted.
5. **[High] No subagent-boundary mechanism** — nothing injects Sage/Alchemist/Oracle role context into spawned subagents or verifies their output; the response schema has no `additionalContext` field at all.
6. **[High] No binary-resolution preflight** — bare `legion-hook` command; missing binary silently degrades to fail-open; `legion doctor` doesn't check it. `Task`/`Agent` spawn tools also unmatched (deliberately dropped, never replaced).
7. **[Medium] Bugs and coverage holes** — `MultiEdit` unconditionally denied (matched but unclassified); Windows `rd/rmdir/del` destructive verbs uncovered; `WebFetch`/`WebSearch` never pre-blocked and post-effect is a pure allow; fixed 10s timeout vs O(n) ledger cost; no receipts persisted anywhere in the live path.

## C. Agents perspective (why Oracle fires and Sage/Alchemist don't)

Root cause: Oracle has two reinforcing, unconditional triggers tied to a **concrete universal event** ("before every successful final delivery") stated five times in the always-loaded constitution. Sage and Alchemist each have one weak trigger phrased as **internal jargon describing a state**, and Alchemist's precondition is structurally almost never true.

1. **[Critical] `AGENTS.md` asymmetry.** Oracle: invariant + nine-sentence runbook + repeated mentions + canonical-sources pointer. Sage: one sentence, no pointer. Alchemist: active discouragement ("`execute` does not imply Alchemist" three times, no positive example). Canonical sources never point to `doctrine/sage.md` or `doctrine/alchemist.md`. Highest-leverage single-file fix.
2. **[Critical] Ambient-by-default is enforced at the runtime layer too** (harness B.1) — the policy-lock condition that would ever require Alchemist cannot arise in a stock install. Decide deliberately: ship a minimal default locked-domain set, or document Alchemist as dormant-until-opt-in.
3. **[High] Sage's description is abstract-state, not symptom-first** — and `agents/sage.md` additionally dropped its own negative-boundary clause (see `sage-audit.md` Finding 1). Rewrite symptom-first with the exclusion restored.
4. **[High] Neither Sage nor Oracle exists in the skills catalog** (`src/registry/skills/index.json`); Alchemist is `discoverability: "explicit"` — natural-language routing can never surface any of them. Options: accept Task-tool-only and strengthen the constitution (preferred), or add a lightweight public `skills/sage` adjudication-checkpoint entry.
5. **[Medium] Alchemist's registry entry over-declares `omniroute`** at the entrypoint level when the skill scopes it to the worker sub-path — probing can mark the whole capability unavailable.
6. **[Medium] Skill-tree reinforcement is one-sided** — all 18 `oracle` mentions in `skills/**` are exclusionary; the only positive three-role routing text is buried in `skills/dispatch/references/agent-routing.md`. Add one positive escalate-to-Sage sentence to `architect`, `debugger`, and `dispatch`.
7. **[Medium] Subagents receive no role/routing context at spawn** (harness B.5) — a SessionStart/SubagentStart `additionalContext` bootstrap naming the three authorities and their triggers is a proven pattern (see absorption catalog: superpowers, addyosmani).

## Priority order across all three perspectives

1. Decide and fix the Arcane fail-open default (B.1 / C.2) — everything else about "gating" is fiction until this is settled.
2. Fix `AGENTS.md` asymmetry + Sage description (C.1, C.3) — cheap, single-file, highest behavioral leverage.
3. Make `Stop` gateable and define an Oracle PASS receipt (B.3, oracle-audit 1-2).
4. Anchor/self-package authority doctrine and extend the closure gate to `agents/`+`doctrine/` (A.1, A.5).
5. Declare and preflight the binaries; unblock a distribution channel (A.2, A.3, B.6).
6. Correct the hook event vocabulary and matchers; fix the `MultiEdit` bug (B.2, B.4, B.7).
