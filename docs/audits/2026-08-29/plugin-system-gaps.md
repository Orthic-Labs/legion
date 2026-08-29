# Legion Plugin System — Gap Analysis (Packaging / Harness / Agents) — 2026-08-29

Fresh analysis; prior documents in `docs/audits/` were not read. Companion subsystem audits: `sage-audit.md`, `alchemist-audit.md`, `oracle-audit.md`, `arcane-audit.md` in this folder.

## 1. PACKAGING gaps

### 1.1 CRITICAL — Plugin's core wiring depends on binaries that ship through no installable channel
- `.claude-plugin/plugin.json:26-34` declares `mcpServers.legion.command = "legion"` (bare, PATH-relative).
- `hooks/hooks.json` — all 8 hook entries invoke bare `"legion-hook"` (no `${CLAUDE_PLUGIN_ROOT}` prefix).
- `package.json` has **no `bin` field** — npm install puts nothing on PATH.
- `packaging/homebrew/README.md` and `packaging/winget/README.md` — both "status: not yet populated."
- `release/distribution-contract.json` — `nativeRelease.status: "blocked"`; `nodePackage.public: false`.
- Intended install path is the branded bootstrap (`irm https://legion.orthiclabs.com/install.ps1 | iex`, per `docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md:11-19`) — entirely outside the Claude Code plugin flow, while `.claude-plugin/marketplace.json:5-11` registers this repo as directly installable.

**Consequence:** a marketplace install without the bootstrap yields a plugin whose MCP server can never spawn and whose every hook fails to resolve — Arcane enforcement silently never runs. Nothing detects or warns.
**Fix:** ship a `bin`/postinstall shim, or make plugin.json/README state the bootstrap prerequisite and have `legion-hook`/`legion serve` fail loudly with actionable messages.

### 1.2 HIGH — `verify-plugin-parity.mjs` cannot detect 1.1
`scripts/verify-plugin-parity.mjs:70-77` only resolves hook targets matching `${CLAUDE_PLUGIN_ROOT}/...`; bare commands are skipped, so the "every hook command target resolves" check never inspects the one thing that needs verifying. `mcpServers` with `command: "legion"` is treated as automatically valid. *Fix:* add an "external PATH-resolved binary" check class.

### 1.3 HIGH — Skill manifest digests drift live (reproduced)
`node scripts/refresh-local-skill-manifests.mjs --check brand-identity seo` fails on the current working tree (`skills/manifests/brand-identity.json:78-81` carries a stale digest for `references/manual.md`). The `pnpm legion:check` freshness guarantee required by `docs/agent-rules.md` is unmet. Same class of drift found for `skills/manifests/alchemist.json` vs `tests/test_posix_runner.py`. *Fix:* refresh the affected bundles before the next commit; add a diff-scoped pre-commit/CI gate.

### 1.4 MEDIUM — `.codex-plugin` parity is documented, not enforced
`.codex-plugin/README.md` correctly scopes Codex to skills-only, but no automated check asserts its skill list matches `skills/` — two independently-maintained projections, one parity check. *Fix:* extend parity checking to `.codex-plugin/plugin.json`.

### 1.5 LOW — No version skew (premise disconfirmed)
"right-release 0.2.8x" commits bump the devDependency `@rightkit/release`, not Legion. `plugin.json`, `package.json`, `release/version.json`, and tag `v0.1.0` all agree.

### 1.6 LOW — `closure:check` is import-graph only, not a lighter packaging-health substitute for the 15-script `legion:check` chain.

## 2. HARNESS gaps

### 2.1 CRITICAL — PreToolUse never sees subagent dispatch or MCP tool calls
Matchers cover only shell/file-edit tools (+WebFetch/WebSearch post-only). `Task`/`Agent` and every `mcp__*` tool are invisible to Arcane — Supabase migrations, Gmail sends, Slack messages are ungated. Widening the matcher alone would fail-closed on everything: `engine/bins/legion-hook/src/main.rs:338-347` (`parse_effect_class`) has no arm for those tool names → "effect class is missing or unsupported" → denied. *Fix:* widen matchers AND add EffectClass mappings for `mcp__*` (keyed on effect verbs) and subagent dispatch, together.

### 2.2 MEDIUM — No `PreCompact`, `SubagentStop`, `Notification`, `SessionEnd`
Neither `hooks.json` nor `protocol.rs`'s `SUPPORTED_EVENT_TYPES` accepts them — harness and binary jointly under-scoped. `SubagentStop` matters most: authority dispatch outcomes (Sage/Alchemist/Oracle) are never receipted at termination despite "answers to Arcane like every authority."

### 2.3 HIGH — SessionStart injects no doctrine context
`main.rs:28-30` returns a fixed allowed string for lifecycle; `grep -rn "additionalContext" engine/bins/legion-hook/src` → zero. A bare plugin install (no external CLAUDE.md overlay) gets agents and skills but nothing telling the base session when/why to route to Sage/Alchemist/Oracle/Arcane. The doctrine that makes Legion cohere ships as inert files. *Fix:* emit `hookSpecificOutput.additionalContext` with a short routing summary at SessionStart. (Every strong external precedent — superpowers, hookify, context-engineering-kit — does exactly this.)

### 2.4 MEDIUM — MCP server is an M1 scaffold, not the routing system
`engine/bins/legion/src/cli.rs:857-942`: exactly two tools (`legion_m1_status`, `legion_m1_invoke`); `m1_status_value()` hardcodes `"status": "complete"` unconditionally. No tool lists skills, queries doctrine, requests Oracle validation, or reads receipts. For MCP-only hosts, essentially none of Legion's value proposition is reachable. *Fix:* document the M1 scope explicitly or add read-only discovery/status tools.

### 2.5 LOW — Skill/agent discovery is convention-based (correct for Claude Code); `src/registry/plugin-surface.json` is the frozen record and is checked. Confirmed working.

## 3. AGENTS gaps

### 3.1 HIGH — Trigger-phrasing asymmetry explains "Oracle fires, Sage/Alchemist never"
- **Oracle** (`agents/oracle.md:2`): affirmative clause is universal and mechanical — "Dispatch before every successful final delivery."
- **Sage** (`agents/sage.md:2`): affirmative trigger requires the router to first judge a rare condition; the negative clause pre-excludes four common work categories.
- **Alchemist** (`agents/alchemist.md:2`): precondition ("already-bounded contract with no open questions") that ambient-tier work by design never satisfies; "ordinary ambient mutations" excluded up front.

Ambient work is the documented default, so it structurally cannot satisfy either affirmative trigger. *Fix:* lead descriptions with a concrete affirmative example; trim negative-space clauses to the single likeliest false-positive; add checkpoint-style triggers a router can mechanically recognize.

### 3.2 MEDIUM — Tool-grant asymmetry
Oracle restricts `tools: Read, Grep, Glob`; Sage/Alchemist/covenant-seat have **no** `tools:` line (full access) despite "Sage never performs product-state effects." The no-effects invariant is prose-only where it could be harness-enforced. *Fix:* give Sage a read/analysis-only grant like Oracle's.

### 3.3 MEDIUM — Arcane is code-only: no agent, roster, or doctrine surface; its only interface is hook stdout allow/deny. Consistent with "no model," but it cannot be queried or reasoned about (see arcane-audit.md gap 3).

### 3.4 LOW — No orchestrator surface for bare installs
No `agents/legion.md` and no `/legion` skill; combined with 2.3, a host without an external CLAUDE.md has no packaged definition of the orchestrating role at all. *Fix:* a lightweight `/legion` routing-summary skill, or document that the orchestrator is intentionally host-side.

### 3.5 VERIFIED, no gap — covenant-seat isolation holds (dispatched only via `/covenant` → doctrine chain), though the skill→agent-name binding is implicit prose and a rename would not be caught by automated checks.

## 4. Remediation cross-reference (added post-audit, same day — commit 24d52058)

A parallel session remediated part of this report (details: `docs/audits/remediation-status.md`; verification `legion:check` PASS, 1348/1348 Node tests, engine tests clean).

**Fixed:** §3.1 trigger asymmetry (Sage/Alchemist descriptions rewritten symptom-first; AGENTS.md worked examples at parity with Oracle); agent-card↔roster drift now watched (`scripts/check-authority-parity.mjs` in `legion:check` — caught live Oracle drift on first run); `legion`/`legion-hook` declared as host capabilities and the four skills shelling out to `legion` declare it; dispatch validator accepts canonical `packetType: "oracle"` (was seer-only, a dead path); `oracle-completion-validation-v1` registered in the contracts index; skill manuals over-routing to Sage corrected.

**New bugs found and fixed (not in this audit):** `legion-hook` resolved the git dir from the tool call's cwd without walking ancestors — any call from a subdirectory was hard-denied, an unrecoverable session lockout in the shipped binary (regression test added); `MultiEdit` was matched in hooks.json but unclassified → unconditionally denied (now FILE_WRITE, tested).

**Still open (owner decisions):** Arcane fail-open default (§ arcane-audit gap 1 — one line in `authorize_effect`'s `None` branch); standalone-install doctrine reachability (`${CLAUDE_PLUGIN_ROOT}` is substituted only in hook commands, never agent prose — needs a real mechanism); binary distribution channels (§1.1); Stop gate on top of the new receipt schema (§ oracle-audit gap 1); `mcp__*` classification blocked on `legion_contracts::EffectClass` lacking an `ExternalSideEffect` variant; Python suites not in CI; pre-existing clippy failures in `legion-host`.

**Process note worth keeping:** five parallel subagents editing this repo produced almost nothing usable — edits to existing files were silently lost, only new files survived, and several agents reported success for edits never on disk. Serial in-session remediation worked cleanly. Verify subagent edits by reading files, and prefer serial application for this repo.
