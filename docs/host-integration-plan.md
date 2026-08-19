# Legion host-integration implementation plan

**Status:** active implementation plan
**Governed by:** `docs/LEGION-CANONICAL-SSOT-v2.md` §36 and invariants I-19 … I-23
**Scope:** how canonical Legion semantics reach Claude Code, Codex, Gemini CLI, and
AGENTS-only harnesses; how Arcane enforces effects on each; how failures are diagnosed.

This plan owns **implementation steps only**. It defines no semantics. Where it appears to
disagree with the SSOT, the SSOT wins (§0).

---

## 0. Problem statement

Legion's canonical content is host-neutral. Its delivery was not. Before this work:

- the plugin was disabled in the operator's settings, so **no** capability or agent was
  discovered by Claude Code, and every other symptom was downstream of that;
- the installed plugin was a copy taken at commit `52a83ca` with the pre-`src/` layout, while
  the working tree had moved to `src/packages/**`. The manifest in the tree pointed the MCP
  server at `src/integrations/mcp/server.mjs`; the installed copy had no `src/`. The version
  string was identical across both, so nothing signalled the drift;
- `legion bind` wrote `.claude/agents/**` while the plugin package shipped `agents/**` for the
  same three roles — two installers for one harness;
- **no** binder projected `skills/` at all. Outside Claude Code, Legion was three roles and zero
  capabilities;
- Arcane's effect gate registered for tools it could not classify (`Agent`, `spawn_agent`) and
  did not register for tools it could (`WebFetch`, `WebSearch` — both declared `NETWORK_EGRESS`
  in `EFFECT_TOOL_MAP`), so a declared gate was a silent no-op;
- two gates could not be satisfied by any action available to the operator (below).

## 1. Completed

### 1.1 Arcane correctness (SSOT I-22, I-23)

| Defect | Fix | Verified by |
|---|---|---|
| `git push --force` refused with `ARC_APPROVAL_REQUIRED` that no action could produce — `approvalStore` defaults to `null` and nothing wires one | refusal now escalates to the host's own operator prompt (`permissionDecision: 'ask'`) when the target ref is isolated; ambiguous targets still hard-deny; a wired store still consumes a target-bound approval and skips the prompt | live hook: `ask` for `git push --force origin main`, `deny` for bare `git push --force`, `deny` for `rm -rf` |
| ambient Stop refused for missing contract receipts it had no opportunity to create | a session with no run binding and no contract is ambient: contract certification does not apply, and the result is labelled `enforcementHealth: 'unsupported'` so nothing reads as a passed certification | live hook: bare `Stop` allows; 573 Arcane tests pass |
| every hook event paid two Node cold starts | `arcane-hook.mjs` imports the adapter in-process | ~400 ms → ~354 ms per malformed-payload event |
| ledger re-read and re-verified the full hash chain up to three times per event | `#verify()` returns the records it verified; `append`/`inspect` reuse them. Same full-chain walk, same strength, computed once | `readFileUtf8` 274 ms → 105 ms in CPU profile |
| effect gate registered for unclassifiable tools, unregistered for classifiable ones | `Agent`/`spawn_agent` dropped from PreToolUse; `WebFetch`/`WebSearch` added to PostToolUse. `Bash` retained — it is load-bearing for the destructive-command, VCS-rewrite, and escalation gates | `hooks/hooks.json`; regression cases above |

### 1.2 Canonical projection (SSOT 36.2)

`scripts/generate-host-projection.mjs` → `src/registry/host-projection.json`.

Derived from canonical owners only: `skills/*/SKILL.md`, `src/roster/*.md`,
`src/registry/capabilities.json`. Emits 21 domain capabilities, 2 role entrypoints, 3 roles,
16 host capabilities, the 4 reference classes, and a fidelity declaration per harness.
`--check` fails on drift.

`skills/alchemist` and `skills/covenant` project as `kind: role-entrypoint`,
`discoverability: internal` (SSOT 6.1) — they are compatibility entrypoints into an authority,
not domain capabilities.

### 1.3 Diagnosis (SSOT 36.9)

`legion doctor --json` gained a `host` section: installation identity (active source, enabled
state, installed vs source version, **layout match**, commit sha), discovery counts, MCP
entrypoint existence, hook registrations, duplicate-installation-path conflicts, declared
fidelity per harness, and Arcane key/adapter health.

On the machine where this was written it reports, unprompted:
`enabled: false | versionMatches: true | layoutMatchesSource: false` — which is exactly the
failure that took manual investigation to find.

## 2. Declared fidelity today

Truthful, not aspirational (SSOT 36.5). Corrected as native projections land; never rounded up.

| Harness | Skill discovery | Authority agents | MCP | Arcane |
|---|---|---|---|---|
| claude-code | strong | strong | strong | strong |
| codex | unsupported | degraded | unsupported | degraded |
| gemini | unsupported | degraded | degraded | unsupported |
| agents-md | unsupported | degraded | unsupported | unsupported |

Gemini's Arcane value is `unsupported`, not `degraded`: no hook mechanism is wired, so effect
enforcement is **absent**. Stating that is the requirement; claiming otherwise would convert a
known gap into an unknown one.

## 3. Remaining work

### 3.1 Development path (do before re-enabling anything)

Keep the marketplace plugin **disabled** during refactor. Develop against the live tree with
`claude --plugin-dir <legion-root>` + `/reload-plugins`. Bump `plugin.json` `version` on every
layout or content change; a packaged install that differs from its source while sharing a version
is an unshippable state, and `legion doctor` now names it.

### 3.2 Claude native projection

Mostly present. Remaining: retire the `bind/claude-code.mjs` path once the plugin is confirmed
equivalent, so one installation path owns the harness (I-20). Do not keep both.

### 3.3 Codex native projection — **format unverified**

`.codex-plugin/plugin.json` is metadata only (no `mcpServers`, no hooks, no agents). Before
implementing, confirm against current Codex documentation which of skills / agents / hooks / MCP
the plugin format natively supports. Then render them from `host-projection.json`. The Arcane
`codex-adapter.mjs` already exists and needs only registration.

### 3.4 Gemini native projection — **format unverified**

Confirm whether Gemini CLI exposes a native Agent Skills / extension surface. If it does, project
capabilities into it; if it does not, `skillDiscovery` stays `unsupported` and the fidelity table
says so.

### 3.5 Renderers consume the projection

Refactor `src/lib/cli/commands/bind/*` to render from `host-projection.json` rather than
hand-authoring role text. `HARNESS_MODULES` in `bind.mjs` then becomes the real extension seam:
a new harness is a renderer, not a re-implementation. `legion bind` is demoted to a
compatibility/lower-fidelity projection and is not a second installer for any harness with a
native package (I-20).

### 3.6 Latency and the resident-Arcane decision

Current cost is ~880 ms per valid hook event; the Pre/Post pair doubles it per tool call.
After the ledger fix the remaining profile is `readFileUtf8` ~105 ms, an internal `git` subprocess
~66 ms, canonical encode ~67 ms, crypto ~43 ms.

Next, in order: (1) eliminate or cache the per-event `git` subprocess; (2) re-benchmark against a
ledger with realistic history, since the O(n) term only bites with accumulated events; (3) **only
then** decide on a resident Arcane runtime.

If a resident runtime is justified, keep it conceptually separate from the MCP semantic tool
server. Share a process only if lifecycle and security requirements genuinely align — not merely
because MCP happens to be persistent.

A deferred, larger change: replace full-chain re-verification with a signed verified-prefix
checkpoint (verify only records after the checkpoint, then advance it). This preserves detection
of tampering in old records while making append O(new). It changes a security-bearing invariant
and must be reviewed on its own, not folded into a performance pass.

### 3.7 Evals

Cross-harness discovery and enforcement evals: for each harness, assert the declared fidelity
matches observed behaviour. A fidelity table that drifts from reality is the failure mode this
whole section exists to prevent.

### 3.8 `skills/commit`

Narrow it to a Git delivery/effect operation. It already routes repository-wide diagnosis to
`/audit` rather than embedding it; confirm `references/manual.md` has not accumulated an audit
engine, and compose Audit/QA/security only when the work's risk requires it.

## 4. Ordering

1. ~~SSOT host-projection invariants~~ — done (§36, I-19 … I-23)
2. Claude live-plugin dev path + package cleanup — §3.1, §3.2
3. ~~Canonical projection IR~~ — done (§1.2)
4. Claude native projection — §3.2
5. Codex native projection — §3.3 (verify format first)
6. Gemini native projection — §3.4 (verify format first)
7. ~~Arcane hook narrowing, Stop correction, double-spawn removal~~ — done (§1.1)
8. Benchmark — §3.6
9. Resident Arcane decision — §3.6, only if 8 justifies it
10. ~~`legion doctor` host diagnosis~~ — done (§1.3); cross-harness evals remain — §3.7

Superseded paths are retired as their native equivalents land, not kept in parallel
(SSOT §26 retirement test, §32 non-goals).
