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

### 3.1 Development path — done

Develop against the live tree, never the installed cache: `npm run plugin:dev` proves the live
plugin surface resolves and prints the `claude --plugin-dir <legion-root>` + `/reload-plugins`
invocation. Keep the marketplace plugin **disabled** while developing so the two do not both own
the harness.

`scripts/verify-plugin-parity.mjs` records the plugin's discoverable surface (skills, agents, MCP,
hooks) and a structural digest in `src/registry/plugin-surface.json`. `--check` fails when that
digest changes without a version bump — the exact drift the installed cache suffered when a
pre-`src/` snapshot shared version `0.1.0-dev.0` with a restructured tree. It runs in
`legion:check` and `prepack`, and `legion doctor` reports the surface digest, counts, and whether
the installed copy's layout still matches its source.

### 3.2 Claude native projection — done

The plugin package is the single installation owner for Claude Code. Parity is proven by
`verify-plugin-parity` (23 skills, 4 agents, 1 MCP server, 8 hook events all resolve), so
`bind/claude-code.mjs` is retired: it detects nothing, writes nothing, and an explicit
`--harness claude-code` request returns a note pointing at the plugin. `legion bind` no longer
competes for the Claude harness (I-20).

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

`src/lib/host-projection.mjs` is the shared read side of the generated projection. The AGENTS.md
binding — the harness-neutral path that covers harnesses without a native package — now carries
the compact capability catalog from it, so a non-Claude harness is no longer three roles and zero
capabilities. Roles already came from `src/lib/roster/index.mjs`, so no role text was duplicated.

Remaining (deferred to whoever owns Codex/Gemini): have those binders render their role and
capability text from the projection too, so `HARNESS_MODULES` becomes a pure renderer seam. Not
done here because neither harness is in use and building a renderer for an unused harness is
machinery without a driver (SSOT 26).

### 3.6 Latency — investigated; the dominant cost is algorithmic, not process-lifecycle

The per-event `git rev-parse HEAD` subprocess is **removed**. `resolveSourceRevision` now reads
HEAD from the git directory directly (`src/packages/arcane/host/source-revision.mjs`), returning
exactly what git would for normal checkouts, packed-refs, detached HEAD, worktrees, and
submodules, and falling back to the subprocess only for a layout it does not recognize. Output is
identical, so no enforcement behaviour changes. CPU profile confirms `spawnSync` at 0 ms after the
change; unit tests assert the resolver matches `git rev-parse HEAD` across all five layouts.

Benchmarked against realistic history — the live workspace already carries **774 ledger events** —
the dominant remaining cost is `readFileUtf8` at ~317 ms for a single event: the ledger reads and
verifies its entire hash chain on every append, which is O(n) in history and the reason a single
hook event is slow once a workspace has been used for a while. The per-event `git` subprocess and
module loading are now minor beside it.

This means a resident Arcane daemon is **not** justified: the cost is algorithmic, and a daemon
would still verify the chain on append. The fix is the deferred, larger change below, which is
security-bearing and out of scope for this host/runtime pass:

> Replace full-chain re-verification with a signed verified-prefix checkpoint (verify only records
> after the checkpoint, then advance it). This preserves tamper detection over old records while
> making append O(new). It changes a security-bearing invariant and must be reviewed on its own,
> not folded into a performance pass. It is a candidate for the SSOT/Arcane owner, not this task.

### 3.7 Evals

Cross-harness discovery and enforcement evals: for each harness, assert the declared fidelity
matches observed behaviour. A fidelity table that drifts from reality is the failure mode this
whole section exists to prevent.

### 3.8 `skills/commit` — deferred to the SSOT/capability owner

Narrowing `skills/commit` touches capability semantics, so it is out of scope for the host/runtime
pass and belongs to the SSOT/capability migration owner. It already routes repository-wide
diagnosis to `/audit` rather than embedding it; the remaining question is whether
`references/manual.md` has accumulated an audit engine, and that is a semantic call.

## 4. Ordering

1. ~~SSOT host-projection invariants~~ — done (§36, I-19 … I-23)
2. ~~Claude live-plugin dev path + package/version lifecycle~~ — done (§3.1)
3. ~~Canonical projection IR~~ — done (§1.2)
4. ~~Claude native projection + retire competing bind path~~ — done (§3.2)
5. Codex native projection — §3.3 (verify format first; deferred, harness not in use)
6. Gemini native projection — §3.4 (verify format first; deferred, harness not in use)
7. ~~Arcane hook narrowing, Stop correction, double-spawn removal~~ — done (§1.1)
8. ~~Benchmark — per-event git subprocess removed; ledger O(n) identified as the dominant cost~~ — done (§3.6)
9. Resident Arcane decision — **not justified** by the measurements; the fix is algorithmic (§3.6)
10. ~~`legion doctor` host diagnosis + plugin surface identity~~ — done (§1.3, §3.1); cross-harness evals remain — §3.7

Host/runtime work is complete. What remains (Codex/Gemini native packages, the ledger-checkpoint
change, `skills/commit` narrowing, cross-harness fidelity evals) is either gated on an unused
harness or is semantic/security-bearing work owned by the SSOT/capability and Arcane owners.

Superseded paths are retired as their native equivalents land, not kept in parallel
(SSOT §26 retirement test, §32 non-goals).
